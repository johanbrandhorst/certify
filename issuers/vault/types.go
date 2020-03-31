package vault

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/vault/api"
)

// AuthMethod defines the interface required to implement
// custom authentication against the Vault server.
type AuthMethod interface {
	SetToken(context.Context, *api.Client) error
}

// ConstantToken implements AuthMethod with a constant token
type ConstantToken string

// SetToken sets the clients token to the constant token value.
func (c ConstantToken) SetToken(_ context.Context, cli *api.Client) error {
	cli.SetToken(string(c))
	return nil
}

// RenewingToken is used for automatically renewing
// the token used to authenticate with Vault. RenewingToken
// requires SetToken to be called at least once before the
// expiry of the initial token.
type RenewingToken struct {
	// Initial is the token used to initially
	// authenticate against Vault. It must be
	// renewable.
	Initial string
	// RenewBefore configures how long before the expiry
	// of the token it should be renewed. Defaults
	// to 30 minutes before expiry.
	RenewBefore time.Duration
	// TimeToLive configures how long the new token
	// should be valid for. Defaults to 24 hours.
	TimeToLive time.Duration

	o sync.Once

	token   string
	tokenMu sync.Mutex
	errC    chan error
	cancel  func()
}

// SetToken implements AuthMethod for RenewingToken.
func (r *RenewingToken) SetToken(ctx context.Context, cli *api.Client) error {
	var err error
	r.o.Do(func() {
		cli.SetToken(string(r.Initial))
		r.token = r.Initial
		if r.RenewBefore <= 0 {
			r.RenewBefore = 30 * time.Minute
		}
		if r.TimeToLive <= 0 {
			r.TimeToLive = 24 * time.Hour
		}
		r.errC = make(chan error)

		req := cli.NewRequest("GET", "/v1/auth/token/lookup-self")
		resp, tErr := cli.RawRequestWithContext(ctx, req)
		if tErr != nil {
			err = tErr
			return
		}
		defer resp.Body.Close()

		tok, tErr := api.ParseSecret(resp.Body)
		if tErr != nil {
			err = tErr
			return
		}

		rn, tErr := tok.TokenIsRenewable()
		if tErr != nil {
			err = tErr
			return
		}

		if !rn {
			err = fmt.Errorf("token was not renewable")
			return
		}

		ttl, tErr := tok.TokenTTL()
		if tErr != nil {
			err = tErr
			return
		}

		// Start background process for renewing the token
		var cctx context.Context
		cctx, r.cancel = context.WithCancel(context.Background())
		go func() {
			for {
				wait := ttl - r.RenewBefore
				if wait < time.Second {
					// Wait for at least one second, in case we somehow end up
					// with a very short wait.
					wait = time.Second
				}

				tk := time.NewTicker(wait)

				select {
				case <-cctx.Done():
					return
				case <-tk.C:
					tk.Stop()
				}

				// Needs renewal
				req := cli.NewRequest("PUT", "/v1/auth/token/renew-self")

				body := map[string]interface{}{"increment": r.TimeToLive.Seconds()}
				if err := req.SetJSONBody(body); err != nil {
					r.errC <- err
					return
				}
				resp, tErr := cli.RawRequestWithContext(cctx, req)
				if tErr != nil {
					r.errC <- err
					return
				}
				defer resp.Body.Close()

				tok, tErr := api.ParseSecret(resp.Body)
				if tErr != nil {
					r.errC <- err
					return
				}
				if err != nil {
					r.errC <- err
					return
				}

				r.tokenMu.Lock()
				r.token = tok.Auth.ClientToken
				r.tokenMu.Unlock()
				ttl = r.TimeToLive
			}
		}()
	})
	if err != nil {
		return err
	}

	select {
	case err = <-r.errC:
		return err
	default:
	}

	r.tokenMu.Lock()
	tok := r.token
	r.tokenMu.Unlock()
	cli.SetToken(tok)

	return nil
}

// Close can be used to release resources associated with the token.
func (r *RenewingToken) Close() error {
	r.cancel()
	return nil
}

// https://www.vaultproject.io/api/secret/pki/index.html#parameters-14
type csrOpts struct {
	CSR               string    `json:"csr"`
	CommonName        string    `json:"common_name"`
	ExcludeCNFromSANS bool      `json:"exclude_cn_from_sans"`
	Format            string    `json:"format"`
	AltNames          otherSans `json:"alt_names,omitempty"`
	IPSans            otherSans `json:"ip_sans,omitempty"`
	URISans           otherSans `json:"uri_sans,omitempty"`
	OtherSans         otherSans `json:"other_sans,omitempty"`
	TimeToLive        ttl       `json:"ttl,omitempty"`
}

type otherSans []string

func (o otherSans) MarshalJSON() ([]byte, error) {
	return []byte(`"` + strings.Join(o, ",") + `"`), nil
}

type ttl time.Duration

func (t ttl) MarshalJSON() ([]byte, error) {
	return []byte(`"` + time.Duration(t).String() + `"`), nil
}
