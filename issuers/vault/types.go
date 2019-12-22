package vault

import (
	"context"
	"strings"
	"time"

	"github.com/hashicorp/vault/api"
)

// AuthMethod defines the interface required to implement
// custom authentication against the Vault server.
type AuthMethod interface {
	GetToken(context.Context, *api.Client) (string, error)
}

// ConstantToken implements AuthMethod with a constant token
type ConstantToken string

// GetToken returns the token
func (c ConstantToken) GetToken(context.Context, *api.Client) (string, error) {
	return string(c), nil
}


// https://www.vaultproject.io/api/secret/pki/index.html#parameters-14
type csrOpts struct {
	CSR               string    `json:"csr"`
	CommonName        string    `json:"common_name"`
	ExcludeCNFromSANS bool      `json:"exclude_cn_from_sans"`
	Format            string    `json:"format"`
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
