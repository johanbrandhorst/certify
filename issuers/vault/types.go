package vault

import (
	"strings"
	"time"
)

// https://www.vaultproject.io/api/secret/pki/index.html#parameters-14
type csrOpts struct {
	CSR               string    `json:"csr"`
	CommonName        string    `json:"common_name"`
	ExcludeCNFromSANS bool      `json:"exclude_cn_from_sans"`
	Format            string    `json:"format"`
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
