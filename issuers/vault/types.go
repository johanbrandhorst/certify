package vault

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"strings"
	"time"
)

// https://www.vaultproject.io/api/secret/pki/index.html#parameters-14
type csrOpts struct {
	CSR               csrBytes  `json:"csr"`
	CommonName        string    `json:"common_name"`
	ExcludeCNFromSANS bool      `json:"exclude_cn_from_sans"`
	Format            string    `json:"format"`
	OtherSans         otherSans `json:"other_sans,omitempty"`
	TimeToLive        ttl       `json:"ttl,omitempty"`
}

type csrBytes []byte

func (c csrBytes) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	err := pem.Encode(&buf, &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: c,
	})
	if err != nil {
		return nil, err
	}
	ret := bytes.TrimSpace(buf.Bytes())
	return json.Marshal(string(ret))
}

type otherSans []string

func (o otherSans) MarshalJSON() ([]byte, error) {
	return []byte(`"` + strings.Join(o, ",") + `"`), nil
}

type ttl time.Duration

func (t ttl) MarshalJSON() ([]byte, error) {
	return []byte(`"` + time.Duration(t).String() + `"`), nil
}
