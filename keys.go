package certify

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"sync"
)

type singletonKey struct {
	key crypto.PrivateKey
	err error
	o   sync.Once
}

func (s *singletonKey) Generate() (crypto.PrivateKey, error) {
	s.o.Do(func() {
		s.key, s.err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	})

	return s.key, s.err
}
