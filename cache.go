package certify

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"

	"github.com/johanbrandhorst/certify/internal/keys"
)

const (
	keyExt  = ".key"
	certExt = ".crt"
)

// Cache describes the interface that certificate caches must implement.
// Cache implementations must be thread safe.
type Cache interface {
	// Get returns a certificate data for the specified key.
	// If there's no such key, Get returns ErrCacheMiss.
	Get(context.Context, string) (*tls.Certificate, error)

	// Put stores the data in the cache under the specified key.
	Put(context.Context, string, *tls.Certificate) error

	// Delete removes a certificate data from the cache under the specified key.
	// If there's no such key in the cache, Delete returns nil.
	Delete(context.Context, string) error
}

// ErrCacheMiss should be returned by Cache implementations
// when a certificate could not be found.
var ErrCacheMiss = errors.New("no matching certificate found")

type memCache struct {
	mu    *sync.RWMutex
	cache map[string]*tls.Certificate
}

// NewMemCache creates an in-memory cache that implements the Cache interface.
func NewMemCache() Cache {
	return &memCache{
		mu:    &sync.RWMutex{},
		cache: map[string]*tls.Certificate{},
	}
}

func (m memCache) Get(_ context.Context, key string) (*tls.Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	cert, ok := m.cache[key]
	if ok {
		return cert, nil
	}

	return nil, ErrCacheMiss
}

func (m *memCache) Put(_ context.Context, key string, cert *tls.Certificate) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.cache[key] = cert
	return nil
}

func (m *memCache) Delete(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.cache, key)
	return nil
}

// DirCache implements Cache using a directory on the local filesystem.
// If the directory does not exist, it will be created with 0700 permissions.
//
// It is strongly based on the acme/autocert DirCache type.
// https://github.com/golang/crypto/blob/88942b9c40a4c9d203b82b3731787b672d6e809b/acme/autocert/cache.go#L40
type DirCache string

// Get reads a certificate data from the specified file name.
func (d DirCache) Get(ctx context.Context, name string) (*tls.Certificate, error) {
	name = filepath.Join(string(d), name)

	var (
		cert tls.Certificate
		err  error
		done = make(chan struct{})
	)

	go func() {
		cert, err = tls.LoadX509KeyPair(name+certExt, name+keyExt)
		if err == nil {
			// Need to parse the Leaf manually for expiration checks
			var leaf *x509.Certificate
			leaf, err = x509.ParseCertificate(cert.Certificate[0])
			if err == nil {
				cert.Leaf = leaf
			}
		}
		close(done)
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-done:
	}

	if os.IsNotExist(err) {
		return nil, ErrCacheMiss
	}
	if err != nil {
		return nil, err
	}

	return &cert, nil
}

// Put writes the certificate data to the specified file name.
// The file will be created with 0600 permissions.
func (d DirCache) Put(ctx context.Context, name string, cert *tls.Certificate) error {
	if err := os.MkdirAll(string(d), 0o700); err != nil {
		return err
	}

	done := make(chan struct{})
	var (
		err             error
		tmpKey, tmpCert string
		newName         = filepath.Join(string(d), name)
	)
	go func() {
		defer close(done)

		var tmpKey, tmpCert string
		if tmpKey, tmpCert, err = d.writeTempFiles(name, cert); err != nil {
			return
		}

		select {
		case <-ctx.Done():
			// Don't overwrite the file if the context was canceled.
		default:
			newName := filepath.Join(string(d), name)
			err = os.Rename(tmpKey, newName+keyExt)
			if err != nil {
				return
			}
			err = os.Rename(tmpCert, newName+certExt)
			if err != nil {
				return
			}
		}
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-done:
	}

	// Clean up after ourselves on error, remove all artifacts from this request
	if err != nil {
		err = removeWrapErr(tmpKey, err)
		err = removeWrapErr(tmpCert, err)
		err = removeWrapErr(newName+keyExt, err)
		err = removeWrapErr(newName+certExt, err)
	}

	return err
}

// Delete removes the specified file name.
func (d DirCache) Delete(ctx context.Context, name string) error {
	name = filepath.Join(string(d), name)
	var (
		err  error
		done = make(chan struct{})
	)
	go func() {
		defer close(done)

		err = removeWrapErr(name+keyExt, err)
		err = removeWrapErr(name+certExt, err)
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-done:
	}

	return err
}

func removeWrapErr(fileName string, err error) error {
	if e := os.Remove(fileName); e != nil && !os.IsNotExist(e) {
		err = fmt.Errorf("failed to delete %s: %v: %v", fileName, e, err)
	}

	return err
}

// writeTempFile writes b to a temporary file, closes the file and returns its path.
func (d DirCache) writeTempFiles(prefix string, cert *tls.Certificate) (string, string, error) {
	keyPath, err := d.writeTempKey(prefix, cert)
	if err != nil {
		return "", "", err
	}

	certPath, err := d.writeTempCert(prefix, cert)
	if err != nil {
		return "", "", err
	}

	return keyPath, certPath, err
}

func (d DirCache) writeTempKey(prefix string, cert *tls.Certificate) (string, error) {
	pem, err := keys.Marshal(cert.PrivateKey)
	if err != nil {
		return "", err
	}

	// TempFile uses 0600 permissions
	f, err := ioutil.TempFile(string(d), prefix+keyExt)
	if err != nil {
		return "", err
	}

	if _, err = f.Write(pem); err != nil {
		return "", err
	}

	return f.Name(), f.Close()
}

func (d DirCache) writeTempCert(prefix string, cert *tls.Certificate) (string, error) {
	f, err := ioutil.TempFile(string(d), prefix+certExt)
	if err != nil {
		return "", err
	}

	for _, c := range cert.Certificate {
		block := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: c,
		}

		err := pem.Encode(f, block)
		if err != nil {
			return "", err
		}
	}

	return f.Name(), f.Close()
}

type noopCache struct{}

func (*noopCache) Get(context.Context, string) (*tls.Certificate, error) {
	return nil, ErrCacheMiss
}

func (*noopCache) Put(context.Context, string, *tls.Certificate) error {
	return nil
}

func (*noopCache) Delete(context.Context, string) error {
	return nil
}
