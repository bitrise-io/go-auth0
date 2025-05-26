package auth0

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"

	"gopkg.in/go-jose/go-jose.v2"
)

var (
	ErrInvalidContentType = errors.New("should have a JSON content type for JWKS endpoint")
	ErrInvalidAlgorithm   = errors.New("algorithm is invalid")
)

type JWKClientOptions struct {
	URI    string
	Client *http.Client
}

type JWKS struct {
	Keys []jose.JSONWebKey `json:"keys"`
}

type JWKClient struct {
	keyCacher KeyCacher
	mu        sync.Mutex
	options   []JWKClientOptions
	extractor RequestTokenExtractor
}

// NewJWKClient creates a new JWKClient instance from the provided options.
// It accepts either a single JWKClientOptions or a slice of JWKClientOptions.
func NewJWKClient[T JWKClientOptions | []JWKClientOptions](options T, extractor RequestTokenExtractor) *JWKClient {
	return NewJWKClientWithCache(options, extractor, nil)
}

// NewJWKClientWithCache creates a new JWKClient instance from the
// provided options and a custom keycacher interface.
// Passing nil to keyCacher will create a persistent key cacher
func NewJWKClientWithCache[T JWKClientOptions | []JWKClientOptions](options T, extractor RequestTokenExtractor, keyCacher KeyCacher) *JWKClient {
	if extractor == nil {
		extractor = RequestTokenExtractorFunc(FromHeader)
	}
	if keyCacher == nil {
		keyCacher = newMemoryPersistentKeyCacher()
	}

	var opts []JWKClientOptions
	switch v := any(options).(type) {
	case JWKClientOptions:
		opts = []JWKClientOptions{v}
	case []JWKClientOptions:
		opts = v
	}

	for i := range opts {
		if opts[i].Client == nil {
			opts[i].Client = http.DefaultClient
		}
	}

	return &JWKClient{
		keyCacher: keyCacher,
		options:   opts,
		extractor: extractor,
	}
}

// GetKey returns the key associated with the provided ID.
func (j *JWKClient) GetKey(ID string) (jose.JSONWebKey, error) {
	j.mu.Lock()
	defer j.mu.Unlock()

	searchedKey, err := j.keyCacher.Get(ID)
	if err != nil {
		keys, err := j.downloadKeys()
		if err != nil {
			return jose.JSONWebKey{}, err
		}
		addedKey, err := j.keyCacher.Add(ID, keys)
		if err != nil {
			return jose.JSONWebKey{}, err
		}
		return *addedKey, nil
	}

	return *searchedKey, nil
}

func (j *JWKClient) downloadKeys() ([]jose.JSONWebKey, error) {
	var allKeys []jose.JSONWebKey
	for _, opt := range j.options {
		req, err := http.NewRequest("GET", opt.URI, new(bytes.Buffer))
		if err != nil {
			return []jose.JSONWebKey{}, err
		}
		resp, err := opt.Client.Do(req)

		if err != nil {
			return []jose.JSONWebKey{}, err
		}
		defer resp.Body.Close()

		if contentH := resp.Header.Get("Content-Type"); !strings.HasPrefix(contentH, "application/json") {
			return []jose.JSONWebKey{}, ErrInvalidContentType
		}

		var jwks = JWKS{}
		err = json.NewDecoder(resp.Body).Decode(&jwks)

		if err != nil {
			return []jose.JSONWebKey{}, err
		}

		if len(jwks.Keys) < 1 {
			return []jose.JSONWebKey{}, ErrNoKeyFound
		}

		allKeys = append(allKeys, jwks.Keys...)
	}
	return allKeys, nil
}

// GetSecret implements the GetSecret method of the SecretProvider interface.
func (j *JWKClient) GetSecret(r *http.Request) (interface{}, error) {
	token, err := j.extractor.Extract(r)
	if err != nil {
		return nil, err
	}

	if len(token.Headers) < 1 {
		return nil, ErrNoJWTHeaders
	}

	header := token.Headers[0]

	return j.GetKey(header.KeyID)
}
