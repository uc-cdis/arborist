package authutils

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	jose "gopkg.in/square/go-jose.v2"
)

// KeysManager handles the storage and updating of a set of JWKs. The
// KeysManager must be configured with the URL for the endpoint of a keys
// provider that returns the JWKS in the format specified by RFC 7517.
type KeysManager struct {
	URL     string
	KeyList []*jose.JSONWebKey
	KeyMap  map[string]*jose.JSONWebKey
}

func NewKeysManager(jwkURL string) KeysManager {
	keysManager := KeysManager{
		URL:     jwkURL,
		KeyList: make([]*jose.JSONWebKey, 0),
		KeyMap:  make(map[string]*jose.JSONWebKey),
	}
	return keysManager
}

// Lookup finds the key with the given ID. If none is found attached to the
// application currently, it makes a request to the URL configured in the
// manager to retrieve new keys.
func (manager *KeysManager) Lookup(keyID string) (*jose.JSONWebKey, error) {
	var jwk *jose.JSONWebKey
	jwk, exists := manager.KeyMap[keyID]
	// If no key is found, refresh the stored key set.
	if !exists {
		if err := manager.Refresh(); err != nil {
			return jwk, err
		}
		jwk, exists = manager.KeyMap[keyID]
		// If still no key is found, return an error.
		if !exists {
			return jwk, errors.New(fmt.Sprintf("no key exists with ID: %s", keyID))
		}
	}
	return jwk, nil
}

// KeysResponse is used for decoding the JSON response from the service issuing
// the RSA keys.
type KeysResponse struct {
	Keys []map[string]string `json:"keys"`
}

// Clear empties all keys from the KeysManager.
func (manager *KeysManager) Clear() {
	manager.KeyList = make([]*jose.JSONWebKey, 0)
	manager.KeyMap = make(map[string]*jose.JSONWebKey)
}

// Insert adds a single jose.JSONWebKey to the KeysManager.
func (manager *KeysManager) Insert(key jose.JSONWebKey) {
	manager.KeyMap[key.KeyID] = &key
	manager.KeyList = append(manager.KeyList, &key)
}

// Refresh makes a request to the URL configured in the KeysManager to update
// the keys it stores with the latest results from the provider.
func (manager *KeysManager) Refresh() error {
	// Get the JSON response from the URL configured in the manager.
	resp, err := http.Get(manager.URL)
	if err != nil {
		return err
	}

	// Parse the response JSON into a jose.JSONWebKeySet.
	var keySet jose.JSONWebKeySet
	err = json.NewDecoder(resp.Body).Decode(&keySet)
	defer resp.Body.Close()
	if err != nil {
		return err
	}

	// Insert the keys parsed into the JWKS into the manager.
	manager.Clear()
	for _, key := range keySet.Keys {
		manager.Insert(key)
	}

	return nil
}

// DefaultKey returns the first key in the list of keys stored by the
// KeysManager. By internal convention, the keys provider should return the
// keys in chronological order, with the most recently-created keys first,
// which is meant to be the default.
func (manager *KeysManager) DefaultKey() *jose.JSONWebKey {
	if len(manager.KeyList) > 0 {
		return manager.KeyList[0]
	} else {
		return nil
	}
}
