// engine_api.go defines public methods for the Engine for use in the
// application endpoints.
//
// These functions are mostly at the "highest level", using []byte types,
// handling the deserialization of inputs and serialization of responses.

package arborist

import (
	"encoding/json"
)

func (engine *Engine) HandleAuthRequest(request *AuthRequest) AuthResponse {
	return engine.giveAuthResponse(request)
}

// HandleAuthRequestBytes is a wrapper around HandleAuthRequest that includes
// JSON encoding and decoding for the request and response bytes.
func (engine *Engine) HandleAuthRequestBytes(bytes []byte) ([]byte, error) {
	var authRequestJSON *AuthRequestJSON
	err := json.Unmarshal(bytes, authRequestJSON)
	if err != nil {
		return nil, err
	}
	authRequest, err := engine.readAuthRequestFromJSON(*authRequestJSON)
	if err != nil {
		return nil, err
	}
	authResponse := engine.HandleAuthRequest(authRequest)
	responseBytes, err := json.Marshal(authResponse)
	if err != nil {
		return nil, err
	}
	return responseBytes, nil
}
