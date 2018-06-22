// engine_api.go defines public methods for the Engine for use in the
// application endpoints.

package arborist

import (
	"encoding/json"
	"fmt"
	"net/http"
)

type Response struct {
	Bytes         []byte
	InternalError error
	ExternalError error
	Code          int
}

func (response *Response) ok() bool {
	return response.InternalError != nil || response.ExternalError != nil
}

// errorResponse takes a Response with a
func (response *Response) addErrorJSON() {
	var errResponse = struct {
		Error string `json:"error"`
		Code  int    `json:"code,omitempty"`
	}{}
	if response.InternalError != nil {
		errResponse.Error = fmt.Sprintf("%s", response.InternalError)
	} else if response.ExternalError != nil {
		errResponse.Error = fmt.Sprintf("%s", response.ExternalError)
	}
	errResponse.Code = response.Code
	bytes, err := json.Marshal(errResponse)
	if err != nil {
		// should never happen
		panic(err)
	}
	response.Bytes = bytes
}

func (response *Response) writeBytes() []byte {
	if !response.ok() {
		response.addErrorJSON()
	}
	return response.Bytes
}

func (response *Response) Write(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Write(response.writeBytes())
	if response.Code > 0 {
		w.WriteHeader(response.Code)
	} else {
		w.WriteHeader(http.StatusOK)
	}
}

func (engine *Engine) HandleAuthRequest(request *AuthRequest) AuthResponse {
	return engine.giveAuthResponse(request)
}

// HandleAuthRequestBytes is a wrapper around HandleAuthRequest that includes
// JSON encoding and decoding for the request and response bytes.
func (engine *Engine) HandleAuthRequestBytes(bytes []byte) *Response {
	var authRequestJSON *AuthRequestJSON
	err := json.Unmarshal(bytes, authRequestJSON)
	if err != nil {
		response := &Response{
			ExternalError: err,
			Code:          http.StatusBadRequest,
		}
		return response
	}
	authRequest, err := engine.readAuthRequestFromJSON(*authRequestJSON)
	if err != nil {
		response := &Response{
			InternalError: err,
			Code:          http.StatusInternalServerError,
		}
		return response
	}
	authResponse := engine.HandleAuthRequest(authRequest)
	responseBytes, err := json.Marshal(authResponse)
	if err != nil {
		response := &Response{
			InternalError: err,
			Code:          http.StatusInternalServerError,
		}
		return response
	}
	response := &Response{Bytes: responseBytes, Code: http.StatusOK}
	return response
}

func (engine *Engine) HandleListPolicyIDsBytes() *Response {
	policyIDs := make([]string, len(engine.policies))
	for policyID := range engine.policies {
		policyIDs = append(policyIDs, policyID)
	}
	policies := struct {
		PolicyIDs []string `json:"policy_ids"`
	}{
		PolicyIDs: policyIDs,
	}
	bytes, err := json.Marshal(policies)
	if err != nil {
		// should never happen
		panic(err)
	}
	return &Response{Bytes: bytes, Code: http.StatusOK}
}

func (engine *Engine) HandleCreatePolicy(policy *Policy) *Response {
	if _, exists := engine.policies[policy.id]; exists {
		err := alreadyExists("policy", "id", policy.id)
		return &Response{
			ExternalError: err,
			Code:          http.StatusConflict,
		}
	}
	engine.policies[policy.id] = policy

	content := struct {
		Created PolicyJSON `json:"created"`
	}{
		Created: policy.toJSON(),
	}
	bytes, err := json.Marshal(content)
	if err != nil {
		// should never happen
		panic(err)
	}

	return &Response{
		Bytes: bytes,
		Code:  http.StatusCreated,
	}
}

func (engine *Engine) HandleCreatePolicyBytes(bytes []byte) *Response {
	var policyJSON *PolicyJSON
	err := json.Unmarshal(bytes, policyJSON)
	if err != nil {
		return &Response{
			ExternalError: err,
			Code:          http.StatusBadRequest,
		}
	}
	policy, err := engine.createPolicyFromJSON(policyJSON)
	if err != nil {
		return &Response{
			ExternalError: err,
			Code:          http.StatusConflict,
		}
	}
	return engine.HandleCreatePolicy(policy)
}

func (engine *Engine) HandleCreateResource(resource *Resource) *Response {
	if _, exists := engine.resources[resource.path]; exists {
		err := alreadyExists("resource", "path", resource.path)
		return &Response{
			ExternalError: err,
			Code:          http.StatusConflict,
		}
	}
	engine.resources[resource.path] = resource

	content := struct {
		Created ResourceJSON `json:"created"`
	}{
		Created: resource.toJSON(),
	}
	bytes, err := json.Marshal(content)
	if err != nil {
		panic(err)
	}

	return &Response{
		Bytes: bytes,
		Code:  http.StatusCreated,
	}
}

func (engine *Engine) HandlePolicyRead(policyID string) *Response {
	policy, exists := engine.policies[policyID]
	if !exists {
		err := notExist("policy", "id", policyID)
		return &Response{
			ExternalError: err,
			Code:          http.StatusNotFound,
		}
	}
	bytes, err := json.Marshal(policy.toJSON())
	if err != nil {
		return &Response{
			InternalError: err,
			Code:          http.StatusInternalServerError,
		}
	}
	return &Response{
		Bytes: bytes,
		Code:  http.StatusOK,
	}
}

func (engine *Engine) HandlePolicyUpdate(policyID string, bytes []byte) *Response {
	var policyJSON *PolicyJSON
	err := json.Unmarshal(bytes, policyJSON)
	if err != nil {
		return &Response{
			ExternalError: err,
			Code:          http.StatusBadRequest,
		}
	}

	updatedPolicy, err := engine.updatePolicyWithJSON(policyID, policyJSON)
	if err != nil {
		return &Response{
			ExternalError: err,
			Code:          http.StatusBadRequest,
		}
	}

	content := struct {
		Updated PolicyJSON `json:"updated"`
	}{
		Updated: updatedPolicy.toJSON(),
	}
	responseBytes, err := json.Marshal(content)
	if err != nil {
		return &Response{
			InternalError: err,
			Code:          http.StatusInternalServerError,
		}
	}

	return &Response{
		Bytes: responseBytes,
		Code:  http.StatusOK,
	}
}

func (engine *Engine) HandlePolicyRemove(policyID string) *Response {
	err := engine.removePolicy(policyID)
	if err != nil {
		return &Response{
			ExternalError: err,
			Code:          http.StatusNotFound,
		}
	}
	return &Response{Code: http.StatusNoContent}
}
