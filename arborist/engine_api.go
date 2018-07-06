// engine_api.go defines public methods for the Engine for use in the
// application endpoints.
//
// These differ from the functions in engine.go in that these functions
// basically all return a Response, which can be used directly in an endpoint
// to write out a response, like this:
//
// ```go
// http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//     // Parse the JSON body first
//     // ...
//
//     response := engine.HandlePolicyUpdate(policyID, body)
//     err := response.Write(w)
//
//     // ...
// })
// ```
//
// (Also, just see the `server/router_*.go` files for actual examples.)

package arborist

import (
	"encoding/json"
	"net/http"
)

type Response struct {
	Bytes         []byte
	InternalError error
	ExternalError error
	Code          int
}

type errorInfo struct {
	Message string `json:"message"`
	Code    int    `json:"code,omitempty"`
}

func (response *Response) ok() bool {
	return response.InternalError == nil && response.ExternalError == nil
}

// errorResponse takes a Response with a
func (response *Response) addErrorJSON() *Response {
	var errResponse = struct {
		Err errorInfo `json:"error"`
	}{
		Err: errorInfo{},
	}
	if response.InternalError != nil {
		if response.Code == 0 {
			response.Code = http.StatusInternalServerError
		}
		errResponse.Err.Message = response.InternalError.Error()
	} else if response.ExternalError != nil {
		if response.Code == 0 {
			response.Code = http.StatusBadRequest
		}
		errResponse.Err.Message = response.ExternalError.Error()
	}
	errResponse.Err.Code = response.Code
	bytes, err := json.Marshal(errResponse)
	if err != nil {
		// should never happen; fix errResponse above
		panic(err)
	}
	response.Bytes = bytes
	return response
}

func (response *Response) Write(w http.ResponseWriter, pretty bool) error {
	if response.Code > 0 {
		w.WriteHeader(response.Code)
	} else {
		w.WriteHeader(http.StatusOK)
	}
	w.Header().Set("Content-Type", "application/json")
	if !response.ok() {
		response.addErrorJSON()
	}

	if pretty {
		response.Prettify()
	}

	response.Bytes = append(response.Bytes, "\n"...)
	_, err := w.Write(response.Bytes)
	if err != nil {
		return err
	}

	return nil
}

func (response *Response) Prettify() *Response {
	content := make(map[string]interface{})
	err := json.Unmarshal(response.Bytes, &content)
	if err != nil {
		// unrecoverable; response has written garbage JSON
		panic(err)
	}
	pretty, err := json.MarshalIndent(content, "", "    ")
	if err != nil {
		// should never happen; previous unmarshal is incorrect for some reason
		panic(err)
	}
	response.Bytes = pretty
	return response
}

// Handlers for auth requests

func (engine *Engine) HandleAuthRequest(request *AuthRequest) AuthResponse {
	return engine.giveAuthResponse(request)
}

// HandleListAuthorizedResources takes a list of policies granted to a user
// and lists all the resources which that user has access to through any role.
func (engine *Engine) HandleListAuthorizedResources(policies []string) *Response {
	resources, err := engine.listAuthedResources(policies)
	if err != nil {
		return &Response{
			ExternalError: err,
			Code:          http.StatusBadRequest,
		}
	}
	paths := make([]string, len(resources))
	for i := range resources {
		paths[i] = resources[i].path
	}
	resourcesObject := struct {
		resources []string `json:"resources"`
	}{
		resources: paths,
	}
	bytes, err := json.Marshal(resourcesObject)
	if err != nil {
		// should never happen; fix struct above
		panic(err)
	}
	return &Response{Bytes: bytes, Code: http.StatusOK}
}

// HandleAuthRequestBytes is a wrapper around HandleAuthRequest that includes
// JSON encoding and decoding for the request and response bytes.
func (engine *Engine) HandleAuthRequestBytes(bytes []byte) *Response {
	var authRequestJSON AuthRequestJSON
	err := json.Unmarshal(bytes, &authRequestJSON)
	if err != nil {
		response := &Response{
			ExternalError: err,
			Code:          http.StatusBadRequest,
		}
		return response
	}
	authRequest, err := engine.readAuthRequestFromJSON(authRequestJSON)
	if err != nil {
		response := &Response{
			ExternalError: err,
			Code:          http.StatusBadRequest,
		}
		return response
	}
	authResponse := engine.HandleAuthRequest(authRequest)
	responseBytes, err := json.Marshal(authResponse.toJSON())
	if err != nil {
		response := &Response{
			InternalError: err,
			Code:          http.StatusInternalServerError,
		}
		return response
	}
	return &Response{Bytes: responseBytes, Code: http.StatusOK}
}

// Handlers for Policy endpoints

func (engine *Engine) HandleListPolicyIDs() *Response {
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

func (engine *Engine) HandlePolicyCreate(bytes []byte) *Response {
	var policyJSON PolicyJSON
	err := json.Unmarshal(bytes, &policyJSON)
	if err != nil {
		return &Response{
			ExternalError: err,
			Code:          http.StatusBadRequest,
		}
	}
	policy, err := engine.createPolicyFromJSON(&policyJSON)
	if err != nil {
		return &Response{
			ExternalError: err,
			Code:          http.StatusConflict,
		}
	}

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

	bytes, err = json.Marshal(content)
	if err != nil {
		// should never happen; fix `content` JSON just above
		panic(err)
	}

	return &Response{
		Bytes: bytes,
		Code:  http.StatusCreated,
	}
}

func (engine *Engine) HandlePolicyCreateBulk(bytes []byte) *Response {
	var policiesJSON PolicyBulkJSON
	err := json.Unmarshal(bytes, &policiesJSON)
	if err != nil {
		return &Response{
			ExternalError: err,
			Code:          http.StatusBadRequest,
		}
	}

	content := struct {
		Created []PolicyJSON `json:"created"`
	}{
		Created: make([]PolicyJSON, 0),
	}

	policies, err := engine.createPoliciesFromJSON(&policiesJSON)
	if err != nil {
		return &Response{
			ExternalError: err,
			Code:          http.StatusBadRequest,
		}
	}

	for _, policy := range policies {
		content.Created = append(content.Created, policy.toJSON())
	}

	responseBytes, err := json.Marshal(content)
	if err != nil {
		return &Response{
			InternalError: err,
			Code:          http.StatusBadRequest,
		}
	}

	return &Response{
		Bytes: responseBytes,
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
	var policyJSON PolicyJSON
	err := json.Unmarshal(bytes, &policyJSON)
	if err != nil {
		return &Response{
			ExternalError: err,
			Code:          http.StatusBadRequest,
		}
	}

	updatedPolicy, err := engine.updatePolicyWithJSON(policyID, &policyJSON)
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

func (engine *Engine) HandlePolicyPatch(policyID string, bytes []byte) *Response {
	var policyJSON PolicyJSON
	err := json.Unmarshal(bytes, &policyJSON)
	if err != nil {
		return &Response{
			ExternalError: err,
			Code:          http.StatusBadRequest,
		}
	}

	updatedPolicy, err := engine.appendPolicyWithJSON(policyID, &policyJSON)
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

// Handlers for Resource endpoints

func (engine *Engine) HandleListResourcePaths() *Response {
	content := struct {
		Paths []string `json:"resource_paths"`
	}{
		Paths: engine.listResourcePaths(),
	}
	bytes, err := json.Marshal(content)
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

func (engine *Engine) HandleResourceRead(resourcePath string) *Response {
	resourceJSON, err := engine.getResourceJSON(resourcePath)
	if err != nil {
		return &Response{
			ExternalError: err,
			Code:          http.StatusNotFound,
		}
	}
	bytes, err := json.Marshal(resourceJSON)
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

func (engine *Engine) HandleResourceCreate(bytes []byte) *Response {
	var resourceJSON ResourceJSON
	err := json.Unmarshal(bytes, &resourceJSON)
	if err != nil {
		return &Response{
			ExternalError: err,
			Code:          http.StatusBadRequest,
		}
	}
	resource, err := engine.addResourceFromJSON(&resourceJSON, "")
	if err != nil {
		return &Response{
			ExternalError: err,
			Code:          http.StatusBadRequest,
		}
	}
	content := struct {
		Created ResourceJSON `json:"created"`
	}{
		Created: resource.toJSON(),
	}
	responseBytes, err := json.Marshal(content)
	if err != nil {
		return &Response{
			InternalError: err,
			Code:          http.StatusBadRequest,
		}
	}
	return &Response{
		Bytes: responseBytes,
		Code:  http.StatusCreated,
	}
}

func (engine *Engine) HandleResourceUpdate(resourcePath string, bytes []byte) *Response {
	var resourceJSON ResourceJSON
	err := json.Unmarshal(bytes, &resourceJSON)
	if err != nil {
		return &Response{
			ExternalError: err,
			Code:          http.StatusBadRequest,
		}
	}
	updatedResource, err := engine.updateResourceWithJSON(resourcePath, &resourceJSON)
	if err != nil {
		return &Response{
			ExternalError: err,
			Code:          http.StatusBadRequest,
		}
	}
	content := struct {
		Updated ResourceJSON `json:"updated"`
	}{
		Updated: updatedResource.toJSON(),
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

func (engine *Engine) HandleResourceRemove(resourcePath string) *Response {
	resource, exists := engine.resources[resourcePath]
	if !exists {
		err := notExist("resource", "path", resourcePath)
		return &Response{
			ExternalError: err,
			Code:          http.StatusNotFound,
		}
	}
	engine.removeResourceRecursively(resource)
	return &Response{Code: http.StatusNoContent}
}

// Handlers for Role endpoints

// HandleListRoleIDs gives a Response containing all the role IDs for roles
// stored in the engine.
func (engine *Engine) HandleListRoleIDs() *Response {
	content := struct {
		IDs []string `json:"role_ids"`
	}{
		IDs: engine.listRoleIDs(),
	}
	bytes, err := json.Marshal(content)
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

// HandleRoleRead gives a Response with the JSON representation of a specific
// role.
func (engine *Engine) HandleRoleRead(roleID string) *Response {
	roleJSON, err := engine.getRoleJSON(roleID)
	if err != nil {
		return &Response{
			ExternalError: err,
			Code:          http.StatusNotFound,
		}
	}
	bytes, err := json.Marshal(roleJSON)
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

// HandleRoleCreate takes an input JSON and uses it to create a new role in the
// engine, returning a Response with either the JSON representation of the
// created role (basically the same as the input) or an error if it occurred.
func (engine *Engine) HandleRoleCreate(bytes []byte) *Response {
	var roleJSON RoleJSON
	err := json.Unmarshal(bytes, &roleJSON)
	if err != nil {
		return &Response{
			ExternalError: err,
			Code:          http.StatusBadRequest,
		}
	}
	role, err := engine.addRoleFromJSON(&roleJSON)
	if err != nil {
		return &Response{
			ExternalError: err,
			Code:          http.StatusBadRequest,
		}
	}
	content := struct {
		Created RoleJSON `json:"created"`
	}{
		Created: role.toJSON(),
	}
	responseBytes, err := json.Marshal(content)
	if err != nil {
		return &Response{
			InternalError: err,
			Code:          http.StatusBadRequest,
		}
	}
	return &Response{
		Bytes: responseBytes,
		Code:  http.StatusCreated,
	}
}

func (engine *Engine) HandleRolesCreate(bytes []byte) *Response {
	var rolesJSON RolesJSON
	err := json.Unmarshal(bytes, &rolesJSON)
	if err != nil {
		return &Response{
			ExternalError: err,
			Code:          http.StatusBadRequest,
		}
	}

	content := struct {
		Created []RoleJSON `json:"created"`
	}{
		Created: make([]RoleJSON, 0),
	}

	for _, roleJSON := range rolesJSON.Roles {
		role, err := engine.addRoleFromJSON(&roleJSON)
		if err != nil {
			return &Response{
				ExternalError: err,
				Code:          http.StatusBadRequest,
			}
		}
		content.Created = append(content.Created, role.toJSON())
	}

	responseBytes, err := json.Marshal(content)
	if err != nil {
		return &Response{
			InternalError: err,
			Code:          http.StatusBadRequest,
		}
	}

	return &Response{
		Bytes: responseBytes,
		Code:  http.StatusCreated,
	}
}

// HandleRoleUpdate takes a roleID identifying an existing role in the engine
// and some bytes containing JSON for updated fields to change in that role; it
// updates the existing role's fields to reflect the values given in the JSON
// input.
func (engine *Engine) HandleRoleUpdate(roleID string, bytes []byte) *Response {
	var roleJSON RoleJSON
	err := json.Unmarshal(bytes, &roleJSON)
	if err != nil {
		return &Response{
			ExternalError: err,
			Code:          http.StatusBadRequest,
		}
	}
	updatedRole, err := engine.updateRoleWithJSON(roleID, &roleJSON)
	if err != nil {
		return &Response{
			ExternalError: err,
			Code:          http.StatusBadRequest,
		}
	}
	content := struct {
		Updated RoleJSON `json:"updated"`
	}{
		Updated: updatedRole.toJSON(),
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

// HandleRolePatch takes a roleID identifying an existing role and some bytes
// containing JSON for fields in a Role; it appends the contents of the input
// JSON to the existing role, so for instance the existing role will keep all
// the permissions it has currently and after the operation also contain all
// the permissions listed in the input JSON.
func (engine *Engine) HandleRolePatch(roleID string, bytes []byte) *Response {
	var roleJSON RoleJSON
	err := json.Unmarshal(bytes, &roleJSON)
	if err != nil {
		return &Response{
			ExternalError: err,
			Code:          http.StatusBadRequest,
		}
	}

	updatedRole, err := engine.appendRoleWithJSON(roleID, &roleJSON)
	if err != nil {
		return &Response{
			ExternalError: err,
			Code:          http.StatusBadRequest,
		}
	}

	content := struct {
		Updated RoleJSON `json:"updated"`
	}{
		Updated: updatedRole.toJSON(),
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

// HandleRoleRemove deletes a role from the engine.
func (engine *Engine) HandleRoleRemove(roleID string) *Response {
	role, exists := engine.roles[roleID]
	if !exists {
		err := notExist("role", "path", roleID)
		return &Response{
			ExternalError: err,
			Code:          http.StatusNotFound,
		}
	}
	err := engine.removeRole(role)
	if err != nil {
		return &Response{
			ExternalError: err,
			Code:          http.StatusBadRequest,
		}
	}
	return &Response{Code: http.StatusNoContent}
}

// Handlers for Engine endpoints

func (engine *Engine) HandleEngineSerialize() *Response {
	engineJSON := engine.toJSON()
	bytes, err := json.Marshal(engineJSON)
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
