// This file defines all the stuff that the engine would care to expose for
// using in the actual endpoints. The central piece is `ArboristOperation` which
// does all the work for writing an HTTP response; functionality from the engine
// need only return that, and then endpoints can call `HandleResponseWriter` to
// create a JSON response.

package arborist

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// jsonPrefix defines what (if anything) to put at line beginnings in JSON
// output.
const jsonPrefix = ""

// jsonIndent defines how to indent output JSON.
const jsonIndent = "  "

// marshal is a local rebinding to use specific JSON indendation (defined
// above).
func marshal(v interface{}) ([]byte, error) {
	return json.MarshalIndent(v, jsonPrefix, jsonIndent)
}

// ArboristOperation is a general struct for containing information desccribing
// a response from the arborist engine after performing some operation.
type ArboristOperation struct {
	Success bool
	Status  int
	JSON    []byte
}

// failedMarshal returns an operation indicating that arborist failed to
// marshal some JSON.
func failedMarshal(err error) ArboristOperation {
	code := http.StatusInternalServerError
	errorInfo := errorInformation{
		Message: fmt.Sprintf("failed to marshal JSON: %s", err),
		Code:    code,
	}
	errorJSON := ErrorJSON{errorInfo}
	return ArboristOperation{
		Success: false,
		Status:  code,
		JSON:    errorJSON.marshal(),
	}
}

// badRequest returns an operation indicating the request was somehow erroneous
// (4XX).
func badRequest(msg string) ArboristOperation {
	code := http.StatusBadRequest
	errorJSON := ErrorJSON{errorInformation{
		Message: msg,
		Code:    code,
	}}
	return ArboristOperation{
		Success: false,
		Status:  code,
		JSON:    errorJSON.marshal(),
	}
}

// roleNotExists returns an operation indicating the requested role to operate
// on does not exist (404).
func roleNotExists(roleID string) ArboristOperation {
	msg := fmt.Sprintf("no role exists with ID: %s", roleID)
	code := http.StatusNotFound
	errorJSON := ErrorJSON{errorInformation{
		Message: msg,
		Code:    code,
	}}
	return ArboristOperation{
		Success: false,
		Status:  code,
		JSON:    errorJSON.marshal(),
	}
}

// successNoContent returns an operation for 204.
func successNoContent() ArboristOperation {
	return ArboristOperation{
		Success: true,
		Status:  http.StatusNoContent,
		JSON:    []byte{},
	}
}

// HandleResponseWriter takes a `ResponseWriter` and write the correct headers,
// status, and response from the results of the operation.
func (operation ArboristOperation) HandleResponseWriter(w http.ResponseWriter) {
	w.WriteHeader(operation.Status)
	w.Header().Set("Content-Type", "application/json")
	w.Write(operation.JSON)
}

// ResourcesList stores a list of resources for a response.
type ResourcesList struct {
	Resources []string `json:"resources"`
}

// Wrapper struct to store an error to convert to JSON. (This is just so the
// JSON can look like `{"error": {...}}`.)
type ErrorJSON struct {
	Error errorInformation `json:"error"`
}

// marshal dumps the error into JSON and assume that this will work correctly,
// ignoring the possible error from the JSON marshalling (so assuming we have
// defined the error JSON structs correctly).
func (errorJSON ErrorJSON) marshal() []byte {
	bytes, _ := marshal(errorJSON)
	return bytes
}

// errorInformation wraps info for error message fields in a JSON response.
type errorInformation struct {
	Message string `json:"message"`
	Code    int    `json:"code"`
}

// ListResources returns the list of just the names of all the roles that exist
// in the engine.
func (engine *AuthEngine) ListResources() ArboristOperation {
	resources := ResourcesList{
		Resources: engine.ListResourceNames(),
	}
	bytes, err := marshal(resources)
	if err != nil {
		return failedMarshal(err)
	}

	return ArboristOperation{
		Success: true,
		Status:  http.StatusOK,
		JSON:    bytes,
	}
}

// CreateRole, given some bytes as input which should be a JSON describing the
// role to create, adds the new role to the engine.
func (engine *AuthEngine) CreateRole(roleJSONBytes []byte) ArboristOperation {
	// Try to parse a role from the input.
	var roleJSON *RoleJSON = &RoleJSON{}
	err := json.Unmarshal(roleJSONBytes, roleJSON)
	if err != nil {
		msg := fmt.Sprintf("failed to parse role from JSON: %s", err)
		return badRequest(msg)
	}

	// Once the role is parsed, try to load it into the engine.
	err = engine.LoadRoleFromJSON(*roleJSON)
	if err != nil {
		msg := fmt.Sprintf("failed to load role: %s", err)
		return badRequest(msg)
	}

	return ArboristOperation{
		Success: true,
		Status:  http.StatusNoContent,
		JSON:    []byte{},
	}
}

// ReadRole, given a role ID, writes out the information about the role.
func (engine *AuthEngine) ReadRole(roleID string) ArboristOperation {
	role := engine.FindRoleNamed(roleID)
	if role == nil {
		return roleNotExists(roleID)
	}

	roleJSON := role.toJSON()
	jsonBytes, err := marshal(roleJSON)
	if err != nil {
		return failedMarshal(err)
	}

	return ArboristOperation{
		Success: true,
		Status:  http.StatusOK,
		JSON:    jsonBytes,
	}
}

// UpdateRole makes updates to the existing role `current_role` from the fields
// in `new_role`. (This can rename the existing role, but otherwise only
// appends the additional data to the existing role.)
func (engine *AuthEngine) UpdateRole(roleID string, roleJSONBytes []byte) ArboristOperation {
	// Try to parse the JSON body.
	var roleJSON *RoleJSON = &RoleJSON{}
	err := json.Unmarshal(roleJSONBytes, roleJSON)
	if err != nil {
		return badRequest(fmt.Sprint(err))
	}

	// Try to actually update the role.
	err = engine.updateRoleWithJSON(roleID, *roleJSON)
	if err != nil {
		return badRequest(fmt.Sprint(err))
	}

	return ArboristOperation{
		Success: true,
		Status:  http.StatusNoContent,
		JSON:    []byte{},
	}
}

// OverwriteRoleWithJSON, given some JSON input describing a role, validates
// the input and overwrite the exiting role with the new one parsed from the
// JSON.
func (engine *AuthEngine) OverwriteRoleWithJSON(roleID string, input []byte) ArboristOperation {
	// Find the role that we want to overwrite. Detach this role before anything
	// else is done, so that the new
	oldRole := engine.FindRoleNamed(roleID)
	if oldRole == nil {
		return roleNotExists(roleID)
	}
	engine.detachRoleRecursively(oldRole)
	parentRole := oldRole.Parent

	var roleJSON *RoleJSON
	err := json.Unmarshal(input, roleJSON)
	if err != nil {
		return badRequest(fmt.Sprint(err))
	}

	newRole, err := engine.recursivelyLoadRoleFromJSON(*roleJSON)
	if err != nil {
		return badRequest(fmt.Sprint(err))
	}

	err = parentRole.insert(newRole)
	if err != nil {
		return badRequest(fmt.Sprint(err))
	}

	return ArboristOperation{
		Success: true,
	}
}

// DropRole completely deletes the given role from the engine. This will drop
// all subroles from beneath this role, and if there were permissions granted
// by only that role then the engine will also drop those.
func (engine *AuthEngine) DropRole(roleID string) ArboristOperation {
	success := ArboristOperation{
		Success: true,
		Status:  http.StatusNoContent,
		JSON:    []byte{},
	}

	role := engine.FindRoleNamed(roleID)

	// If the role already doesn't exist...we're done.
	if role == nil {
		return success
	}

	for _, role := range role.allSubroles() {
		// Disassociate the role from all the permissions it granted.
		for permission := range role.Permissions {
			permission.noLongerGrantedBy(role)
			engine.dropPermissionIfOrphaned(permission)
		}
		engine.detachRole(role)
	}

	return success
}

func (engine *AuthEngine) AddService(serviceID string) ArboristOperation {
	service := NewService(serviceID)
	engine.services[serviceID] = service
	return successNoContent()
}

// Serialize dumps the state of the `engine` into a JSON blob, suitable for
// storing on disk and eventually recreating the current state of the engine
// from this JSON.
func (engine *AuthEngine) Serialize() ArboristOperation {
	engineJSON := engine.toJSON()
	jsonBytes, err := marshal(engineJSON)
	if err != nil {
		return failedMarshal(err)
	}
	return ArboristOperation{
		Success: true,
		Status:  http.StatusOK,
		JSON:    jsonBytes,
	}
}
