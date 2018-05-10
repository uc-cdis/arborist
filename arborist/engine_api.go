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

const JSONPREFIX = ""
const JSONINDENT = "    "

// Local rebinding to use specific JSON indendation.
func marshal(v interface{}) ([]byte, error) {
	return json.MarshalIndent(v, JSONPREFIX, JSONINDENT)
}

// General struct for containing information desccribing a response from the
// arborist engine after performing some operation.
type ArboristOperation struct {
	Success bool
	Status  int
	JSON    []byte
}

// Take a `ResponseWriter` and write the correct headers, status, and response
// from the results of the operation.
func (operation ArboristOperation) HandleResponseWriter(w http.ResponseWriter) {
	w.WriteHeader(operation.Status)
	w.Header().Set("Content-Type", "application/json")
	w.Write(operation.JSON)
}

// Store a list of resources for a response.
type ResourcesList struct {
	Resources []string `json:"resources"`
}

// Wrapper struct to store an error to convert to JSON.
type ErrorJSON struct {
	Error errorInformation `json:"error"`
}

// Just dump the error into JSON and assume that this will work correctly,
// ignoring the possible error from the JSON marshalling (so assuming we have
// defined the error JSON structs correctly).
func (errorJSON ErrorJSON) marshal() []byte {
	bytes, _ := marshal(errorJSON)
	return bytes
}

// Wrapped struct for error message fields in a JSON response.
type errorInformation struct {
	Message string `json:"message"`
	Code    int    `json:"code"`
}

// Return an operation indicating that arborist failed to marshal some JSON.
func failedMarshal(err error) ArboristOperation {
	errorInfo := errorInformation{
		Message: fmt.Sprintf("failed to marshal JSON: %s", err),
		Code:    http.StatusInternalServerError,
	}
	errorJSON := ErrorJSON{errorInfo}
	return ArboristOperation{
		Success: false,
		Status:  http.StatusInternalServerError,
		JSON:    errorJSON.marshal(),
	}
}

func badRequest(msg string) ArboristOperation {
	errorJSON := ErrorJSON{errorInformation{
		Message: msg,
		Code:    http.StatusBadRequest,
	}}
	return ArboristOperation{
		Success: false,
		Status:  http.StatusBadRequest,
		JSON:    errorJSON.marshal(),
	}
}

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

// Given some bytes as input which should be a JSON describing the role to
// create, add the new role to the engine.
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

func (engine *AuthEngine) WriteRole(roleID string) ArboristOperation {
	role, err := engine.FindRoleNamed(roleID)
	if err != nil {
		return badRequest(fmt.Sprint(err))
	}

	roleJSON := role.toJSON()
	jsonBytes, err := json.Marshal(roleJSON)
	if err != nil {
		return failedMarshal(err)
	}

	return ArboristOperation{
		Success: true,
		Status:  http.StatusOK,
		JSON:    jsonBytes,
	}
}

// Make updates to the existing role `current_role` from the fields in
// `new_role`. (This can rename the existing role, but otherwise only appends
// the additional data to the existing role.)
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

// Given some JSON input describing a role, validate the input and overwrite the
// exiting role with the new one parsed from the JSON.
func (engine *AuthEngine) OverwriteRoleWithJSON(roleID string, input []byte) ArboristOperation {
	// To overwrite the role, just load the JSON into a new role as with
	// inserting a new role beneath the root, and switch the role to point at
	// the new value.

	// TODO

	return ArboristOperation{}
}

// Completely delete the given role from the engine. This will drop all subroles
// from beneath this role, and if there were permissions granted by only that
// role then the engine will also drop those.
func (engine *AuthEngine) DropRole(roleID string) ArboristOperation {
	role, err := engine.FindRoleNamed(roleID)
	if err != nil {
		return badRequest(fmt.Sprint(err))
	}

	all_roles_to_drop := role.allSubroles()

	for _, role := range all_roles_to_drop {
		// Disassociate the role from all the permissions it granted.
		for permission := range role.Permissions {
			permission.noLongerGrantedBy(role)
			engine.dropPermissionIfOrphaned(permission)
		}

		// Disassociate the role from its parent role. (The parent role should never
		// be nil.)
		parent_role := role.Parent
		delete(parent_role.Subroles, role)

		// Remove the role from the engine's role map.
		delete(engine.roles, role.ID)
	}

	return ArboristOperation{
		Success: true,
		Status:  http.StatusNoContent,
		JSON:    []byte{},
	}
}
