package arborist

import (
	"encoding/json"
	"sync"
)

// Represent the auth engine which contains the role forest (tree, really) and
// can issue authorization decisions based on some input roles and the tree.
type AuthEngine struct {
	// The base role of the tree. The root role is kept empty aside from its
	// subroles, which form the roots of trees in the forest.
	root_role Role

	// Keep track of the role names used. This way, the engine searches for
	// roles by name in constant time, and can also check in constant time that
	// new roles have unique names. Make sure to add new roles to the map.
	roles map[string]*Role

	// Keep track of the resources used. The resources are "scoped" by the
	// service to which they belong, which is the string argument in the outer
	// map.
	resources map[string]map[*Resource]struct{}
}

// Create a new engine with a blank role tree (containing just the root role).
func NewAuthEngine() (AuthEngine, error) {
	var engine AuthEngine

	root_role, err := newRole("root")
	if err != nil {
		return engine, err
	}

	roles := make(map[string]*Role, 1)
	roles["root"] = &root_role

	engine = AuthEngine{
		root_role: root_role,
		roles:     roles,
	}

	return engine, nil
}

func (engine *AuthEngine) allResources() []*Resource {
	var result []*Resource
	for _, resources_map := range engine.resources {
		for resource := range resources_map {
			result = append(result, resource)
		}
	}
	return result
}

func (engine *AuthEngine) findResourceForSerivce(service string, resourceID string) *Resource {
	serviceResources, exists := engine.resources[service]
	if !exists {
		return nil
	}

	for resource := range serviceResources {
		if resource.ID == resourceID {
			return resource
		}
	}

	return nil
}

func (engine *AuthEngine) allRoles() []*Role {
	return engine.root_role.allSubroles()
}

// Look up the first role in the tree satisfying the predicate function.
func (engine *AuthEngine) findRole(predicate func(Role) bool) (*Role, error) {
	var result_role *Role
	var err error

	for _, role := range engine.allRoles() {
		if predicate(*role) {
			result_role = role
			break
		}
	}

	return result_role, err
}

// Look up a role with the given name. (Basically a special case of `findRole`.)
func (engine *AuthEngine) findRoleNamed(ID string) (*Role, error) {
	return engine.findRole(func(role Role) bool { return role.ID == ID })
}

// Insert a new role immediately under the root.
func (engine *AuthEngine) insertRole(role Role) error {
	if _, exists := engine.roles[role.ID]; exists {
		return errorRoleNameTaken{role.ID}
	}
	engine.roles[role.ID] = &role
	engine.root_role.Subroles[&role] = struct{}{}
	return nil
}

// Insert a role as a child underneath the given parent role.
func (engine *AuthEngine) insertRoleAt(parent_role Role, child_role Role) error {
	parent, err := engine.findRoleNamed(parent_role.ID)
	if err != nil {
		return err
	}
	parent.Subroles[&child_role] = struct{}{}
	return nil
}

// Make updates to the existing role `current_role` from the fields in
// `new_role`. (This can rename the existing role, but otherwise only appends
// the additional data to the existing role.)
func (engine *AuthEngine) updateRole(current_role *Role, new_role Role) error {
	// Make sure that, if the name should be updated, the new name is unique.
	if _, exists := engine.roles[new_role.ID]; exists {
		return errorRoleNameTaken{new_role.ID}
	}

	current_role.update(new_role)

	return nil
}

func (engine *AuthEngine) overwriteRole(current_role *Role, new_role Role) error {
	// Make sure that, if the name should be updated, the new name is unique.
	if _, exists := engine.roles[new_role.ID]; exists {
		return errorRoleNameTaken{new_role.ID}
	}

	*current_role = new_role
	return nil
}

// Parameters that constitute an authorization request:
//     - A list of roles the user possesses
//     - A list of attempted actions for which the engine must authorize the
//       user
//     - A dictionary of constraints which put limits on the attempted action(s)
//
// NOTE that the `authRequest.Action.Resource` field will not be initialized by
// unmarshalling from JSON, because this requires the engine to look up the
// resource. Parse an `authRequest` using the `AuthEngine.parseRequest` function.
type authRequest struct {
	Roles       []*Role     `json:"roles"`
	Tags        []string    `json:"tags"`
	Action      Action      `json:"actions"`
	Constraints Constraints `json:"constraints"`
}

func (engine *AuthEngine) parseRequest(body []byte) (*authRequest, error) {
	var request *authRequest = &authRequest{}
	err := json.Unmarshal(body, request)

	// Find the resource for this request.
	service := request.Action.Service
	resourceID := request.Action.ResourceID
	(*request).Action.Resource = engine.findResourceForSerivce(service, resourceID)

	return request, err
}

// Struct to contain all the information for an authorization decision issued by
// the engine.
type authResponse struct {
	// Whether or not the request is authorized.
	Auth bool `json:"auth"`

	// If a role resulted in the granting of authorization, then include its
	// name in the output.
	Role_ID *string `json:"role_id"`

	// This field contains the permission that resulted in authorization.
	PermissionGranting *Permission `json:"permission_matching"`

	// If the request is denied, this field contains a list of permissions
	// which were relevant to the auth request (that is, had a partly matching
	// action) but insufficient for authorization. If the request is approved
	// then this list should be left empty.
	PermissionsMismatching []*Permission `json:"permissions_mismatching"`
}

// Process an `authRequest` and return an `authResponse`.
func (engine *AuthEngine) checkAuth(request authRequest) authResponse {
	// Take only the roles with matching tags.
	var roles []*Role
	for _, role := range request.Roles {
		if role.hasTags(request.Tags) {
			roles = append(roles, role)
		}
	}

	// This will be the default response that gets built up from the cases where
	// the roles did not authorize the action, and returned if no authorization
	// is found.
	default_response := authResponse{
		Auth:                   false,
		Role_ID:                nil,
		PermissionGranting:     nil,
		PermissionsMismatching: make([]*Permission, 0),
	}

	// We will concurrently have each role check for authorization for the
	// requested action, and return immediately if any roles return a positive
	// response. Otherwise, we have to wait for every role to finish its checks,
	// and then we just return the `default_response`.

	// Make a channel with room for 1 `authResponse` for a role to write to in
	// the event that it determines positive authorization.
	response_channel := make(chan authResponse, 1)
	defer close(response_channel)

	// This `WaitGroup` will track the completion of all the roles' checks.
	// Every role sends a `wg.Done()` after its check.
	var wg sync.WaitGroup
	wg.Add(len(roles))

	// Make a channel to indicate whether all the roles are done yet.
	done_channel := make(chan struct{}, 0)
	defer close(done_channel)

	// Wait for all roles to complete, and then close the channel to indicate
	// that the roles are done checking.
	go func() {
		wg.Wait()
		close(done_channel)
	}()

	for _, role := range roles {
		go func(role *Role, response_channel chan authResponse) {
			role_response := role.validate(request.Action, request.Constraints)
			// If this role permits the action, then write just that into the
			// response channel; don't need any other values in the response.
			// Otherwise, update the default response to include mismatched
			// permissions found from this check.
			if role_response.Auth {
				response_channel <- authResponse{
					Auth:                   true,
					Role_ID:                &role.ID,
					PermissionGranting:     role_response.PermissionGranting,
					PermissionsMismatching: make([]*Permission, 0),
				}
			} else {
				ps := &default_response.PermissionsMismatching
				*ps = append(*ps, role_response.PermissionsMismatching...)
			}
			wg.Done()
		}(role, response_channel)
	}

	// Wait either for a single response in the `response_channel`, or for the
	// `done_channel` to close at the end of all the iteration.
	select {
	case response := <-response_channel:
		return response
	case <-done_channel:
		return default_response
	}
}
