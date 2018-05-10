package arborist

import (
	"encoding/json"
	"errors"
	"sync"
)

// Represent the auth engine which contains the role forest (tree, really) and
// can issue authorization decisions based on some input roles and the tree.
type AuthEngine struct {
	// The base role of the tree. The root role is kept empty aside from its
	// subroles, which form the roots of trees in the forest.
	root_role *Role

	// Keep track of the role names used. This way, the engine searches for
	// roles by name in constant time, and can also check in constant time that
	// new roles have unique names. Make sure to add new roles to the map.
	roles map[string]*Role

	// Keep track of the resources used. The resources are "scoped" by the
	// service to which they belong, which is the string argument in the outer
	// map. So, this `resources` field maps from strings for service name to
	// maps of resource name to resource.
	resources map[string]map[string]*Resource

	// Keep track of existing permissions by ID.
	permissions map[string]*Permission

	// Keep track of services by ID.
	services map[string]*Service
}

// Create a new engine with a blank role tree (containing just the root role).
func NewAuthEngine() (*AuthEngine, error) {
	root_role, err := NewRole("root")
	if err != nil {
		return nil, err
	}

	roles := make(map[string]*Role, 1)
	roles["root"] = root_role

	resources := make(map[string]map[string]*Resource)

	permissions := make(map[string]*Permission)

	services := make(map[string]*Service)

	engine := &AuthEngine{
		root_role:   root_role,
		roles:       roles,
		resources:   resources,
		permissions: permissions,
		services:    services,
	}

	return engine, nil
}

// Return just the names of all the roles stored in the engine.
func (engine *AuthEngine) ListRoleNames() []string {
	var result []string = make([]string, 0)
	for role_name := range engine.roles {
		result = append(result, role_name)
	}
	return result
}

// Return just the names of the services that have been stored.
func (engine *AuthEngine) ListServiceNames() []string {
	var result []string = make([]string, 0)
	for service_name := range engine.services {
		result = append(result, service_name)
	}
	return result
}

// Return slice of all the names of the resources stored in the engine.
func (engine *AuthEngine) ListResourceNames() []string {
	var result []string = make([]string, 0)
	for resource_name := range engine.resources {
		result = append(result, resource_name)
	}
	return result
}

// Return a list of references to all the resources created in this engine.
func (engine *AuthEngine) allResources() []*Resource {
	var result []*Resource
	for _, resources_map := range engine.resources {
		for _, resource := range resources_map {
			result = append(result, resource)
		}
	}
	return result
}

// Look up a particular resource in a particular service.
func (engine *AuthEngine) findResourceForSerivce(service string, resourceID string) *Resource {
	serviceResources, exists := engine.resources[service]
	if !exists {
		return nil
	}

	for _, resource := range serviceResources {
		if resource.ID == resourceID {
			return resource
		}
	}

	return nil
}

// Return a list of references to ALL the roles in the engine (basically
// flattening the tree).
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
func (engine *AuthEngine) FindRoleNamed(ID string) (*Role, error) {
	return engine.findRole(func(role Role) bool { return role.ID == ID })
}

func (engine *AuthEngine) FindServiceNamed(id string) *Service {
	return engine.services[id]
}

// Look up a service by ID, or create it if it doesn't exist.
func (engine *AuthEngine) findOrCreateService(id string) (*Service, error) {
	service, exists := engine.services[id]
	if !exists {
		// Create new service with given ID.
		service = NewService(id)
		engine.services[id] = service
	}

	return service, nil
}

// Look up the resource with ID `resourceID` under the service with ID
// `serviceID`, or create it if it doesn't exist. (This will *not* do anything
// for the service if it doesn't exist, so handle that part first.)
func (engine *AuthEngine) findOrCreateResource(service *Service, resourceID string) *Resource {
	resource, contains := engine.resources[service.ID][resourceID]
	if contains {
		return resource
	} else {
		resource = NewResource(resourceID)
		resource.service = service
		return resource
	}
}

func (engine *AuthEngine) LoadRoleFromJSON(roleJSON RoleJSON) error {
	role, err := engine.recursivelyLoadRoleFromJSON(roleJSON)
	if err != nil {
		return err
	}

	// Link the created role under the root role and record its ID in the
	// engine.
	engine.root_role.Subroles[role] = struct{}{}
	engine.roles[role.ID] = role

	return nil
}

// Given some JSON input which should describe a new role, validate the JSON
// input and construct a new `Role` which has pointers correctly aimed into the
// roles, permissions, etc. that exist in the engine already.
func (engine *AuthEngine) recursivelyLoadRoleFromJSON(roleJSON RoleJSON) (*Role, error) {
	// Make sure a role with this name doesn't exist yet.
	_, exists := engine.roles[roleJSON.ID]
	if exists {
		err := errors.New("role already exists")
		return nil, err
	}

	role, err := NewRole(roleJSON.ID)
	if err != nil {
		return nil, err
	}

	for _, tag := range roleJSON.Tags {
		role.Tags[tag] = struct{}{}
	}

	// Load permissions for this role from the JSON.
	for _, permissionJSON := range roleJSON.Permissions {
		permission, err := engine.LoadPermissionFromJSON(permissionJSON)
		if err != nil {
			return nil, err
		}
		role.Permissions[permission] = struct{}{}
	}

	// Load subroles from the JSON.
	for _, subroleJSON := range roleJSON.Subroles {
		subrole, err := engine.recursivelyLoadRoleFromJSON(subroleJSON)
		if err != nil {
			return nil, err
		}
		role.Subroles[subrole] = struct{}{}
	}

	// Link subroles to parent (this one).
	for subrole := range role.Subroles {
		subrole.Parent = role
	}

	return role, nil
}

func (engine *AuthEngine) updateRoleWithJSON(roleID string, additionJSON RoleJSON) error {
	role, err := engine.FindRoleNamed(roleID)
	if err != nil {
		return err
	}
	roleAdditions, err := engine.recursivelyLoadRoleFromJSON(additionJSON)
	if err != nil {
		return err
	}
	role.update(roleAdditions)
	return nil
}

// If there are no longer any roles which grant the given permission, then
// remove it from the set of permissions listed in the engine.
func (engine *AuthEngine) dropPermissionIfOrphaned(permission *Permission) {
	if len(permission.rolesGranting) == 0 {
		delete(engine.permissions, permission.ID)
	}
}

// Load a permission from some JSON and create new sub-fields in the engine as
// necessary.
func (engine *AuthEngine) LoadPermissionFromJSON(permissionJSON PermissionJSON) (*Permission, error) {
	var permission *Permission = newPermission(permissionJSON.ID)
	action, err := engine.actionFromJSON(permissionJSON.Action)
	if err != nil {
		return nil, err
	}
	permission.Action = *action
	permission.Constraints = permissionJSON.Constraints
	return permission, nil
}

// Load an `Action` from some JSON describing the action.
//
// The engine attempts to look up the service and resource by their ID; if they
// don't exist yet they are created and added to the engine, and the resource
// will be "floating" (not connected to any other resources in the hierarchy).
func (engine *AuthEngine) actionFromJSON(actionJSON ActionJSON) (*Action, error) {
	var action *Action = newAction()

	// Look up or create service and resource.
	service, err := engine.findOrCreateService(actionJSON.Service)
	if err != nil {
		return nil, err
	}

	resource := engine.findOrCreateResource(service, actionJSON.Resource)
	if err != nil {
		return nil, err
	}

	// Assign to the result `Action`.
	action.Service = service
	action.Resource = resource

	return action, nil
}

// Load a `Service` from some JSON.
//
// The resouces under the service will be created as necessary.
func (engine *AuthEngine) LoadServiceFromJSON(serviceJSON ServiceJSON) (*Service, error) {
	var service *Service = NewService(serviceJSON.ID)

	// Create the resource map for this service in the engine.
	engine.resources[service.ID] = make(map[string]*Resource)

	// Load in the resources from the mapping given, creating them as necessary.
	for uri, resource_name := range serviceJSON.URIsToResources {
		resource := engine.findOrCreateResource(service, resource_name)
		service.uri_to_resource[uri] = resource
	}

	// Put the service itself into the engine's mapping.
	engine.services[service.ID] = service

	return service, nil
}

// Insert a role as a child underneath the given parent role.
func (engine *AuthEngine) insertRoleAt(parent_role Role, child_role Role) error {
	parent, err := engine.FindRoleNamed(parent_role.ID)
	if err != nil {
		return err
	}
	parent.Subroles[&child_role] = struct{}{}
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
// resource. Parse an `authRequest` using the `AuthEngine.ParseRequest` function.
type authRequest struct {
	Roles       []*Role     `json:"roles"`
	Tags        []string    `json:"tags"`
	Action      Action      `json:"actions"`
	Constraints Constraints `json:"constraints"`
}

func (engine *AuthEngine) ParseRequest(body []byte) (*authRequest, error) {
	var request *authRequest = &authRequest{}
	err := json.Unmarshal(body, request)

	// Find the resource for this request.
	service := request.Action.Service
	resourceID := request.Action.Resource.ID

	(*request).Action.Resource = engine.findResourceForSerivce(service.ID, resourceID)

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

// Process an `authRequest` (which represents a request for authorization on an
// action, given some roles held by the requester) and return an `authResponse`.
func (engine *AuthEngine) CheckAuth(request authRequest) authResponse {
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
