package arborist

import (
	"strings"
)

type Engine struct {
	rootResource *Resource
	roles        map[string]*Role
	resources    map[string]*Resource
	permissions  map[string]*Permission
	policies     map[string]*Policy
}

func makeEngine() *Engine {
	return &Engine{
		roles:       make(map[string]*Role),
		resources:   make(map[string]*Resource),
		permissions: make(map[string]*Permission),
		policies:    make(map[string]*Policy),
	}
}

// In the case of Action, there's nothing special we have to do and there's
// actually not even an ActionJSON type, so for that just read in the JSON.

func (engine *Engine) readPermissionFromJSON(permissionJSON PermissionJSON) *Permission {
	permission := Permission{
		id:          permissionJSON.ID,
		description: permissionJSON.Description,
		action:      permissionJSON.Action,
		constraints: permissionJSON.Constraints,
	}
	return &permission
}

// readRole uses the information stored in the Engine to load a RoleJSON into a
// *Role (without modifying the engine at all).
func (engine *Engine) readRoleFromJSON(roleJSON RoleJSON) (*Role, error) {
	permissions := make(map[*Permission]struct{})
	for _, permissionJSON := range roleJSON.Permissions {
		permission := engine.readPermissionFromJSON(permissionJSON)
		permissions[permission] = struct{}{}
	}
	role := Role{
		id:          roleJSON.ID,
		description: roleJSON.Description,
		permissions: permissions,
	}
	return &role, nil
}

// readResourceFromJSON uses the information stored in the Engine to load a
// ResourceJSON into a *Resource (without modifying the engine at all).
//
// NOTE: the returned Resource should have a parent node filled out for that
// field, but the parent itself will NOT have the resource in its subresources
// yet.
func (engine *Engine) readResourceFromJSON(resourceJSON *ResourceJSON) (*Resource, error) {
	subresources := make(map[*Resource]struct{})
	for _, subresourceJSON := range resourceJSON.Subresources {
		subresource, err := engine.readResourceFromJSON(&subresourceJSON)
		if err != nil {
			return nil, err
		}
		subresources[subresource] = struct{}{}
	}

	// Find the parent resource, if the path given has at least two segments.
	var parent *Resource
	if len(strings.Split(resourceJSON.Path, "/")) > 0 {
		pathSegments := strings.Split(resourceJSON.Path, "/")[1:]
		if len(pathSegments) > 1 {
			parentPathSegments := pathSegments[:len(pathSegments)-1]
			parentPath := pathString(parentPathSegments)
			var exists bool
			parent, exists = engine.resources[parentPath]
			if !exists {
				err := notExist("resource", "path", parentPath)
				return nil, err
			}
		} else {
			parent = nil
		}
	}

	resource, err := NewResource(
		resourceJSON.Name,
		resourceJSON.Description,
		parent,
		subresources,
	)
	if err != nil {
		return nil, err
	}
	return resource, nil
}

// readResourceFromJSON uses the information stored in the Engine to load an
// AuthRequestJSON into an *AuthRequest (without modifying the engine at all).
func (engine *Engine) readAuthRequestFromJSON(requestJSON AuthRequestJSON) (*AuthRequest, error) {
	policies := make(map[*Policy]struct{})
	for _, policyID := range requestJSON.PolicyIDs {
		policy, exists := engine.policies[policyID]
		if !exists {
			err := notExist("policy", "id", policyID)
			return nil, err
		}
		policies[policy] = struct{}{}
	}

	resource, exists := engine.resources[requestJSON.ResourcePath]
	if !exists {
		err := notExist("resource", "path", requestJSON.ResourcePath)
		return nil, err
	}

	authRequest := AuthRequest{
		policies:    policies,
		resource:    resource,
		action:      &requestJSON.Action,
		constraints: requestJSON.Constraints,
	}

	return &authRequest, nil
}

func (engine *Engine) readBulkAuthRequest(bulkJSON BulkAuthRequestJSON) (*BulkAuthRequest, error) {
	requests := make([]*AuthRequest, 0)
	for _, requestJSON := range bulkJSON.Requests {
		request, err := engine.readAuthRequestFromJSON(requestJSON)
		if err != nil {
			return nil, err
		}
		requests = append(requests, request)
	}
	bulkAuthRequest := BulkAuthRequest{requests: requests}
	return &bulkAuthRequest, nil
}

func (engine *Engine) giveAuthResponse(authRequest *AuthRequest) AuthResponse {
	action := authRequest.action
	constraints := authRequest.constraints
	resource := authRequest.resource
	for policy := range authRequest.policies {
		if policy.allows(action, constraints, resource) {
			return AuthResponse{auth: true}
		}
	}
	return AuthResponse{auth: false}
}

// The returned error is non-nil iff there is a role or a resource which was
// used in the policy that does not exist in the engine.
func (engine *Engine) createPolicyFromJSON(policyJSON *PolicyJSON) (*Policy, error) {
	roles := make(map[*Role]struct{}, len(policyJSON.Roles))
	for _, roleJSON := range policyJSON.Roles {
		role, exists := engine.roles[roleJSON.ID]
		if !exists {
			err := notExist("role", "id", roleJSON.ID)
			return nil, err
		}
		roles[role] = struct{}{}
	}

	resources := make(map[*Resource]struct{}, len(policyJSON.Resources))
	for _, resourceJSON := range policyJSON.Resources {
		resource, exists := engine.resources[resourceJSON.Path]
		if !exists {
			err := notExist("resource", "path", resourceJSON.Path)
			return nil, err
		}
		resources[resource] = struct{}{}
	}

	policy := &Policy{
		id:          policyJSON.ID,
		description: policyJSON.Description,
		roles:       roles,
		resources:   resources,
	}

	return policy, nil
}

func (engine *Engine) addRole(role *Role) (*Role, error) {
	if _, exists := engine.roles[role.id]; exists {
		err := alreadyExists("role", "id", role.id)
		return nil, err
	}
	engine.roles[role.id] = role

	return role, nil
}

func (engine *Engine) addRoleFromJSON(roleJSON *RoleJSON) (*Role, error) {
	role, err := engine.readRoleFromJSON(*roleJSON)
	if err != nil {
		return nil, err
	}
	return engine.addRole(role)
}

// addResource adds an already-instantiated resource into the engine.
func (engine *Engine) addResource(resource *Resource) (*Resource, error) {
	if _, exists := engine.resources[resource.path]; exists {
		err := alreadyExists("resource", "path", resource.path)
		return nil, err
	}
	// The resource is not yet attached underneath the parent
	engine.resources[resource.path] = resource
	if resource.parent != nil {
		resource.parent.addSubresource(resource)
	}
	return resource, nil
}

// createResourceFromJSON goes through the whole process of loading a *Resource
// from a *ResourceJSON and registering it in the engine.
func (engine *Engine) addResourceFromJSON(resourceJSON *ResourceJSON) (*Resource, error) {
	resource, err := engine.readResourceFromJSON(resourceJSON)
	if err != nil {
		return nil, err
	}
	return engine.addResource(resource)
}

func (engine *Engine) updatePolicyWithJSON(policyID string, policyJSON *PolicyJSON) (*Policy, error) {
	// TODO
	return nil, nil
}

func (engine *Engine) removePolicy(policyID string) error {
	_, exists := engine.policies[policyID]
	if !exists {
		return notExist("policy", "id", policyID)
	}
	delete(engine.policies, policyID)
	return nil
}

func (engine *Engine) listResourcePaths() []string {
	result := make([]string, 0)
	for resourcePath := range engine.resources {
		result = append(result, resourcePath)
	}
	return result
}

// getResourceJSON returns the ResourceJSON representation for a resource with
// the given path. An error is returned if the resource does not exist.
func (engine *Engine) getResourceJSON(resourcePath string) (*ResourceJSON, error) {
	resource, exists := engine.resources[resourcePath]
	if !exists {
		err := notExist("resource", "path", resourcePath)
		return nil, err
	}
	resourceJSON := resource.toJSON()
	return &resourceJSON, nil
}

// removeResource deletes a single resource from the engine, iff it has no
// subresources. This function is a no-op if the resource does not exist, or if
// the resource contained subresources underneath it.
func (engine *Engine) removeLeafResource(resource *Resource) {
	if resource == nil {
		return
	}
	if len(resource.subresources) > 0 {
		return
	}
	if resource.parent != nil {
		delete(resource.parent.subresources, resource)
	}
	delete(engine.resources, resource.path)
}

// removeResourceRecursively deletes this resources, and also removes the
// subresources recursively.
//
// This funciton is a no-op if the resource does not exist.
func (engine *Engine) removeResourceRecursively(resource *Resource) {
	if resource == nil {
		return
	}
	toRemove := make([]*Resource, 0)
	queue := []*Resource{resource}
	var next *Resource
	for len(queue) > 0 {
		next, queue = queue[0], queue[1:]
		toRemove = append(toRemove, next)
		for subresource := range next.subresources {
			queue = append(queue, subresource)
		}
	}
	// Reverse toRemove, so that the leaves are first. Removing the resources
	// starting from the front now, every resource will have no subresources
	// left underneath it, so we are always removing leaves.
	for i, j := 0, len(toRemove)-1; i < j; i, j = i+1, j-1 {
		toRemove[i], toRemove[j] = toRemove[j], toRemove[i]
	}
	for _, resource := range toRemove {
		engine.removeLeafResource(resource)
	}
}
