// engine.go defines the Engine structure which is the central entity for
// storing information and issuing authorization decisions. This file contains
// methods for the Engine which handle various operations on the constitutent
// models, particularly for doing basic CRUD operations with roles, resources,
// and policies.

package arborist

import (
	"fmt"
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

func NewAuthEngine() *Engine {
	engine := makeEngine()

	// Create and insert the root resource in the engine.
	rootResource, err := NewResource("", "root", nil, nil)
	if err != nil {
		// should not happen/unrecoverable; fix this function and/or NewResource
		panic(err)
	}
	_, err = engine.addResource(rootResource)
	if err != nil {
		// should not happen/unrecoverable; fix this function and/or addResource
		panic(fmt.Sprintf("failed to initialize auth engine: %s", err))
	}

	return engine
}

// readPermissionFromJSON instantiates a PermissionJSON into a Permission. This
// generally shouldn't need to be used except in the other functions to load
// other entities from JSON.
func (engine *Engine) readPermissionFromJSON(permissionJSON PermissionJSON) *Permission {
	permission, exists := engine.permissions[permissionJSON.ID]
	if exists {
		return permission
	}
	return &Permission{
		id:          permissionJSON.ID,
		description: permissionJSON.Description,
		action:      permissionJSON.Action,
		constraints: permissionJSON.Constraints,
	}
}

// Operations for working with roles

// getRoleJSON returns the RoleJSON representation for a role with the given
// ID. An error is returned if the resource does not exist.
func (engine *Engine) getRoleJSON(roleID string) (*RoleJSON, error) {
	role, exists := engine.roles[roleID]
	if !exists {
		return nil, notExist("role", "id", roleID)
	}
	roleJSON := role.toJSON()
	return &roleJSON, nil
}

// listRoleIDs lists the ID field for all the roles currently stored in the
// engine.
func (engine *Engine) listRoleIDs() []string {
	result := make([]string, len(engine.roles))
	for _, role := range engine.roles {
		result = append(result, role.id)
	}
	return result
}

// readRole uses the information stored in the Engine to load a RoleJSON into a
// *Role (without modifying the engine at all).
func (engine *Engine) readRoleFromJSON(roleJSON *RoleJSON) (*Role, error) {
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

func (engine *Engine) addRole(role *Role) (*Role, error) {
	if _, exists := engine.roles[role.id]; exists {
		err := alreadyExists("role", "id", role.id)
		return nil, err
	}
	engine.roles[role.id] = role

	return role, nil
}

func (engine *Engine) addRoleFromJSON(roleJSON *RoleJSON) (*Role, error) {
	role, err := engine.readRoleFromJSON(roleJSON)
	if err != nil {
		return nil, err
	}
	return engine.addRole(role)
}

// updateRoleWithJSON finds a role with the given ID in the engine and uses the
// contents of the RoleJSON to overwrite the fields in the existing role with
// the new stuff from the JSON.
func (engine *Engine) updateRoleWithJSON(roleID string, roleJSON *RoleJSON) (*Role, error) {
	role, exists := engine.roles[roleID]
	if !exists {
		err := notExist("role", "id", roleID)
		return nil, err
	}

	roleJSON.defaultsFromRole(role)

	updatedRole, err := engine.readRoleFromJSON(roleJSON)
	if err != nil {
		return nil, err
	}

	*role = *updatedRole

	return role, nil
}

//
func (engine *Engine) appendRoleWithJSON(roleID string, roleJSON *RoleJSON) (*Role, error) {
	role, exists := engine.roles[roleID]
	if !exists {
		err := notExist("role", "id", roleID)
		return nil, err
	}

	updatedRole, err := engine.readRoleFromJSON(roleJSON)
	if err != nil {
		return nil, err
	}
	role.appendFrom(updatedRole)

	return role, nil
}

// checkDeleteRole checks if it's fine to delete this role from the engine. It
// is NOT fine if there are policies which refer to this role, in which case it
// returns an error.
func (engine *Engine) checkDeleteRole(role *Role) error {
	for _, policy := range engine.policies {
		for policyRole := range policy.roles {
			if role.id == policyRole.id {
				return noDelete(
					"role",
					"id",
					role.id,
					fmt.Sprintf("in use by policy %s", policy.id),
				)
			}
		}
	}
	return nil
}

// removeRole deletes the given role from the engine. An error is returned if
// deleting the role would leave the engine in an incorrect state, namely if
// there are any policies referencing this role. Policies using the role should
// be deleted before the role is.
func (engine *Engine) removeRole(role *Role) error {
	if role == nil {
		return nil
	}
	err := engine.checkDeleteRole(role)
	if err != nil {
		return err
	}
	delete(engine.roles, role.id)
	return nil
}

// Operations for working with resources

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

// readResourceFromJSON uses the information stored in the Engine to load a
// ResourceJSON into a *Resource (without modifying the engine at all).
//
// NOTE: the returned Resource should have a parent node filled out for that
// field, but the parent itself will NOT have the resource in its subresources
// yet. If the load is successful then the caller should do this.
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

	// NewResource will do some basic validation for the resource creation,
	// specifically that the name is valid.
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

//
// TODO: fix the create/load logic for permission IDs vs actual permissions
// inside roles or whatever
//

// addResourceFromJSON goes through the whole process of loading a *Resource
// from a *ResourceJSON and registering it in the engine.
func (engine *Engine) addResourceFromJSON(resourceJSON *ResourceJSON) (*Resource, error) {
	resource, err := engine.readResourceFromJSON(resourceJSON)
	if err != nil {
		return nil, err
	}
	return engine.addResource(resource)
}

// addResource adds an already-instantiated resource into the engine. An error
// is returned if the resource already exists.
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

func (engine *Engine) updateResourceWithJSON(resourcePath string, resourceJSON *ResourceJSON) (*Resource, error) {
	resource, exists := engine.resources[resourcePath]
	if !exists {
		err := notExist("resource", "path", resourcePath)
		return nil, err
	}

	// In the case of resources, we don't really need to do any validation for
	// the updates; because the possible new resources will already be "scoped"
	// underneath this resource, there's no concern for global naming
	// conflicts, as the new ones here are guaranteed to have unique paths. So,
	// as long as they loaded correctly, this is fine.

	// Allow the input JSON to omit some fields (name, description, etc.), so
	// we load these from the resource we're trying to update.
	resourceJSON.defaultsFromResource(resource)

	updatedResource, err := engine.readResourceFromJSON(resourceJSON)
	if err != nil {
		return nil, err
	}

	*resource = *updatedResource

	return resource, nil
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

// Operations for working with policies

// The returned error is non-nil iff there is a role or a resource which was
// used in the policy that does not exist in the engine.
func (engine *Engine) createPolicyFromJSON(policyJSON *PolicyJSON) (*Policy, error) {
	roles := make(map[*Role]struct{}, len(policyJSON.RoleIDs))
	for _, roleID := range policyJSON.RoleIDs {
		role, exists := engine.roles[roleID]
		if !exists {
			err := notExist("role", "id", roleID)
			return nil, err
		}
		roles[role] = struct{}{}
	}

	resources := make(map[*Resource]struct{}, len(policyJSON.ResourcePaths))
	for _, resourcePath := range policyJSON.ResourcePaths {
		resource, exists := engine.resources[resourcePath]
		if !exists {
			err := notExist("resource", "path", resourcePath)
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

// updatePolicyWithJSON finds a policy with the given ID (returning an error if
// not found), and replaces the contents of the policy with any given fields in
// the JSON input. It returns a pointer to the same policy, which should now be
// updated with the new contents.
func (engine *Engine) updatePolicyWithJSON(policyID string, policyJSON *PolicyJSON) (*Policy, error) {
	policy, exists := engine.policies[policyID]
	if !exists {
		err := notExist("policy", "id", policyID)
		return nil, err
	}

	// Allow the input JSON to omit some fields (e.g. the ID, if it doesn't
	// need to be changed), so we load these from the policy we're trying to
	// update.
	policyJSON.defaultsFromPolicy(policy)

	updatedPolicy, err := engine.readPolicyFromJSON(policyJSON)
	if err != nil {
		return nil, err
	}

	*policy = *updatedPolicy

	return policy, nil
}

func (engine *Engine) appendPolicyWithJSON(policyID string, policyJSON *PolicyJSON) (*Policy, error) {
	policy, exists := engine.policies[policyID]
	if !exists {
		err := notExist("policy", "id", policyID)
		return nil, err
	}

	updatedPolicy, err := engine.readPolicyFromJSON(policyJSON)
	if err != nil {
		return nil, err
	}
	policy.appendFrom(updatedPolicy)

	return policy, nil
}

func (engine *Engine) removePolicy(policyID string) error {
	_, exists := engine.policies[policyID]
	if !exists {
		return notExist("policy", "id", policyID)
	}
	delete(engine.policies, policyID)
	return nil
}

func (engine *Engine) readPolicyFromJSON(policyJSON *PolicyJSON) (*Policy, error) {
	roles := make(map[*Role]struct{}, len(policyJSON.RoleIDs))
	for _, roleID := range policyJSON.RoleIDs {
		role, exists := engine.roles[roleID]
		if !exists {
			err := notExist("role", "id", roleID)
			return nil, err
		}
		roles[role] = struct{}{}
	}

	resources := make(map[*Resource]struct{}, len(policyJSON.ResourcePaths))
	for _, resourcePath := range policyJSON.ResourcePaths {
		resource, exists := engine.resources[resourcePath]
		if !exists {
			err := notExist("resource", "path", resourcePath)
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

// readAuthRequestFromJSON uses the information stored in the Engine to load an
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
