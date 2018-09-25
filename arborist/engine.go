// engine.go defines the Engine structure which is the central entity for
// storing information and issuing authorization decisions. This file contains
// methods for the Engine which handle various operations on the constitutent
// models, particularly for doing basic CRUD operations with roles, resources,
// and policies.

package arborist

import (
	"encoding/json"
	"fmt"

	"github.com/uc-cdis/go-s3/s3client"
)

type Engine struct {
	rootResource *Resource
	roles        map[string]*Role
	resources    map[string]*Resource
	permissions  map[string]*Permission
	policies     map[string]*Policy
}

// makeEngine just does the necessary allocations (i.e. maps) to return a
// functioning Engine structure, and skips the rest of the setup such as adding
// a root resource node. Should use only for NewAuthEngine and tests.
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
//
// FIXME (rudyardrichter, 2018-07): fix the create/load logic for permission
// IDs vs actual permissions inside roles. Maybe allow passing just permission
// ID in roles if the permission already exists? Maybe make all permissions
// pass by value?
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
	var i = 0
	for _, role := range engine.roles {
		result[i] = role.id
		i++
	}
	return result
}

// readRoleFromJSON uses the information stored in the Engine to load a
// RoleJSON into a *Role (without modifying the engine at all).
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

// listResourcePaths returns a slice of paths for all resources in the engine.
//
// Note that because `engine.resources` is a map, the order of paths in the
// slice is not guaranteed to be in any particular order.
func (engine *Engine) listResourcePaths() []string {
	result := make([]string, len(engine.resources))
	i := 0
	for resourcePath := range engine.resources {
		result[i] = resourcePath
		i++
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
//
// Also note that there's no validation here for conflicts with existing
// resources having the same paths; all that has to happen when the engine adds
// this resource to the tree.
//
// An error is returned if a resource exists in the engine already with what
// the path will be to this resource, or if the resource input is invalid for
// any reason, or if any subresource creation returns an error.
func (engine *Engine) readResourceFromJSON(resourceJSON *ResourceJSON, parentPath string) (*Resource, error) {
	var parent *Resource
	var exists bool
	// Find the parent resource (if a path was given).
	if parentPath == "" {
		parent = engine.rootResource
	} else {
		parent, exists = engine.resources[parentPath]
		if !exists {
			err := notExist("resource", "path", parentPath)
			return nil, err
		}
	}

	//// NewResource will do some basic validation for the resource creation,
	//// specifically that the name is valid.
	//resource, err := NewResource(
	//	resourceJSON.Name,
	//	resourceJSON.Description,
	//	parent,
	//	nil,
	//)
	//if err != nil {
	//	return nil, err
	//}

	//subresources := make(map[*Resource]struct{})
	//for _, subresourceJSON := range resourceJSON.Subresources {
	//	subresource, err := engine.readSubresourceFromJSON(&subresourceJSON, resource)
	//	if err != nil {
	//		return nil, err
	//	}
	//	subresources[subresource] = struct{}{}
	//}

	//return resource, nil

	return engine.readSubresourceFromJSON(resourceJSON, parent)
}

func (engine *Engine) readSubresourceFromJSON(resourceJSON *ResourceJSON, parent *Resource) (*Resource, error) {
	resource, err := NewResource(
		resourceJSON.Name,
		resourceJSON.Description,
		parent,
		nil,
	)
	if err != nil {
		return nil, err
	}

	for _, subresourceJSON := range resourceJSON.Subresources {
		subresource, err := engine.readSubresourceFromJSON(&subresourceJSON, resource)
		if err != nil {
			return nil, err
		}
		resource.addSubresource(subresource)
	}

	return resource, nil
}

// addResourceFromJSON goes through the whole process of loading a *Resource
// from a *ResourceJSON and registering it in the engine.
func (engine *Engine) addResourceFromJSON(resourceJSON *ResourceJSON, parentPath string) (*Resource, error) {
	resource, err := engine.readResourceFromJSON(resourceJSON, parentPath)
	if err != nil {
		return nil, err
	}
	return engine.addResource(resource)
}

// addResource adds an already-instantiated resource into the engine. An error
// is returned if the resource already exists.
func (engine *Engine) addResource(resource *Resource) (*Resource, error) {
	// Check that none of the paths for this resource or its subresources exist
	// yet in the engine.
	done := make(chan struct{})
	for r := range resource.traverse(done) {
		if _, exists := engine.resources[r.path]; exists {
			done <- struct{}{}
			return nil, alreadyExists("resource", "path", r.path)
		}
	}

	// Add all the paths for this resource and its subresources to the engine.
	done = make(chan struct{})
	for r := range resource.traverse(done) {
		engine.resources[r.path] = r
	}

	// The resource is not yet attached underneath the parent, so do that.
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

	engine.removeResourceRecursively(resource)

	updatedResource, err := engine.readResourceFromJSON(resourceJSON, "")
	if err != nil {
		return nil, err
	}

	*resource = *updatedResource
	engine.addResource(resource)

	return resource, nil
}

// removeLeafResource deletes a single resource from the engine, if and only if
// it has no subresources; this function is a no-op if the resource does not
// exist, or if the resource contained subresources underneath it.
func (engine *Engine) removeLeafResource(resource *Resource) {
	if resource == nil {
		return
	}
	if len(resource.subresources) > 0 {
		return
	}
	if resource.parent != nil {
		resource.parent.rmSubresource(resource)
	}
	delete(engine.resources, resource.path)
}

// removeResourceRecursively deletes this resources, and also removes the
// subresources recursively.
//
// This function is a no-op if the resource does not exist.
func (engine *Engine) removeResourceRecursively(resource *Resource) {
	if resource == nil {
		return
	}
	toRemove := []*Resource{}
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

func (engine *Engine) addPolicy(policy *Policy) error {
	if _, exists := engine.policies[policy.id]; exists {
		return alreadyExists("policy", "id", policy.id)
	}
	engine.policies[policy.id] = policy
	return nil
}

// createPolicyFromJSON reads in a PolicyJSON and returns a Policy which has
// pointers to Roles and Resources from the engine.
//
// The returned error is non-nil if and only if there is a role or a resource
// which was used in the policy that does not exist in the engine.
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

	resources := make(map[string]struct{}, len(policyJSON.ResourcePaths))
	for _, resourcePath := range policyJSON.ResourcePaths {
		_, exists := engine.resources[resourcePath]
		if !exists {
			err := notExist("resource", "path", resourcePath)
			return nil, err
		}
		resources[resourcePath] = struct{}{}
	}

	policy := &Policy{
		id:          policyJSON.ID,
		description: policyJSON.Description,
		roles:       roles,
		resources:   resources,
	}

	err := engine.addPolicy(policy)
	if err != nil {
		return nil, err
	}

	return policy, nil
}

func (engine *Engine) validatePolicies(policiesJSON *PolicyBulkJSON) ([]*Policy, error) {
	policies := []*Policy{}
	for _, policyJSON := range policiesJSON.Policies {
		// Check that the policy doesn't exist yet.
		if _, exists := engine.policies[policyJSON.ID]; exists {
			return nil, alreadyExists("policy", "id", policyJSON.ID)
		}
		// Check that the roles exist.
		roles := make(map[*Role]struct{}, len(policyJSON.RoleIDs))
		for _, roleID := range policyJSON.RoleIDs {
			role, exists := engine.roles[roleID]
			if !exists {
				return nil, notExist("role", "id", roleID)
			}
			roles[role] = struct{}{}
		}
		// Check that the resources exist.
		resources := make(map[string]struct{}, len(policyJSON.ResourcePaths))
		for _, resourcePath := range policyJSON.ResourcePaths {
			_, exists := engine.resources[resourcePath]
			if !exists {
				return nil, notExist("resource", "path", resourcePath)
			}
			resources[resourcePath] = struct{}{}
		}
		policy := &Policy{
			id:          policyJSON.ID,
			description: policyJSON.Description,
			roles:       roles,
			resources:   resources,
		}
		policies = append(policies, policy)
	}
	return policies, nil
}

func (engine *Engine) createPoliciesFromJSON(policiesJSON *PolicyBulkJSON) ([]*Policy, error) {
	policies, err := engine.validatePolicies(policiesJSON)
	if err != nil {
		return nil, err
	}
	for _, policy := range policies {
		engine.policies[policy.id] = policy
	}
	return policies, nil
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

// appendPolicyWithJSON is the same as updatePolicyWithJSON, except instead of
// overwriting the existing policy the fields are appended with new content.
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

// removePolicy deletes the policy with the given ID from the engine. If no
// such policy exists, this function is just a no-op.
func (engine *Engine) removePolicy(policyID string) error {
	delete(engine.policies, policyID)
	return nil
}

// readPolicyFromJSON transforms a PolicyJSON to a Policy, without modifying
// anything in the engine. It returns an error if any roles or resources in
// the PolicyJSON do not exist in the engine.
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

	resources := make(map[string]struct{}, len(policyJSON.ResourcePaths))
	for _, resourcePath := range policyJSON.ResourcePaths {
		_, exists := engine.resources[resourcePath]
		if !exists {
			err := notExist("resource", "path", resourcePath)
			return nil, err
		}
		resources[resourcePath] = struct{}{}
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
func (engine *Engine) readAuthRequestFromJSON(requestJSON *AuthRequestJSON) (*AuthRequest, error) {
	policies := make(map[*Policy]struct{})
	for _, policyID := range requestJSON.User.Policies {
		policy, exists := engine.policies[policyID]
		if !exists {
			err := notExist("policy", "id", policyID)
			return nil, err
		}
		policies[policy] = struct{}{}
	}

	resource, exists := engine.resources[requestJSON.Request.Resource]
	if !exists {
		err := notExist("resource", "path", requestJSON.Request.Resource)
		return nil, err
	}

	authRequest := AuthRequest{
		policies:    policies,
		resource:    resource,
		action:      &requestJSON.Request.Action,
		constraints: requestJSON.Request.Constraints,
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

// listAuthedResources takes a list of policy IDs (which all must exist in the
// engine, otherwise this function returns an error) and returns a list of all
// the resources which those policies grant any form of access to).
func (engine *Engine) listAuthedResources(policyIDs []string) ([]*Resource, error) {
	resources := []*Resource{}
	for _, policyID := range policyIDs {
		policy, exists := engine.policies[policyID]
		if !exists {
			return nil, notExist("policy", "id", policyID)
		}
		for resourcePath := range policy.resources {
			done := make(chan struct{})
			for r := range engine.resources[resourcePath].traverse(done) {
				resources = append(resources, r)
			}
		}
	}
	return resources, nil
}

//HandleUpdateModel updates data model to S3
func (engine *Engine) HandleUpdateModel() {
	fmt.Println("Not implemented")
	bytes, err := json.Marshal(engine.toJSON())
	if err != nil {
		panic(err)
	}
	awsClient := s3client.AwsClient{}
	awsClient.LoadConfigFile("/credentials.json")
	err = awsClient.UploadObjectToS3(bytes, "xssxs", "model.json")
	if err != nil {
		panic(err)

	}

}

func (engine *Engine) loadModelFromS3() {

	awsClient := s3client.AwsClient{}
	awsClient.LoadConfigFile("./credentials.json")
	//awsClient.createNewSession()

	//buff, _ := readFile("result.csv")

	//err := awsClient.UploadObjectToS3(buff, "xssxs", "result3.txt")

}
