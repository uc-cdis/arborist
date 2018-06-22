package arborist

import (
	"strings"
)

type Engine struct {
	roles       map[string]*Role
	resources   map[string]*Resource
	permissions map[string]*Permission
	policies    map[string]*Policy
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

func (engine *Engine) readRoleFromJSON(roleJSON RoleJSON) *Role {
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
	return &role
}

func (engine *Engine) readResourceFromJSON(resourceJSON ResourceJSON) (*Resource, error) {
	subresources := make(map[*Resource]struct{})
	for _, subresourceJSON := range resourceJSON.Subresources {
		subresource, err := engine.readResourceFromJSON(subresourceJSON)
		if err != nil {
			return nil, err
		}
		subresources[subresource] = struct{}{}
	}

	var parent *Resource
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

	resource, err := NewResource(resourceJSON.Name, resourceJSON.Description, parent, subresources)
	if err != nil {
		return nil, err
	}

	return resource, nil
}

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

func (engine *Engine) createRoleFromJSON(roleJSON *RoleJSON) (*Role, error) {
	// TODO
	return nil, nil
}

func (engine *Engine) createResourceFromJSON(resourceJSON *ResourceJSON) (*Resource, error) {
	// TODO
	return nil, nil
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
