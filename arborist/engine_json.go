package arborist

import (
	"time"
)

type EngineJSON struct {
	Permissions []PermissionJSON `json:"permissions"`
	Roles       []RoleJSON       `json:"roles"`
	Resources   []ResourceJSON   `json:"resources"`
	Policies    []PolicyJSON     `json:"policies"`
	Timestamp   int64            `json:"timestamp"`
}

func (engine *Engine) toJSON() EngineJSON {
	permissions := make([]PermissionJSON, 0)
	for _, permission := range engine.permissions {
		permissionJSON := permission.toJSON()
		permissions = append(permissions, permissionJSON)
	}

	roles := make([]RoleJSON, 0)
	for _, role := range engine.roles {
		roleJSON := role.toJSON()
		roles = append(roles, roleJSON)
	}

	resources := make([]ResourceJSON, 0)
	for _, resource := range engine.resources {
		resourceJSON := resource.toJSON()
		resources = append(resources, resourceJSON)
	}

	policies := make([]PolicyJSON, 0)
	for _, policy := range engine.policies {
		policyJSON := policy.toJSON()
		policies = append(policies, policyJSON)
	}

	timestamp := time.Now().Unix()

	return EngineJSON{
		Permissions: permissions,
		Roles:       roles,
		Resources:   resources,
		Policies:    policies,
		Timestamp:   timestamp,
	}
}
