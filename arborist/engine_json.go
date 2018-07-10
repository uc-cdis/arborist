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
	permissions := make([]PermissionJSON, len(engine.permissions))
	i := 0
	for _, permission := range engine.permissions {
		permissions[i] = permission.toJSON()
		i++
	}

	roles := make([]RoleJSON, len(engine.roles))
	i = 0
	for _, role := range engine.roles {
		roles[i] = role.toJSON()
		i++
	}

	resources := make([]ResourceJSON, len(engine.resources))
	i = 0
	for _, resource := range engine.resources {
		resources[i] = resource.toJSON()
		i++
	}

	policies := make([]PolicyJSON, len(engine.policies))
	i = 0
	for _, policy := range engine.policies {
		policies[i] = policy.toJSON()
		i++
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
