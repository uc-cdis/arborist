package arborist

type PolicyJSON struct {
	ID          string         `json:"id"`
	Description string         `json:"description"`
	Roles       []RoleJSON     `json:"roles"`
	Resources   []ResourceJSON `json:"resources"`
}

func (policy *Policy) toJSON() PolicyJSON {
	roles := make([]RoleJSON, 0)
	for role := range policy.roles {
		roles = append(roles, role.toJSON())
	}
	resources := make([]ResourceJSON, 0)
	for resource := range policy.resources {
		resources = append(resources, resource.toJSON())
	}
	return PolicyJSON{
		ID:          policy.id,
		Description: policy.description,
		Roles:       roles,
		Resources:   resources,
	}
}
