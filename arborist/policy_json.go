package arborist

type PolicyJSON struct {
	ID            string   `json:"id"`
	Description   string   `json:"description"`
	RoleIDs       []string `json:"role_ids"`
	ResourcePaths []string `json:"resource_paths"`
}

func (policy *Policy) toJSON() PolicyJSON {
	roleIDs := make([]string, len(policy.roles))
	for role := range policy.roles {
		roleIDs = append(roleIDs, role.id)
	}
	resourcePaths := make([]string, len(policy.resources))
	for resource := range policy.resources {
		resourcePaths = append(resourcePaths, resource.path)
	}
	return PolicyJSON{
		ID:            policy.id,
		Description:   policy.description,
		RoleIDs:       roleIDs,
		ResourcePaths: resourcePaths,
	}
}

// defaultsFromPolicy fills out any empty fields in the PolicyJSON with the
// contents of the given Policy.
func (policyJSON *PolicyJSON) defaultsFromPolicy(policy *Policy) {
	if policyJSON.ID == "" {
		policyJSON.ID = policy.id
	}
	if policyJSON.Description == "" {
		policyJSON.Description = policy.description
	}
	if policyJSON.RoleIDs == nil || len(policyJSON.RoleIDs) == 0 {
		roleIDs := make([]string, len(policy.roles))
		for role := range policy.roles {
			roleIDs = append(roleIDs, role.id)
		}
		policyJSON.RoleIDs = roleIDs
	}
	if policyJSON.ResourcePaths == nil || len(policyJSON.ResourcePaths) == 0 {
		paths := make([]string, len(policy.resources))
		for resource := range policy.resources {
			paths = append(paths, resource.path)
		}
		policyJSON.ResourcePaths = paths
	}
}
