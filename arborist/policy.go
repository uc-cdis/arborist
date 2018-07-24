package arborist

import ()

// Represent a policy in the RBAC model. A Policy connects a set of Roles to a
// set of Resources, granting all the permissions from all the roles over all
// of the encapsulated resources.
type Policy struct {
	id          string
	description string
	roles       map[*Role]struct{}
	resources   map[*Resource]struct{}
}

// appendFrom takes a second policy and adds all the contents of the given
// policy to the existing one. This can include updating the ID or description
// (which will overwrite), but in the case of adding roles or resources from
// the updated Policy, these are appended to the existing ones on the previous
// policy, rather than overwriting.
func (policy *Policy) appendFrom(updated *Policy) {
	if updated.id != "" {
		policy.id = updated.id
	}
	if updated.description != "" {
		policy.description = updated.description
	}
	if updated.roles != nil && len(updated.roles) > 0 {
		for role := range updated.roles {
			policy.roles[role] = struct{}{}
		}
	}
	if updated.resources != nil && len(updated.resources) > 0 {
		for resource := range updated.resources {
			policy.resources[resource] = struct{}{}
		}
	}
}

func (policy *Policy) allows(action *Action, constraints Constraints, resource *Resource) bool {
	if _, exists := policy.resources[resource]; !exists {
		return false
	}

	for role := range policy.roles {
		if role.allows(action, constraints) {
			return true
		}
	}

	return false
}
