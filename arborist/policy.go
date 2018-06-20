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
