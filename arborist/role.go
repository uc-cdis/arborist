package arborist

import (
	"unicode/utf8"
)

type Role struct {
	id          string
	description string
	permissions map[*Permission]struct{}
}

func validateRoleID(id string) error {
	if !utf8.Valid([]byte(id)) {
		return nameError(id, "role", "only UTF8 allowed")
	}
	return nil
}

func NewRole(id string, description string) (*Role, error) {
	err := validateRoleID(id)
	if err != nil {
		return nil, err
	}

	role := Role{
		id:          id,
		description: description,
		permissions: make(map[*Permission]struct{}),
	}

	return &role, nil
}

func (role *Role) equals(other *Role) bool {
	return role.id == other.id
}

func (role *Role) allows(action *Action, constraints Constraints) bool {
	for permission := range role.permissions {
		if permission.allows(action, constraints) {
			return true
		}
	}
	return false
}

func (role *Role) appendFrom(other *Role) {
	if other.id != "" {
		role.id = other.id
	}
	if other.description != "" {
		role.description = other.description
	}
	for permission := range other.permissions {
		role.permissions[permission] = struct{}{}
	}
}
