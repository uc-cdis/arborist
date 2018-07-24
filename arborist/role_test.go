package arborist

import (
	"strings"
	"testing"
)

func exampleRole() *Role {
	return &Role{
		id:          "example-role",
		description: "example role for testing",
		permissions: make(map[*Permission]struct{}),
	}
}

func TestRoleEquals(t *testing.T) {
	role := exampleRole()

	t.Run("true", func(t *testing.T) {
		if !role.equals(role) {
			t.Error("role does not equal itself")
		}
	})

	t.Run("false", func(t *testing.T) {
		otherRole := exampleRole()
		otherRole.id = strings.Join([]string{role.id, "-different"}, "")
		if role.equals(otherRole) {
			t.Error("role equals role with different ID")
		}
	})
}
