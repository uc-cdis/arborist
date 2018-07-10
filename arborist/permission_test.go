package arborist

import (
	"strings"
	"testing"
)

func examplePermission(action *Action) *Permission {
	return &Permission{
		id:          "example",
		description: "an example permission for testing",
		action:      *action,
		constraints: make(map[string]string),
	}
}

func TestPermissionEquals(t *testing.T) {
	exampleAction := &Action{"foo", "bar"}
	permission := examplePermission(exampleAction)
	if !permission.equals(permission) {
		t.Error("permission does not equal itself")
	}
	otherPermission := examplePermission(exampleAction)
	otherPermission.id = strings.Join([]string{permission.id, "-differentID"}, "")
	if permission.equals(otherPermission) {
		t.Error("permission equals different permission")
	}
}

func TestPermissionAllows(t *testing.T) {
	exampleAction := &Action{"foo", "bar"}
	actionIncorrectService := &Action{"baz", "bar"}
	actionIncorrectMethod := &Action{"foo", "baz"}

	permission := examplePermission(exampleAction)

	constraints := map[string]string{"color": "red"}
	permissionWithConstraints := examplePermission(exampleAction)
	permissionWithConstraints.constraints = constraints

	emptyConstraints := map[string]string{}

	invalidConstraintsKey := map[string]string{"number": "five"}
	invalidConstraintsValue := map[string]string{"color": "blue"}

	t.Run("withoutConstraints", func(t *testing.T) {
		t.Run("valid", func(t *testing.T) {
			if !permission.allows(exampleAction, emptyConstraints) {
				t.Error("does not allow valid action")
			}
		})

		t.Run("invalidService", func(t *testing.T) {
			if permission.allows(actionIncorrectService, emptyConstraints) {
				t.Error("allows action with incorrect service")
			}
		})

		t.Run("invalidMethod", func(t *testing.T) {
			if permission.allows(actionIncorrectMethod, emptyConstraints) {
				t.Error("allows action with incorrect method")
			}
		})
	})

	t.Run("withConstraints", func(t *testing.T) {
		t.Run("valid", func(t *testing.T) {
			if !permissionWithConstraints.allows(exampleAction, constraints) {
				t.Error("does not allow valid action and constraints")
			}
		})

		t.Run("validNoConstraintsRequired", func(t *testing.T) {
			if !permissionWithConstraints.allows(exampleAction, emptyConstraints) {
				t.Error("does not allow valid action and empty constraints")
			}
		})

		t.Run("invalidWrongConstraint", func(t *testing.T) {
			if permissionWithConstraints.allows(exampleAction, invalidConstraintsKey) {
				t.Error("allows valid action but missing constraint key")
			}
		})

		t.Run("validActionInvalidConstraintValue", func(t *testing.T) {
			if permissionWithConstraints.allows(exampleAction, invalidConstraintsValue) {
				t.Error("allows valid action with invalid constraints")
			}
		})
	})
}
