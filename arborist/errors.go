package arborist

import (
	"fmt"
)

// Error indicating that a role cannot be added because the name already exists
// and belongs to a different role registered in the engine.
type errorRoleNameTaken struct {
	role_name string
}

func (e errorRoleNameTaken) Error() string {
	return fmt.Sprintf("role already exists: `%s`", e.role_name)
}
