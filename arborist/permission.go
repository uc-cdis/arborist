package arborist

type Constraints map[string]string

type constraintsDecision struct {
	valid   bool
	partial bool
}

func NewEmptyConstraints() Constraints {
	return make(map[string]string)
}

func (constraints Constraints) validate(try_constraints Constraints) constraintsDecision {
	decision := constraintsDecision{
		valid:   true,
		partial: false,
	}

	for constraint_key, constraint_val := range constraints {
		if try_constraint_val, contains := try_constraints[constraint_key]; contains {
			// If the constraint value doesn't match, then the constraints are
			// invalid but there is a partial match.
			if try_constraint_val != constraint_val {
				decision.valid = false
				decision.partial = true
			}
		} else {
			// The constraint is missing completely, not even mismatched.
			decision.valid = false
		}
	}

	return decision
}

type Permission struct {
	ID          string
	Action      Action
	Constraints Constraints

	// Keep track of the roles that grant this permission.
	rolesGranting map[string]struct{}
}

// Create a new `Permission`.
func newPermission(ID string) *Permission {
	return &Permission{
		ID:            ID,
		Action:        *newAction(),
		Constraints:   make(map[string]string),
		rolesGranting: make(map[string]struct{}),
	}
}

// Record that the `role` grants this `permission`.
func (permission *Permission) grantedBy(role *Role) {
	permission.rolesGranting[role.ID] = struct{}{}
}

// Record that the `role` has been modified, and no longer grants the
// `permission`.
func (permission *Permission) noLongerGrantedBy(role *Role) {
	delete(permission.rolesGranting, role.ID)
}

type permissionDecision struct {
	auth                  bool
	permissionGranting    *Permission
	permissionMismatching *Permission
}

// Given an attempted action `try_action` under constraints `try_constraints`,
// check if the `permission` allows the action. The result contains a boolean
// indicating authorization, and he permission itself if auth is granted; if
// auth fails but some parts of the action are valid, or if the action is valid
// but some constraints don't match, then the permission is included in the
// `permissionMismatching` field.
func (permission Permission) validate(try_action Action, try_constraints Constraints) permissionDecision {
	decision := permissionDecision{
		auth:                  false,
		permissionGranting:    nil,
		permissionMismatching: nil,
	}

	action_valid := permission.Action.validate(try_action)
	constraints_valid := permission.Constraints.validate(try_constraints)

	// If everything is valid, note that this permission is granting auth. If
	// the action validates or at least partially validates, then mark that the
	// permission is mismatching. Otherwise the validation completely fails.
	if action_valid.valid && constraints_valid.valid {
		decision.permissionGranting = &permission
	} else if (action_valid.valid && !constraints_valid.valid) || action_valid.someValid() {
		decision.permissionMismatching = &permission
	}

	return decision
}

type Permissions []*Permission

// Given an attempted action `try_action` under constraints `try_constraints`,
// check if any of the `permissions` allow the action.
func (permissions Permissions) validate(try_action Action, try_constraints Constraints) authResponse {
	var auth authResponse = authResponse{}

	for _, permission := range permissions {
		decision := permission.validate(try_action, try_constraints)
		if decision.auth {
			return authResponse{
				Auth:               true,
				Role_ID:            nil,
				PermissionGranting: permission,
			}
		} else if decision.permissionMismatching != nil {
			auth.PermissionsMismatching = append(auth.PermissionsMismatching, decision.permissionMismatching)
		}
	}

	return auth
}

func (permission *Permission) toJSON() PermissionJSON {
	return PermissionJSON{
		ID:          permission.ID,
		Action:      permission.Action.toJSON(),
		Constraints: permission.Constraints,
	}
}

type PermissionJSON struct {
	ID          string      `json:"id"`
	Action      ActionJSON  `json:"action"`
	Constraints Constraints `json:"constraints"`
}
