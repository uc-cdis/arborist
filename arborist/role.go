package arborist

import (
	"errors"
)

// Representation of a role in the RBAC model.
//
// Subroles and permissions are sets of pointers to other roles and permissions.
// (The `map[*Role]struct{}` etc. is just a hack to implement a "set" so we can
// have constant-time lookup to check membership, as opposed to searching
// through a slice.)
type Role struct {
	ID          string
	Tags        map[string]string
	Permissions map[*Permission]struct{}
	Subroles    map[*Role]struct{}

	Parent *Role
}

// Create a new role with the given name and empty sets of subroles,
// permissions, and tags.
//
// NOTE:
//     - The new role does not point to a parent node yet.
//     - The role ID is not guaranteed to be unique here; the engine must check
//       that.
func NewRole(ID string) (*Role, error) {
	var role Role

	role = Role{
		ID:          ID,
		Tags:        make(map[string]string),
		Permissions: make(map[*Permission]struct{}),
		Subroles:    make(map[*Role]struct{}),
		Parent:      nil,
	}

	return &role, nil
}

// Check for equality from one `Role` to another. Role names are enforced as
// unique identifiers, so checking those for equality is sufficient.
func (role *Role) equals(other_role *Role) bool {
	return role.ID == other_role.ID
}

// Try to add a subrole underneath this role.
//
// This fails if there is already a subrole with the same name as the new one.
//
// NOTE: this function does not enforce global role name uniqueness, which the
// `AuthEngine` handles. This function should not be used unless the engine has
// already validated the new role to add.
func (role *Role) insert(subrole *Role) error {
	var err error

	if _, contains := role.Subroles[subrole]; contains {
		err = errors.New("role exists already")
	} else {
		role.Subroles[subrole] = struct{}{}
	}

	return err
}

// permit records that this role allows the given permission, adding it to the
// set of permissions this role grants.
func (role *Role) permit(permission *Permission) {
	role.Permissions[permission] = struct{}{}
}

// hasTags checks if this role contains all the tags in the given list.
func (role *Role) hasTags(tags map[string]string) bool {
	result := true
	for inputTag, inputValue := range tags {
		roleValue, contains := role.Tags[inputTag]
		if !contains || roleValue != inputValue {
			result = false
			break
		}
	}
	return result
}

// allSubroles returns a slice of all the subroles accessible in the tree
// beneath this role.
func (role *Role) allSubroles() []*Role {
	var result []*Role
	var queue roleQueue
	queue.pushBack(role)

	for queue.nonempty() {
		next := queue.popFront()
		result = append(result, next)
		for role := range next.Subroles {
			queue.pushBack(role)
		}
	}

	return result
}

// update appends the contents of all the fields in `input_role` onto the
// existing fields in `role`. This can include overwriting the current name with
// a new name given in the input role.
func (role *Role) update(input_role *Role) {
	if input_role.ID != "" {
		role.ID = input_role.ID
	}

	for subrole := range input_role.Subroles {
		role.Subroles[subrole] = struct{}{}
	}

	for permission := range input_role.Permissions {
		role.Permissions[permission] = struct{}{}
	}

	for tag, value := range input_role.Tags {
		role.Tags[tag] = value
	}
}

// allPermissions collects all the permissions this role implies, accumulating
// the permissions for every subrole starting from this one.
func (role *Role) allPermissions() Permissions {
	var permissions Permissions

	for _, subrole := range role.allSubroles() {
		for permission := range subrole.Permissions {
			permissions = append(permissions, permission)
		}
	}

	return permissions
}

// validate checks if the attempted action and constraints are allowed under
// this role.
func (role *Role) validate(try_action Action, try_constraints Constraints) authResponse {
	auth := role.allPermissions().validate(try_action, try_constraints)
	if auth.Auth {
		auth.Role_ID = &role.ID
	}
	return auth
}

// toJSON converts a `Role` to a `RoleJSON`.
func (role *Role) toJSON() RoleJSON {
	var i uint

	subroles := make([]RoleJSON, len(role.Subroles))
	i = 0
	for subrole := range role.Subroles {
		subroles[i] = subrole.toJSON()
	}

	permissions := make([]PermissionJSON, len(role.Permissions))
	i = 0
	for permission := range role.Permissions {
		permissions[i] = permission.toJSON()
	}

	return RoleJSON{
		ID:          role.ID,
		Subroles:    subroles,
		Permissions: permissions,
		Tags:        role.Tags,
	}
}

// RoleJSON represents a `Role` in JSON format. In particular, the subroles,
// permissions, and tags, which are stored as maps in the role, should should
// just be arrays in the JSON output. This is *only* used for marshalling roles
// to and from JSON.
type RoleJSON struct {
	ID          string            `json:"id"`
	Tags        map[string]string `json:"tags"`
	Subroles    []RoleJSON        `json:"subroles"`
	Permissions []PermissionJSON  `json:"permissions"`
}

// RoleQueue provides utility of iterating through a queue of roles (used by the
// engine for traversing through the roles tree).
type roleQueue []*Role

func newRoleQueue() roleQueue {
	return make([]*Role, 0)
}

func (queue *roleQueue) pushFront(role *Role) *roleQueue {
	*queue = append([]*Role{role}, *queue...)
	return queue
}

func (queue *roleQueue) pushBack(role *Role) *roleQueue {
	*queue = append(*queue, role)
	return queue
}

func (queue *roleQueue) popFront() *Role {
	var result *Role
	result, *queue = (*queue)[0], (*queue)[1:]
	return result
}

func (queue *roleQueue) popBack() *Role {
	var result *Role
	result, *queue = (*queue)[len(*queue)-1], (*queue)[:len(*queue)-1]
	return result
}

func (queue *roleQueue) nonempty() bool {
	return len(*queue) > 0
}
