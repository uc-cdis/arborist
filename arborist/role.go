package arborist

import (
	"encoding/json"
	"errors"
)

// Representation of a role in the RBAC model.
//
// Subroles and permissions are sets of pointers to other roles and permissions.
// We must keep the locations of the roles etc. in memory because the engine may
// update them directly. (The `map[*Role]struct{}` is just a hack to implement a
// "set" so we can have constant-time lookup to check membership.)
type Role struct {
	ID          string                   `json:"id"`
	Tags        map[string]struct{}      `json:"tags"`
	Subroles    map[*Role]struct{}       `json:"subroles"`
	Permissions map[*Permission]struct{} `json:"permissions"`

	parent *Role
}

// Represent a `Role` in JSON format. In particular, the subroles, permissions,
// and tags, which are stored as maps in the role, should should just be arrays
// in the JSON output. This is *only* used for marshalling a `Role` to JSON.
type RoleJSON struct {
	ID          string       `json:"id"`
	Tags        []string     `json:"tags"`
	Subroles    []RoleJSON   `json:"subroles"`
	Permissions []Permission `json:"permissions"`
}

// Define the way that roles are marshalled into JSON.
func (role Role) MarshalJSON() ([]byte, error) {
	return json.Marshal(role.toJSON())
}

// Define the way that roles are unmarshalled from JSON.
func (role *Role) UnmarshalJSON(data []byte) error {
	var roleJSON *RoleJSON = &RoleJSON{}
	err := json.Unmarshal(data, roleJSON)
	if err != nil {
		return err
	}
	role.fromJSON(*roleJSON)
	return nil
}

// Create a new role with the given name and empty sets of subroles,
// permissions, and tags.
//
// NOTE:
//     - The new role does not point to a parent node yet.
//     - The role ID is not guaranteed to be unique here; the engine must check
//       that.
func newRole(ID string) (Role, error) {
	var role Role

	role = Role{
		ID:          ID,
		Subroles:    make(map[*Role]struct{}),
		Permissions: make(map[*Permission]struct{}),
		Tags:        make(map[string]struct{}),
		parent:      nil,
	}

	return role, nil
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

func (role *Role) filter(predicate func(Role) bool) []*Role {
	var result []*Role
	for _, r := range role.allSubroles() {
		if predicate(*r) {
			result = append(result, r)
		}
	}
	return result
}

func (role *Role) hasTags(tags []string) bool {
	result := true
	for _, tag := range tags {
		if _, contains := role.Tags[tag]; !contains {
			result = false
			break
		}
	}
	return result
}

func (role *Role) allSubroles() []*Role {
	var result []*Role
	var queue roleQueue
	queue.append(role)

	for queue.nonempty() {
		next := queue.pop()
		result = append(result, next)
		for role := range next.Subroles {
			queue.append(role)
		}
	}

	return result
}

// Append the contents of all the fields in `input_role` onto the existing
// fields in `role`. This can include overwriting the current name with a new
// name given in the input role.
func (role *Role) update(input_role Role) {
	if input_role.ID != "" {
		role.ID = input_role.ID
	}

	for subrole := range input_role.Subroles {
		role.Subroles[subrole] = struct{}{}
	}

	for permission := range input_role.Permissions {
		role.Permissions[permission] = struct{}{}
	}

	for tag := range input_role.Tags {
		role.Tags[tag] = struct{}{}
	}
}

// Convert a `Role` to a `RoleJSON`.
func (role *Role) toJSON() RoleJSON {
	var i uint

	Subroles := make([]RoleJSON, len(role.Subroles))
	i = 0
	for subrole := range role.Subroles {
		Subroles[i] = subrole.toJSON()
	}

	Permissions := make([]Permission, len(role.Permissions))
	i = 0
	for permission := range role.Permissions {
		Permissions[i] = *permission
	}

	Tags := make([]string, len(role.Tags))
	i = 0
	for tag := range role.Tags {
		Tags[i] = tag
	}

	return RoleJSON{
		ID:          role.ID,
		Subroles:    Subroles,
		Permissions: Permissions,
		Tags:        Tags,
	}
}

// Convert this `Role` to the contents of `RoleJSON`.
func (role *Role) fromJSON(roleJSON RoleJSON) {
	Subroles := make(map[*Role]struct{})
	for _, subroleJSON := range roleJSON.Subroles {
		var subrole Role = Role{}
		subrole.fromJSON(subroleJSON)
		Subroles[&subrole] = struct{}{}
	}
	role.Subroles = Subroles

	Permissions := make(map[*Permission]struct{})
	for _, permission := range roleJSON.Permissions {
		Permissions[&permission] = struct{}{}
	}
	role.Permissions = Permissions

	Tags := make(map[string]struct{})
	for _, tag := range roleJSON.Tags {
		Tags[tag] = struct{}{}
	}
	role.Tags = Tags
}

// Collect all the permissions this role implies, accumulating the permissions
// for every subrole starting from this one.
func (role *Role) allPermissions() Permissions {
	var permissions Permissions

	for _, subrole := range role.allSubroles() {
		for permission := range subrole.Permissions {
			permissions = append(permissions, permission)
		}
	}

	return permissions
}

func (role *Role) validate(try_action Action, try_constraints Constraints) authResponse {
	auth := role.allPermissions().validate(try_action, try_constraints)
	if auth.Auth {
		auth.Role_ID = &role.ID
	}
	return auth
}

type roleQueue []*Role

func (queue *roleQueue) append(role *Role) *roleQueue {
	*queue = append(*queue, role)
	return queue
}

func (queue *roleQueue) pop() *Role {
	var result *Role = (*queue)[0]
	*queue = (*queue)[1:]
	return result
}

func (queue *roleQueue) nonempty() bool {
	return len(*queue) > 0
}
