package arborist

type RoleJSON struct {
	ID          string           `json:"id"`
	Description string           `json:"description"`
	Permissions []PermissionJSON `json:"permissions"`
}

func (role *Role) toJSON() RoleJSON {
	permissions := make([]PermissionJSON, 0)
	for permission := range role.permissions {
		permissions = append(permissions, permission.toJSON())
	}
	return RoleJSON{
		ID:          role.id,
		Description: role.description,
		Permissions: permissions,
	}
}

func (roleJSON *RoleJSON) defaultsFromRole(role *Role) {
	if roleJSON.ID == "" {
		roleJSON.ID = role.id
	}
	if roleJSON.Description == "" {
		roleJSON.Description = role.description
	}
	if roleJSON.Permissions == nil {
		roleJSON.Permissions = make([]PermissionJSON, 0)
	}
	if len(roleJSON.Permissions) == 0 {
		for permission := range role.permissions {
			roleJSON.Permissions = append(roleJSON.Permissions, permission.toJSON())
		}
	}
}
