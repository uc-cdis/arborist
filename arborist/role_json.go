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
