package arborist

type PermissionJSON struct {
	ID          string            `json:"id"`
	Description string            `json:"description"`
	Action      Action            `json:"action"`
	Constraints map[string]string `json:"constraints"`
}

func (permission *Permission) toJSON() PermissionJSON {
	return PermissionJSON{
		ID:          permission.id,
		Description: permission.description,
		Action:      permission.action,
		Constraints: permission.constraints,
	}
}
