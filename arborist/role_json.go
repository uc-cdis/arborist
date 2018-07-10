package arborist

import (
	"encoding/json"
)

func (role *Role) toJSON() RoleJSON {
	permissions := make([]PermissionJSON, len(role.permissions))
	i := 0
	for permission := range role.permissions {
		permissions[i] = permission.toJSON()
		i++
	}
	return RoleJSON{
		ID:          role.id,
		Description: role.description,
		Permissions: permissions,
	}
}

type RoleJSON struct {
	ID          string           `json:"id"`
	Description string           `json:"description"`
	Permissions []PermissionJSON `json:"permissions"`
}

func (roleJSON *RoleJSON) UnmarshalJSON(data []byte) error {
	fields := make(map[string]interface{})
	err := json.Unmarshal(data, &fields)
	if err != nil {
		return err
	}
	optionalFields := map[string]struct{}{
		"description": struct{}{},
	}
	err = validateJSON("role", roleJSON, fields, optionalFields)
	if err != nil {
		return err
	}

	// Trick to use `json.Unmarshal` inside here, making a type alias which we
	// cast the RoleJSON to. Since this is just type conversion there's no
	// runtime cost.
	type loader RoleJSON
	err = json.Unmarshal(data, (*loader)(roleJSON))
	if err != nil {
		return err
	}

	return nil
}

func (roleJSON *RoleJSON) defaultsFromRole(role *Role) {
	if roleJSON.ID == "" {
		roleJSON.ID = role.id
	}
	if roleJSON.Description == "" {
		roleJSON.Description = role.description
	}
	if roleJSON.Permissions == nil {
		roleJSON.Permissions = make([]PermissionJSON, len(role.permissions))
		i := 0
		for permission := range role.permissions {
			roleJSON.Permissions[i] = permission.toJSON()
			i++
		}
	}
	if len(roleJSON.Permissions) == 0 {
		for permission := range role.permissions {
			roleJSON.Permissions = append(roleJSON.Permissions, permission.toJSON())
		}
	}
}

type RolesJSON struct {
	Roles []RoleJSON `json:"roles"`
}
