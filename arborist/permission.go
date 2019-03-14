package arborist

import (
	"encoding/json"

	"github.com/jmoiron/sqlx"
)

type Permission struct {
	Name        string            `json:"id"`
	Description string            `json:"description"`
	Action      Action            `json:"action"`
	Constraints map[string]string `json:"constraints"`
}

type PermissionFromQuery struct {
	ID          int64             `db:"id"`
	RoleID      int64             `db:"role_id"`
	Name        string            `db:"name"`
	Description *string           `db:"description"`
	Service     string            `db:"service"`
	Method      string            `db:"method"`
	Constraints map[string]string `db:"constraints"`
}

func (permission *Permission) UnmarshalJSON(data []byte) error {
	fields := make(map[string]interface{})
	err := json.Unmarshal(data, &fields)
	if err != nil {
		return err
	}
	optionalFields := map[string]struct{}{
		"description": struct{}{},
		"constraints": struct{}{},
	}
	err = validateJSON("permission", permission, fields, optionalFields)
	if err != nil {
		return err
	}

	// Trick to use `json.Unmarshal` inside here, making a type alias which we
	// cast the permission to.
	type loader Permission
	err = json.Unmarshal(data, (*loader)(permission))
	if err != nil {
		return err
	}

	// make the constraints always at least `{}` and not null
	if permission.Constraints == nil {
		permission.Constraints = make(Constraints)
	}

	return nil
}

func permissionWithNameExists(db *sqlx.DB, name string) (bool, error) {
	stmt := `
		SELECT COUNT(*)
		FROM permission
		WHERE name = $1
	`
	var count int
	err := db.Get(&count, stmt, name)
	if err != nil {
		return false, err
	}
	exists := count == 1
	return exists, nil
}

func permissionsWithNamesExist(db *sqlx.DB, names []string) (bool, error) {
	stmt := `
		SELECT COUNT(*)
		FROM permission
		WHERE name IN ($1)
	`
	var count int
	err := db.Get(&count, stmt, names)
	if err != nil {
		return false, err
	}
	exists := count == len(names)
	return exists, nil
}
