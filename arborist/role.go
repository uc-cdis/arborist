package arborist

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

type Role struct {
	Name        string       `json:"id"`
	Description string       `json:"description"`
	Permissions []Permission `json:"permissions"`
}

func (role *Role) UnmarshalJSON(data []byte) error {
	fields := make(map[string]interface{})
	err := json.Unmarshal(data, &fields)
	if err != nil {
		return err
	}
	optionalFields := map[string]struct{}{
		"description": struct{}{},
	}
	err = validateJSON("role", role, fields, optionalFields)
	if err != nil {
		return err
	}

	// Trick to use `json.Unmarshal` inside here, making a type alias which we
	// cast the Role to. Since this is just type conversion there's no
	// runtime cost.
	type loader Role
	err = json.Unmarshal(data, (*loader)(role))
	if err != nil {
		return err
	}

	return nil
}

// The `description` field uses `*string` to represent nullability.
type RoleFromQuery struct {
	ID          int64          `db:"id"`
	Name        string         `db:"name"`
	Description *string        `db:"description"`
	Permissions pq.StringArray `db:"permissions"`
}

func (roleFromQuery *RoleFromQuery) standardize() Role {
	role := Role{
		Name: roleFromQuery.Name,
	}
	permissions := []Permission{}
	for _, permissionFromQuery := range roleFromQuery.Permissions {
		s := strings.TrimLeft(permissionFromQuery, "(")
		s = strings.TrimRight(s, ")")
		split := strings.Split(s, ",")
		name, service, method := split[0], split[1], split[2]
		constraints := map[string]string{}
		if split[3] != "" {
			err := json.Unmarshal([]byte(split[3]), &constraints)
			if err != nil {
				panic("got bad permission constraints format from database")
			}
		}
		permission := Permission{
			Name: name,
			Action: Action{
				Service: service,
				Method:  method,
			},
			Constraints: constraints,
		}
		permissions = append(permissions, permission)
	}
	role.Permissions = permissions
	if roleFromQuery.Description != nil {
		role.Description = *roleFromQuery.Description
	}
	return role
}

func roleWithName(db *sqlx.DB, name string) (*RoleFromQuery, error) {
	stmt := `
		SELECT
			role.id,
			role.name,
			array_remove(array_agg((permission.name, permission.service, permission.method, permission.constraints)), (NULL::text,NULL::text,NULL::text,NULL::jsonb)) AS permissions
		FROM role
		LEFT JOIN permission ON permission.role_id = role.id
		WHERE role.name = $1
		GROUP BY role.id
		LIMIT 1
	`
	role := RoleFromQuery{}
	err := db.Get(&role, stmt, name)
	if err != nil {
		return nil, err
	}
	return &role, nil
}

func listRolesFromDb(db *sqlx.DB) ([]RoleFromQuery, error) {
	stmt := `
		SELECT
			role.id,
			role.name,
			array_remove(array_agg((permission.name, permission.service, permission.method, permission.constraints)), (NULL::text,NULL::text,NULL::text,NULL::jsonb)) AS permissions
		FROM role
		LEFT JOIN permission ON permission.role_id = role.id
		GROUP BY role.id
	`
	roles := []RoleFromQuery{}
	err := db.Select(&roles, stmt)
	if err != nil {
		return nil, err
	}
	return roles, nil
}

func (role *Role) createInDb(db *sqlx.DB) *ErrorResponse {
	tx, err := db.Beginx()
	if err != nil {
		msg := fmt.Sprintf("couldn't open database transaction: %s", err.Error())
		return newErrorResponse(msg, 500, &err)
	}

	// First, insert permissions if they don't exist yet. If they don't exist
	// then use the contents of this role to create them; if they exist already
	// then IGNORE the contents, and use what's in the database. In postgres we
	// can use `ON CONFLICT DO NOTHING` for this.

	var roleID int
	stmt := `
		INSERT INTO role(name, description)
		VALUES ($1, $2)
		RETURNING id
	`
	row := tx.QueryRowx(stmt, role.Name, role.Description)
	err = row.Scan(&roleID)
	if err != nil {
		// should add more checking here to guarantee the correct error
		_ = tx.Rollback()
		// this should only fail because the role was not unique. return error
		// accordingly
		msg := fmt.Sprintf("failed to insert role: role with this ID already exists: %s", role.Name)
		return newErrorResponse(msg, 409, &err)
	}

	// create permissions as necessary
	permissionTable := "permission(role_id, name, service, method, constraints, description)"
	stmt = multiInsertStmt(permissionTable, len(role.Permissions))
	stmt += " ON CONFLICT DO NOTHING"
	permissionRows := []interface{}{}
	for _, permission := range role.Permissions {
		constraints, err := json.Marshal(permission.Constraints)
		if err != nil {
			_ = tx.Rollback()
			msg := fmt.Sprintf(
				"couldn't write constraints for permission %s: %s",
				permission.Name,
				err.Error(),
			)
			return newErrorResponse(msg, 500, &err)
		}
		row := []interface{}{
			roleID,
			permission.Name,
			permission.Action.Service,
			permission.Action.Method,
			constraints,
			permission.Description,
		}
		permissionRows = append(permissionRows, row...)
	}
	_, err = tx.Exec(stmt, permissionRows...)
	if err != nil {
		_ = tx.Rollback()
		msg := fmt.Sprintf("couldn't create permissions: %s", err.Error())
		return newErrorResponse(msg, 500, &err)
	}

	err = tx.Commit()
	if err != nil {
		_ = tx.Rollback()
		msg := fmt.Sprintf("couldn't commit database transaction: %s", err.Error())
		return newErrorResponse(msg, 500, &err)
	}

	return nil
}

func (role *Role) deleteInDb(db *sqlx.DB) *ErrorResponse {
	stmt := "DELETE FROM role WHERE name = $1"
	_, err := db.Exec(stmt, role.Name)
	if err != nil {
		// TODO: verify correct error
		msg := fmt.Sprintf("failed to delete role: role does not exist: `%s", role.Name)
		return newErrorResponse(msg, 404, nil)
	}
	return nil
}
