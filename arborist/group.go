package arborist

import (
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

const AnonymousGroup = "anonymous"
const LoggedInGroup = "logged-in"

type Group struct {
	Name     string   `json:"name"`
	Users    []string `json:"users"`
	Policies []string `json:"policies"`
}

func (group *Group) UnmarshalJSON(data []byte) error {
	fields := make(map[string]interface{})
	err := json.Unmarshal(data, &fields)
	if err != nil {
		return err
	}
	optionalFields := map[string]struct{}{
		"users":    struct{}{},
		"policies": struct{}{},
	}
	err = validateJSON("group", group, fields, optionalFields)
	if err != nil {
		return err
	}

	// Trick to use `json.Unmarshal` inside here, making a type alias which we
	// cast the Role to. Since this is just type conversion there's no
	// runtime cost.
	type loader Group
	err = json.Unmarshal(data, (*loader)(group))
	if err != nil {
		return err
	}

	return nil
}

type GroupFromQuery struct {
	Name     string         `db:"name"`
	Users    pq.StringArray `db:"users"`
	Policies pq.StringArray `db:"policies"`
}

func (groupFromQuery *GroupFromQuery) standardize() Group {
	group := Group{
		Name:     groupFromQuery.Name,
		Users:    groupFromQuery.Users,
		Policies: groupFromQuery.Policies,
	}
	return group
}

func groupWithName(db *sqlx.DB, name string) (*GroupFromQuery, error) {
	stmt := `
		SELECT
			grp.name,
			array_remove(array_agg(DISTINCT usr.name), NULL) AS users,
			array_remove(array_agg(DISTINCT policy.name), NULL) AS policies
		FROM grp
		LEFT JOIN grp_policy ON grp_policy.grp_id = grp.id
		LEFT JOIN policy ON policy.id = grp_policy.policy_id
		LEFT JOIN usr_grp ON usr_grp.grp_id = grp.id
		LEFT JOIN usr ON usr.id = usr_grp.usr_id
		WHERE grp.name = $1
		GROUP BY grp.id
		LIMIT 1
	`
	groups := []GroupFromQuery{}
	err := db.Select(&groups, stmt, name)
	if err != nil {
		return nil, err
	}
	if len(groups) == 0 {
		return nil, nil
	}
	group := groups[0]
	return &group, nil
}

func listGroupsFromDb(db *sqlx.DB) ([]GroupFromQuery, error) {
	stmt := `
		SELECT
			grp.name,
			array_remove(array_agg(DISTINCT usr.name), NULL) as users,
			array_remove(array_agg(DISTINCT policy.name), NULL) AS policies
		FROM grp
		LEFT JOIN usr_grp ON grp.id = usr_grp.grp_id
		LEFT JOIN usr ON usr.id = usr_grp.usr_id
		LEFT JOIN grp_policy ON grp.id = grp_policy.grp_id
		LEFT JOIN policy ON policy.id = grp_policy.policy_id
		GROUP BY grp.id
	`
	groups := []GroupFromQuery{}
	err := db.Select(&groups, stmt)
	if err != nil {
		return nil, err
	}
	return groups, nil
}

func (group *Group) users(tx *sqlx.Tx) ([]UserFromQuery, error) {
	if len(group.Users) == 0 {
		return []UserFromQuery{}, nil
	}
	users := []UserFromQuery{}
	usersStmt := selectInStmt("usr", "name", group.Users)
	err := tx.Select(&users, usersStmt)
	if err != nil {
		return nil, err
	}
	return users, nil
}

func (group *Group) policies(tx *sqlx.Tx) ([]PolicyFromQuery, error) {
	if len(group.Policies) == 0 {
		return []PolicyFromQuery{}, nil
	}
	policies := []PolicyFromQuery{}
	policiesStmt := selectInStmt("policy", "name", group.Policies)
	err := tx.Select(&policies, policiesStmt)
	if err != nil {
		return nil, err
	}
	return policies, nil
}

func (group *Group) createInDb(tx *sqlx.Tx, authzProvider sql.NullString) *ErrorResponse {
	var groupID int
	stmt := "INSERT INTO grp(name) VALUES ($1) RETURNING id"
	row := tx.QueryRowx(stmt, group.Name)
	err := row.Scan(&groupID)
	if err != nil {
		// should add more checking here to guarantee the correct error
		// this should only fail because the group was not unique. return error
		// accordingly
		msg := fmt.Sprintf("failed to insert group: group with this name already exists: %s", group.Name)
		return newErrorResponse(msg, 409, &err)
	}

	return group.attachUsrAndPolicy(tx, groupID, authzProvider)
}

func (group *Group) attachUsrAndPolicy(tx *sqlx.Tx, groupID int, authzProvider sql.NullString) *ErrorResponse {
	// add users to the group
	if len(group.Users) > 0 {
		users, err := group.users(tx)
		if err != nil {
			msg := fmt.Sprintf("database call for users failed: %s", err.Error())
			return newErrorResponse(msg, 500, &err)
		}
		stmt := multiInsertStmt("usr_grp(usr_id, grp_id, authz_provider)", len(group.Users))
		userGroupRows := []interface{}{}
		for _, user := range users {
			userGroupRows = append(userGroupRows, user.ID, groupID, authzProvider)
		}
		if len(group.Users) > len(users) {
			msg := fmt.Sprintf("failed to create group %s while adding users: Some users do not exist", group.Name)
			return newErrorResponse(msg, 400, nil)
		}
		_, err = tx.Exec(stmt, userGroupRows...)
		if err != nil {
			msg := fmt.Sprintf("failed to create group while adding users: %s", err.Error())
			return newErrorResponse(msg, 500, &err)
		}
	}

	// add policies to the group
	if len(group.Policies) > 0 {
		policies, err := group.policies(tx)
		if err != nil {
			msg := fmt.Sprintf("database call for policies failed: %s", err.Error())
			return newErrorResponse(msg, 500, &err)
		}
		stmt := multiInsertStmt("grp_policy(grp_id, policy_id, authz_provider)", len(group.Policies))
		groupPolicyRows := []interface{}{}
		for _, policy := range policies {
			groupPolicyRows = append(groupPolicyRows, groupID, policy.ID, authzProvider)
		}
		if len(group.Policies) > len(policies) {
			msg := fmt.Sprintf("failed to create group %s while adding policies: Some policies do not exist", group.Name)
			return newErrorResponse(msg, 400, nil)
		}
		_, err = tx.Exec(stmt, groupPolicyRows...)
		if err != nil {
			msg := fmt.Sprintf("failed to create group while adding policies: %s", err.Error())
			return newErrorResponse(msg, 500, &err)
		}
	}

	return nil
}

func (group *Group) deleteInDb(tx *sqlx.Tx) *ErrorResponse {
	if group.Name == AnonymousGroup || group.Name == LoggedInGroup {
		return newErrorResponse("can't delete built-in groups", 400, nil)
	}
	stmt := "DELETE FROM grp WHERE name = $1"
	_, err := tx.Exec(stmt, group.Name)
	if err != nil {
		// TODO: verify correct error
		// group does not exist; that's fine
		return nil
	}
	return nil
}

func (group *Group) overwriteInDb(tx *sqlx.Tx, authzProvider sql.NullString) *ErrorResponse {
	var groupID int
	stmt := "SELECT id FROM grp WHERE name = $1 FOR UPDATE"
	row := tx.QueryRowx(stmt, group.Name)
	err := row.Scan(&groupID)
	if err != nil {
		return group.createInDb(tx, authzProvider)
	}

	stmt = "DELETE FROM usr_grp WHERE grp_id = $1"
	if authzProvider.Valid {
		stmt += " AND authz_provider = $2"
		_, err = tx.Exec(stmt, groupID, authzProvider.String)
	} else {
		_, err = tx.Exec(stmt, groupID)
	}
	if err != nil {
		var msg string
		if authzProvider.Valid {
			msg = fmt.Sprintf("failed to clear %s usr_grp for %s", authzProvider.String, group.Name)
		} else {
			msg = fmt.Sprintf("failed to clear usr_grp for %s", group.Name)
		}
		return newErrorResponse(msg, 500, &err)
	}

	stmt = "DELETE FROM grp_policy WHERE grp_id = $1"
	if authzProvider.Valid {
		stmt += " AND authz_provider = $2"
		_, err = tx.Exec(stmt, groupID, authzProvider.String)
	} else {
		_, err = tx.Exec(stmt, groupID)
	}
	if err != nil {
		var msg string
		if authzProvider.Valid {
			msg = fmt.Sprintf("failed to clear %s grp_policy for %s", authzProvider.String, group.Name)
		} else {
			msg = fmt.Sprintf("failed to clear grp_policy for %s", group.Name)
		}
		return newErrorResponse(msg, 500, &err)
	}

	return group.attachUsrAndPolicy(tx, groupID, authzProvider)
}

func grantGroupPolicy(db *sqlx.DB, groupName string, policyName string, authzProvider sql.NullString) *ErrorResponse {
	stmt := `
		INSERT INTO grp_policy(grp_id, policy_id, authz_provider)
		VALUES ((SELECT id FROM grp WHERE name = $1), (SELECT id FROM policy WHERE name = $2), $3)
	`
	_, err := db.Exec(stmt, groupName, policyName, authzProvider)
	if err != nil {
		group, err := groupWithName(db, groupName)
		if group == nil {
			msg := fmt.Sprintf(
				"failed to grant policy to group: group does not exist: %s",
				groupName,
			)
			return newErrorResponse(msg, 404, nil)
		}
		if err != nil {
			msg := "group query failed"
			return newErrorResponse(msg, 500, &err)
		}
		policy, err := policyWithName(db, policyName)
		if policy == nil {
			msg := fmt.Sprintf(
				"failed to grant policy to group: policy does not exist: %s",
				policyName,
			)
			return newErrorResponse(msg, 400, nil)
		}
		if err != nil {
			msg := "policy query failed"
			return newErrorResponse(msg, 500, &err)
		}
		// at this point, we assume the group already has this policy. this is fine.
	}
	return nil
}

func revokeGroupPolicy(db *sqlx.DB, groupName string, policyName string, authzProvider sql.NullString) *ErrorResponse {
	stmt := `
		DELETE FROM grp_policy
		WHERE grp_id = (SELECT id FROM grp WHERE name = $1)
		AND policy_id = (SELECT id FROM policy WHERE name = $2)
	`
	var err error = nil
	if authzProvider.Valid {
		stmt += " AND authz_provider = $3"
		_, err = db.Exec(stmt, groupName, policyName, authzProvider)
	} else {
		_, err = db.Exec(stmt, groupName, policyName)
	}
	if err != nil {
		msg := "revoke policy query failed"
		return newErrorResponse(msg, 500, &err)
	}
	return nil
}
