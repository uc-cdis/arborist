package arborist

import (
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

func (group *Group) createInDb(tx *sqlx.Tx) *ErrorResponse {
	// First, insert permissions if they don't exist yet. If they don't exist
	// then use the contents of this group to create them; if they exist already
	// then IGNORE the contents, and use what's in the database. In postgres we
	// can use `ON CONFLICT DO NOTHING` for this.

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

	// add users to the group
	if len(group.Users) > 0 {
		users, err := group.users(tx)
		if err != nil {
			msg := fmt.Sprintf("database call for users failed: %s", err.Error())
			return newErrorResponse(msg, 500, &err)
		}
		stmt = multiInsertStmt("usr_grp(usr_id, grp_id)", len(group.Users))
		userGroupRows := []interface{}{}
		for _, user := range users {
			userGroupRows = append(userGroupRows, user.ID)
			userGroupRows = append(userGroupRows, groupID)
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
		stmt = multiInsertStmt("grp_policy(grp_id, policy_id)", len(group.Policies))
		groupPolicyRows := []interface{}{}
		for _, policy := range policies {
			groupPolicyRows = append(groupPolicyRows, groupID)
			groupPolicyRows = append(groupPolicyRows, policy.ID)
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

func (group *Group) overwriteInDb(tx *sqlx.Tx) *ErrorResponse {
	errResponse := group.deleteInDb(tx)
	if errResponse != nil {
		return errResponse
	}
	return group.createInDb(tx)
}

func grantGroupPolicy(db *sqlx.DB, groupName string, policyName string) *ErrorResponse {
	stmt := `
		INSERT INTO grp_policy(grp_id, policy_id)
		VALUES ((SELECT id FROM grp WHERE name = $1), (SELECT id FROM policy WHERE name = $2))
	`
	_, err := db.Exec(stmt, groupName, policyName)
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

func revokeGroupPolicy(db *sqlx.DB, groupName string, policyName string) *ErrorResponse {
	stmt := `
		DELETE FROM grp_policy
		WHERE grp_id = (SELECT id FROM grp WHERE name = $1)
		AND policy_id = (SELECT id FROM policy WHERE name = $2)
	`
	_, err := db.Exec(stmt, groupName, policyName)
	if err != nil {
		msg := "revoke policy query failed"
		return newErrorResponse(msg, 500, &err)
	}
	return nil
}
