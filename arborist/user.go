package arborist

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

type PolicyBinding struct {
	Policy    string  `json:"policy"`
	Role      string  `json:"role"`
	Resource  string  `json:"resource"`
	ExpiresAt *string `json:"expires_at"`
}

func (policyBinding *PolicyBinding) standardize() PolicyBinding {
	policyBinding.Resource = UnderscoreDecode(policyBinding.Resource)
	policy := PolicyBinding{
		Policy:    policyBinding.Policy,
		Role:      policyBinding.Role,
		Resource:  UnderscoreDecode(policyBinding.Resource),
		ExpiresAt: policyBinding.ExpiresAt,
	}
	return policy
}

type User struct {
	Name     string          `json:"name"`
	Email    string          `json:"email,omitempty"`
	Groups   []string        `json:"groups"`
	Policies []PolicyBinding `json:"policies"`
}

type Users struct {
	Users    []User          `json:"users"`
	Policies []PolicyBinding `json:"policies"`
	Groups   []string        `json:"groups"`
}

func (user *User) UnmarshalJSON(data []byte) error {
	fields := make(map[string]interface{})
	err := json.Unmarshal(data, &fields)
	if err != nil {
		return err
	}
	optionalFields := map[string]struct{}{
		"email":    struct{}{},
		"groups":   struct{}{},
		"policies": struct{}{},
	}
	err = validateJSON("user", user, fields, optionalFields)
	if err != nil {
		return err
	}

	// Trick to use `json.Unmarshal` inside here, making a type alias which we
	// cast the Role to. Since this is just type conversion there's no
	// runtime cost.
	type loader User
	err = json.Unmarshal(data, (*loader)(user))
	if err != nil {
		return err
	}

	return nil
}

type UserFromQuery struct {
	ID       int64          `db:"id"`
	Name     string         `db:"name"`
	Email    *string        `db:"email"`
	Groups   pq.StringArray `db:"groups"`
	Policies []byte         `db:"policies"`
}

func (userFromQuery *UserFromQuery) standardize() User {
	if len(userFromQuery.Policies) == 0 {
		userFromQuery.Policies = []byte("[]")
	}
	policies := []PolicyBinding{}
	resultPolicies := []PolicyBinding{}
	err := json.Unmarshal(userFromQuery.Policies, &policies)
	for _, policyBinding := range policies {
		policy := policyBinding.standardize()
		resultPolicies = append(resultPolicies, policy)
	}
	if err != nil {
		// debug
		fmt.Printf("ERROR: UserFromQuery loader is broken: %s\n", err.Error())
	}
	user := User{
		Name:     userFromQuery.Name,
		Groups:   userFromQuery.Groups,
		Policies: resultPolicies,
	}
	if userFromQuery.Email != nil {
		user.Email = *userFromQuery.Email
	}
	return user
}

func userWithName(db *sqlx.DB, name string) (*UserFromQuery, error) {
	stmt := `
		SELECT
			usr.id,
			usr.name,
			usr.email,
			array_remove(array_agg(DISTINCT grp.name), NULL) AS groups,
			(
				SELECT json_agg(json_build_object('policy', policy.name, 'expires_at', usr_policy.expires_at))
				FROM usr_policy
				INNER JOIN policy ON policy.id = usr_policy.policy_id
				WHERE usr_policy.usr_id = usr.id
			) AS policies
		FROM usr
		LEFT JOIN usr_grp ON usr_grp.usr_id = usr.id
		LEFT JOIN grp ON grp.id = usr_grp.grp_id
		WHERE usr.name = $1
		GROUP BY usr.id
	`
	users := []UserFromQuery{}
	err := db.Select(&users, stmt, name)
	if err != nil {
		return nil, err
	}
	if len(users) == 0 {
		return nil, nil
	}
	user := users[0]
	user.Groups = append(user.Groups, LoggedInGroup)
	return &user, nil
}

func listUsersFromDb(db *sqlx.DB, r *http.Request) ([]UserFromQuery, *Pagination, error) {
	stmt := `
		SELECT
			usr.id,
			usr.name,
			usr.email,
			array_remove(array_agg(DISTINCT grp.name), NULL) AS groups,
			(
				SELECT json_agg(json_build_object('policy', policy.name, 'expires_at', usr_policy.expires_at, 'role', role.name, 'resource', resource.name, 'resource_path', resource.path)) 
				FROM usr_policy
				INNER JOIN policy ON policy.id = usr_policy.policy_id
				INNER JOIN policy_role ON policy_role.policy_id = policy.id
				INNER JOIN role ON role.id = policy_role.role_id
				INNER JOIN policy_resource ON policy_resource.policy_id = policy.id
				INNER JOIN resource ON resource.id = policy_resource.resource_id
				WHERE usr_policy.usr_id = usr.id
			) AS policies
		FROM usr
		LEFT JOIN usr_grp ON usr.id = usr_grp.usr_id
		LEFT JOIN grp ON grp.id = usr_grp.grp_id
	`
	vars := r.URL.Query()
	conditions := make([]string, 0)
	rolesConditions := make([]string, 0)
	resourceConditions := make([]string, 0)
	groupConditions := make([]string, 0)
	if len(vars["roles[]"]) != 0 {
		for _, v := range vars["roles[]"] {
			rolesConditions = append(rolesConditions, "'" + v + "'")
		}
		if len(rolesConditions) != 0 {
			conditions = append(conditions, "ARRAY[" + strings.Join(rolesConditions, ", ") + "] <@ array_agg(DISTINCT role.name)")
		}
	}
	if len(vars["resources[]"]) != 0 {
		for _, v := range vars["resources[]"] {
			resourceConditions = append(resourceConditions, "'" + v + "'")
		}
		if len(resourceConditions) != 0 {
			conditions = append(conditions, "ARRAY[" + strings.Join(resourceConditions, ",") + "] <@ array_agg(resource.tag)")
		}
	}
	if len(vars["groups[]"]) != 0 {
		for _, v := range vars["groups[]"] {
			groupConditions = append(groupConditions, "'" + v + "'")
		}
		if len(groupConditions) != 0 {
			conditions = append(conditions, "ARRAY[" + strings.Join(groupConditions, ",") + "] <@ array_remove(array_agg(DISTINCT grp.name), NULL)")
		}
	}
	if len(resourceConditions) != 0 || len(rolesConditions) != 0 {
		stmt = stmt + `
		LEFT JOIN usr_policy ON usr_policy.usr_id = usr.id LEFT JOIN policy ON policy.id = usr_policy.policy_id`
		if len(rolesConditions) != 0 {
			stmt = stmt + `
			LEFT JOIN policy_role ON policy_role.policy_id = policy.id LEFT JOIN role ON role.id = policy_role.role_id
			`
		}
		if len(resourceConditions) != 0 {
			stmt = stmt + `
			LEFT JOIN policy_resource ON policy_resource.policy_id = policy.id LEFT JOIN resource ON resource.id = policy_resource.resource_id
			`
		}
	}
	stmt = stmt + `
		GROUP BY usr.id
	`
	if len(conditions) != 0 {
		stmt = stmt + "HAVING " + strings.Join(conditions, " AND ")
	}
	users := []UserFromQuery{}
	pagination, err := SelectWithPagination(db, &users, stmt, r)
	if err != nil {
		return nil, nil, err
	}
	return users, pagination, nil
}

func (user *User) createInDb(db *sqlx.DB) *ErrorResponse {
	tx, err := db.Beginx()
	if err != nil {
		msg := fmt.Sprintf("couldn't open database transaction: %s", err.Error())
		return newErrorResponse(msg, 500, &err)
	}

	// First, insert permissions if they don't exist yet. If they don't exist
	// then use the contents of this user to create them; if they exist already
	// then IGNORE the contents, and use what's in the database. In postgres we
	// can use `ON CONFLICT DO NOTHING` for this.

	var userID int
	stmt := `
		INSERT INTO usr(name, email)
		VALUES ($1, $2)
		RETURNING id
	`
	row := tx.QueryRowx(stmt, user.Name, user.Email)
	err = row.Scan(&userID)
	if err != nil {
		// should add more checking here to guarantee the correct error
		_ = tx.Rollback()
		// this should only fail because the user was not unique. return error
		// accordingly
		msg := fmt.Sprintf("failed to insert user: user with this ID already exists: %s", user.Name)
		return newErrorResponse(msg, 409, &err)
	}

	err = tx.Commit()
	if err != nil {
		_ = tx.Rollback()
		msg := fmt.Sprintf("couldn't commit database transaction: %s", err.Error())
		return newErrorResponse(msg, 500, &err)
	}

	return nil
}

func (users *Users) multiCreateInDb(db *sqlx.DB) *ErrorResponse {
	tx, err := db.Beginx()
	if err != nil {
		msg := fmt.Sprintf("couldn't open database transaction: %s", err.Error())
		return newErrorResponse(msg, 500, &err)
	}

	// First, insert policy if they don't exist yet. if they exist already
	// then ONLY need to bind the policy to the user.

	for _, user := range users.Users {
		var userID int
		stmt := `
			INSERT INTO usr(name, email)
			VALUES ($1, $2)
			RETURNING id
		`
		row := tx.QueryRowx(stmt, user.Name, user.Email)
		err := row.Scan(&userID)
		if err != nil {
			_ = tx.Rollback()
			// this should only fail because the user was not unique. return error
			// accordingly
			msg := fmt.Sprintf("failed to insert user: user with this ID already exists: %s", user.Name)
			return newErrorResponse(msg, 409, &err)
		}

		stmt = multiInsertStmt("usr_grp(usr_id, grp_id)", len(users.Groups))
		userGroupRows := []interface{}{}
		for i, groupName := range users.Groups {
			if groupName == AnonymousGroup || groupName == LoggedInGroup {
				_ = tx.Rollback()
				return newErrorResponse("can't add users to built-in groups", 400, nil)
			}
			stmt = strings.Replace(stmt, "$"+strconv.Itoa(i*2+2),
				"(SELECT id FROM grp WHERE name = $"+strconv.Itoa(i*2+2)+")", 1)
			userGroupRows = append(userGroupRows, userID)
			userGroupRows = append(userGroupRows, groupName)
		}

		_, err = tx.Exec(stmt, userGroupRows...)
		if err != nil {
			_ = tx.Rollback()
			msg := fmt.Sprintf("failed to bind group while adding users: %s", err.Error())
			return newErrorResponse(msg, 500, &err)
		}

		newPolicies := make([] struct {
			policyBinding PolicyBinding
			policyID      int64
		}, 0)
		userPolicyStmt := multiInsertStmt("usr_policy(usr_id,policy_id)", len(users.Policies))
		userPolicyRows := []interface{}{}
		for _, policyBinding := range users.Policies {
			var policyID int64
			policyInDb, err := policyWithName(db, policyBinding.Policy)
			if err != nil {
				_ = tx.Rollback()
				msg := "policy query failed"
				return newErrorResponse(msg, 500, &err)
			}
			if policyInDb == nil {
				// policy does not exist
				stmt := "INSERT INTO policy(name, description) VALUES ($1, $2) RETURNING id"
				row := tx.QueryRowx(stmt, policyBinding.Policy, "")
				err := row.Scan(&policyID)

				if err != nil {
					_ = tx.Rollback()
					msg := fmt.Sprintf("failed to insert policy: policy with this ID already exists: %s",
						policyBinding.Policy)
					return newErrorResponse(msg, 409, &err)
				}
				newPolicies = append(newPolicies, struct {
					policyBinding PolicyBinding
					policyID      int64
				}{policyBinding: policyBinding, policyID: policyID})
			} else {
				policyID = policyInDb.ID
			}
			userPolicyRows = append(userPolicyRows, userID)
			userPolicyRows = append(userPolicyRows, policyID)
		}

		policyRoleStmt := multiInsertStmt("policy_role(policy_id, role_id)", len(newPolicies))
		policyResourceStmt := multiInsertStmt("policy_resource(policy_id, resource_id)", len(newPolicies))
		policyRoleRows := []interface{}{}
		policyResourceRows := []interface{}{}

		if len(newPolicies) != 0 {
			// New policy requires binding of role and resource
			for i, policy := range newPolicies {
				// Create policy with resource and role
				policyRoleStmt = strings.Replace(policyRoleStmt, "$"+strconv.Itoa(i*2+2),
					"(SELECT id FROM role WHERE name = $"+strconv.Itoa(i*2+2)+")", 1)
				policyResourceStmt = strings.Replace(policyResourceStmt, "$"+strconv.Itoa(i*2+2),
					"(SELECT id FROM resource WHERE name = $"+strconv.Itoa(i*2+2)+")", 1)
				policyRoleRows = append(policyRoleRows, policy.policyID)
				policyRoleRows = append(policyRoleRows, policy.policyBinding.Role)
				policyResourceRows = append(policyResourceRows, policy.policyID)
				// Resource name needs to encode
				policyResourceRows = append(policyResourceRows, UnderscoreEncode(policy.policyBinding.Resource))
			}

			_, err = tx.Exec(policyRoleStmt, policyRoleRows...)
			if err != nil {
				_ = tx.Rollback()
				msg := fmt.Sprintf("failed to bind Role with policy while adding users: %s", err.Error())
				return newErrorResponse(msg, 500, &err)
			}

			_, err = tx.Exec(policyResourceStmt, policyResourceRows...)
			if err != nil {
				_ = tx.Rollback()
				msg := fmt.Sprintf("failed to bind Resource with policy while adding users: %s", err.Error())
				return newErrorResponse(msg, 500, &err)
			}
		}

		_, err = tx.Exec(userPolicyStmt, userPolicyRows...)
		if err != nil {
			_ = tx.Rollback()
			msg := fmt.Sprintf("failed to bind user with policy while adding users: %s", err.Error())
			return newErrorResponse(msg, 500, &err)
		}
	}

	err = tx.Commit()
	if err != nil {
		_ = tx.Rollback()
		msg := fmt.Sprintf("couldn't commit database transaction: %s", err.Error())
		return newErrorResponse(msg, 500, &err)
	}

	return nil
}

func (user *User) deleteInDb(db *sqlx.DB) *ErrorResponse {
	stmt := "DELETE FROM usr WHERE name = $1"
	_, err := db.Exec(stmt, user.Name)
	if err != nil {
		// TODO: verify correct error
		// user does not exist; that's fine
		return nil
	}
	return nil
}

func grantUserPolicy(db *sqlx.DB, username string, policyName string, expiresAt *time.Time, authzProvider sql.NullString) *ErrorResponse {
	stmt := `
		INSERT INTO usr_policy(usr_id, policy_id, expires_at, authz_provider)
		VALUES ((SELECT id FROM usr WHERE name = $1), (SELECT id FROM policy WHERE name = $2), $3, $4)
		ON CONFLICT (usr_id, policy_id) DO UPDATE SET expires_at = EXCLUDED.expires_at
	`
	_, err := db.Exec(stmt, username, policyName, expiresAt, authzProvider)
	if err != nil {
		user, err := userWithName(db, username)
		if user == nil {
			msg := fmt.Sprintf(
				"failed to grant policy to user: user does not exist: %s",
				username,
			)
			return newErrorResponse(msg, 404, nil)
		}
		if err != nil {
			msg := "user query failed"
			return newErrorResponse(msg, 500, &err)
		}
		policy, err := policyWithName(db, policyName)
		if policy == nil {
			msg := fmt.Sprintf(
				"failed to grant policy to user: policy does not exist: %s",
				policyName,
			)
			return newErrorResponse(msg, 400, nil)
		}
		if err != nil {
			msg := "policy query failed"
			return newErrorResponse(msg, 500, &err)
		}
		// at this point, we assume the user already has this policy. this is fine.
	}
	return nil
}

func revokeUserPolicy(db *sqlx.DB, username string, policyName string, authzProvider sql.NullString) *ErrorResponse {
	stmt := `
		DELETE FROM usr_policy
		WHERE usr_id = (SELECT id FROM usr WHERE name = $1)
		AND policy_id = (SELECT id FROM policy WHERE name = $2)
	`
	var err error = nil
	if authzProvider.Valid {
		stmt += " AND authz_provider = $3"
		_, err = db.Exec(stmt, username, policyName, authzProvider)
	} else {
		_, err = db.Exec(stmt, username, policyName)
	}
	if err != nil {
		msg := "revoke policy query failed"
		return newErrorResponse(msg, 500, &err)
	}
	return nil
}

func revokeUserPolicyAll(db *sqlx.DB, username string, authzProvider sql.NullString) *ErrorResponse {
	stmt := `
		DELETE FROM usr_policy
		WHERE usr_id = (SELECT id FROM usr WHERE name = $1)
	`
	var err error = nil
	if authzProvider.Valid {
		stmt += " AND authz_provider = $2"
		_, err = db.Exec(stmt, username, authzProvider)
	} else {
		_, err = db.Exec(stmt, username)
	}
	if err != nil {
		msg := "revoke policy query failed"
		return newErrorResponse(msg, 500, &err)
	}
	return nil
}

func addUserToGroup(db *sqlx.DB, username string, groupName string, expiresAt *time.Time, authzProvider sql.NullString) *ErrorResponse {
	if groupName == AnonymousGroup || groupName == LoggedInGroup {
		return newErrorResponse("can't add users to built-in groups", 400, nil)
	}
	if username == "" {
		return newErrorResponse("missing `username` argument", 400, nil)
	}
	stmt := `
		INSERT INTO usr_grp(usr_id, grp_id, expires_at, authz_provider)
		VALUES ((SELECT id FROM usr WHERE name = $1), (SELECT id FROM grp WHERE name = $2), $3, $4)
		ON CONFLICT (usr_id, grp_id) DO UPDATE SET expires_at = EXCLUDED.expires_at
	`
	_, err := db.Exec(stmt, username, groupName, expiresAt, authzProvider)
	if err != nil {
		user, err := userWithName(db, username)
		if user == nil {
			msg := fmt.Sprintf(
				"failed to add user to group: user does not exist: `%s`",
				username,
			)
			return newErrorResponse(msg, 400, nil)
		}
		if err != nil {
			msg := "user query failed"
			return newErrorResponse(msg, 500, &err)
		}
		group, err := groupWithName(db, groupName)
		if group == nil {
			msg := fmt.Sprintf(
				"failed to add user to group: group does not exist: %s",
				groupName,
			)
			return newErrorResponse(msg, 404, nil)
		}
		if err != nil {
			msg := "group query failed"
			return newErrorResponse(msg, 500, &err)
		}
		// at this point, we assume the user is already in the group. this is fine
	}
	return nil
}

func removeUserFromGroup(db *sqlx.DB, username string, groupName string, authzProvider sql.NullString) *ErrorResponse {
	stmt := `
		DELETE FROM usr_grp
		WHERE usr_id = (SELECT id FROM usr WHERE name = $1)
		AND grp_id = (SELECT id FROM grp WHERE name = $2)
	`
	var err error = nil
	if authzProvider.Valid {
		stmt += " AND authz_provider = $3"
		_, err = db.Exec(stmt, username, groupName, authzProvider)
	} else {
		_, err = db.Exec(stmt, username, groupName)
	}
	if err != nil {
		msg := "remove user from group query failed"
		return newErrorResponse(msg, 500, &err)
	}
	return nil
}
