package arborist

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

type PolicyBinding struct {
	Policy    string  `json:"policy"`
	ExpiresAt *string `json:"expires_at"`
}

type User struct {
	Name     string          `json:"name"`
	Email    string          `json:"email,omitempty"`
	Groups   []string        `json:"groups"`
	Policies []PolicyBinding `json:"policies"`
}

type UserWithScalars struct {
	Name  *string `json:"name,omitempty"`
	Email *string `json:"email,omitempty"`
}

func (user *User) UnmarshalJSON(data []byte) error {
	fields := make(map[string]interface{})
	err := json.Unmarshal(data, &fields)
	if err != nil {
		return err
	}
	optionalFields := map[string]struct{}{
		"email":    {},
		"groups":   {},
		"policies": {},
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
	err := json.Unmarshal(userFromQuery.Policies, &policies)
	if err != nil {
		// debug
		fmt.Printf("ERROR: UserFromQuery loader is broken: %s\n", err.Error())
	}
	user := User{
		Name:     userFromQuery.Name,
		Groups:   userFromQuery.Groups,
		Policies: policies,
	}
	if userFromQuery.Email != nil {
		user.Email = *userFromQuery.Email
	}
	return user
}

func userWithName(db *sqlx.DB, name string) (*UserFromQuery, error) {
	// NOTE @mpingram 2019-12-11: An explanation of the user's policies and their expiration
	// dates returned from this query.
	// The user's policies can come from three different sources, and policies from different
	// sources expire in different ways:
	// 1. Policies granted to the user:
	// 		- Policies granted to the user have an expiration date (`usr_policy.expires_at`).
	// 2. Policies in user's groups:
	//		- Policies granted to groups the user is a member of expire when the user's membership
	// 		in that group expires (`usr_group.expires_at`).
	// 3. Policies granted to the Anonymous and LoggedIn groups:
	// 		- Membership in the built-in groups does not expire. We use expires_at = NULL to represent
	// 		'no expiration for this policy'.
	stmt := `
		SELECT
			usr.id,
			usr.name,
			usr.email,
			array_remove(array_agg(DISTINCT grp.name), NULL) AS groups,
			(
				SELECT json_agg(json_build_object('policy', all_policies.name, 'expires_at', all_policies.expires_at))
				FROM (
					SELECT policy.name AS name, usr_policy.expires_at AS expires_at
					FROM usr_policy
					INNER JOIN policy ON policy.id = usr_policy.policy_id
					WHERE usr_policy.usr_id = usr.id
					UNION
					SELECT policy.name AS name, usr_grp.expires_at AS expires_at
					FROM usr_grp
					INNER JOIN grp_policy ON grp_policy.grp_id = usr_grp.grp_id
					INNER JOIN policy ON policy.id = grp_policy.policy_id
					WHERE usr_grp.usr_id = usr.id
					UNION
					SELECT policy.name AS name, NULL AS expires_at
					FROM grp
					INNER JOIN grp_policy ON grp_policy.grp_id = grp.id
					INNER JOIN policy ON policy.id = grp_policy.policy_id
					WHERE grp.name IN ($2, $3) 
				) AS all_policies
			) AS policies
		FROM usr
		LEFT JOIN usr_grp ON usr_grp.usr_id = usr.id
		LEFT JOIN grp ON (
			grp.id = usr_grp.grp_id OR grp.name IN ($2, $3)
		)
		WHERE usr.name = $1
		GROUP BY usr.id
	`
	users := []UserFromQuery{}
	err := db.Select(
		&users,
		stmt,
		name,           // $1
		AnonymousGroup, // $2
		LoggedInGroup,  // $3
	)
	if err != nil {
		return nil, err
	}
	if len(users) == 0 {
		return nil, nil
	}
	user := users[0]
	return &user, nil
}

func listUsersFromDb(db *sqlx.DB) ([]UserFromQuery, error) {
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
		LEFT JOIN usr_grp ON usr.id = usr_grp.usr_id
		LEFT JOIN grp ON grp.id = usr_grp.grp_id
		GROUP BY usr.id
	`
	users := []UserFromQuery{}
	err := db.Select(&users, stmt)
	if err != nil {
		return nil, err
	}
	return users, nil
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

func (user *User) updateInDb(db *sqlx.DB, name *string, email *string) *ErrorResponse {
	stmt := `
		UPDATE usr
		SET
			name = COALESCE($1, name),
			email = COALESCE($2, email)
		WHERE
			name = $3
	`
	result, err := db.Exec(stmt, name, email, user.Name)
	if err != nil {
		// this should only fail because the target name was not unique
		msg := fmt.Sprintf(`failed to update name to "%s": user with this name already exists`, *name)
		return newErrorResponse(msg, 409, &err)
	}

	rowsAffeted, _ := result.RowsAffected()
	if rowsAffeted == 0 {
		msg := fmt.Sprintf(
			"failed to update user: user does not exist: %s",
			user.Name,
		)
		return newErrorResponse(msg, 404, nil)
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
