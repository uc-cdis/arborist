package arborist

import (
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

// UserFromQuery is used to read out a "standard" query for a user into a struct.
//
// This struct should be loaded into using the query in `userWithName`.
//
// `Policies` contains TODO
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

func grantUserPolicy(db *sqlx.DB, username string, policyName string, expiresAt *time.Time) *ErrorResponse {
	stmt := `
		INSERT INTO usr_policy(usr_id, policy_id, expires_at)
		VALUES ((SELECT id FROM usr WHERE name = $1), (SELECT id FROM policy WHERE name = $2), $3)
		ON CONFLICT (usr_id, policy_id) DO UPDATE SET expires_at = EXCLUDED.expires_at
	`
	_, err := db.Exec(stmt, username, policyName, expiresAt)
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

func revokeUserPolicy(db *sqlx.DB, username string, policyName string) *ErrorResponse {
	stmt := `
		DELETE FROM usr_policy
		WHERE usr_id = (SELECT id FROM usr WHERE name = $1)
		AND policy_id = (SELECT id FROM policy WHERE name = $2)
	`
	_, err := db.Exec(stmt, username, policyName)
	if err != nil {
		msg := "revoke policy query failed"
		return newErrorResponse(msg, 500, &err)
	}
	return nil
}

func revokeUserPolicyAll(db *sqlx.DB, username string) *ErrorResponse {
	stmt := `
		DELETE FROM usr_policy
		WHERE usr_id = (SELECT id FROM usr WHERE name = $1)
	`
	_, err := db.Exec(stmt, username)
	if err != nil {
		msg := "revoke policy query failed"
		return newErrorResponse(msg, 500, &err)
	}
	return nil
}

func addUserToGroup(db *sqlx.DB, username string, groupName string, expiresAt *time.Time) *ErrorResponse {
	if groupName == AnonymousGroup || groupName == LoggedInGroup {
		return newErrorResponse("can't add users to built-in groups", 400, nil)
	}
	if username == "" {
		return newErrorResponse("missing `username` argument", 400, nil)
	}
	stmt := `
		INSERT INTO usr_grp(usr_id, grp_id, expires_at)
		VALUES ((SELECT id FROM usr WHERE name = $1), (SELECT id FROM grp WHERE name = $2), $3)
		ON CONFLICT (usr_id, grp_id) DO UPDATE SET expires_at = EXCLUDED.expires_at
	`
	_, err := db.Exec(stmt, username, groupName, expiresAt)
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

func removeUserFromGroup(db *sqlx.DB, username string, groupName string) *ErrorResponse {
	stmt := `
		DELETE FROM usr_grp
		WHERE usr_id = (SELECT id FROM usr WHERE name = $1)
		AND grp_id = (SELECT id FROM grp WHERE name = $2)
	`
	_, err := db.Exec(stmt, username, groupName)
	if err != nil {
		msg := "remove user from group query failed"
		return newErrorResponse(msg, 500, &err)
	}
	return nil
}

