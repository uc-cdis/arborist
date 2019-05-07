package arborist

import (
	"fmt"

	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

type User struct {
	Name     string   `json:"name"`
	Email    string   `json:"email,omitempty"`
	Groups   []string `json:"groups"`
	Policies []string `json:"policies"`
}

type UserFromQuery struct {
	Name     string         `db:"name"`
	Email    *string        `db:"email"`
	Groups   pq.StringArray `db:"groups"`
	Policies pq.StringArray `db:"policies"`
}

func (userFromQuery *UserFromQuery) standardize() User {
	user := User{
		Name:     userFromQuery.Name,
		Groups:   userFromQuery.Groups,
		Policies: userFromQuery.Policies,
	}
	if userFromQuery.Email != nil {
		user.Email = *userFromQuery.Email
	}
	return user
}

func userWithName(db *sqlx.DB, name string) (*UserFromQuery, error) {
	stmt := `
		SELECT
			usr.name,
			usr.email,
			array_remove(array_agg(grp.name), NULL) AS groups,
			array_remove(array_agg(policy.name), NULL) AS policies
		FROM usr
		LEFT JOIN usr_grp ON usr.id = usr_grp.usr_id
		LEFT JOIN grp ON grp.id = usr_grp.grp_id
		LEFT JOIN usr_policy ON usr.id = usr_policy.usr_id
		LEFT JOIN policy ON policy.id = usr_policy.policy_id
		WHERE usr.name = $1
		GROUP BY usr.id
		LIMIT 1
	`
	users := []UserFromQuery{}
	err := db.Select(&users, stmt, name)
	if len(users) == 0 {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	user := users[0]
	return &user, nil
}

func listUsersFromDb(db *sqlx.DB) ([]UserFromQuery, error) {
	stmt := `
		SELECT
			usr.name,
			usr.email,
			array_remove(array_agg(grp.name), NULL) AS groups,
			array_remove(array_agg(policy.name), NULL) AS policies
		FROM usr
		LEFT JOIN usr_grp ON usr.id = usr_grp.usr_id
		LEFT JOIN grp ON grp.id = usr_grp.grp_id
		LEFT JOIN usr_policy ON usr.id = usr_policy.usr_id
		LEFT JOIN policy ON policy.id = usr_policy.policy_id
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

func grantUserPolicy(db *sqlx.DB, username string, policyName string) *ErrorResponse {
	stmt := `
		INSERT INTO usr_policy(usr_id, policy_id)
		VALUES ((SELECT id FROM usr WHERE name = $1), (SELECT id FROM policy WHERE name = $2))
	`
	_, err := db.Exec(stmt, username, policyName)
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

func addUserToGroup(db *sqlx.DB, username string, groupName string) *ErrorResponse {
	if groupName == AnonymousGroup || groupName == LoggedInGroup {
		return newErrorResponse("can't add users to built-in groups", 400, nil)
	}
	stmt := `
		INSERT INTO usr_grp(usr_id, grp_id)
		VALUES ((SELECT id FROM usr WHERE name = $1), (SELECT id FROM grp WHERE name = $2))
	`
	_, err := db.Exec(stmt, username, groupName)
	if err != nil {
		user, err := userWithName(db, username)
		if user == nil {
			msg := fmt.Sprintf(
				"failed to add user to group: user does not exist: %s",
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
