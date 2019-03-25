package arborist

import (
	"fmt"

	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

type User struct {
	Name   string   `json:"name"`
	Email  string   `json:"email,omitempty"`
	Groups []string `json:"groups"`
}

type UserFromQuery struct {
	Name   string         `db:"name"`
	Email  *string        `db:"email"`
	Groups pq.StringArray `db:"groups"`
}

func (userFromQuery *UserFromQuery) standardize() User {
	user := User{
		Name:   userFromQuery.Name,
		Groups: userFromQuery.Groups,
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
			array_remove(array_agg(grp.name), NULL) AS groups
		FROM usr
		LEFT JOIN usr_grp ON usr.id = usr_grp.usr_id
		LEFT JOIN grp ON grp.id = usr_grp.grp_id
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
			array_remove(array_agg(grp.name), NULL) AS groups
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
		fmt.Println(err)
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
		msg := fmt.Sprintf("failed to delete user: user does not exist: %s", user.Name)
		return newErrorResponse(msg, 404, nil)
	}
	return nil
}
