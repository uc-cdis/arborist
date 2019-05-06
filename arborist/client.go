package arborist

import (
	"fmt"

	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

type Client struct {
	ClientID string   `json:"clientID"`
	Policies []string `json:"policies"`
}

type ClientFromQuery struct {
	ClientID string         `db:"external_client_id"`
	Policies pq.StringArray `db:"policies"`
}

func (clientFromQuery *ClientFromQuery) standardize() Client {
	client := Client{
		ClientID: clientFromQuery.ClientID,
		Policies: clientFromQuery.Policies,
	}
	return client
}

func clientWithClientID(db *sqlx.DB, clientID string) (*ClientFromQuery, error) {
	stmt := `
		SELECT
			client.external_client_id,
			array_remove(array_agg(policy.name), NULL) AS policies
		FROM client
		LEFT JOIN client_policy ON client.id = client_policy.client_id
		LEFT JOIN policy ON policy.id = client_policy.policy_id
		WHERE client.external_client_id = $1
		GROUP BY client.id
		LIMIT 1
	`
	clients := []ClientFromQuery{}
	err := db.Select(&clients, stmt, clientID)
	if len(clients) == 0 {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	client := clients[0]
	return &client, nil
}

func listClientsFromDb(db *sqlx.DB) ([]ClientFromQuery, error) {
	stmt := `
		SELECT
			client.external_client_id,
			array_remove(array_agg(policy.name), NULL) AS policies
		FROM client
		LEFT JOIN client_policy ON client.id = client_policy.client_id
		LEFT JOIN policy ON policy.id = client_policy.policy_id
		GROUP BY client.id
	`
	clients := []ClientFromQuery{}
	err := db.Select(&clients, stmt)
	if err != nil {
		return nil, err
	}
	return clients, nil
}

func (client *Client) createInDb(db *sqlx.DB) *ErrorResponse {
	tx, err := db.Beginx()
	if err != nil {
		msg := fmt.Sprintf("couldn't open database transaction: %s", err.Error())
		return newErrorResponse(msg, 500, &err)
	}

	// First, insert permissions if they don't exist yet. If they don't exist
	// then use the contents of this client to create them; if they exist already
	// then IGNORE the contents, and use what's in the database. In postgres we
	// can use `ON CONFLICT DO NOTHING` for this.

	var clientDBID int
	stmt := `
		INSERT INTO client(external_client_id)
		VALUES ($1)
		RETURNING id
	`
	row := tx.QueryRowx(stmt, client.ClientID)
	err = row.Scan(&clientDBID)
	if err != nil {
		// should add more checking here to guarantee the correct error
		_ = tx.Rollback()
		// this should only fail because the client was not unique. return error
		// accordingly
		msg := fmt.Sprintf("failed to insert client: client with this ID already exists: %s", client.ClientID)
		return newErrorResponse(msg, 409, &err)
	}

	if len(client.Policies) > 0 {
		remaining := make(map[string]interface{})
		for _, policy := range client.Policies {
			remaining[policy] = nil
		}

		stmt = `
			WITH policies AS (
				SELECT id, name FROM policy WHERE name = ANY($1)
			),
			client_policies AS (
				INSERT INTO client_policy (client_id, policy_id)
				SELECT $2, id FROM policies
			)
			SELECT name FROM policies
		`
		rows, err := tx.Query(stmt, pq.Array(client.Policies), clientDBID)
		if err != nil {
			_ = tx.Rollback()
			return newErrorResponse("failed to grant policy", 500, &err)
		}
		for rows.Next() {
			var policy string
			err = rows.Scan(&policy)
			if err != nil {
				_ = tx.Rollback()
				return newErrorResponse("failed to grant policy", 500, &err)
			}
			delete(remaining, policy)
		}
		if len(remaining) != 0 {
			_ = tx.Rollback()
			missingPolicies := make([]string, len(remaining))
			i := 0
			for policy := range remaining {
				missingPolicies[i] = policy
				i++
			}
			msg := fmt.Sprintf(
				"failed to grant policy to client: policies does not exist: %v",
				missingPolicies,
			)
			return newErrorResponse(msg, 404, &err)
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

func (client *Client) deleteInDb(db *sqlx.DB) *ErrorResponse {
	stmt := "DELETE FROM client WHERE external_client_id = $1"
	_, err := db.Exec(stmt, client.ClientID)
	if err != nil {
		// TODO: verify correct error
		msg := fmt.Sprintf("failed to delete client: client does not exist: %s", client.ClientID)
		return newErrorResponse(msg, 404, nil)
	}
	return nil
}

func grantClientPolicy(db *sqlx.DB, clientID string, policyName string) *ErrorResponse {
	stmt := `
		INSERT INTO client_policy(client_id, policy_id)
		VALUES ((SELECT id FROM client WHERE external_client_id = $1), (SELECT id FROM policy WHERE name = $2))
	`
	_, err := db.Exec(stmt, clientID, policyName)
	if err != nil {
		client, err := clientWithClientID(db, clientID)
		if client == nil {
			msg := fmt.Sprintf(
				"failed to grant policy to client: client does not exist: %s",
				clientID,
			)
			return newErrorResponse(msg, 404, nil)
		}
		if err != nil {
			msg := "client query failed"
			return newErrorResponse(msg, 500, &err)
		}
		policy, err := policyWithName(db, policyName)
		if policy == nil {
			msg := fmt.Sprintf(
				"failed to grant policy to client: policy does not exist: %s",
				policyName,
			)
			return newErrorResponse(msg, 404, nil)
		}
		if err != nil {
			msg := "policy query failed"
			return newErrorResponse(msg, 500, &err)
		}
		// at this point, we assume the client already has this policy. this is fine.
	}
	return nil
}

func revokeClientPolicy(db *sqlx.DB, clientID string, policyName string) *ErrorResponse {
	stmt := `
		DELETE FROM client_policy
		WHERE client_id = (SELECT id FROM client WHERE external_client_id = $1)
		AND policy_id = (SELECT id FROM policy WHERE name = $2)
	`
	_, err := db.Exec(stmt, clientID, policyName)
	if err != nil {
		msg := "revoke policy query failed"
		return newErrorResponse(msg, 500, &err)
	}
	return nil
}

func revokeClientPolicyAll(db *sqlx.DB, clientID string) *ErrorResponse {
	stmt := `
		DELETE FROM client_policy
		WHERE client_id = (SELECT id FROM client WHERE external_client_id = $1)
	`
	_, err := db.Exec(stmt, clientID)
	if err != nil {
		msg := "revoke policy query failed"
		return newErrorResponse(msg, 500, &err)
	}
	return nil
}
