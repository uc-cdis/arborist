package arborist

import (
	"encoding/json"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

type AuthRequestJSON struct {
	User    AuthRequestJSON_User    `json:"user"`
	Request AuthRequestJSON_Request `json:"request"`
}

type AuthRequestJSON_User struct {
	Token string `json:"token"`
	// The Policies field is optional, and if the request provides a token
	// this gets filled in using the Token field.
	Policies  []string `json:"policies,omitempty"`
	Audiences []string `json:"aud,omitempty"`
}

func (requestJSON *AuthRequestJSON_User) UnmarshalJSON(data []byte) error {
	fields := make(map[string]interface{})
	err := json.Unmarshal(data, &fields)
	if err != nil {
		return err
	}
	optionalFields := map[string]struct{}{
		"policies": struct{}{},
		"aud":      struct{}{},
	}
	err = validateJSON("auth request", requestJSON, fields, optionalFields)
	if err != nil {
		return err
	}

	// Trick to use `json.Unmarshal` inside here, making a type alias which we
	// cast the AuthRequestJSON to.
	type loader AuthRequestJSON_User
	err = json.Unmarshal(data, (*loader)(requestJSON))
	if err != nil {
		return err
	}

	return nil
}

type AuthRequestJSON_Request struct {
	Resource    string      `json:"resource"`
	Action      Action      `json:"action"`
	Constraints Constraints `json:"constraints,omitempty"`
}

// UnmarshalJSON defines the deserialization from JSON into an AuthRequestJSON
// struct, which includes validating that required fields are present.
// (Required fields are anything not in the `optionalFields` variable.)
func (requestJSON *AuthRequestJSON_Request) UnmarshalJSON(data []byte) error {
	fields := make(map[string]interface{})
	err := json.Unmarshal(data, &fields)
	if err != nil {
		return err
	}
	optionalFields := map[string]struct{}{
		"constraints": struct{}{},
	}
	err = validateJSON("auth request", requestJSON, fields, optionalFields)
	if err != nil {
		return err
	}

	// Trick to use `json.Unmarshal` inside here, making a type alias which we
	// cast the AuthRequestJSON to.
	type loader AuthRequestJSON_Request
	err = json.Unmarshal(data, (*loader)(requestJSON))
	if err != nil {
		return err
	}

	return nil
}

func authorize(db *sqlx.DB, token *TokenInfo, resource string, service string, method string) (bool, error) {
	exp, args, err := Parse(resource)
	if err != nil {
		return false, err
	}

	stmt := `
SELECT coalesce(text2ltree("unnest") @> allowed, FALSE) FROM (
       SELECT array_agg(resource.path) AS allowed
         FROM usr
    LEFT JOIN usr_policy
           ON usr_policy.usr_id = usr.id
    LEFT JOIN policy_resource
           ON policy_resource.policy_id = usr_policy.policy_id
    LEFT JOIN resource
           ON resource.id = policy_resource.resource_id
        WHERE usr.name = $1
          AND EXISTS (
                     SELECT 1
                       FROM policy_role
                  LEFT JOIN permission
                         ON permission.role_id = policy_role.role_id
                      WHERE policy_role.policy_id = usr_policy.policy_id
                        AND permission.service = $2
                        AND permission.method = $3
              )
          AND ($4 OR usr_policy.policy_id IN (
                  SELECT id
                    FROM policy
                   WHERE policy.name = ANY($5)
              ))
) _, unnest($6::text[]);
`

	rows, err := db.Query(stmt,
		token.username,  // $1
		service,  // $2
		method,  // $3
		len(token.policies) == 0,  // $4
		pq.Array(token.policies),  // $5
		pq.Array(args),  // $6
	)
	if err != nil {
		return false, err
	}

	i := 0
	vars := make(map[string]bool)
	for rows.Next() {
		var result bool
		err = rows.Scan(&result)
		if err != nil {
			return false, err
		}
		vars[args[i]] = result
		i ++
	}

	return Eval(exp, vars)
}
