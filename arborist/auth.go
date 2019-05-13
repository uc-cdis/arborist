package arborist

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

type AuthRequestJSON struct {
	User     AuthRequestJSON_User      `json:"user"`
	Request  *AuthRequestJSON_Request  `json:"request"`
	Requests []AuthRequestJSON_Request `json:"requests"`
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

type Constraints = map[string]string

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

type AuthRequest struct {
	Username string
	ClientID string
	Policies []string
	Resource string
	Service  string
	Method   string
	stmts    *CachedStmts
}

type AuthResponse struct {
	Auth bool `json:"auth"`
}

func parse(resource string) (Expression, []string, []string, error) {
	// parse the resource string
	exp, args, err := Parse(resource)
	if err != nil {
		// TODO (rudyardrichter, 2019-04-05): this can return some pretty
		// unintelligible errors from the yacc code. so far callers are OK to
		// validate inputs, but could do better to return more readable errors
		return nil, nil, nil, err
	}

	resources := make([]string, len(args))
	// format resource path for DB
	for i, arg := range args {
		resources[i] = formatPathForDb(arg)
	}

	return exp, args, resources, nil
}

// Authorize a request where the end user is anonymous, so there is no token
// involved, and access is granted only through the built-in anonymous group.
func authorizeAnonymous(request *AuthRequest) (*AuthResponse, error) {
	exp, args, resources, err := parse(request.Resource)

	// run authorization query
	rows, err := request.stmts.Query(
		`
		SELECT coalesce(text2ltree("unnest") <@ allowed, FALSE) FROM (
			SELECT array_agg(resource.path) AS allowed FROM (
				SELECT policy_id FROM grp_policy
				INNER JOIN grp ON grp_policy.grp_id = grp.id
				WHERE grp.name = 'anonymous'
			) AS policies
			JOIN policy_resource ON policy_resource.policy_id = policies.policy_id
			JOIN resource ON resource.id = policy_resource.resource_id
			WHERE EXISTS (
				SELECT 1 FROM policy_role
				JOIN permission ON permission.role_id = policy_role.role_id
				WHERE policy_role.policy_id = policies.policy_id
				AND permission.service = $1
				AND permission.method = $2
			) AND (
				$3 OR policies.policy_id IN (
					SELECT id FROM policy
					WHERE policy.name = ANY($4)
				)
			)
		) _, unnest($5::text[])
		`,
		request.Service,            // $1
		request.Method,             // $2
		len(request.Policies) == 0, // $3
		pq.Array(request.Policies), // $4
		pq.Array(resources),        // $5
	)
	if err != nil {
		return nil, err
	}

	rv, err := evaluate(exp, args, rows)
	if err != nil {
		return nil, err
	}
	return &AuthResponse{rv}, nil
}

// Authorize the given token to access resources by service and method.
// The given resource can be an expression of slash-separated resource paths
// connected with `and`, `or` or `not`. The priority of these boolean operators
// is: `not > and > or`. When in doubt, use parenthesises to specify explicitly.
func authorizeUser(request *AuthRequest) (*AuthResponse, error) {
	exp, args, resources, err := parse(request.Resource)
	rows, err := request.stmts.Query(
		`
		SELECT coalesce(text2ltree("unnest") <@ allowed, FALSE) FROM (
			SELECT (
				SELECT array_agg(resource.path) AS allowed FROM (
					SELECT policy_id FROM usr_policy
					WHERE usr_id = usr.id
					UNION
					SELECT policy_id FROM grp_policy
					INNER JOIN grp ON grp_policy.grp_id = grp.id
					LEFT JOIN usr_grp ON grp_policy.grp_id = usr_grp.grp_id
					WHERE (
						usr_grp.usr_id = usr.id
						OR grp.name = 'anonymous'
						OR grp.name = 'logged-in'
					)
				) AS policies
				JOIN policy_resource ON policy_resource.policy_id = policies.policy_id
				JOIN resource ON resource.id = policy_resource.resource_id
				WHERE EXISTS (
					SELECT 1 FROM policy_role
					JOIN permission ON permission.role_id = policy_role.role_id
					WHERE policy_role.policy_id = policies.policy_id
					AND (permission.service = $2 OR permission.service = '*')
					AND (permission.method = $3 OR permission.method = '*')
				) AND (
					$4 OR policies.policy_id IN (
						SELECT id FROM policy
						WHERE policy.name = ANY($5)
					)
				)
			) FROM usr
			WHERE usr.name = $1
		) _, unnest($6::text[])
		`,
		request.Username,           // $1
		request.Service,            // $2
		request.Method,             // $3
		len(request.Policies) == 0, // $4
		pq.Array(request.Policies), // $5
		pq.Array(resources),        // $6
	)
	if err != nil {
		return nil, err
	}

	rv, err := evaluate(exp, args, rows)
	if err != nil {
		return nil, err
	}
	return &AuthResponse{rv}, nil
}

// This is similar as authorizeUser, only that this method checks for clientID only
func authorizeClient(request *AuthRequest) (*AuthResponse, error) {
	exp, args, resources, err := parse(request.Resource)
	rows, err := request.stmts.Query(
		`
		SELECT coalesce(text2ltree("unnest") <@ allowed, FALSE) FROM (
			SELECT array_agg(resource.path) AS allowed FROM client
			JOIN client_policy ON client_policy.client_id = client.id
			JOIN policy_resource ON policy_resource.policy_id = client_policy.policy_id
			JOIN resource ON resource.id = policy_resource.resource_id
			WHERE client.external_client_id = $1
			AND EXISTS (
				SELECT 1 FROM policy_role
				JOIN permission ON permission.role_id = policy_role.role_id
				WHERE policy_role.policy_id = client_policy.policy_id
				AND (permission.service = $2 OR permission.service = '*')
				AND (permission.method = $3 OR permission.method = '*')
			)
		) _, unnest($4::text[]);
		`,
		request.ClientID,    // $1
		request.Service,     // $2
		request.Method,      // $3
		pq.Array(resources), // $4
	)
	if err != nil {
		return nil, err
	}

	rv, err := evaluate(exp, args, rows)
	if err != nil {
		return nil, err
	}
	return &AuthResponse{rv}, nil
}

func evaluate(exp Expression, args []string, rows *sql.Rows) (bool, error) {
	// build the map for evaluation
	i := 0
	vars := make(map[string]bool)
	for rows.Next() {
		var result bool
		err := rows.Scan(&result)
		if err != nil {
			return false, err
		}
		vars[args[i]] = result
		i++
	}
	if i != len(args) {
		// user not found (i = 0)
		return false, nil
	}

	// evaluate the result
	rv, err := Eval(exp, vars)
	if err != nil {
		return false, err
	}
	return rv, nil
}

func authorizedResources(db *sqlx.DB, request *AuthRequest) ([]ResourceFromQuery, *ErrorResponse) {
	// if policies are specified in the request, we can use those (simplest query).
	if request.Policies != nil && len(request.Policies) > 0 {
		values := ""
		for _, policy := range request.Policies {
			// FIXME (rudyardrichter, 2019-05-09): this could be a SQL
			// vulnerability if passed arbitrary inputs. As it is this only
			// gets passed the policies from decoded validated tokens.
			values += fmt.Sprintf("('%s'), ", policy)
		}
		values = strings.TrimRight(values, ", ")
		selectPolicyWhereName := fmt.Sprintf(
			"SELECT id FROM policy INNER JOIN (VALUES %s) values(v) ON name = v",
			values,
		)
		stmt := fmt.Sprintf(
			`
			SELECT
				resource.id,
				resource.name,
				resource.path,
				resource.tag,
				resource.description,
				array(
					SELECT child.path
					FROM resource AS child
					WHERE child.path ~ (
						CAST ((ltree2text(resource.path) || '.*{1}') AS lquery)
					)
				) AS subresources
			FROM resource
			INNER JOIN policy_resource ON resource.id = policy_resource.resource_id
			INNER JOIN usr_policy ON usr_policy.policy_id = policy_resource.policy_id
			WHERE (policy_resource.policy_id IN (%s))
			`,
			selectPolicyWhereName,
		)
		resources := []ResourceFromQuery{}
		err := db.Select(&resources, stmt)
		if err != nil {
			return nil, newErrorResponse("resources query (using policies) failed", 500, &err)
		}
		return resources, nil
	}
	resources := []ResourceFromQuery{}
	var err error
	if request.ClientID == "" {
		if request.Username == "" {
			return nil, newErrorResponse("missing username in auth request", 400, nil)
		}
		stmt := `
			SELECT
				resource.id,
				resource.name,
				resource.path,
				resource.tag,
				resource.description,
				array(
					SELECT child.path
					FROM resource AS child
					WHERE child.path ~ (
						CAST ((ltree2text(resource.path) || '.*{1}') AS lquery)
					)
				) AS subresources
			FROM (
				SELECT usr_policy.policy_id
				FROM usr
				JOIN usr_policy ON usr.id = usr_policy.usr_id
				WHERE usr.name = $1
			) policies
			INNER JOIN policy_resource ON policy_resource.policy_id = policies.policy_id
			INNER JOIN resource ON resource.id = policy_resource.resource_id
		`
		err = db.Select(&resources, stmt, request.Username)
		if err != nil {
			errResponse := newErrorResponse(
				"resources query (using username) failed",
				500,
				&err,
			)
			return nil, errResponse
		}
		return resources, nil
	} else {
		stmt := `
			SELECT
				resource.id,
				resource.name,
				resource.path,
				resource.tag,
				resource.description,
				array(
					SELECT child.path
					FROM resource AS child
					WHERE child.path ~ (
						CAST ((ltree2text(resource.path) || '.*{1}') AS lquery)
					)
				) AS subresources
			FROM (
				SELECT usr_policy.policy_id
				FROM usr
				JOIN usr_policy ON usr.id = usr_policy.usr_id
				WHERE usr.name = $1
				UNION
				SELECT client_policy.policy_id
				FROM client
				JOIN client_policy ON client_policy.client_id = client.id
				WHERE client.external_client_id = $2
			) policies
			LEFT JOIN policy_resource ON policy_resource.policy_id = policies.policy_id
			LEFT JOIN resource ON resource.id = policy_resource.resource_id
		`
		err = db.Select(&resources, stmt, request.Username, request.ClientID)
		if err != nil {
			errResponse := newErrorResponse(
				"resources query (using username + client) failed",
				500,
				&err,
			)
			return nil, errResponse
		}
		return resources, nil
	}
}
