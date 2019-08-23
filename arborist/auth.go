package arborist

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
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

	optionalFieldsPath := map[string]struct{}{
		"constraints": struct{}{},
	}
	err = validateJSON("auth request", requestJSON, fields, optionalFieldsPath)
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
				AND permission.service = $1 OR permission.service = '*'
				AND permission.method = $2 OR permission.service = '*'
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
	var exp Expression
	var args []string
	var resources []string
	var rows *sql.Rows
	var err error
	var tag string

	resource := request.Resource

	// See if the resource field is a path or a tag.
	if !strings.HasPrefix(resource, "/") {
		tag = resource
		resource = ""
	}

	if resource != "" {
		exp, args, resources, err = parse(resource)
		rows, err = request.stmts.Query(
			`
			SELECT coalesce(text2ltree(request) <@ allowed, FALSE) FROM (
				SELECT array_agg(resource.path) AS allowed FROM (
					SELECT usr_policy.policy_id FROM usr
					INNER JOIN usr_policy ON usr_policy.usr_id = usr.id
					WHERE usr.name = $1
					UNION
					SELECT grp_policy.policy_id FROM usr
					INNER JOIN usr_grp ON usr_grp.usr_id = usr.id
					INNER JOIN grp_policy ON grp_policy.grp_id = usr_grp.grp_id
					WHERE usr.name = $1
					UNION
					SELECT grp_policy.policy_id FROM grp
					INNER JOIN grp_policy ON grp_policy.grp_id = grp.id
					WHERE grp.name = 'anonymous' OR grp.name = 'logged-in'
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
			) _, unnest($6::text[]) AS request
			`,
			request.Username,           // $1
			request.Service,            // $2
			request.Method,             // $3
			len(request.Policies) == 0, // $4
			pq.Array(request.Policies), // $5
			pq.Array(resources),        // $6
		)
	} else if tag != "" {
		exp, args, resources, err = parse(tag)
		rows, err = request.stmts.Query(
			`
			SELECT coalesce(request <@ allowed, FALSE) FROM (
				SELECT array_agg(resource.path) AS allowed FROM (
					SELECT usr_policy.policy_id FROM usr
					INNER JOIN usr_policy ON usr_policy.usr_id = usr.id
					WHERE usr.name = $1
					UNION
					SELECT grp_policy.policy_id FROM usr
					INNER JOIN usr_grp ON usr_grp.usr_id = usr.id
					INNER JOIN grp_policy ON grp_policy.grp_id = usr_grp.grp_id
					WHERE usr.name = $1
					UNION
					SELECT grp_policy.policy_id FROM grp
					INNER JOIN grp_policy ON grp_policy.grp_id = grp.id
					WHERE grp.name = 'anonymous' OR grp.name = 'logged-in'
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
			) _,
			(SELECT resource.path AS request FROM unnest($6::text[]) JOIN resource ON resource.tag = "unnest") asdf
			`,
			request.Username,           // $1
			request.Service,            // $2
			request.Method,             // $3
			len(request.Policies) == 0, // $4
			pq.Array(request.Policies), // $5
			pq.Array(resources),        // $6
		)
	} else {
		err = errors.New("missing resource in auth request")
	}
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
	var exp Expression
	var args []string
	var resources []string
	var rows *sql.Rows
	var err error
	var tag string

	resource := request.Resource

	// See if the resource field is a path or a tag.
	if !strings.HasPrefix(resource, "/") {
		tag = resource
		resource = ""
	}

	if resource != "" {
		exp, args, resources, err = parse(resource)
		rows, err = request.stmts.Query(
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
	} else if tag != "" {
		exp, args, resources, err = parse(tag)
		rows, err = request.stmts.Query(
			`
			SELECT coalesce(request <@ allowed, FALSE) FROM (
				SELECT array_agg(resource.path) AS allowed FROM (
					SELECT client_policy.policy_id FROM client
					INNER JOIN client_policy ON client_policy.client_id = client.id
					WHERE client.external_client_id = $1
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
			) _,
			(SELECT resource.path AS request FROM unnest($6::text[]) JOIN resource ON resource.tag = "unnest") asdf
			`,
			request.ClientID,           // $1
			request.Service,            // $2
			request.Method,             // $3
			len(request.Policies) == 0, // $4
			pq.Array(request.Policies), // $5
			pq.Array(resources),        // $6
		)
	} else {
		err = errors.New("missing both resource and tag in auth request")
	}

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

func authRequestFromGET(decode func(string, []string) (*TokenInfo, error), r *http.Request) (*AuthRequest, *ErrorResponse) {
	resourcePath := ""
	resourcePathQS, ok := r.URL.Query()["resource"]
	if ok {
		resourcePath = resourcePathQS[0]
	}
	service := ""
	serviceQS, ok := r.URL.Query()["service"]
	if ok {
		service = serviceQS[0]
	}
	method := ""
	methodQS, ok := r.URL.Query()["method"]
	if ok {
		method = methodQS[0]
	}
	// get JWT from auth header and decode it
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		msg := "auth request missing auth header"
		return nil, newErrorResponse(msg, 401, nil)
	}
	userJWT := strings.TrimPrefix(authHeader, "Bearer ")
	userJWT = strings.TrimPrefix(userJWT, "bearer ")
	aud := []string{"openid"}
	info, err := decode(userJWT, aud)
	if err != nil {
		return nil, newErrorResponse(err.Error(), 401, &err)
	}

	authRequest := AuthRequest{
		Username: info.username,
		ClientID: info.clientID,
		Policies: info.policies,
		Resource: resourcePath,
		Service:  service,
		Method:   method,
	}

	return &authRequest, nil
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
		// alternative: SELECT DISTINCT * FROM resource WHERE resource.path <@ ARRAY(SELECT resource.path FROM (SELECT usr_policy.policy_id FROM usr JOIN usr_policy ON usr.id = usr_policy.usr_id WHERE usr.name = $1) policies INNER JOIN policy_resource ON policy_resource.policy_id = policies.policy_id INNER JOIN resource ON resource.id = policy_resource.resource_id);
		stmt := `
			SELECT DISTINCT
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
				SELECT grp_policy.policy_id
				FROM grp
				JOIN grp_policy ON grp_policy.grp_id = grp.id
				JOIN usr_grp ON usr_grp.grp_id = grp.id
				JOIN usr ON usr.id = usr_grp.usr_id
				WHERE usr.name = $1
			) policies
			INNER JOIN policy_resource ON policy_resource.policy_id = policies.policy_id
			INNER JOIN resource AS roots ON roots.id = policy_resource.resource_id
			LEFT JOIN resource ON resource.path <@ roots.path
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
			SELECT DISTINCT
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
				UNION
				SELECT grp_policy.policy_id
				FROM grp
				JOIN grp_policy ON grp_policy.grp_id = grp.id
				JOIN usr_grp ON usr_grp.grp_id = grp.id
				JOIN usr ON usr.id = usr_grp.usr_id
				WHERE usr.name = $1
			) policies
			LEFT JOIN policy_resource ON policy_resource.policy_id = policies.policy_id
			INNER JOIN resource AS roots ON roots.id = policy_resource.resource_id
			LEFT JOIN resource ON resource.path <@ roots.path
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

type AuthMapping struct {
	Path       string `json:"path"`
	Permission struct {
		Service string `json:"service"`
		Method  string `json:"method"`
	} `json:"permission"`
}

func authMapping(db *sqlx.DB, username string) ([]AuthMapping, *ErrorResponse) {
	mappings := []AuthMapping{}
	stmt := `
		SELECT
			resource.path,
			array_agg(DISTINCT (permission.service, permission.method)) AS permission
		FROM usr
		INNER JOIN usr_policy ON usr_policy.usr_id = usr.id
		INNER JOIN policy ON policy.id = usr_policy.policy_id
		INNER JOIN policy_resource ON policy_resource.policy_id = policy.id
		INNER JOIN resource AS roots ON roots.id = policy_resource.resource_id
		INNER JOIN policy_role ON policy_role.policy_id = policy.id
		INNER JOIN permission ON permission.role_id = policy_role.role_id
		INNER JOIN resource ON resource.path <@ roots.path
		WHERE usr.name = $1
		GROUP BY resource.id;
	`
	err := db.Select(&mappings, stmt, username)
	if err != nil {
		errResponse := newErrorResponse("mapping query failed", 500, &err)
		return nil, errResponse
	}
	return mappings, nil
}
