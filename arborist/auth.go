package arborist

import (
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
	Token  string `json:"token"`
	UserId string `json:"user_id"`
	// The Policies field is optional, and if the request provides a token
	// this gets filled in using the Token field.
	// Could use UserId if its provided instead of Token
	Policies []string `json:"policies,omitempty"`
	Scopes   []string `json:"scope,omitempty"`
}

func (requestJSON *AuthRequestJSON_User) UnmarshalJSON(data []byte) error {
	fields := make(map[string]interface{})
	err := json.Unmarshal(data, &fields)
	if err != nil {
		return err
	}

	optionalFields := map[string]struct{}{
		"policies": {},
		"scope":    {},
	}

	// either user_id is required or token is required
	// if one is provided the other should be optional
	if _, exists := fields["user_id"]; !exists {
		optionalFields["user_id"] = struct{}{}
	} else if _, exists := fields["token"]; !exists {
		optionalFields["token"] = struct{}{}
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
		"constraints": {},
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

// Authorize a request where the end user is anonymous, so there is no token
// involved, and access is granted only through the built-in anonymous group.
func authorizeAnonymous(request *AuthRequest) (*AuthResponse, error) {
	var tag string
	var err error

	resource := request.Resource
	// See if the resource field is a path or a tag.
	if strings.HasPrefix(resource, "/") {
		resource = FormatPathForDb(resource)
	} else {
		tag = resource
		resource = ""
	}

	var authorized []bool

	if resource != "" {
		// run authorization query
		err = request.stmts.Select(
			`
			SELECT coalesce(text2ltree($5) <@ allowed, FALSE) FROM (
				SELECT array_agg(resource.path) AS allowed FROM (
					SELECT policy_id FROM grp_policy
					INNER JOIN grp ON grp_policy.grp_id = grp.id
					WHERE grp.name = $6
				) AS policies
				LEFT JOIN policy_resource ON policy_resource.policy_id = policies.policy_id
				LEFT JOIN resource ON resource.id = policy_resource.resource_id
				WHERE EXISTS (
					SELECT 1 FROM policy_role
					JOIN permission ON permission.role_id = policy_role.role_id
					WHERE policy_role.policy_id = policies.policy_id
					AND (permission.service = $1 OR permission.service = '*')
					AND (permission.method = $2 OR permission.method = '*')
				) AND (
					$3 OR policies.policy_id IN (
						SELECT id FROM policy
						WHERE policy.name = ANY($4)
					)
				)
			) _
			`,
			&authorized,
			request.Service,            // $1
			request.Method,             // $2
			len(request.Policies) == 0, // $3
			pq.Array(request.Policies), // $4
			resource,                   // $5
			AnonymousGroup,             // $6
		)
	} else if tag != "" {
		err = request.stmts.Select(
			`
			SELECT coalesce((SELECT resource.path AS request FROM resource WHERE resource.tag = $5) <@ allowed, FALSE) FROM (
				SELECT array_agg(resource.path) AS allowed FROM (
					SELECT policy_id FROM grp_policy
					INNER JOIN grp ON grp_policy.grp_id = grp.id
					WHERE grp.name = $6
				) AS policies
				JOIN policy_resource ON policy_resource.policy_id = policies.policy_id
				JOIN resource ON resource.id = policy_resource.resource_id
				WHERE EXISTS (
					SELECT 1 FROM policy_role
					JOIN permission ON permission.role_id = policy_role.role_id
					WHERE policy_role.policy_id = policies.policy_id
					AND (permission.service = $1 OR permission.service = '*')
					AND (permission.method = $2 OR permission.method = '*')
				) AND (
					$3 OR policies.policy_id IN (
						SELECT id FROM policy
						WHERE policy.name = ANY($4)
					)
				)
			) _
			`,
			&authorized,
			request.Service,            // $1
			request.Method,             // $2
			len(request.Policies) == 0, // $3
			pq.Array(request.Policies), // $4
			resource,                   // $5
			AnonymousGroup,             // $6
		)
	} else {
		err = errors.New("missing resource in auth request")
	}
	if err != nil {
		return nil, err
	}
	result := len(authorized) > 0 && authorized[0]
	return &AuthResponse{result}, nil
}

// Authorize the given token to access resources by service and method.
func authorizeUser(request *AuthRequest) (*AuthResponse, error) {
	var authorized []bool
	var tag string
	var err error

	resource := request.Resource
	// See if the resource field is a path or a tag.
	if strings.HasPrefix(resource, "/") {
		resource = FormatPathForDb(resource)
	} else {
		tag = resource
		resource = ""
	}

	if resource != "" {
		err = request.stmts.Select(
			`
			SELECT coalesce(text2ltree($6) <@ allowed, FALSE) FROM (
				SELECT array_agg(resource.path) AS allowed FROM (
					SELECT usr_policy.policy_id FROM usr
					INNER JOIN usr_policy ON usr_policy.usr_id = usr.id
					WHERE LOWER(usr.name) = $1 AND (usr_policy.expires_at IS NULL OR NOW() < usr_policy.expires_at)
					UNION
					SELECT grp_policy.policy_id FROM usr
					INNER JOIN usr_grp ON usr_grp.usr_id = usr.id
					INNER JOIN grp_policy ON grp_policy.grp_id = usr_grp.grp_id
					WHERE LOWER(usr.name) = $1 AND (usr_grp.expires_at IS NULL OR NOW() < usr_grp.expires_at)
					UNION
					SELECT grp_policy.policy_id FROM grp
					INNER JOIN grp_policy ON grp_policy.grp_id = grp.id
					WHERE grp.name IN ($7, $8)
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
			) _
			`,
			&authorized,
			strings.ToLower(request.Username), // $1
			request.Service,                   // $2
			request.Method,                    // $3
			len(request.Policies) == 0,        // $4
			pq.Array(request.Policies),        // $5
			resource,                          // $6
			AnonymousGroup,                    // $7
			LoggedInGroup,                     // $8
		)
	} else if tag != "" {
		err = request.stmts.Select(
			`
			SELECT coalesce((SELECT resource.path FROM resource WHERE resource.tag = $6) <@ allowed, FALSE) FROM (
				SELECT array_agg(resource.path) AS allowed FROM (
					SELECT usr_policy.policy_id FROM usr
					INNER JOIN usr_policy ON usr_policy.usr_id = usr.id
					WHERE LOWER(usr.name) = $1 AND (usr_policy.expires_at IS NULL OR NOW() < usr_policy.expires_at)
					UNION
					SELECT grp_policy.policy_id FROM usr
					INNER JOIN usr_grp ON usr_grp.usr_id = usr.id
					INNER JOIN grp_policy ON grp_policy.grp_id = usr_grp.grp_id
					WHERE LOWER(usr.name) = $1 AND (usr_grp.expires_at IS NULL OR NOW() < usr_grp.expires_at)
					UNION
					SELECT grp_policy.policy_id FROM grp
					INNER JOIN grp_policy ON grp_policy.grp_id = grp.id
					WHERE grp.name IN ($7, $8)
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
			) _
			`,
			&authorized,
			strings.ToLower(request.Username), // $1
			request.Service,                   // $2
			request.Method,                    // $3
			len(request.Policies) == 0,        // $4
			pq.Array(request.Policies),        // $5
			tag,                               // $6
			AnonymousGroup,                    // $7
			LoggedInGroup,                     // $8
		)
	} else {
		err = errors.New("missing resource in auth request")
	}
	if err != nil {
		return nil, err
	}
	result := len(authorized) > 0 && authorized[0]
	return &AuthResponse{result}, nil
}

// This is similar to authorizeUser, only that this method checks for clientID only
func authorizeClient(request *AuthRequest) (*AuthResponse, error) {
	var err error
	var tag string
	var authorized []bool

	resource := request.Resource
	// See if the resource field is a path or a tag.
	if strings.HasPrefix(resource, "/") {
		resource = FormatPathForDb(resource)
	} else {
		tag = resource
		resource = ""
	}

	if resource != "" {
		err = request.stmts.Select(
			`
			SELECT coalesce(text2ltree($4) <@ allowed, FALSE) FROM (
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
			) _
			`,
			&authorized,
			request.ClientID, // $1
			request.Service,  // $2
			request.Method,   // $3
			resource,         // $4
		)
	} else if tag != "" {
		err = request.stmts.Select(
			`
			SELECT coalesce((SELECT resource.path FROM resource WHERE resource.tag = $6) <@ allowed, FALSE) FROM (
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
			) _
			`,
			&authorized,
			request.ClientID,           // $1
			request.Service,            // $2
			request.Method,             // $3
			len(request.Policies) == 0, // $4
			pq.Array(request.Policies), // $5
			tag,                        // $6
		)
	} else {
		err = errors.New("missing resource in auth request")
	}
	if err != nil {
		return nil, err
	}
	result := len(authorized) > 0 && authorized[0]
	return &AuthResponse{result}, nil
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
	scopes := []string{"openid"}
	info, err := decode(userJWT, scopes)
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

// authorizedResources returns the resources that are accessible (with any action)
// to the username in AuthRequest. This includes the resources accessible to the
// `anonymous` and `logged-in` groups. If the username in AuthRequest does not exist
// in the db, this this function will NOT throw an error, but will return only
// the resources accessible to the `anonymous` and `logged-in` groups.
//
// See the FIXME inside. Be careful how this is called, until the implementation is updated.
func authorizedResources(db *sqlx.DB, request *AuthRequest) ([]ResourceFromQuery, *ErrorResponse) {
	// if policies are specified in the request, we can use those (simplest query).
	if len(request.Policies) > 0 {
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
			WHERE (policy_resource.policy_id IN (%s)) AND (
				usr_policy.expires_at IS NULL OR NOW() < usr_policy.expires_at
			)
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
				WHERE LOWER(usr.name) = $1 AND (usr_policy.expires_at IS NULL OR NOW() < usr_policy.expires_at)
				UNION
				SELECT grp_policy.policy_id
				FROM grp
				JOIN grp_policy ON grp_policy.grp_id = grp.id
				JOIN usr_grp ON usr_grp.grp_id = grp.id
				JOIN usr ON usr.id = usr_grp.usr_id
				WHERE LOWER(usr.name) = $1 AND (usr_grp.expires_at IS NULL OR NOW() < usr_grp.expires_at)
				UNION
				SELECT grp_policy.policy_id
				FROM grp
				JOIN grp_policy ON grp_policy.grp_id = grp.id
				WHERE grp.name IN ($2, $3)
			) policies
			INNER JOIN policy_resource ON policy_resource.policy_id = policies.policy_id
			INNER JOIN resource AS roots ON roots.id = policy_resource.resource_id
			LEFT JOIN resource ON resource.path <@ roots.path
		`
		err := db.Select(
			&resources,
			stmt,
			strings.ToLower(request.Username), // $1
			AnonymousGroup,                    // $2
			LoggedInGroup,                     // $3
		)
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
				WHERE LOWER(usr.name) = $1 AND (usr_policy.expires_at IS NULL OR NOW() < usr_policy.expires_at)
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
				WHERE LOWER(usr.name) = $1 AND (usr_grp.expires_at IS NULL OR NOW() < usr_grp.expires_at)
			) policies
			LEFT JOIN policy_resource ON policy_resource.policy_id = policies.policy_id
			INNER JOIN resource AS roots ON roots.id = policy_resource.resource_id
			LEFT JOIN resource ON resource.path <@ roots.path
		`
		err := db.Select(&resources, stmt, strings.ToLower(request.Username), request.ClientID)
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

// authorizedResourcesForGroups returns the resources that are accessible (with any action)
// to these groups.
func authorizedResourcesForGroups(db *sqlx.DB, groups ...string) ([]ResourceFromQuery, *ErrorResponse) {
	resources := []ResourceFromQuery{}
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
			SELECT grp_policy.policy_id
			FROM grp
			JOIN grp_policy ON grp_policy.grp_id = grp.id
			WHERE grp.name IN (?)
		) policies
		INNER JOIN policy_resource ON policy_resource.policy_id = policies.policy_id
		INNER JOIN resource AS roots ON roots.id = policy_resource.resource_id
		LEFT JOIN resource ON resource.path <@ roots.path
	`
	// sqlx.In allows safely binding variable numbers of arguments as bindvars.
	// See https://jmoiron.github.io/sqlx/#inQueries,
	query, args, err := sqlx.In(stmt, groups)
	if err != nil {
		errResponse := newErrorResponse("mapping query failed", 500, &err)
		errResponse.log.Error("%s", err.Error())
		return nil, errResponse
	}
	// db.Rebind converts the '?' bindvar syntax required by sqlx.In to postgres $1 bindvar syntax
	query = db.Rebind(query)
	err = db.Select(&resources, query, args...)
	if err != nil {
		errResponse := newErrorResponse(
			"resources query (using no username) failed",
			500,
			&err,
		)
		return nil, errResponse
	}
	return resources, nil
}

type AuthMappingQuery struct {
	Path    string `json:"path"`
	Service string `json:"service"`
	Method  string `json:"method"`
}

type AuthMapping map[string][]Action

// authMappingForUser gets the auth mapping for the user with this username.
// The user's auth mapping includes the permissions of the `anonymous` and
// `logged-in` groups.
// If there is no user with this username in the db, this function will NOT
// throw an error, but will return only the auth mapping of the `anonymous`
// and `logged-in` groups.
func authMappingForUser(db *sqlx.DB, username string) (AuthMapping, *ErrorResponse) {
	mappingQuery := []AuthMappingQuery{}
	stmt := `
		SELECT DISTINCT resource.path, permission.service, permission.method
		FROM
		(
			SELECT usr_policy.policy_id FROM usr
			INNER JOIN usr_policy ON usr_policy.usr_id = usr.id
			WHERE LOWER(usr.name) = $1 AND (usr_policy.expires_at IS NULL OR NOW() < usr_policy.expires_at)
			UNION
			SELECT grp_policy.policy_id FROM usr
			INNER JOIN usr_grp ON usr_grp.usr_id = usr.id
			INNER JOIN grp_policy ON grp_policy.grp_id = usr_grp.grp_id
			WHERE LOWER(usr.name) = $1 AND (usr_grp.expires_at IS NULL OR NOW() < usr_grp.expires_at)
			UNION
			SELECT grp_policy.policy_id FROM grp
			INNER JOIN grp_policy ON grp_policy.grp_id = grp.id
			WHERE grp.name IN ($2, $3)
		) AS policies
		INNER JOIN policy_resource ON policy_resource.policy_id = policies.policy_id
		INNER JOIN resource AS roots ON roots.id = policy_resource.resource_id
		INNER JOIN policy_role ON policy_role.policy_id = policies.policy_id
		INNER JOIN permission ON permission.role_id = policy_role.role_id
		INNER JOIN resource ON resource.path <@ roots.path
	`
	err := db.Select(
		&mappingQuery,
		stmt,
		strings.ToLower(username), // $1
		AnonymousGroup,            // $2
		LoggedInGroup,             // $3
	)
	if err != nil {
		errResponse := newErrorResponse("mapping query failed", 500, &err)
		errResponse.log.Error("%s", err.Error())
		return nil, errResponse
	}
	mapping := make(AuthMapping)
	for _, authMap := range mappingQuery {
		path := formatDbPath(authMap.Path)
		action := Action{Service: authMap.Service, Method: authMap.Method}
		mapping[path] = append(mapping[path], action)
	}
	return mapping, nil
}

// authMappingForGroups returns the auth mapping of resources associated with groups.
func authMappingForGroups(db *sqlx.DB, groups ...string) (AuthMapping, *ErrorResponse) {
	mappingQuery := []AuthMappingQuery{}
	stmt := `
		SELECT DISTINCT resource.path, permission.service, permission.method
		FROM
		(
			SELECT grp_policy.policy_id FROM grp
			INNER JOIN grp_policy ON grp_policy.grp_id = grp.id
			WHERE grp.name IN (?)
		) AS policies
		INNER JOIN policy_resource ON policy_resource.policy_id = policies.policy_id
		INNER JOIN resource AS roots ON roots.id = policy_resource.resource_id
		INNER JOIN policy_role ON policy_role.policy_id = policies.policy_id
		INNER JOIN permission ON permission.role_id = policy_role.role_id
		INNER JOIN resource ON resource.path <@ roots.path
	`
	// sqlx.In allows safely binding variable numbers of arguments as bindvars.
	// See https://jmoiron.github.io/sqlx/#inQueries,
	query, args, err := sqlx.In(stmt, groups)
	if err != nil {
		errResponse := newErrorResponse("mapping query failed", 500, &err)
		errResponse.log.Error("%s", err.Error())
		return nil, errResponse
	}
	// db.Rebind converts the '?' bindvar syntax required by sqlx.In to postgres $1 bindvar syntax
	query = db.Rebind(query)
	err = db.Select(&mappingQuery, query, args...)
	if err != nil {
		errResponse := newErrorResponse("mapping query failed", 500, &err)
		errResponse.log.Error("%s", err.Error())
		return nil, errResponse
	}
	mapping := make(AuthMapping)
	for _, authMap := range mappingQuery {
		path := formatDbPath(authMap.Path)
		action := Action{Service: authMap.Service, Method: authMap.Method}
		mapping[path] = append(mapping[path], action)
	}
	return mapping, nil
}

// authMappingForClient gets the auth mapping for a client ID.
// It does NOT includes the permissions of the `anonymous` and
// `logged-in` groups.
// If there is no client with this ID in the db, this function will NOT
// throw an error, but will return an empty response.
func authMappingForClient(db *sqlx.DB, clientID string) (AuthMapping, *ErrorResponse) {
	mappingQuery := []AuthMappingQuery{}
	stmt := `
		SELECT DISTINCT resource.path, permission.service, permission.method
		FROM
		(
			SELECT client_policy.policy_id FROM client
			INNER JOIN client_policy ON client_policy.client_id = client.id
			WHERE client.external_client_id = $1
		) AS policies
		INNER JOIN policy_resource ON policy_resource.policy_id = policies.policy_id
		INNER JOIN resource AS roots ON roots.id = policy_resource.resource_id
		INNER JOIN policy_role ON policy_role.policy_id = policies.policy_id
		INNER JOIN permission ON permission.role_id = policy_role.role_id
		INNER JOIN resource ON resource.path <@ roots.path
	`
	err := db.Select(
		&mappingQuery,
		stmt,
		clientID, // $1
	)
	if err != nil {
		errResponse := newErrorResponse("mapping query failed", 500, &err)
		errResponse.log.Error(err.Error())
		return nil, errResponse
	}
	mapping := make(AuthMapping)
	for _, authMap := range mappingQuery {
		path := formatDbPath(authMap.Path)
		action := Action{Service: authMap.Service, Method: authMap.Method}
		mapping[path] = append(mapping[path], action)
	}
	return mapping, nil
}
