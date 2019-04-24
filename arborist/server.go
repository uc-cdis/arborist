package arborist

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"regexp"
	"strings"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
)

type JWTDecoder interface {
	Decode(string) (*map[string]interface{}, error)
}

type Server struct {
	db     *sqlx.DB
	jwtApp JWTDecoder
	logger *LogHandler
	stmts  *CachedStmts
}

func NewServer() *Server {
	return &Server{}
}

func (server *Server) WithLogger(logger *log.Logger) *Server {
	server.logger = &LogHandler{logger: logger}
	return server
}

func (server *Server) WithJWTApp(jwtApp JWTDecoder) *Server {
	server.jwtApp = jwtApp
	return server
}

func (server *Server) WithDB(db *sqlx.DB) *Server {
	server.db = db
	server.stmts = NewCachedStmts(db)
	return server
}

func (server *Server) Init() (*Server, error) {
	if server.db == nil {
		return nil, errors.New("arborist server initialized without database")
	}
	if server.jwtApp == nil {
		return nil, errors.New("arborist server initialized without JWT app")
	}
	if server.logger == nil {
		return nil, errors.New("arborist server initialized without logger")
	}

	return server, nil
}

// For some reason this is not allowed:
//
//    `{resourcePath:/[a-zA-Z0-9_\-\/]+}`
//
// so we put the slash at the front here and fix it in parseResourcePath.
const resourcePath string = `/{resourcePath:[a-zA-Z0-9_\-\/]+}`

func parseResourcePath(r *http.Request) string {
	path, exists := mux.Vars(r)["resourcePath"]
	if !exists {
		return ""
	}
	// We have to add a slash at the front here; see resourcePath constant.
	return strings.Join([]string{"/", path}, "")
}

func (server *Server) MakeRouter(out io.Writer) http.Handler {
	router := mux.NewRouter().StrictSlash(true)

	//router.Handle("/", server.handleRoot).Methods("GET")

	router.HandleFunc("/health", server.handleHealth).Methods("GET")

	router.Handle("/auth/proxy", http.HandlerFunc(server.handleAuthProxy)).Methods("GET")
	router.Handle("/auth/{identity:(?:request|client)}", http.HandlerFunc(parseJSON(server.handleAuthRequest))).Methods("POST")
	router.Handle("/auth/resources", http.HandlerFunc(parseJSON(server.handleListAuthResources))).Methods("POST")

	router.Handle("/policy", http.HandlerFunc(server.handlePolicyList)).Methods("GET")
	router.Handle("/policy", http.HandlerFunc(parseJSON(server.handlePolicyCreate))).Methods("POST")
	router.Handle("/policy/{policyID}", http.HandlerFunc(server.handlePolicyRead)).Methods("GET")
	router.Handle("/policy/{policyID}", http.HandlerFunc(server.handlePolicyDelete)).Methods("DELETE")

	router.Handle("/resource", http.HandlerFunc(server.handleResourceList)).Methods("GET")
	router.Handle("/resource", http.HandlerFunc(parseJSON(server.handleResourceCreate))).Methods("POST")
	router.Handle("/resource/tag/{tag}", http.HandlerFunc(server.handleResourceReadByTag)).Methods("GET")
	router.Handle("/resource"+resourcePath, http.HandlerFunc(server.handleResourceRead)).Methods("GET")
	router.Handle("/resource"+resourcePath, http.HandlerFunc(parseJSON(server.handleSubresourceCreate))).Methods("POST")
	router.Handle("/resource"+resourcePath, http.HandlerFunc(server.handleResourceDelete)).Methods("DELETE")

	router.Handle("/role", http.HandlerFunc(server.handleRoleList)).Methods("GET")
	router.Handle("/role", http.HandlerFunc(parseJSON(server.handleRoleCreate))).Methods("POST")
	router.Handle("/role/{roleID}", http.HandlerFunc(server.handleRoleRead)).Methods("GET")
	router.Handle("/role/{roleID}", http.HandlerFunc(server.handleRoleDelete)).Methods("DELETE")

	router.Handle("/user", http.HandlerFunc(server.handleUserList)).Methods("GET")
	router.Handle("/user", http.HandlerFunc(parseJSON(server.handleUserCreate))).Methods("POST")
	router.Handle("/user/{username}", http.HandlerFunc(server.handleUserRead)).Methods("GET")
	router.Handle("/user/{username}", http.HandlerFunc(server.handleUserDelete)).Methods("DELETE")
	router.Handle("/user/{username}/policy", http.HandlerFunc(parseJSON(server.handleUserGrantPolicy))).Methods("POST")
	router.Handle("/user/{username}/policy", http.HandlerFunc(server.handleUserRevokeAll)).Methods("DELETE")
	router.Handle("/user/{username}/policy/{policyName}", http.HandlerFunc(server.handleUserRevokePolicy)).Methods("DELETE")

	router.Handle("/client", http.HandlerFunc(server.handleClientList)).Methods("GET")
	router.Handle("/client", http.HandlerFunc(parseJSON(server.handleClientCreate))).Methods("POST")
	router.Handle("/client/{clientID}", http.HandlerFunc(server.handleClientRead)).Methods("GET")
	router.Handle("/client/{clientID}", http.HandlerFunc(server.handleClientDelete)).Methods("DELETE")
	router.Handle("/client/{clientID}/policy", http.HandlerFunc(parseJSON(server.handleClientGrantPolicy))).Methods("POST")
	router.Handle("/client/{clientID}/policy", http.HandlerFunc(server.handleClientRevokeAll)).Methods("DELETE")
	router.Handle("/client/{clientID}/policy/{policyName}", http.HandlerFunc(server.handleClientRevokePolicy)).Methods("DELETE")

	router.Handle("/group", http.HandlerFunc(server.handleGroupList)).Methods("GET")
	router.Handle("/group", http.HandlerFunc(parseJSON(server.handleGroupCreate))).Methods("POST")
	router.Handle("/group/{groupName}", http.HandlerFunc(server.handleGroupRead)).Methods("GET")
	router.Handle("/group/{groupName}", http.HandlerFunc(server.handleGroupDelete)).Methods("DELETE")
	router.Handle("/group/{groupName}/user", http.HandlerFunc(parseJSON(server.handleGroupAddUser))).Methods("POST")
	router.Handle("/group/{groupName}/user/{username}", http.HandlerFunc(server.handleGroupRemoveUser)).Methods("DELETE")
	router.Handle("/group/{groupName}/policy", http.HandlerFunc(parseJSON(server.handleGroupGrantPolicy))).Methods("POST")
	router.Handle("/group/{groupName}/policy/{policyName}", http.HandlerFunc(server.handleGroupRevokePolicy)).Methods("DELETE")

	router.NotFoundHandler = http.HandlerFunc(handleNotFound)

	// remove trailing slashes sent in URLs
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.URL.Path = strings.TrimSuffix(r.URL.Path, "/")
		router.ServeHTTP(w, r)
	})

	return handlers.CombinedLoggingHandler(out, handler)
}

// parseJSON abstracts JSON parsing for handler functions that should
// receive a valid JSON input in the request body. It takes a modified
// handler function as input, which should include the body in `[]byte`
// form as an additional argument, and returns a function with the usual
// handler signature.
func parseJSON(baseHandler func(http.ResponseWriter, *http.Request, []byte)) func(http.ResponseWriter, *http.Request) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			msg := fmt.Sprintf("could not parse valid JSON from request: %s", err.Error())
			response := newErrorResponse(msg, 400, nil)
			_ = response.write(w, r)
			return
		}
		baseHandler(w, r, body)
	}
	return handler
}

var regWhitespace *regexp.Regexp = regexp.MustCompile(`\s`)

func loggableJSON(bytes []byte) []byte {
	return regWhitespace.ReplaceAll(bytes, []byte(""))
}

func (server *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	err := server.db.Ping()
	if err != nil {
		server.logger.Error("database ping failed; returning unhealthy")
		response := newErrorResponse("database unavailable", 500, nil)
		_ = response.write(w, r)
	}
	w.WriteHeader(http.StatusOK)
}

func handleNotFound(w http.ResponseWriter, r *http.Request) {
	response := struct {
		Error struct {
			Message string `json:"message"`
			Code    int    `json:"code"`
		} `json:"error"`
	}{
		Error: struct {
			Message string `json:"message"`
			Code    int    `json:"code"`
		}{
			Message: "not found",
			Code:    404,
		},
	}
	_ = jsonResponseFrom(response, 404).write(w, r)
}

func (server *Server) handleAuthProxy(w http.ResponseWriter, r *http.Request) {
	// Get QS arguments
	resourcePathQS, ok := r.URL.Query()["resource"]
	if !ok {
		msg := "auth proxy request missing `resource` argument"
		server.logger.Info(msg)
		errResponse := newErrorResponse(msg, 400, nil)
		_ = errResponse.write(w, r)
		return
	}
	resourcePath := resourcePathQS[0]
	serviceQS, ok := r.URL.Query()["service"]
	if !ok {
		msg := "auth proxy request missing `service` argument"
		server.logger.Info(msg)
		errResponse := newErrorResponse(msg, 400, nil)
		_ = errResponse.write(w, r)
		return
	}
	service := serviceQS[0]
	methodQS, ok := r.URL.Query()["method"]
	if !ok {
		msg := "auth proxy request missing `method` argument"
		server.logger.Info(msg)
		errResponse := newErrorResponse(msg, 400, nil)
		_ = errResponse.write(w, r)
		return
	}
	method := methodQS[0]
	// get JWT from auth header and decode it
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		msg := "auth proxy request missing auth header"
		server.logger.Info(msg)
		errResponse := newErrorResponse(msg, 401, nil)
		_ = errResponse.write(w, r)
		return
	}
	userJWT := strings.TrimPrefix(authHeader, "Bearer ")
	userJWT = strings.TrimPrefix(userJWT, "bearer ")
	aud := []string{"openid"}
	info, err := server.decodeToken(userJWT, aud)
	if err != nil {
		server.logger.Info(err.Error())
		errResponse := newErrorResponse(err.Error(), 401, &err)
		_ = errResponse.write(w, r)
		return
	}

	w.Header().Set("REMOTE_USER", info.username)

	var authRequest = AuthRequest{
		Username: info.username,
		ClientID: info.clientID,
		Policies: info.policies,
		Resource: resourcePath,
		Service:  service,
		Method:   method,
		stmts:    server.stmts,
	}

	handle := func(rv *AuthResponse, err error) bool {
		if err != nil {
			msg := fmt.Sprintf("could not authorize: %s", err.Error())
			server.logger.Info("tried to handle auth request but input was invalid: %s", msg)
			response := newErrorResponse(msg, 400, nil)
			_ = response.write(w, r)
			return true
		}
		if !rv.Auth {
			errResponse := newErrorResponse(
				"Unauthorized: user does not have access to this resource", 403, nil)
			_ = errResponse.write(w, r)
			return true
		}
		return false
	}

	rv, err := authorizeUser(&authRequest)
	if handle(rv, err) {
		return
	}

	if authRequest.ClientID != "" {
		rv, err = authorizeClient(&authRequest)
		handle(rv, err)
	}
}

func (server *Server) handleAuthRequest(w http.ResponseWriter, r *http.Request, body []byte) {
	authRequestJSON := &AuthRequestJSON{}
	err := json.Unmarshal(body, authRequestJSON)
	if err != nil {
		msg := fmt.Sprintf("could not parse auth request from JSON: %s", err.Error())
		server.logger.Info("tried to handle auth request but input was invalid: %s", msg)
		response := newErrorResponse(msg, 400, nil)
		_ = response.write(w, r)
		return
	}

	var aud []string
	if authRequestJSON.User.Audiences == nil {
		aud = []string{"openid"}
	} else {
		aud = make([]string, len(authRequestJSON.User.Audiences))
		copy(aud, authRequestJSON.User.Audiences)
	}

	isAnonymous := authRequestJSON.User.Token == ""
	var info *TokenInfo
	if !isAnonymous {
		info, err = server.decodeToken(authRequestJSON.User.Token, aud)
		if err != nil {
			server.logger.Info(err.Error())
			errResponse := newErrorResponse(err.Error(), 401, &err)
			_ = errResponse.write(w, r)
			return
		}
	}
	policies := []string{}
	if info != nil {
		policies = info.policies
	}
	if authRequestJSON.User.Policies != nil {
		policies = authRequestJSON.User.Policies
	}

	requests := []AuthRequestJSON_Request{}
	if authRequestJSON.Request != nil {
		requests = append(requests, *authRequestJSON.Request)
	}
	requests = append(requests, authRequestJSON.Requests...)
	identity := mux.Vars(r)["identity"]

	for _, authRequest := range requests {
		// if no token is provided, use anonymous group to check auth
		if isAnonymous {
			request := AuthRequest{
				Resource: authRequest.Resource,
				Service:  authRequest.Action.Service,
				Method:   authRequest.Action.Method,
				stmts:    server.stmts,
			}
			rv, err := authorizeAnonymous(&request)
			if err != nil {
				msg := fmt.Sprintf("could not authorize: %s", err.Error())
				server.logger.Info("tried to handle auth request but input was invalid: %s", msg)
				response := newErrorResponse(msg, 400, nil)
				_ = response.write(w, r)
				return
			}
			if !rv.Auth {
				_ = jsonResponseFrom(rv, 200).write(w, r)
				return
			}
			continue
		}

		// check that the request has minimum necessary information
		if authRequest.Resource == "" {
			msg := "missing resource in auth request"
			_ = newErrorResponse(msg, 400, nil).write(w, r)
			return
		}
		if info.policies == nil || len(info.policies) == 0 {
			if identity == "client" {
				if info.clientID == "" {
					msg := "missing both clientID and policies in request (at least one is required)"
					_ = newErrorResponse(msg, 400, nil).write(w, r)
					return
				}
			} else {
				if info.username == "" {
					msg := "missing both username and policies in request (at least one is required)"
					_ = newErrorResponse(msg, 400, nil).write(w, r)
					return
				}
			}
		}

		request := &AuthRequest{
			Username: info.username,
			ClientID: info.clientID,
			Policies: policies,
			Resource: authRequest.Resource,
			Service:  authRequest.Action.Service,
			Method:   authRequest.Action.Method,
			stmts:    server.stmts,
		}

		var rv *AuthResponse
		var err error
		if identity == "client" {
			rv, err = authorizeClient(request)
		} else {
			rv, err = authorizeUser(request)
		}
		if err != nil {
			msg := fmt.Sprintf("could not authorize: %s", err.Error())
			server.logger.Info("tried to handle auth request but input was invalid: %s", msg)
			response := newErrorResponse(msg, 400, nil)
			_ = response.write(w, r)
			return
		}
		if !rv.Auth {
			_ = jsonResponseFrom(rv, 200).write(w, r)
			return
		}
	}

	result := AuthResponse{
		Auth: true,
	}
	_ = jsonResponseFrom(result, 200).write(w, r)
}

func (server *Server) handleListAuthResources(w http.ResponseWriter, r *http.Request, body []byte) {
	authRequest := struct {
		User struct {
			Token     string   `json:"token"`
			Policies  []string `json:"policies,omitempty"`
			Audiences []string `json:"aud,omitempty"`
		} `json:"user"`
	}{}
	err := json.Unmarshal(body, &authRequest)
	if err != nil {
		msg := fmt.Sprintf("could not parse auth request from JSON: %s", err.Error())
		server.logger.Info("tried to handle auth request but input was invalid: %s", msg)
		response := newErrorResponse(msg, 400, nil)
		_ = response.write(w, r)
		return
	}
	var aud []string
	if authRequest.User.Audiences == nil {
		aud = []string{"openid"}
	} else {
		aud = make([]string, len(authRequest.User.Audiences))
		copy(aud, authRequest.User.Audiences)
	}

	info, err := server.decodeToken(authRequest.User.Token, aud)
	if err != nil {
		server.logger.Info(err.Error())
		errResponse := newErrorResponse(err.Error(), 401, &err)
		_ = errResponse.write(w, r)
		return
	}

	request := &AuthRequest{
		Username: info.username,
		ClientID: info.clientID,
		Policies: info.policies,
	}
	if authRequest.User.Policies != nil {
		request.Policies = authRequest.User.Policies
	}

	resourcesFromQuery, err := authorizedResources(server.db, request)
	if err != nil {
		server.logger.Info(err.Error())
		errResponse := newErrorResponse(err.Error(), 401, &err)
		_ = errResponse.write(w, r)
		return
	}

	resources := []ResourceOut{}
	for _, resourceFromQuery := range resourcesFromQuery {
		resources = append(resources, resourceFromQuery.standardize())
	}

	resourcePaths := make([]string, len(resources))
	for i := range resources {
		resourcePaths[i] = resources[i].Path
	}

	response := struct {
		Resources []string `json:"resources"`
	}{
		Resources: resourcePaths,
	}

	_ = jsonResponseFrom(response, http.StatusOK).write(w, r)
}

func (server *Server) handlePolicyList(w http.ResponseWriter, r *http.Request) {
	policiesFromQuery, err := listPoliciesFromDb(server.db)
	policies := []Policy{}
	for _, policyFromQuery := range policiesFromQuery {
		policies = append(policies, policyFromQuery.standardize())
	}
	if err != nil {
		msg := fmt.Sprintf("policies query failed: %s", err.Error())
		errResponse := newErrorResponse(msg, 500, nil)
		server.logger.Error(errResponse.Error.Message)
		_ = errResponse.write(w, r)
		return
	}
	result := struct {
		Policies []Policy `json:"policies"`
	}{
		Policies: policies,
	}
	_ = jsonResponseFrom(result, http.StatusOK).write(w, r)
}

func (server *Server) handlePolicyCreate(w http.ResponseWriter, r *http.Request, body []byte) {
	policy := &Policy{}
	err := json.Unmarshal(body, policy)
	if err != nil {
		msg := fmt.Sprintf("could not parse policy from JSON: %s", err.Error())
		server.logger.Info("tried to create policy but input was invalid: %s", msg)
		response := newErrorResponse(msg, 400, nil)
		_ = response.write(w, r)
		return
	}
	errResponse := policy.createInDb(server.db)
	if errResponse != nil {
		if errResponse.Error.Code >= 500 {
			server.logger.Error(errResponse.Error.Message)
		} else {
			server.logger.Info(errResponse.Error.Message)
		}
		_ = errResponse.write(w, r)
		return
	}
	created := struct {
		Created *Policy `json:"created"`
	}{
		Created: policy,
	}
	_ = jsonResponseFrom(created, 201).write(w, r)
}

func (server *Server) handlePolicyRead(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["policyID"]
	policyFromQuery, err := policyWithName(server.db, name)
	if policyFromQuery == nil {
		msg := fmt.Sprintf("no policy found with id: %s", name)
		errResponse := newErrorResponse(msg, 404, nil)
		server.logger.Error(errResponse.Error.Message)
		_ = errResponse.write(w, r)
		return
	}
	if err != nil {
		msg := fmt.Sprintf("policy query failed: %s", err.Error())
		errResponse := newErrorResponse(msg, 500, nil)
		server.logger.Error(errResponse.Error.Message)
		_ = errResponse.write(w, r)
		return
	}
	policy := policyFromQuery.standardize()
	_ = jsonResponseFrom(policy, http.StatusOK).write(w, r)
}

func (server *Server) handlePolicyDelete(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["policyID"]
	policy := &Policy{Name: name}
	errResponse := policy.deleteInDb(server.db)
	if errResponse != nil {
		server.logger.Info(errResponse.Error.Message)
		_ = errResponse.write(w, r)
		return
	}
	_ = jsonResponseFrom(nil, http.StatusNoContent).write(w, r)
}

func (server *Server) handleResourceList(w http.ResponseWriter, r *http.Request) {
	resourcesFromQuery, err := listResourcesFromDb(server.db)
	resources := []ResourceOut{}
	for _, resourceFromQuery := range resourcesFromQuery {
		resources = append(resources, resourceFromQuery.standardize())
	}
	if err != nil {
		msg := fmt.Sprintf("resources query failed: %s", err.Error())
		errResponse := newErrorResponse(msg, 500, nil)
		server.logger.Error(errResponse.Error.Message)
		_ = errResponse.write(w, r)
		return
	}
	result := struct {
		Resources []ResourceOut `json:"resources"`
	}{
		Resources: resources,
	}
	_ = jsonResponseFrom(result, http.StatusOK).write(w, r)
}

func (server *Server) handleResourceCreate(w http.ResponseWriter, r *http.Request, body []byte) {
	resource := &ResourceIn{}
	err := json.Unmarshal(body, resource)
	if err != nil {
		msg := "could not parse resource from JSON; make sure input has correct types"
		server.logger.Info(
			"tried to create resource but input was invalid; offending JSON: %s",
			loggableJSON(body),
		)
		response := newErrorResponse(msg, 400, nil)
		_ = response.write(w, r)
		return
	}
	if resource.Path == "" {
		server.handleSubresourceCreate(w, r, body)
		return

		err := missingRequiredField("resource", "path")
		server.logger.Info(err.Error())
		response := newErrorResponse(err.Error(), 400, &err)
		_ = response.write(w, r)
		return
	}
	resourceFromQuery, errResponse := resource.createInDb(server.db)
	if errResponse != nil {
		if errResponse.Error.Code >= 500 {
			server.logger.Error(errResponse.Error.Message)
		} else {
			server.logger.Info(errResponse.Error.Message)
		}
		_ = errResponse.write(w, r)
		return
	}
	created := resourceFromQuery.standardize()
	result := struct {
		Created *ResourceOut `json:"created"`
	}{
		Created: &created,
	}
	_ = jsonResponseFrom(result, 201).write(w, r)
}

func (server *Server) handleSubresourceCreate(w http.ResponseWriter, r *http.Request, body []byte) {
	resource := &ResourceIn{}
	err := json.Unmarshal(body, resource)
	if err != nil {
		msg := fmt.Sprintf("could not parse resource from JSON: %s", err.Error())
		server.logger.Info("tried to create resource but input was invalid: %s", msg)
		response := newErrorResponse(msg, 400, nil)
		_ = response.write(w, r)
		return
	}
	if resource.Name == "" {
		err := missingRequiredField("resource", "name")
		server.logger.Info(err.Error())
		response := newErrorResponse(err.Error(), 400, &err)
		_ = response.write(w, r)
		return
	}
	parentPath := parseResourcePath(r)
	resource.Path = parentPath + "/" + resource.Name
	resourceFromQuery, errResponse := resource.createInDb(server.db)
	if errResponse != nil {
		if errResponse.Error.Code >= 500 {
			server.logger.Error(errResponse.Error.Message)
		} else {
			server.logger.Info(errResponse.Error.Message)
		}
		_ = errResponse.write(w, r)
		return
	}
	created := resourceFromQuery.standardize()
	result := struct {
		Created *ResourceOut `json:"created"`
	}{
		Created: &created,
	}
	_ = jsonResponseFrom(result, 201).write(w, r)
}

func (server *Server) handleResourceRead(w http.ResponseWriter, r *http.Request) {
	path := parseResourcePath(r)
	resourceFromQuery, err := resourceWithPath(server.db, path)
	if resourceFromQuery == nil {
		msg := fmt.Sprintf("no resource found with path: `%s`", path)
		errResponse := newErrorResponse(msg, 404, nil)
		_ = errResponse.write(w, r)
		return
	}
	if err != nil {
		msg := fmt.Sprintf("resource query failed: %s", err.Error())
		errResponse := newErrorResponse(msg, 500, nil)
		server.logger.Error(errResponse.Error.Message)
		_ = errResponse.write(w, r)
		return
	}
	resource := resourceFromQuery.standardize()
	_ = jsonResponseFrom(resource, http.StatusOK).write(w, r)
}

func (server *Server) handleResourceReadByTag(w http.ResponseWriter, r *http.Request) {
	tag := mux.Vars(r)["tag"]
	resourceFromQuery, err := resourceWithTag(server.db, tag)
	if resourceFromQuery == nil {
		msg := fmt.Sprintf("no resource found with tag: `%s`", tag)
		errResponse := newErrorResponse(msg, 404, nil)
		_ = errResponse.write(w, r)
		return
	}
	if err != nil {
		msg := fmt.Sprintf("resource query failed: %s", err.Error())
		errResponse := newErrorResponse(msg, 500, nil)
		server.logger.Error(errResponse.Error.Message)
		_ = errResponse.write(w, r)
		return
	}
	resource := resourceFromQuery.standardize()
	_ = jsonResponseFrom(resource, http.StatusOK).write(w, r)
}

func (server *Server) handleResourceDelete(w http.ResponseWriter, r *http.Request) {
	path := parseResourcePath(r)
	resource := ResourceIn{Path: path}
	errResponse := resource.deleteInDb(server.db)
	if errResponse != nil {
		server.logger.Info(errResponse.Error.Message)
		_ = errResponse.write(w, r)
		return
	}
	_ = jsonResponseFrom(nil, http.StatusNoContent).write(w, r)
}

func (server *Server) handleRoleList(w http.ResponseWriter, r *http.Request) {
	rolesFromQuery, err := listRolesFromDb(server.db)
	if err != nil {
		msg := fmt.Sprintf("roles query failed: %s", err.Error())
		errResponse := newErrorResponse(msg, 500, nil)
		server.logger.Error(errResponse.Error.Message)
		_ = errResponse.write(w, r)
		return
	}
	roles := []Role{}
	for _, roleFromQuery := range rolesFromQuery {
		roles = append(roles, roleFromQuery.standardize())
	}
	result := struct {
		Roles []Role `json:"roles"`
	}{
		Roles: roles,
	}
	_ = jsonResponseFrom(result, http.StatusOK).write(w, r)
}

func (server *Server) handleRoleCreate(w http.ResponseWriter, r *http.Request, body []byte) {
	role := &Role{}
	err := json.Unmarshal(body, role)
	if err != nil {
		msg := fmt.Sprintf("could not parse role from JSON: %s", err.Error())
		server.logger.Info("tried to create role but input was invalid: %s", msg)
		response := newErrorResponse(msg, 400, nil)
		_ = response.write(w, r)
		return
	}
	errResponse := role.createInDb(server.db)
	if errResponse != nil {
		if errResponse.Error.Code >= 500 {
			server.logger.Error(errResponse.Error.Message)
		} else {
			server.logger.Info(errResponse.Error.Message)
		}
		_ = errResponse.write(w, r)
		return
	}
	created := struct {
		Created *Role `json:"created"`
	}{
		Created: role,
	}
	_ = jsonResponseFrom(created, 201).write(w, r)
}

func (server *Server) handleRoleRead(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["roleID"]
	roleFromQuery, err := roleWithName(server.db, name)
	if roleFromQuery == nil {
		msg := fmt.Sprintf("no role found with id: %s", name)
		errResponse := newErrorResponse(msg, 404, nil)
		server.logger.Error(errResponse.Error.Message)
		_ = errResponse.write(w, r)
		return
	}
	if err != nil {
		msg := fmt.Sprintf("role query failed: %s", err.Error())
		errResponse := newErrorResponse(msg, 500, nil)
		server.logger.Error(errResponse.Error.Message)
		_ = errResponse.write(w, r)
		return
	}
	role := roleFromQuery.standardize()
	_ = jsonResponseFrom(role, http.StatusOK).write(w, r)
}

func (server *Server) handleRoleDelete(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["roleID"]
	role := &Role{Name: name}
	errResponse := role.deleteInDb(server.db)
	if errResponse != nil {
		server.logger.Info(errResponse.Error.Message)
		_ = errResponse.write(w, r)
		return
	}
	_ = jsonResponseFrom(nil, http.StatusNoContent).write(w, r)
}

func (server *Server) handleUserList(w http.ResponseWriter, r *http.Request) {
	usersFromQuery, err := listUsersFromDb(server.db)
	if err != nil {
		msg := fmt.Sprintf("users query failed: %s", err.Error())
		errResponse := newErrorResponse(msg, 500, nil)
		server.logger.Error(errResponse.Error.Message)
		_ = errResponse.write(w, r)
		return
	}
	users := []User{}
	for _, userFromQuery := range usersFromQuery {
		users = append(users, userFromQuery.standardize())
	}
	result := struct {
		Users []User `json:"users"`
	}{
		Users: users,
	}
	_ = jsonResponseFrom(result, http.StatusOK).write(w, r)
}

func (server *Server) handleUserCreate(w http.ResponseWriter, r *http.Request, body []byte) {
	user := &User{}
	err := json.Unmarshal(body, user)
	if err != nil {
		msg := fmt.Sprintf("could not parse user from JSON: %s", err.Error())
		server.logger.Info("tried to create user but input was invalid: %s", msg)
		response := newErrorResponse(msg, 400, nil)
		_ = response.write(w, r)
		return
	}
	errResponse := user.createInDb(server.db)
	if errResponse != nil {
		if errResponse.Error.Code >= 500 {
			server.logger.Error(errResponse.Error.Message)
		} else {
			server.logger.Info(errResponse.Error.Message)
		}
		_ = errResponse.write(w, r)
		return
	}
	created := struct {
		Created *User `json:"created"`
	}{
		Created: user,
	}
	_ = jsonResponseFrom(created, 201).write(w, r)
}

func (server *Server) handleUserRead(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["username"]
	userFromQuery, err := userWithName(server.db, name)
	if userFromQuery == nil {
		msg := fmt.Sprintf("no user found with username: %s", name)
		errResponse := newErrorResponse(msg, 404, nil)
		server.logger.Error(errResponse.Error.Message)
		_ = errResponse.write(w, r)
		return
	}
	if err != nil {
		msg := fmt.Sprintf("user query failed: %s", err.Error())
		errResponse := newErrorResponse(msg, 500, nil)
		server.logger.Error(errResponse.Error.Message)
		_ = errResponse.write(w, r)
		return
	}
	user := userFromQuery.standardize()
	_ = jsonResponseFrom(user, http.StatusOK).write(w, r)
}

func (server *Server) handleUserDelete(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["username"]
	user := User{Name: name}
	errResponse := user.deleteInDb(server.db)
	if errResponse != nil {
		server.logger.Info(errResponse.Error.Message)
		_ = errResponse.write(w, r)
		return
	}
	_ = jsonResponseFrom(nil, http.StatusNoContent).write(w, r)
}

func (server *Server) handleUserGrantPolicy(w http.ResponseWriter, r *http.Request, body []byte) {
	username := mux.Vars(r)["username"]
	requestPolicy := struct {
		PolicyName string `json:"policy"`
	}{}
	err := json.Unmarshal(body, &requestPolicy)
	if err != nil {
		msg := fmt.Sprintf("could not parse policy name in JSON: %s", err.Error())
		server.logger.Info("tried to grant policy to user but input was invalid: %s", msg)
		response := newErrorResponse(msg, 400, nil)
		_ = response.write(w, r)
		return
	}
	errResponse := grantUserPolicy(server.db, username, requestPolicy.PolicyName)
	if errResponse != nil {
		server.logger.Info(errResponse.Error.Message)
		_ = errResponse.write(w, r)
		return
	}
	server.logger.Info("granted policy %s to user %s", requestPolicy.PolicyName, username)
	_ = jsonResponseFrom(nil, http.StatusNoContent).write(w, r)
}

func (server *Server) handleUserRevokeAll(w http.ResponseWriter, r *http.Request) {
	username := mux.Vars(r)["username"]
	errResponse := revokeUserPolicyAll(server.db, username)
	if errResponse != nil {
		server.logger.Info(errResponse.Error.Message)
		_ = errResponse.write(w, r)
		return
	}
	_ = jsonResponseFrom(nil, http.StatusNoContent).write(w, r)
}

func (server *Server) handleUserRevokePolicy(w http.ResponseWriter, r *http.Request) {
	username := mux.Vars(r)["username"]
	policyName := mux.Vars(r)["policyName"]
	errResponse := revokeUserPolicy(server.db, username, policyName)
	if errResponse != nil {
		server.logger.Info(errResponse.Error.Message)
		_ = errResponse.write(w, r)
		return
	}
	_ = jsonResponseFrom(nil, http.StatusNoContent).write(w, r)
}

func (server *Server) handleClientList(w http.ResponseWriter, r *http.Request) {
	clientsFromQuery, err := listClientsFromDb(server.db)
	if err != nil {
		msg := fmt.Sprintf("clients query failed: %s", err.Error())
		errResponse := newErrorResponse(msg, 500, nil)
		server.logger.Error(errResponse.Error.Message)
		_ = errResponse.write(w, r)
		return
	}
	clients := []Client{}
	for _, clientFromQuery := range clientsFromQuery {
		clients = append(clients, clientFromQuery.standardize())
	}
	result := struct {
		Clients []Client `json:"clients"`
	}{
		Clients: clients,
	}
	_ = jsonResponseFrom(result, http.StatusOK).write(w, r)
}

func (server *Server) handleClientCreate(w http.ResponseWriter, r *http.Request, body []byte) {
	client := &Client{}
	err := json.Unmarshal(body, client)
	if err != nil {
		msg := fmt.Sprintf("could not parse client from JSON: %s", err.Error())
		server.logger.Info("tried to create client but input was invalid: %s", msg)
		response := newErrorResponse(msg, 400, nil)
		_ = response.write(w, r)
		return
	}
	errResponse := client.createInDb(server.db)
	if errResponse != nil {
		if errResponse.Error.Code >= 500 {
			server.logger.Error(errResponse.Error.Message)
		} else {
			server.logger.Info(errResponse.Error.Message)
		}
		_ = errResponse.write(w, r)
		return
	}
	created := struct {
		Created *Client `json:"created"`
	}{
		Created: client,
	}
	_ = jsonResponseFrom(created, 201).write(w, r)
}

func (server *Server) handleClientRead(w http.ResponseWriter, r *http.Request) {
	clientID := mux.Vars(r)["clientID"]
	clientFromQuery, err := clientWithClientID(server.db, clientID)
	if clientFromQuery == nil {
		msg := fmt.Sprintf("no client found with clientID: %s", clientID)
		errResponse := newErrorResponse(msg, 404, nil)
		server.logger.Error(errResponse.Error.Message)
		_ = errResponse.write(w, r)
		return
	}
	if err != nil {
		msg := fmt.Sprintf("client query failed: %s", err.Error())
		errResponse := newErrorResponse(msg, 500, nil)
		server.logger.Error(errResponse.Error.Message)
		_ = errResponse.write(w, r)
		return
	}
	client := clientFromQuery.standardize()
	_ = jsonResponseFrom(client, http.StatusOK).write(w, r)
}

func (server *Server) handleClientDelete(w http.ResponseWriter, r *http.Request) {
	clientID := mux.Vars(r)["clientID"]
	client := Client{ClientID: clientID}
	errResponse := client.deleteInDb(server.db)
	if errResponse != nil {
		server.logger.Info(errResponse.Error.Message)
		_ = errResponse.write(w, r)
		return
	}
	_ = jsonResponseFrom(nil, http.StatusNoContent).write(w, r)
}

func (server *Server) handleClientGrantPolicy(w http.ResponseWriter, r *http.Request, body []byte) {
	clientID := mux.Vars(r)["clientID"]
	requestPolicy := struct {
		PolicyName string `json:"policy"`
	}{}
	err := json.Unmarshal(body, &requestPolicy)
	if err != nil {
		msg := fmt.Sprintf("could not parse policy name in JSON: %s", err.Error())
		server.logger.Info("tried to grant policy to client but input was invalid: %s", msg)
		response := newErrorResponse(msg, 400, nil)
		_ = response.write(w, r)
		return
	}
	errResponse := grantClientPolicy(server.db, clientID, requestPolicy.PolicyName)
	if errResponse != nil {
		server.logger.Info(errResponse.Error.Message)
		_ = errResponse.write(w, r)
		return
	}
	_ = jsonResponseFrom(nil, http.StatusNoContent).write(w, r)
}

func (server *Server) handleClientRevokeAll(w http.ResponseWriter, r *http.Request) {
	clientID := mux.Vars(r)["clientID"]
	errResponse := revokeClientPolicyAll(server.db, clientID)
	if errResponse != nil {
		server.logger.Info(errResponse.Error.Message)
		_ = errResponse.write(w, r)
		return
	}
	_ = jsonResponseFrom(nil, http.StatusNoContent).write(w, r)
}

func (server *Server) handleClientRevokePolicy(w http.ResponseWriter, r *http.Request) {
	clientID := mux.Vars(r)["clientID"]
	policyName := mux.Vars(r)["policyName"]
	errResponse := revokeClientPolicy(server.db, clientID, policyName)
	if errResponse != nil {
		server.logger.Info(errResponse.Error.Message)
		_ = errResponse.write(w, r)
		return
	}
	_ = jsonResponseFrom(nil, http.StatusNoContent).write(w, r)
}

func (server *Server) handleGroupList(w http.ResponseWriter, r *http.Request) {
	groupsFromQuery, err := listGroupsFromDb(server.db)
	if err != nil {
		msg := fmt.Sprintf("groups query failed: %s", err.Error())
		errResponse := newErrorResponse(msg, 500, nil)
		server.logger.Error(errResponse.Error.Message)
		_ = errResponse.write(w, r)
		return
	}
	groups := []Group{}
	for _, groupFromQuery := range groupsFromQuery {
		groups = append(groups, groupFromQuery.standardize())
	}
	result := struct {
		Groups []Group `json:"groups"`
	}{
		Groups: groups,
	}
	_ = jsonResponseFrom(result, http.StatusOK).write(w, r)
}

func (server *Server) handleGroupCreate(w http.ResponseWriter, r *http.Request, body []byte) {
	group := &Group{}
	err := json.Unmarshal(body, group)
	if err != nil {
		msg := fmt.Sprintf("could not parse group from JSON: %s", err.Error())
		server.logger.Info("tried to create group but input was invalid: %s", msg)
		response := newErrorResponse(msg, 400, nil)
		_ = response.write(w, r)
		return
	}
	errResponse := group.createInDb(server.db)
	if errResponse != nil {
		if errResponse.Error.Code >= 500 {
			server.logger.Error(errResponse.Error.Message)
		} else {
			server.logger.Info(errResponse.Error.Message)
		}
		_ = errResponse.write(w, r)
		return
	}
	created := struct {
		Created *Group `json:"created"`
	}{
		Created: group,
	}
	_ = jsonResponseFrom(created, 201).write(w, r)
}

func (server *Server) handleGroupRead(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["groupName"]
	groupFromQuery, err := groupWithName(server.db, name)
	if groupFromQuery == nil {
		msg := fmt.Sprintf("no group found with name: %s", name)
		errResponse := newErrorResponse(msg, 404, nil)
		server.logger.Error(errResponse.Error.Message)
		_ = errResponse.write(w, r)
		return
	}
	if err != nil {
		msg := fmt.Sprintf("group query failed: %s", err.Error())
		errResponse := newErrorResponse(msg, 500, nil)
		server.logger.Error(errResponse.Error.Message)
		_ = errResponse.write(w, r)
		return
	}
	group := groupFromQuery.standardize()
	_ = jsonResponseFrom(group, http.StatusOK).write(w, r)
}

func (server *Server) handleGroupDelete(w http.ResponseWriter, r *http.Request) {
	groupName := mux.Vars(r)["groupName"]
	group := Group{Name: groupName}
	errResponse := group.deleteInDb(server.db)
	if errResponse != nil {
		server.logger.Info(errResponse.Error.Message)
		_ = errResponse.write(w, r)
		return
	}
	_ = jsonResponseFrom(nil, http.StatusNoContent).write(w, r)
}

func (server *Server) handleGroupAddUser(w http.ResponseWriter, r *http.Request, body []byte) {
	groupName := mux.Vars(r)["groupName"]
	requestUser := struct {
		Username string `json:"username"`
	}{}
	err := json.Unmarshal(body, &requestUser)
	if err != nil {
		msg := fmt.Sprintf("could not parse username in JSON: %s", err.Error())
		server.logger.Info("tried to add user to group but input was invalid: %s", msg)
		response := newErrorResponse(msg, 400, nil)
		_ = response.write(w, r)
		return
	}
	errResponse := addUserToGroup(server.db, requestUser.Username, groupName)
	if errResponse != nil {
		server.logger.Info(errResponse.Error.Message)
		_ = errResponse.write(w, r)
		return
	}
	_ = jsonResponseFrom(nil, http.StatusNoContent).write(w, r)
}

func (server *Server) handleGroupRemoveUser(w http.ResponseWriter, r *http.Request) {
	groupName := mux.Vars(r)["groupName"]
	username := mux.Vars(r)["username"]
	errResponse := removeUserFromGroup(server.db, username, groupName)
	if errResponse != nil {
		server.logger.Info(errResponse.Error.Message)
		_ = errResponse.write(w, r)
		return
	}
	_ = jsonResponseFrom(nil, http.StatusNoContent).write(w, r)
}

func (server *Server) handleGroupGrantPolicy(w http.ResponseWriter, r *http.Request, body []byte) {
	groupName := mux.Vars(r)["groupName"]
	requestPolicy := struct {
		PolicyName string `json:"policy"`
	}{}
	err := json.Unmarshal(body, &requestPolicy)
	if err != nil {
		msg := fmt.Sprintf("could not parse policy name in JSON: %s", err.Error())
		server.logger.Info("tried to grant policy to group %s but input was invalid: %s", groupName, msg)
		response := newErrorResponse(msg, 400, nil)
		_ = response.write(w, r)
		return
	}
	errResponse := grantGroupPolicy(server.db, groupName, requestPolicy.PolicyName)
	if errResponse != nil {
		server.logger.Info(errResponse.Error.Message)
		_ = errResponse.write(w, r)
		return
	}
	_ = jsonResponseFrom(nil, http.StatusNoContent).write(w, r)
}

func (server *Server) handleGroupRevokePolicy(w http.ResponseWriter, r *http.Request) {
	groupName := mux.Vars(r)["groupName"]
	policyName := mux.Vars(r)["policyName"]
	errResponse := revokeGroupPolicy(server.db, groupName, policyName)
	if errResponse != nil {
		server.logger.Info(errResponse.Error.Message)
		_ = errResponse.write(w, r)
		return
	}
	_ = jsonResponseFrom(nil, http.StatusNoContent).write(w, r)
}
