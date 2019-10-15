package arborist

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

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
//    `{resourcePath:/.+}`
//
// so we put the slash at the front here and fix it in parseResourcePath.
const resourcePath string = `/{resourcePath:.+}`

func parseResourcePath(r *http.Request) string {
	path, exists := mux.Vars(r)["resourcePath"]
	if !exists {
		return ""
	}
	// We have to add a slash at the front here; see resourcePath constant.
	return strings.Join([]string{"/", path}, "")
}

func getAuthZProvider(r *http.Request) sql.NullString {
	rv := r.Header.Get("X-AuthZ-Provider")
	if len(rv) == 0 {
		return sql.NullString{}
	} else {
		return sql.NullString{String: rv, Valid: true}
	}
}

func (server *Server) MakeRouter(out io.Writer) http.Handler {
	router := mux.NewRouter().StrictSlash(true)

	//router.Handle("/", server.handleRoot).Methods("GET")

	router.HandleFunc("/health", server.handleHealth).Methods("GET")

	router.Handle("/auth/mapping", http.HandlerFunc(server.handleAuthMappingGET)).Methods("GET")
	router.Handle("/auth/mapping", http.HandlerFunc(server.parseJSON(server.handleAuthMappingPOST))).Methods("POST")
	router.Handle("/auth/proxy", http.HandlerFunc(server.handleAuthProxy)).Methods("GET")
	router.Handle("/auth/request", http.HandlerFunc(server.parseJSON(server.handleAuthRequest))).Methods("POST")
	router.Handle("/auth/resources", http.HandlerFunc(server.handleListAuthResourcesGET)).Methods("GET")
	router.Handle("/auth/resources", http.HandlerFunc(server.parseJSON(server.handleListAuthResourcesPOST))).Methods("POST")

	router.Handle("/policy", http.HandlerFunc(server.handlePolicyList)).Methods("GET")
	router.Handle("/policy", http.HandlerFunc(server.parseJSON(server.handlePolicyCreate))).Methods("POST")
	// delete this (PUT /policy) route after 3.0.0
	router.Handle("/policy", http.HandlerFunc(server.parseJSON(server.handlePolicyOverwrite))).Methods("PUT")
	router.Handle("/policy/{policyID}", http.HandlerFunc(server.parseJSON(server.handlePolicyOverwrite))).Methods("PUT")
	router.Handle("/policy/{policyID}", http.HandlerFunc(server.handlePolicyRead)).Methods("GET")
	router.Handle("/policy/{policyID}", http.HandlerFunc(server.handlePolicyDelete)).Methods("DELETE")

	router.Handle("/resource", http.HandlerFunc(server.handleResourceList)).Methods("GET")
	router.Handle("/resource", http.HandlerFunc(server.parseJSON(server.handleResourceCreate))).Methods("POST", "PUT")
	router.Handle("/resource/tag/{tag}", http.HandlerFunc(server.handleResourceReadByTag)).Methods("GET")
	router.Handle("/resource"+resourcePath, http.HandlerFunc(server.handleResourceRead)).Methods("GET")
	router.Handle("/resource"+resourcePath, http.HandlerFunc(server.parseJSON(server.handleResourceCreate))).Methods("POST", "PUT")
	router.Handle("/resource"+resourcePath, http.HandlerFunc(server.handleResourceDelete)).Methods("DELETE")

	router.Handle("/role", http.HandlerFunc(server.handleRoleList)).Methods("GET")
	router.Handle("/role", http.HandlerFunc(server.parseJSON(server.handleRoleCreate))).Methods("POST")
	router.Handle("/role/{roleID}", http.HandlerFunc(server.handleRoleRead)).Methods("GET")
	router.Handle("/role/{roleID}", http.HandlerFunc(server.handleRoleDelete)).Methods("DELETE")

	router.Handle("/user", http.HandlerFunc(server.handleUserList)).Methods("GET")
	router.Handle("/user", http.HandlerFunc(server.parseJSON(server.handleUserCreate))).Methods("POST")
	router.Handle("/users", http.HandlerFunc(server.parseJSON(server.handleUsersCreate))).Methods("POST")
	router.Handle("/user/{username}", http.HandlerFunc(server.handleUserRead)).Methods("GET")
	router.Handle("/user/{username}", http.HandlerFunc(server.handleUserDelete)).Methods("DELETE")
	router.Handle("/user/{username}/policy", http.HandlerFunc(server.parseJSON(server.handleUserGrantPolicy))).Methods("POST")
	router.Handle("/user/{username}/policy", http.HandlerFunc(server.handleUserRevokeAll)).Methods("DELETE")
	router.Handle("/user/{username}/policy/{policyName}", http.HandlerFunc(server.handleUserRevokePolicy)).Methods("DELETE")
	router.Handle("/user/{username}/resources", http.HandlerFunc(server.handleUserListResources)).Methods("GET")

	router.Handle("/client", http.HandlerFunc(server.handleClientList)).Methods("GET")
	router.Handle("/client", http.HandlerFunc(server.parseJSON(server.handleClientCreate))).Methods("POST")
	router.Handle("/client/{clientID}", http.HandlerFunc(server.handleClientRead)).Methods("GET")
	router.Handle("/client/{clientID}", http.HandlerFunc(server.handleClientDelete)).Methods("DELETE")
	router.Handle("/client/{clientID}/policy", http.HandlerFunc(server.parseJSON(server.handleClientGrantPolicy))).Methods("POST")
	router.Handle("/client/{clientID}/policy", http.HandlerFunc(server.handleClientRevokeAll)).Methods("DELETE")
	router.Handle("/client/{clientID}/policy/{policyName}", http.HandlerFunc(server.handleClientRevokePolicy)).Methods("DELETE")

	router.Handle("/group", http.HandlerFunc(server.handleGroupList)).Methods("GET")
	router.Handle("/group", http.HandlerFunc(server.parseJSON(server.handleGroupCreate))).Methods("POST", "PUT")
	router.Handle("/group/{groupName}", http.HandlerFunc(server.handleGroupRead)).Methods("GET")
	router.Handle("/group/{groupName}", http.HandlerFunc(server.handleGroupDelete)).Methods("DELETE")
	router.Handle("/group/{groupName}/user", http.HandlerFunc(server.parseJSON(server.handleGroupAddUser))).Methods("POST")
	router.Handle("/group/{groupName}/user/{username}", http.HandlerFunc(server.handleGroupRemoveUser)).Methods("DELETE")
	router.Handle("/group/{groupName}/policy", http.HandlerFunc(server.parseJSON(server.handleGroupGrantPolicy))).Methods("POST")
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
func (server *Server) parseJSON(baseHandler func(http.ResponseWriter, *http.Request, []byte)) func(http.ResponseWriter, *http.Request) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		if r.Body == nil {
			response := newErrorResponse("expected JSON body in the request", 400, nil)
			response.log.write(server.logger)
			_ = response.write(w, r)
			return
		}
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			msg := fmt.Sprintf("could not parse valid JSON from request: %s", err.Error())
			response := newErrorResponse(msg, 400, nil)
			response.log.write(server.logger)
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
		return
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

func (server *Server) handleAuthMappingGET(w http.ResponseWriter, r *http.Request) {
	username := ""
	usernameQS, ok := r.URL.Query()["username"]
	if ok {
		username = usernameQS[0]
	} else if authHeader := r.Header.Get("Authorization"); authHeader != "" {
		// Fall back to JWT for username. Added for Arborist UI integration...
		server.logger.Info("No username in query args; falling back to jwt...")
		userJWT := strings.TrimPrefix(authHeader, "Bearer ")
		userJWT = strings.TrimPrefix(userJWT, "bearer ")
		aud := []string{"openid"}
		info, err := server.decodeToken(userJWT, aud)
		if err != nil {
			server.logger.Info("tried to fall back to jwt for username but jwt decode failed: %s", err.Error())
		} else {
			server.logger.Info("found username in jwt: %s", info.username)
			username = info.username
		}
	}
	mappings, errResponse := authMapping(server.db, username)
	if errResponse != nil {
		errResponse.log.write(server.logger)
		_ = errResponse.write(w, r)
		return
	}
	_ = jsonResponseFrom(mappings, http.StatusOK).write(w, r)
}

func (server *Server) handleAuthMappingPOST(w http.ResponseWriter, r *http.Request, body []byte) {
	var errResponse *ErrorResponse = nil
	requestBody := struct {
		Username string `json:"username"`
	}{}
	err := json.Unmarshal(body, &requestBody)
	if err != nil {
		msg := fmt.Sprintf("could not parse JSON: %s", err.Error())
		server.logger.Info("tried to handle auth mapping request but input was invalid: %s", msg)
		errResponse = newErrorResponse(msg, 400, nil)
	}
	if requestBody.Username == "" {
		msg := "missing `username` argument"
		server.logger.Info(msg)
		errResponse = newErrorResponse(msg, 400, nil)
	}
	if errResponse != nil {
		_ = errResponse.write(w, r)
		return
	}
	mappings, errResponse := authMapping(server.db, requestBody.Username)
	if errResponse != nil {
		errResponse.log.write(server.logger)
		_ = errResponse.write(w, r)
		return
	}
	_ = jsonResponseFrom(mappings, http.StatusOK).write(w, r)
}

func (server *Server) handleAuthProxy(w http.ResponseWriter, r *http.Request) {
	authRequest, errResponse := authRequestFromGET(server.decodeToken, r)
	if errResponse != nil {
		errResponse.log.write(server.logger)
		_ = errResponse.write(w, r)
		return
	}
	if authRequest.Resource == "" {
		msg := "auth proxy request missing `resource` argument"
		errResponse = newErrorResponse(msg, 400, nil)
	}
	if authRequest.Service == "" {
		msg := "auth proxy request missing `service` argument"
		errResponse = newErrorResponse(msg, 400, nil)
	}
	if authRequest.Method == "" {
		msg := "auth request missing `method` argument"
		errResponse = newErrorResponse(msg, 400, nil)
	}
	if errResponse != nil {
		errResponse.log.write(server.logger)
		_ = errResponse.write(w, r)
		return
	}
	authRequest.stmts = server.stmts
	w.Header().Set("REMOTE_USER", authRequest.Username)

	rv, err := authorizeUser(authRequest)
	if err != nil {
		msg := fmt.Sprintf("could not authorize user: %s", err.Error())
		server.logger.Info("tried to handle auth request but input was invalid: %s", msg)
		response := newErrorResponse(msg, 400, nil)
		_ = response.write(w, r)
		return
	}
	if rv.Auth {
		server.logger.Debug("user is authorized")
	}
	if err == nil && rv.Auth && authRequest.ClientID != "" {
		rv, err = authorizeClient(authRequest)
		if err != nil {
			msg := fmt.Sprintf("could not authorize client: %s", err.Error())
			server.logger.Info("error during client auth check: %s", msg)
			response := newErrorResponse(msg, 400, nil)
			_ = response.write(w, r)
			return
		}
		if rv.Auth {
			server.logger.Debug("client is authorized")
		}
	}
	if !rv.Auth {
		errResponse := newErrorResponse(
			"Unauthorized: user does not have access to this resource", 403, nil)
		_ = errResponse.write(w, r)
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

	if len(requests) == 0 {
		_ = newErrorResponse("auth request missing resources", 400, nil).write(w, r)
		return
	}

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

		if info.username == "" && (info.policies == nil || len(info.policies) == 0) {
			msg := "missing both username and policies in request (at least one is required)"
			_ = newErrorResponse(msg, 400, nil).write(w, r)
			return
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
		server.logger.Info("handling auth request: %#v", *request)
		rv, err := authorizeUser(request)
		if err != nil {
			msg := fmt.Sprintf("could not authorize user: %s", err.Error())
			server.logger.Info("tried to handle auth request but input was invalid: %s", msg)
			response := newErrorResponse(msg, 400, nil)
			_ = response.write(w, r)
			return
		}
		if rv.Auth {
			server.logger.Debug("user is authorized")
		} else {
			server.logger.Debug("user is unauthorized")
		}
		if rv.Auth && request.ClientID != "" {
			rv, err = authorizeClient(request)
			if err == nil && rv.Auth {
				server.logger.Debug("client is authorized")
			} else {
				server.logger.Debug("client is unauthorized")
			}
		}
		if err != nil {
			msg := fmt.Sprintf("could not authorize client: %s", err.Error())
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

func (server *Server) handleListAuthResourcesGET(w http.ResponseWriter, r *http.Request) {
	authRequest := &AuthRequest{}
	var errResponse *ErrorResponse
	authRequest, errResponse = authRequestFromGET(server.decodeToken, r)
	if errResponse != nil {
		errResponse.log.write(server.logger)
		_ = errResponse.write(w, r)
		return
	}
	server.makeAuthResourcesResponse(w, r, authRequest, errResponse)
}

func (server *Server) handleListAuthResourcesPOST(w http.ResponseWriter, r *http.Request, body []byte) {
	authRequest := &AuthRequest{}
	var errResponse *ErrorResponse
	request := struct {
		User AuthRequestJSON_User `json:"user"`
	}{}
	err := json.Unmarshal(body, &request)
	if err != nil {
		msg := fmt.Sprintf("could not parse auth request from JSON: %s", err.Error())
		server.logger.Info("tried to handle auth request but input was invalid: %s", msg)
		response := newErrorResponse(msg, 400, nil)
		_ = response.write(w, r)
		return
	}
	// TODO
	// make sure not empty
	/*
		if (request.User == AuthRequestJSON_User{}) {
			server.logger.Info("auth resources request missing user field", msg)
			response := newErrorResponse(msg, 400, nil)
			_ = response.write(w, r)
			return
		}
	*/
	var aud []string
	if request.User.Audiences == nil {
		aud = []string{"openid"}
	} else {
		aud = make([]string, len(request.User.Audiences))
		copy(aud, request.User.Audiences)
	}

	info, err := server.decodeToken(request.User.Token, aud)
	if err != nil {
		server.logger.Info(err.Error())
		errResponse := newErrorResponse(err.Error(), 401, &err)
		_ = errResponse.write(w, r)
		return
	}

	authRequest.Username = info.username
	authRequest.ClientID = info.clientID
	authRequest.Policies = info.policies
	if request.User.Policies != nil {
		authRequest.Policies = request.User.Policies
	}
	server.makeAuthResourcesResponse(w, r, authRequest, errResponse)
}

func (server *Server) makeAuthResourcesResponse(w http.ResponseWriter, r *http.Request, authRequest *AuthRequest, errResponse *ErrorResponse) {
	if errResponse != nil {
		errResponse.log.write(server.logger)
		_ = errResponse.write(w, r)
		return
	}

	resourcesFromQuery, errResponse := authorizedResources(server.db, authRequest)
	if errResponse != nil {
		errResponse.log.write(server.logger)
		_ = errResponse.write(w, r)
		return
	}
	resources := []ResourceOut{}
	for _, resourceFromQuery := range resourcesFromQuery {
		resources = append(resources, resourceFromQuery.standardize())
	}

	useTags := false
	_, ok := r.URL.Query()["tags"]
	if ok {
		useTags = true
	}

	response := struct {
		Resources []string `json:"resources"`
	}{}
	resultList := make([]string, len(resources))
	for i := range resources {
		if useTags {
			resultList[i] = resources[i].Tag
		} else {
			resultList[i] = resources[i].Path
		}
	}
	response.Resources = resultList

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
		errResponse.log.write(server.logger)
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
	errResponse := transactify(server.db, policy.createInDb)
	if errResponse != nil {
		errResponse.log.write(server.logger)
		_ = errResponse.write(w, r)
		return
	}
	server.logger.Info("created policy %s", policy.Name)
	created := struct {
		Created *Policy `json:"created"`
	}{
		Created: policy,
	}
	_ = jsonResponseFrom(created, 201).write(w, r)
}

func (server *Server) handlePolicyOverwrite(w http.ResponseWriter, r *http.Request, body []byte) {
	policy := &Policy{}
	err := json.Unmarshal(body, policy)
	if err != nil {
		msg := fmt.Sprintf("could not parse policy from JSON: %s", err.Error())
		server.logger.Info("tried to create policy but input was invalid: %s", msg)
		response := newErrorResponse(msg, 400, nil)
		_ = response.write(w, r)
		return
	}
	// Overwrite policy name from json with policy name from query arg.
	// After 3.0.0, when PUT /policy is deprecated and only PUT /policy/{policyID} is allowed,
	// can remove the !="" check. For now, if policy name not found in url, default to name in json.
	if mux.Vars(r)["policyID"] != "" {
		policy.Name = mux.Vars(r)["policyID"]
	}
	errResponse := transactify(server.db, policy.updateInDb)
	if errResponse != nil {
		errResponse.log.write(server.logger)
		_ = errResponse.write(w, r)
		return
	}
	server.logger.Info("overwrote policy %s", policy.Name)
	updated := struct {
		Updated *Policy `json:"updated"`
	}{
		Updated: policy,
	}
	_ = jsonResponseFrom(updated, 201).write(w, r)
}

func (server *Server) handlePolicyRead(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["policyID"]
	policyFromQuery, err := policyWithName(server.db, name)
	if policyFromQuery == nil {
		msg := fmt.Sprintf("no policy found with id: %s", name)
		errResponse := newErrorResponse(msg, 404, nil)
		errResponse.log.write(server.logger)
		_ = errResponse.write(w, r)
		return
	}
	if err != nil {
		msg := fmt.Sprintf("policy query failed: %s", err.Error())
		errResponse := newErrorResponse(msg, 500, nil)
		errResponse.log.write(server.logger)
		_ = errResponse.write(w, r)
		return
	}
	policy := policyFromQuery.standardize()
	_ = jsonResponseFrom(policy, http.StatusOK).write(w, r)
}

func (server *Server) handlePolicyDelete(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["policyID"]
	policy := &Policy{Name: name}
	errResponse := transactify(server.db, policy.deleteInDb)
	if errResponse != nil {
		errResponse.log.write(server.logger)
		_ = errResponse.write(w, r)
		return
	}
	server.logger.Info("deleted policy %s", name)
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
		errResponse.log.write(server.logger)
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

var regSlashes *regexp.Regexp = regexp.MustCompile(`/+`)

func (server *Server) handleResourceCreate(w http.ResponseWriter, r *http.Request, body []byte) {
	// parse & validate resource input
	resource := &ResourceIn{}
	errResponse := unmarshal(body, resource)
	if errResponse != nil {
		errResponse.log.write(server.logger)
		_ = errResponse.write(w, r)
		return
	}

	parentPath := parseResourcePath(r)
	resource.addPath(parentPath)

	// check if the `p` flag is added in which case we want to create the
	// parent resources first.
	_, createParentsFlag := r.URL.Query()["p"]
	if createParentsFlag {
		server.logger.Info("creating parent resources for %s", resource.Path)
		segments := strings.Split(strings.TrimLeft(resource.Path, "/"), "/")
		for i := 0; i < len(segments)-1; i++ {
			path := "/" + strings.Join(segments[:i+1], "/")
			toCreate := ResourceIn{Path: path}
			_ = transactify(server.db, toCreate.createRecursively)
		}
	}

	errResponse = nil
	if r.Method == "PUT" {
		errResponse = transactify(server.db, resource.overwriteInDb)
	} else {
		errResponse = transactify(server.db, resource.createInDb)
	}
	if errResponse != nil && errResponse.HTTPError.Code != 409 {
		// `transactify` returns 500 if there was a SQL error. Here we'll assume
		// that this would be because of an invalid resource input from the caller.
		// This could definitely do with some better error handling to make sure
		// this is accurate.
		if errResponse.HTTPError.Code == 500 {
			errResponse.HTTPError.Code = 400
		}
		// TODO: patch error message to be intelligible if dumping resource path
		errResponse.log.write(server.logger)
		_ = errResponse.write(w, r)
		return
	}
	resourceFromQuery, err := resourceWithPath(server.db, resource.Path)
	if err != nil {
		errResponse := newErrorResponse(err.Error(), 500, &err)
		errResponse.log.write(server.logger)
		_ = errResponse.write(w, r)
		return
	}
	if resourceFromQuery == nil {
		msg := fmt.Sprintf(
			"couldn't return resource for %s, but it may have been created OK",
			resource.Path,
		)
		errResponse := newErrorResponse(msg, 500, &err)
		errResponse.log.write(server.logger)
		_ = errResponse.write(w, r)
		return
	}
	out := resourceFromQuery.standardize()
	if errResponse != nil {
		// otherwise, must be 409 (already handled non-409 errors).
		server.logger.Info("not creating resource %s (%s), already exists", out.Path, out.Tag)
		result := struct {
			Error  HTTPError    `json:"error"`
			Exists *ResourceOut `json:"exists"`
		}{
			Error:  errResponse.HTTPError,
			Exists: &out,
		}
		_ = jsonResponseFrom(result, 409).write(w, r)
		return
	}

	server.logger.Info("created resource %s (%s)", out.Path, out.Tag)
	result := struct {
		Created *ResourceOut `json:"created"`
	}{
		Created: &out,
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
		errResponse.log.write(server.logger)
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
		errResponse.log.write(server.logger)
		_ = errResponse.write(w, r)
		return
	}
	resource := resourceFromQuery.standardize()
	_ = jsonResponseFrom(resource, http.StatusOK).write(w, r)
}

func (server *Server) handleResourceDelete(w http.ResponseWriter, r *http.Request) {
	path := parseResourcePath(r)
	resource := ResourceIn{Path: path}
	errResponse := transactify(server.db, resource.deleteInDb)
	if errResponse != nil {
		errResponse.log.write(server.logger)
		_ = errResponse.write(w, r)
		return
	}
	server.logger.Info("deleted resource %s", resource.Path)
	_ = jsonResponseFrom(nil, http.StatusNoContent).write(w, r)
}

func (server *Server) handleRoleList(w http.ResponseWriter, r *http.Request) {
	rolesFromQuery, err := listRolesFromDb(server.db)
	if err != nil {
		msg := fmt.Sprintf("roles query failed: %s", err.Error())
		errResponse := newErrorResponse(msg, 500, nil)
		errResponse.log.write(server.logger)
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
		errResponse.log.write(server.logger)
		_ = errResponse.write(w, r)
		return
	}
	server.logger.Info("created role %s", role.Name)
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
		errResponse.log.write(server.logger)
		_ = errResponse.write(w, r)
		return
	}
	if err != nil {
		msg := fmt.Sprintf("role query failed: %s", err.Error())
		errResponse := newErrorResponse(msg, 500, nil)
		errResponse.log.write(server.logger)
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
		errResponse.log.write(server.logger)
		_ = errResponse.write(w, r)
		return
	}
	server.logger.Info("deleted role %s", role.Name)
	_ = jsonResponseFrom(nil, http.StatusNoContent).write(w, r)
}

func (server *Server) handleUserList(w http.ResponseWriter, r *http.Request) {
	usersFromQuery, pagination, err := listUsersFromDb(server.db, r)
	if err != nil {
		msg := fmt.Sprintf("users query failed: %s", err.Error())
		errResponse := newErrorResponse(msg, 500, nil)
		errResponse.log.write(server.logger)
		_ = errResponse.write(w, r)
		return
	}
	users := []User{}
	for _, userFromQuery := range usersFromQuery {
		users = append(users, userFromQuery.standardize())
	}
	result := struct {
		Users []User `json:"users"`
		Pagination *Pagination `json:"pagination"`
	}{
		Users: users,
		Pagination: pagination,
	}
	_ = jsonResponseFrom(result, http.StatusOK).write(w, r)
}

func (server *Server) handleUsersCreate(w http.ResponseWriter, r *http.Request, body []byte) {
	users := &Users{}
	err := json.Unmarshal(body, users)
	if err != nil {
		msg := fmt.Sprintf("could not parse users from JSON: %s", err.Error())
		server.logger.Info("tried to create users but input was invalid: %s", msg)
		response := newErrorResponse(msg, 400, nil)
		_ = response.write(w, r)
		return
	}
	errResponse := users.multiCreateInDb(server.db)
	if errResponse != nil {
		errResponse.log.write(server.logger)
		_ = errResponse.write(w, r)
		return
	}
	for _, user := range users.Users {
		server.logger.Info("created user %s", user.Name)
	}
	created := struct {
		Created *Users `json:"created"`
	}{
		Created: users,
	}
	_ = jsonResponseFrom(created, 201).write(w, r)
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
		errResponse.log.write(server.logger)
		_ = errResponse.write(w, r)
		return
	}
	server.logger.Info("created user %s", user.Name)
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
	if err != nil {
		msg := fmt.Sprintf("user query failed: %s", err.Error())
		errResponse := newErrorResponse(msg, 500, nil)
		errResponse.log.write(server.logger)
		_ = errResponse.write(w, r)
		return
	}
	if userFromQuery == nil {
		msg := fmt.Sprintf("no user found with username: %s", name)
		errResponse := newErrorResponse(msg, 404, nil)
		errResponse.log.write(server.logger)
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
		errResponse.log.write(server.logger)
		_ = errResponse.write(w, r)
		return
	}
	server.logger.Info("deleted user %s", name)
	_ = jsonResponseFrom(nil, http.StatusNoContent).write(w, r)
}

func (server *Server) handleUserGrantPolicy(w http.ResponseWriter, r *http.Request, body []byte) {
	username := mux.Vars(r)["username"]
	requestPolicy := struct {
		PolicyName string `json:"policy"`
		ExpiresAt  string `json:"expires_at"`
	}{}
	err := json.Unmarshal(body, &requestPolicy)
	if err != nil {
		msg := fmt.Sprintf("could not parse policy name in JSON: %s", err.Error())
		server.logger.Info("tried to grant policy to user but input was invalid: %s", msg)
		response := newErrorResponse(msg, 400, nil)
		_ = response.write(w, r)
		return
	}
	var expiresAt *time.Time
	if requestPolicy.ExpiresAt != "" {
		exp, err := time.Parse(time.RFC3339, requestPolicy.ExpiresAt)
		if err != nil {
			msg := "could not parse `expires_at` (must be in RFC 3339 format; see specification: https://tools.ietf.org/html/rfc3339#section-5.8)"
			server.logger.Info("tried to grant policy to user but `expires_at` was invalid format")
			response := newErrorResponse(msg, 400, nil)
			_ = response.write(w, r)
			return
		}
		expiresAt = &exp
	}
	errResponse := grantUserPolicy(server.db, username, requestPolicy.PolicyName, expiresAt, getAuthZProvider(r))
	if errResponse != nil {
		errResponse.log.write(server.logger)
		_ = errResponse.write(w, r)
		return
	}
	server.logger.Info("granted policy %s to user %s", requestPolicy.PolicyName, username)
	_ = jsonResponseFrom(nil, http.StatusNoContent).write(w, r)
}

func (server *Server) handleUserRevokeAll(w http.ResponseWriter, r *http.Request) {
	username := mux.Vars(r)["username"]
	authzProvider := getAuthZProvider(r)
	errResponse := revokeUserPolicyAll(server.db, username, authzProvider)
	if errResponse != nil {
		errResponse.log.write(server.logger)
		_ = errResponse.write(w, r)
		return
	}
	if authzProvider.Valid {
		server.logger.Info("revoked all %s policies for user %s", authzProvider.String, username)
	} else {
		server.logger.Info("revoked all policies for user %s", username)
	}
	_ = jsonResponseFrom(nil, http.StatusNoContent).write(w, r)
}

func (server *Server) handleUserRevokePolicy(w http.ResponseWriter, r *http.Request) {
	username := mux.Vars(r)["username"]
	policyName := mux.Vars(r)["policyName"]
	errResponse := revokeUserPolicy(server.db, username, policyName, getAuthZProvider(r))
	if errResponse != nil {
		errResponse.log.write(server.logger)
		_ = errResponse.write(w, r)
		return
	}
	server.logger.Info("revoked policy %s for user %s", policyName, username)
	_ = jsonResponseFrom(nil, http.StatusNoContent).write(w, r)
}

func (server *Server) handleUserListResources(w http.ResponseWriter, r *http.Request) {
	username := mux.Vars(r)["username"]

	// check if user exists at all first
	user, err := userWithName(server.db, username)
	if user == nil || err != nil {
		msg := fmt.Sprintf("no user found with username: `%s`", username)
		errResponse := newErrorResponse(msg, 404, nil)
		errResponse.log.write(server.logger)
		_ = errResponse.write(w, r)
		return
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
	request := &AuthRequest{
		Username: username,
		Service:  service,
		Method:   method,
	}
	resourcesFromQuery, errResponse := authorizedResources(server.db, request)
	if errResponse != nil {
		_ = errResponse.write(w, r)
		return
	}
	useTags := false
	_, ok = r.URL.Query()["tags"]
	if ok {
		useTags = true
	}
	resources := make([]string, len(resourcesFromQuery))
	for i := range resourcesFromQuery {
		if useTags {
			resources[i] = resourcesFromQuery[i].Tag
		} else {
			resources[i] = resourcesFromQuery[i].standardize().Path
		}
	}
	result := struct {
		Resources []string `json:"resources"`
	}{
		Resources: resources,
	}
	_ = jsonResponseFrom(result, http.StatusOK).write(w, r)
}

func (server *Server) handleClientList(w http.ResponseWriter, r *http.Request) {
	clientsFromQuery, err := listClientsFromDb(server.db)
	if err != nil {
		msg := fmt.Sprintf("clients query failed: %s", err.Error())
		errResponse := newErrorResponse(msg, 500, nil)
		errResponse.log.write(server.logger)
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
	errResponse := client.createInDb(server.db, getAuthZProvider(r))
	if errResponse != nil {
		errResponse.log.write(server.logger)
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
		errResponse.log.write(server.logger)
		_ = errResponse.write(w, r)
		return
	}
	if err != nil {
		msg := fmt.Sprintf("client query failed: %s", err.Error())
		errResponse := newErrorResponse(msg, 500, nil)
		errResponse.log.write(server.logger)
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
		errResponse.log.write(server.logger)
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
	errResponse := grantClientPolicy(server.db, clientID, requestPolicy.PolicyName, getAuthZProvider(r))
	if errResponse != nil {
		errResponse.log.write(server.logger)
		_ = errResponse.write(w, r)
		return
	}
	_ = jsonResponseFrom(nil, http.StatusNoContent).write(w, r)
}

func (server *Server) handleClientRevokeAll(w http.ResponseWriter, r *http.Request) {
	clientID := mux.Vars(r)["clientID"]
	errResponse := revokeClientPolicyAll(server.db, clientID, getAuthZProvider(r))
	if errResponse != nil {
		errResponse.log.write(server.logger)
		_ = errResponse.write(w, r)
		return
	}
	_ = jsonResponseFrom(nil, http.StatusNoContent).write(w, r)
}

func (server *Server) handleClientRevokePolicy(w http.ResponseWriter, r *http.Request) {
	clientID := mux.Vars(r)["clientID"]
	policyName := mux.Vars(r)["policyName"]
	errResponse := revokeClientPolicy(server.db, clientID, policyName, getAuthZProvider(r))
	if errResponse != nil {
		errResponse.log.write(server.logger)
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
		errResponse.log.write(server.logger)
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
	authzProvider := getAuthZProvider(r)
	errResponse := transactify(server.db, func(tx *sqlx.Tx) *ErrorResponse {
		if r.Method == "PUT" {
			return group.overwriteInDb(tx, authzProvider)
		} else {
			return group.createInDb(tx, authzProvider)
		}
	})
	if errResponse != nil {
		errResponse.log.write(server.logger)
		_ = errResponse.write(w, r)
		return
	}
	if r.Method == "PUT" {
		server.logger.Info("overwrote group %s", group.Name)
	} else {
		server.logger.Info("created group %s", group.Name)
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
		errResponse.log.write(server.logger)
		_ = errResponse.write(w, r)
		return
	}
	if err != nil {
		msg := fmt.Sprintf("group query failed: %s", err.Error())
		errResponse := newErrorResponse(msg, 500, nil)
		errResponse.log.write(server.logger)
		_ = errResponse.write(w, r)
		return
	}
	group := groupFromQuery.standardize()
	_ = jsonResponseFrom(group, http.StatusOK).write(w, r)
}

func (server *Server) handleGroupDelete(w http.ResponseWriter, r *http.Request) {
	groupName := mux.Vars(r)["groupName"]
	group := Group{Name: groupName}
	errResponse := transactify(server.db, group.deleteInDb)
	if errResponse != nil {
		errResponse.log.write(server.logger)
		_ = errResponse.write(w, r)
		return
	}
	_ = jsonResponseFrom(nil, http.StatusNoContent).write(w, r)
}

func (server *Server) handleGroupAddUser(w http.ResponseWriter, r *http.Request, body []byte) {
	groupName := mux.Vars(r)["groupName"]
	requestUser := struct {
		Username  string `json:"username"`
		ExpiresAt string `json:"expires_at"`
	}{}
	err := json.Unmarshal(body, &requestUser)
	if err != nil {
		msg := fmt.Sprintf("could not parse username in JSON: %s", err.Error())
		server.logger.Info("tried to add user to group but input was invalid: %s", msg)
		response := newErrorResponse(msg, 400, nil)
		_ = response.write(w, r)
		return
	}
	var expiresAt *time.Time
	if requestUser.ExpiresAt != "" {
		exp, err := time.Parse(time.RFC3339, requestUser.ExpiresAt)
		if err != nil {
			msg := "could not parse `expires_at` (must be in RFC 3339 format; see specification: https://tools.ietf.org/html/rfc3339#section-5.8)"
			server.logger.Info("tried to grant policy to user but `expires_at` was invalid format")
			response := newErrorResponse(msg, 400, nil)
			_ = response.write(w, r)
			return
		}
		expiresAt = &exp
	}
	errResponse := addUserToGroup(server.db, requestUser.Username, groupName, expiresAt, getAuthZProvider(r))
	if errResponse != nil {
		errResponse.log.write(server.logger)
		_ = errResponse.write(w, r)
		return
	}
	server.logger.Info("added user %s to group %s", requestUser.Username, groupName)
	_ = jsonResponseFrom(nil, http.StatusNoContent).write(w, r)
}

func (server *Server) handleGroupRemoveUser(w http.ResponseWriter, r *http.Request) {
	groupName := mux.Vars(r)["groupName"]
	username := mux.Vars(r)["username"]
	errResponse := removeUserFromGroup(server.db, username, groupName, getAuthZProvider(r))
	if errResponse != nil {
		errResponse.log.write(server.logger)
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
	errResponse := grantGroupPolicy(server.db, groupName, requestPolicy.PolicyName, getAuthZProvider(r))
	if errResponse != nil {
		errResponse.log.write(server.logger)
		_ = errResponse.write(w, r)
		return
	}
	_ = jsonResponseFrom(nil, http.StatusNoContent).write(w, r)
}

func (server *Server) handleGroupRevokePolicy(w http.ResponseWriter, r *http.Request) {
	groupName := mux.Vars(r)["groupName"]
	policyName := mux.Vars(r)["policyName"]
	errResponse := revokeGroupPolicy(server.db, groupName, policyName, getAuthZProvider(r))
	if errResponse != nil {
		errResponse.log.write(server.logger)
		_ = errResponse.write(w, r)
		return
	}
	_ = jsonResponseFrom(nil, http.StatusNoContent).write(w, r)
}
