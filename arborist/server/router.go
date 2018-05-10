package server

import (
	"fmt"

	"github.com/gorilla/mux"

	"github.com/uc-cdis/arborist/arborist"
)

type EndpointInformation struct {
	HealthCheckURL string `json:"health_check_url"`
	AuthURL        string `json:"auth_url"`
	RoleBaseURL    string `json:"role_base_url"`
}

func (endpointInfo EndpointInformation) fullURLs(baseURL string) EndpointInformation {
	return EndpointInformation{
		HealthCheckURL: fmt.Sprintf("%s%s", baseURL, endpointInfo.HealthCheckURL),
		AuthURL:        fmt.Sprintf("%s%s", baseURL, endpointInfo.AuthURL),
		RoleBaseURL:    fmt.Sprintf("%s%s", baseURL, endpointInfo.RoleBaseURL),
	}
}

// Record the endpoints mapping so that the server can return some information
// about what endpoints are located at what URLs.
var Endpoints EndpointInformation = EndpointInformation{
	HealthCheckURL: "/health",
	AuthURL:        "/auth",
	RoleBaseURL:    "/role/",
}

// Create a router to serve endpoints for role CRUD and auth decisions.
func MakeRouter(engine *arborist.AuthEngine, config *ServerConfig) mux.Router {
	router := mux.NewRouter().StrictSlash(config.StrictSlashes)

	router.Handle("/", handleRoot(config)).Methods("GET")

	// Authentication checking.
	router.Handle("/auth", handleAuth(engine)).Methods("POST")

	// Healtcheck endpoint.
	router.HandleFunc("/health", handleHealthCheck)

	// Endpoints for roles.
	roles := router.PathPrefix("/role").Subrouter()
	roles.Handle("/", handleListRoles(engine)).Methods("GET")
	roles.Handle("/", handleRoleCreate(engine)).Methods("POST")
	// Methods on a specific role.
	role := roles.PathPrefix("/{role}").Subrouter()
	role.Handle("", handleRoleGet(engine)).Methods("GET")
	role.Handle("", handleRoleUpdate(engine)).Methods("PATCH")
	role.Handle("", handleRoleDelete(engine)).Methods("DELETE")
	role.Handle("", handleRoleOverwrite(engine)).Methods("PUT")

	// Endpoints for services.
	services := router.PathPrefix("/service").Subrouter()
	services.Handle("/", handleListServices(engine)).Methods("GET")
	services.Handle("/", handleServiceCreate(engine)).Methods("POST")

	// Endpoints for resources.
	resources := router.PathPrefix("/resource").Subrouter()
	resources.Handle("/", handleListResources(engine)).Methods("GET")
	resources.Handle("/", handleCreateResource(engine)).Methods("POST")

	return *router
}
