package arborist

import (
	"github.com/gorilla/mux"
)

// Create a router to serve endpoints for role CRUD and auth decisions.
func MakeRouter(engine *AuthEngine, strict_slashes bool) mux.Router {
	router := mux.NewRouter().StrictSlash(strict_slashes)

	// Authentication checking.
	router.Handle("/auth", handleAuth(engine)).Methods("POST")

	// Healtcheck endpoint.
	router.HandleFunc("/health", handleHealthCheck)

	// Role CRUD endpoints.
	role := router.PathPrefix("/role/{role_id}").Subrouter()
	role.Handle("", handleRoleGet(engine)).Methods("GET")
	role.Handle("", handleRoleCreate(engine)).Methods("POST")
	role.Handle("", handleRoleUpdate(engine)).Methods("PATCH")
	role.Handle("", handleRoleOverwrite(engine)).Methods("PUT")

	return *router
}
