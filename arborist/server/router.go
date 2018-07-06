package server

import (
	"github.com/gorilla/mux"
)

func (server *Server) MakeRouter() *mux.Router {
	versionRouter := mux.NewRouter().StrictSlash(server.config.StrictSlashes)

	router := versionRouter.PathPrefix("/v0").Subrouter()
	router.Handle("/", handleRoot(server.config)).Methods("GET")
	router.HandleFunc("/health", handleHealthCheck).Methods("GET")

	server.addAuthRouter(router)
	server.addEngineRouter(router)
	server.addResourceRouter(router)
	server.addRoleRouter(router)
	server.addPolicyRouter(router)

	return router
}
