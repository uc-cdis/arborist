package server

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/uc-cdis/arborist/arborist"
)

func handleListPolicies(engine *arborist.Engine) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bytes, err := engine.HandleListPolicyIDsBytes()
		if err != nil {
			msg := fmt.Sprintf("%s", err)
			http.Error(w, msg, http.StatusInternalServerError)
			return
		}
		writeJSON(w, bytes)
	})
}

func handlePolicyCreate(engine *arborist.Engine) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// TODO
	})
}

func addPolicyRouter(mainRouter mux.Router, engine *arborist.Engine) {
	policyRouter := mainRouter.PathPrefix("/policy").Subrouter()
	policyRouter.Handle("/", handleListPolicies(engine)).Methods("GET")
}
