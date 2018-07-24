// This file defines addPolicyRouter for adding a router for the set of
// endpoints under `/policy` to a main router. This router handles list,
// create, read, update, and delete operations on the policies in the arborist
// engine.

package server

import (
	"io/ioutil"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/uc-cdis/arborist/arborist"
)

func handleListPolicies(engine *arborist.Engine) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := engine.HandleListPolicyIDs().Write(w, wantPrettyJSON(r))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})
}

func handlePolicyCreate(engine *arborist.Engine) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			writeJSONReadError(w, err)
			return
		}

		var response *arborist.Response
		if r.URL.Query().Get("bulk") == "true" {
			response = engine.HandlePolicyCreateBulk(body)
		} else {
			response = engine.HandlePolicyCreate(body)
		}

		err = response.Write(w, wantPrettyJSON(r))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})
}

func handlePolicyGet(engine *arborist.Engine) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		policyID := mux.Vars(r)["policyID"]
		err := engine.HandlePolicyRead(policyID).Write(w, wantPrettyJSON(r))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})
}

func handlePolicyUpdate(engine *arborist.Engine) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			writeJSONReadError(w, err)
			return
		}
		policyID := mux.Vars(r)["policyID"]
		err = engine.HandlePolicyUpdate(policyID, body).Write(w, wantPrettyJSON(r))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})
}

func handlePolicyPatch(engine *arborist.Engine) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			writeJSONReadError(w, err)
			return
		}
		policyID := mux.Vars(r)["policyID"]
		err = engine.HandlePolicyPatch(policyID, body).Write(w, wantPrettyJSON(r))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})
}

func handlePolicyRemove(engine *arborist.Engine) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		policyID := mux.Vars(r)["policyID"]
		err := engine.HandlePolicyRemove(policyID).Write(w, wantPrettyJSON(r))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})
}

// addPolicyRouter attaches the handlers defined in this file to a main router,
// using the prefix `/policy`.
func (server *Server) addPolicyRouter(mainRouter *mux.Router) {
	policyRouter := mainRouter.PathPrefix("/policy").Subrouter()
	policyRouter.Handle("/", handleListPolicies(server.Engine)).Methods("GET")
	policyRouter.Handle("/", handlePolicyCreate(server.Engine)).Methods("POST")
	policyRouter.Handle("/{policyID}", handlePolicyGet(server.Engine)).Methods("GET")
	policyRouter.Handle("/{policyID}", handlePolicyPatch(server.Engine)).Methods("PATCH")
	policyRouter.Handle("/{policyID}", handlePolicyUpdate(server.Engine)).Methods("PUT")
	policyRouter.Handle("/{policyID}", handlePolicyRemove(server.Engine)).Methods("DELETE")
}
