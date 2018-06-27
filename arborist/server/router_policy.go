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
		engine.HandleListPolicyIDs().Write(w)
	})
}

func handlePolicyCreate(engine *arborist.Engine) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			writeJSONReadError(w, err)
			return
		}
		engine.HandleCreatePolicyBytes(body).Write(w)
	})
}

func handlePolicyGet(engine *arborist.Engine) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		policyID := mux.Vars(r)["policyID"]
		engine.HandlePolicyRead(policyID).Write(w)
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
		engine.HandlePolicyUpdate(policyID, body).Write(w)
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
		engine.HandlePolicyPatch(policyID, body).Write(w)
	})
}

func handlePolicyRemove(engine *arborist.Engine) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		policyID := mux.Vars(r)["policyID"]
		engine.HandlePolicyRemove(policyID).Write(w)
	})
}

// addPolicyRouter attaches the handlers defined in this file to a main router,
// using the prefix `/policy`.
func addPolicyRouter(mainRouter *mux.Router, engine *arborist.Engine) {
	policyRouter := mainRouter.PathPrefix("/policy").Subrouter()
	policyRouter.Handle("/", handleListPolicies(engine)).Methods("GET")
	policyRouter.Handle("/", handlePolicyCreate(engine)).Methods("POST")
	policyRouter.Handle("/{policyID}", handlePolicyGet(engine)).Methods("GET")
	policyRouter.Handle("/{policyID}", handlePolicyPatch(engine)).Methods("PATCH")
	policyRouter.Handle("/{policyID}", handlePolicyUpdate(engine)).Methods("PUT")
	policyRouter.Handle("/{policyID}", handlePolicyRemove(engine)).Methods("DELETE")
}
