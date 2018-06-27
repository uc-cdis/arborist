// This file defines addRoleRouter for adding a router for the set of
// endpoints under `/role` to a main router. This router handles list,
// create, read, update, and delete operations on the policies in the arborist
// engine.

package server

import (
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/uc-cdis/arborist/arborist"
)

func handleListRoles(engine *arborist.Engine) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := engine.HandleListRoleIDs()
		if pretty := r.URL.Query().Get("prettyJSON"); pretty == "true" {
			response.Prettify()
		}
		err := response.Write(w)
		if err != nil {
			http.Error(w, fmt.Sprintf("%s", err), http.StatusInternalServerError)
		}
	})
}

func handleRoleCreate(engine *arborist.Engine) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			writeJSONReadError(w, err)
			return
		}
		response := engine.HandleRoleCreate(body)
		if pretty := r.URL.Query().Get("prettyJSON"); pretty == "true" {
			response.Prettify()
		}
		err = response.Write(w)
		if err != nil {
			http.Error(w, fmt.Sprintf("%s", err), http.StatusInternalServerError)
		}
	})
}

func handleRoleGet(engine *arborist.Engine) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		roleID := mux.Vars(r)["roleID"]
		err := engine.HandleRoleRead(roleID).Write(w)
		if err != nil {
			http.Error(w, fmt.Sprintf("%s", err), http.StatusInternalServerError)
		}
	})
}

func handleRoleUpdate(engine *arborist.Engine) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			writeJSONReadError(w, err)
			return
		}
		roleID := mux.Vars(r)["roleID"]
		err = engine.HandleRoleUpdate(roleID, body).Write(w)
		if err != nil {
			http.Error(w, fmt.Sprintf("%s", err), http.StatusInternalServerError)
		}
	})
}

func handleRolePatch(engine *arborist.Engine) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			writeJSONReadError(w, err)
			return
		}
		roleID := mux.Vars(r)["roleID"]
		err = engine.HandleRolePatch(roleID, body).Write(w)
		if err != nil {
			http.Error(w, fmt.Sprintf("%s", err), http.StatusInternalServerError)
		}
	})
}

func handleRoleRemove(engine *arborist.Engine) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		roleID := mux.Vars(r)["roleID"]
		err := engine.HandleRoleRemove(roleID).Write(w)
		if err != nil {
			http.Error(w, fmt.Sprintf("%s", err), http.StatusInternalServerError)
		}
	})
}

// addRoleRouter attaches the handlers defined in this file to a main router,
// using the prefix `/role`.
func addRoleRouter(mainRouter *mux.Router, engine *arborist.Engine) {
	roleRouter := mainRouter.PathPrefix("/role").Subrouter()
	roleRouter.Handle("/", handleListRoles(engine)).Methods("GET")
	roleRouter.Handle("/", handleRoleCreate(engine)).Methods("POST")

	roleOperations := roleRouter.PathPrefix("/{roleID}").Subrouter()
	roleOperations.Handle("", handleRoleGet(engine)).Methods("GET")
	roleOperations.Handle("", handleRolePatch(engine)).Methods("PATCH")
	roleOperations.Handle("", handleRoleUpdate(engine)).Methods("PUT")
	roleOperations.Handle("", handleRoleRemove(engine)).Methods("DELETE")
}
