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
		err := response.Write(w, wantPrettyJSON(r))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
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

		var response *arborist.Response
		if r.URL.Query().Get("bulk") == "true" {
			response = engine.HandleRolesCreate(body)
		} else {
			response = engine.HandleRoleCreate(body)
		}

		err = response.Write(w, wantPrettyJSON(r))
		if err != nil {
			http.Error(w, fmt.Sprintf("%s", err), http.StatusInternalServerError)
			return
		}
	})
}

func handleRoleGet(engine *arborist.Engine) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		roleID := mux.Vars(r)["roleID"]
		err := engine.HandleRoleRead(roleID).Write(w, wantPrettyJSON(r))
		if err != nil {
			http.Error(w, fmt.Sprintf("%s", err), http.StatusInternalServerError)
			return
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
		err = engine.HandleRoleUpdate(roleID, body).Write(w, wantPrettyJSON(r))
		if err != nil {
			http.Error(w, fmt.Sprintf("%s", err), http.StatusInternalServerError)
			return
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
		err = engine.HandleRolePatch(roleID, body).Write(w, wantPrettyJSON(r))
		if err != nil {
			http.Error(w, fmt.Sprintf("%s", err), http.StatusInternalServerError)
			return
		}
	})
}

func handleRoleRemove(engine *arborist.Engine) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		roleID := mux.Vars(r)["roleID"]
		err := engine.HandleRoleRemove(roleID).Write(w, wantPrettyJSON(r))
		if err != nil {
			http.Error(w, fmt.Sprintf("%s", err), http.StatusInternalServerError)
			return
		}
	})
}

// addRoleRouter attaches the handlers defined in this file to a main router,
// using the prefix `/role`.
func (server *Server) addRoleRouter(mainRouter *mux.Router) {
	roleRouter := mainRouter.PathPrefix("/role").Subrouter()
	roleRouter.Handle("/", handleListRoles(server.engine)).Methods("GET")
	roleRouter.Handle("/", handleRoleCreate(server.engine)).Methods("POST")

	roleOperations := roleRouter.PathPrefix("/{roleID}").Subrouter()
	roleOperations.Handle("", handleRoleGet(server.engine)).Methods("GET")
	roleOperations.Handle("", handleRolePatch(server.engine)).Methods("PATCH")
	roleOperations.Handle("", handleRoleUpdate(server.engine)).Methods("PUT")
	roleOperations.Handle("", handleRoleRemove(server.engine)).Methods("DELETE")
}
