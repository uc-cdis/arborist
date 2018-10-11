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

func handleSyncModel(engine *arborist.Engine) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			writeJSONReadError(w, err)
			return
		}

		response := engine.HandleSyncModelFromS3(body)

		err = response.Write(w, wantPrettyJSON(r))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})
}

func handlePostModelToS3(engine *arborist.Engine) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			writeJSONReadError(w, err)
			return
		}

		response := engine.HandlePostModelToS3(body)

		err = response.Write(w, wantPrettyJSON(r))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

	})
}

// syncModelRouter attaches the handlers defined in this file to a main router,
// using the prefix `/model`.
func (server *Server) syncModelRouter(mainRouter *mux.Router) {
	modelRouter := mainRouter.PathPrefix("/model").Subrouter()
	modelRouter.Handle("/", handleSyncModel(server.Engine)).Methods("PUT")
	modelRouter.Handle("/", handlePostModelToS3(server.Engine)).Methods("POST")
}
