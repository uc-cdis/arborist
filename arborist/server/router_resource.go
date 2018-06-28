// This file defines addResourceRouter for adding a router for the set of
// endpoints under `/resource` to a main router. This router handles list,
// create, read, update, and delete operations on the policies in the arborist
// engine.

package server

import (
	"io/ioutil"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/uc-cdis/arborist/arborist"
)

func handleListResources(engine *arborist.Engine) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := engine.HandleListResourcePaths()
		err := response.Write(w, wantPrettyJSON(r))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})
}

func handleResourceCreate(engine *arborist.Engine) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			writeJSONReadError(w, err)
			return
		}
		response := engine.HandleResourceCreate(body)
		err = response.Write(w, wantPrettyJSON(r))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})
}

func handleResourceGet(engine *arborist.Engine) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resourcePath := mux.Vars(r)["resourcePath"]
		response := engine.HandleResourceRead(resourcePath)
		err := response.Write(w, wantPrettyJSON(r))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})
}

func handleResourceUpdate(engine *arborist.Engine) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			writeJSONReadError(w, err)
			return
		}
		resourcePath := mux.Vars(r)["resourcePath"]
		response := engine.HandleResourceUpdate(resourcePath, body)
		err = response.Write(w, wantPrettyJSON(r))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})
}

func handleResourceRemove(engine *arborist.Engine) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resourcePath := mux.Vars(r)["resourcePath"]
		response := engine.HandleResourceRemove(resourcePath)
		err := response.Write(w, wantPrettyJSON(r))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})
}

// addResourceRouter attaches the handlers defined in this file to a main
// router, using the prefix `/resource`.
func addResourceRouter(mainRouter *mux.Router, engine *arborist.Engine) {
	resourceRouter := mainRouter.PathPrefix("/resource").Subrouter()
	resourceRouter.Handle("/", handleListResources(engine)).Methods("GET")
	resourceRouter.Handle("/", handleResourceCreate(engine)).Methods("POST")
	resourceRouter.Handle("/{resourcePath}", handleResourceGet(engine)).Methods("GET")
	resourceRouter.Handle("/{resourcePath}", handleResourceUpdate(engine)).Methods("PUT")
	resourceRouter.Handle("/{resourcePath}", handleResourceRemove(engine)).Methods("DELETE")
}
