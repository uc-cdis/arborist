package server

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/uc-cdis/arborist/arborist"
)

// handleAuth handles `POST` `/auth`.
//
// Issue an authorization decision.
func handleAuthRequest(engine *arborist.Engine) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Try to read the request body.
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			msg := fmt.Sprintf("failed to read request body; encountered error: %s", err)
			http.Error(w, msg, http.StatusBadRequest)
			return
		}
		response := engine.HandleAuthRequestBytes(body)
		err = response.Write(w, wantPrettyJSON(r))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})
}

func (server *Server) handleListResourceAuth() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Try to read the request body.
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			msg := fmt.Sprintf("failed to read request body; encountered error: %s", err)
			http.Error(w, msg, http.StatusBadRequest)
			return
		}

		requestFields := struct {
			request struct {
				token string `json:"token"`
			} `json:"request"`
		}{}
		err = json.Unmarshal(body, &requestFields)
		if err != nil {
			msg := "incorrect format in request body"
			http.Error(w, msg, http.StatusBadRequest)
		}
		encodedToken := requestFields.request.token
		policies, err := server.readPoliciesFromJWT(encodedToken)
		response := server.engine.HandleListAuthorizedResources(policies)
		err = response.Write(w, wantPrettyJSON(r))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})
}

func (server *Server) addAuthRouter(mainRouter *mux.Router) {
	authRouter := mainRouter.PathPrefix("/auth").Subrouter()
	authRouter.Handle("/request", handleAuthRequest(server.engine)).Methods("POST")
	authRouter.Handle("/resources", server.handleListResourceAuth()).Methods("POST")
}
