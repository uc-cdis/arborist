package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/uc-cdis/arborist/arborist"
	"github.com/uc-cdis/go-authutils/authutils"
)

// tokenReader extracts the `context.user.policies` field from a token. This
// function is used for passing to `arborist.Engine.HandleAuthRequestBytes` so
// that arborist can get the policies out of a JWT.
func (server *Server) tokenReader(token string) ([]string, error) {
	missingRequiredField := func(field string) error {
		msg := fmt.Sprintf(
			"failed to decode token: missing required field `%s`",
			field,
		)
		server.Log.Error(msg)
		return errors.New(msg)
	}
	fieldTypeError := func(field string) error {
		msg := fmt.Sprintf(
			"failed to decode token: field `%s` has wrong type",
			field,
		)
		server.Log.Error(msg)
		return errors.New(msg)
	}

	server.Log.Info("decoding token: %s", token)
	claims, err := server.JWTApp.Decode(token)
	if err != nil {
		server.Log.Error("error decoding token: %s", err.Error())
		return nil, err
	}
	expected := &authutils.Expected{
		Audiences: []string{"openid"},
	}
	err = expected.Validate(claims)
	if err != nil {
		server.Log.Error("error decoding token: %s", err.Error())
		return nil, err
	}

	contextInterface, exists := (*claims)["context"]
	if !exists {
		return nil, missingRequiredField("context")
	}
	context, casted := contextInterface.(map[string]interface{})
	if !casted {
		return nil, fieldTypeError("context")
	}
	userInterface, exists := context["user"]
	if !exists {
		return nil, missingRequiredField("user")
	}
	user, casted := userInterface.(map[string]interface{})
	if !casted {
		return nil, fieldTypeError("user")
	}
	policiesInterface, exists := user["policies"]
	if !exists {
		return nil, missingRequiredField("policies")
	}
	// policiesInterface should really be a []string
	policiesInterfaceSlice, casted := policiesInterface.([]interface{})
	if !casted {
		return nil, fieldTypeError("policies")
	}
	policies := make([]string, len(policiesInterfaceSlice))
	for i, policyInterface := range policiesInterfaceSlice {
		policyString, casted := policyInterface.(string)
		if !casted {
			return nil, fieldTypeError("policies")
		}
		policies[i] = policyString
	}
	return policies, nil
}

// handleAuth handles `POST` `/auth`.
//
// Issue an authorization decision.
func (server *Server) handleAuthRequest(engine *arborist.Engine) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Try to read the request body.
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			msg := fmt.Sprintf("failed to read request body; encountered error: %s", err)
			http.Error(w, msg, http.StatusBadRequest)
			return
		}
		response := engine.HandleAuthRequestBytes(body, server.tokenReader)
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

		// FIXME (rudyardrichter, 2018-07-24): consolidate this with the
		// HandleAuthRequest stuff; this should not be doing a separate way of
		// handling token decoding
		requestFields := struct {
			User struct {
				Token string `json:"token"`
			} `json:"user"`
			Request struct {
				Action struct {
					Service string `json:"service"`
					Method  string `json:"method"`
				} `json:"action"`
			} `json:"request"`
		}{}
		err = json.Unmarshal(body, &requestFields)
		if err != nil {
			msg := "incorrect format in request body"
			newErrorJSON(msg, http.StatusBadRequest).write(w, wantPrettyJSON(r))
			return
		}
		encodedToken := requestFields.User.Token
		policies, err := server.tokenReader(encodedToken)
		if err != nil {
			newErrorJSON(err.Error(), http.StatusUnauthorized).
				write(w, wantPrettyJSON(r))
			return
		}
		response := server.Engine.HandleListAuthorizedResources(policies)
		err = response.Write(w, wantPrettyJSON(r))
		if err != nil {
			newErrorJSON(err.Error(), http.StatusBadRequest).
				write(w, wantPrettyJSON(r))
			return
		}
	})
}

func (server *Server) addAuthRouter(mainRouter *mux.Router) {
	authRouter := mainRouter.PathPrefix("/auth").Subrouter()
	authRouter.Handle("/request", server.handleAuthRequest(server.Engine)).Methods("POST")
	authRouter.Handle("/resources", server.handleListResourceAuth()).Methods("POST")
}
