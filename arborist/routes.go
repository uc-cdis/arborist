package arborist

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/gorilla/mux"
)

// For the URL paths like `/role/<role>`, parse the role name from the URL and
// return the corresponding role from the auth engine.
func findRoleFromURL(engine *AuthEngine, r *http.Request) (*Role, error) {
	var role *Role

	// Get the role name from the URL.
	role_name, contains := mux.Vars(r)["role"]
	if !contains {
		err := errors.New("path missing role component")
		return role, err
	}

	return engine.findRoleNamed(role_name)
}

// Issue an authorization decision.
//
// For the `/auth` endpoint.
func handleAuth(engine *AuthEngine) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Try to read the request body.
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			msg := fmt.Sprintf("failed to read request body; encountered error: %s", err)
			http.Error(w, msg, http.StatusBadRequest)
			return
		}

		// Parse an `authRequest` from the request body.
		request, err := engine.parseRequest(body)
		if err != nil {
			msg := fmt.Sprintf("failed to parse auth request; encountered error: %s", err)
			http.Error(w, msg, http.StatusInternalServerError)
			return
		}

		// Have the auth engine check for authorization and issue a response;
		// put the response into JSON.
		response := engine.checkAuth(*request)
		response_json, err := json.Marshal(response)
		if err != nil {
			msg := fmt.Sprintf("failed to format response as JSON; encountered error: %s", err)
			http.Error(w, msg, http.StatusInternalServerError)
		}

		// Write out the response JSON and output 200.
		w.WriteHeader(http.StatusOK)
		w.Header().Set("content-type", "application/json")
		fmt.Fprintf(w, string(response_json))
	})
}

// Handle the health check route to indicate that the server is functioning.
// Just return a 200 code and no response.
func handleHealthCheck(w http.ResponseWriter, r *http.Request) {
	// Just return 200.
	w.WriteHeader(http.StatusOK)
}

// Handle `GET` `/role/<role>`: return the information for the requested role in
// JSON.
func handleRoleGet(engine *AuthEngine) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Find the matching role.
		role, err := findRoleFromURL(engine, r)
		if err != nil {
			msg := fmt.Sprintf("could not find role; encountered error: %s", err)
			http.Error(w, msg, http.StatusInternalServerError)
		}

		// Try to write the role out as JSON.
		role_json, err := json.Marshal(role)
		if err != nil {
			msg := fmt.Sprintf("failed to write role as JSON; encountered error: %s", err)
			http.Error(w, msg, http.StatusInternalServerError)
		}

		// Write out the role JSON and output 200.
		w.WriteHeader(http.StatusOK)
		w.Header().Set("content-type", "application/json")
		fmt.Fprintf(w, string(role_json))
	})
}

// Handle `POST` `/role/<role>`: create a new role in the engine.
func handleRoleCreate(engine *AuthEngine) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get the role name from the URL.
		role_name, contains := mux.Vars(r)["role"]
		if !contains {
			msg := "path missing role component"
			http.Error(w, msg, http.StatusBadRequest)
		}

		// Try to read the request body.
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			msg := fmt.Sprintf("failed to read request body; encountered error: %s", err)
			http.Error(w, msg, http.StatusBadRequest)
		}

		// Try to parse a role from the body.
		var role Role
		err = json.Unmarshal(body, role)
		if err != nil {
			msg := fmt.Sprintf("failed to parse role; encountered error: %s", err)
			http.Error(w, msg, http.StatusBadRequest)
		}

		if role_name != role.ID {
			msg := fmt.Sprintf("failed to create role; names don't match: `%s` and `%s`", role_name, role.ID)
			http.Error(w, msg, http.StatusBadRequest)
		}

		// Try to use the engine to insert the role.
		err = engine.insertRole(role)
		if err != nil {
			msg := fmt.Sprintf("failed to insert role: %s", err)
			http.Error(w, msg, http.StatusBadRequest)
		}

		// Role inserted successfully; no output necessary, so return 204.
		w.WriteHeader(http.StatusNoContent)
	})
}

func handleRoleUpdate(engine *AuthEngine) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Try to read the request body.
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			msg := fmt.Sprintf("failed to read request body; encountered error: %s", err)
			http.Error(w, msg, http.StatusBadRequest)
		}

		// Look up the role given in the path.
		role, err := findRoleFromURL(engine, r)
		if err != nil {
			msg := fmt.Sprintf("failed to find role; encountered error: %s", err)
			http.Error(w, msg, http.StatusBadRequest)
		}

		// Try to parse a role from the body.
		var input_role Role
		err = json.Unmarshal(body, input_role)
		if err != nil {
			msg := fmt.Sprintf("failed to parse role; encountered error: %s", err)
			http.Error(w, msg, http.StatusBadRequest)
		}

		engine.updateRole(role, input_role)

		w.WriteHeader(http.StatusNoContent)
	})
}

func handleRoleOverwrite(engine *AuthEngine) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Try to read the request body.
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			msg := fmt.Sprintf("failed to read request body; encountered error: %s", err)
			http.Error(w, msg, http.StatusBadRequest)
		}

		// Look up the role given in the path.
		role, err := findRoleFromURL(engine, r)
		if err != nil {
			msg := fmt.Sprintf("failed to find role; encountered error: %s", err)
			http.Error(w, msg, http.StatusBadRequest)
		}

		// Try to parse a role from the body.
		var input_role Role
		err = json.Unmarshal(body, input_role)
		if err != nil {
			msg := fmt.Sprintf("failed to parse role; encountered error: %s", err)
			http.Error(w, msg, http.StatusBadRequest)
		}

		engine.overwriteRole(role, input_role)

		w.WriteHeader(http.StatusNoContent)
	})
}
