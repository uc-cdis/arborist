package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/uc-cdis/arborist/arborist"
)

// Return information about the available endpoints.
//
// For the root endpoint.
func handleRoot(config *ServerConfig) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		endpoints := config.EndpointInfo.fullURLs(config.BaseURL)
		response_json, err := json.MarshalIndent(endpoints, "", "    ")
		if err != nil {
			msg := "failed to marshal endpoint information"
			http.Error(w, msg, http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(response_json)
		w.WriteHeader(http.StatusOK)
	})
}

// handleAuth handles `POST` `/auth`.
//
// Issue an authorization decision.
func handleAuth(engine *arborist.AuthEngine) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Try to read the request body.
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			msg := fmt.Sprintf("failed to read request body; encountered error: %s", err)
			http.Error(w, msg, http.StatusBadRequest)
			return
		}

		// Parse an `authRequest` from the request body.
		request, err := engine.ParseRequest(body)
		if err != nil {
			msg := fmt.Sprintf("failed to parse auth request; encountered error: %s", err)
			http.Error(w, msg, http.StatusInternalServerError)
			return
		}

		// Have the auth engine check for authorization and issue a response;
		// put the response into JSON.
		response := engine.CheckAuth(*request)
		response_json, err := json.Marshal(response)
		if err != nil {
			msg := fmt.Sprintf("failed to format response as JSON; encountered error: %s", err)
			http.Error(w, msg, http.StatusInternalServerError)
		}

		// Write out the response JSON and output 200.
		w.Header().Set("Content-Type", "application/json")
		w.Write(response_json)
		w.WriteHeader(http.StatusOK)
	})
}

// handleHealthCheck handles the health check route to indicate that the
// server is functioning.  Just return a 200 code and no response.
func handleHealthCheck(w http.ResponseWriter, r *http.Request) {
	// Just return 200.
	w.WriteHeader(http.StatusOK)
}

// handleListRoles handles `GET` `/role/`.
//
// Return just a list of role names (and not any other information from the
// roles). This way, the return value from this endpoint describes what are
// valid values to use for `role` in the `/role/{role}` path.
func handleListRoles(engine *arborist.AuthEngine) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		roles := struct {
			Roles []string `json:"roles"`
		}{
			Roles: engine.ListRoleNames(),
		}
		bytes, err := json.MarshalIndent(roles, "", "    ")
		if err != nil {
			msg := fmt.Sprintf("could not marshal roles into json: %s", err)
			http.Error(w, msg, http.StatusInternalServerError)
			return
		}

		// Write out the role names.
		w.Header().Set("Content-Type", "application/json")
		w.Write(bytes)
	})
}

// handleRoleCreate handles `POST` `/role/`.
//
// Create a new role in the engine.
func handleRoleCreate(engine *arborist.AuthEngine) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Try to read the request body.
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			msg := fmt.Sprintf("failed to read request body; encountered error: %s", err)
			http.Error(w, msg, http.StatusBadRequest)
			return
		}

		operation := engine.CreateRole(body)
		operation.HandleResponseWriter(w)
	})
}

// getRoleFromPath extracts the role ID from a path like `/role/{role}`.
func getRoleFromPath(r *http.Request) (string, error) {
	roleID, contains := mux.Vars(r)["role"]
	if !contains {
		err := errors.New("path missing role component")
		return "", err
	}
	return roleID, nil
}

// handleRoleGet handles `GET` `/role/{role}`.
//
// Return the information for the requested role in JSON.
func handleRoleGet(engine *arborist.AuthEngine) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Find the matching role.
		roleID, err := getRoleFromPath(r)
		if err != nil {
			msg := fmt.Sprintf("could not find role; encountered error: %s", err)
			http.Error(w, msg, http.StatusInternalServerError)
			return
		}
		operation := engine.WriteRole(roleID)
		operation.HandleResponseWriter(w)
	})
}

// handleRoleUpdate handles `PATCH` `/role/{role}`.
//
// Update role in the engine and append some new content to it.
func handleRoleUpdate(engine *arborist.AuthEngine) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Try to read the request body.
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			msg := fmt.Sprintf("failed to read request body; encountered error: %s", err)
			http.Error(w, msg, http.StatusBadRequest)
		}

		roleID, err := getRoleFromPath(r)
		if err != nil {
			msg := fmt.Sprintf("could not find role; encountered error: %s", err)
			http.Error(w, msg, http.StatusInternalServerError)
			return
		}

		operation := engine.UpdateRole(roleID, body)
		operation.HandleResponseWriter(w)
	})
}

// handleRoleOverwrite handles `PUT` `/role/{role}`.
//
// Overwrite a role in the engine with the new role specified in JSON body.
//
// NOTE: this will drop unused subroles out of the tree entirely. Use with
// caution.
func handleRoleOverwrite(engine *arborist.AuthEngine) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Try to read the request body.
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			msg := fmt.Sprintf("failed to read request body; encountered error: %s", err)
			http.Error(w, msg, http.StatusBadRequest)
		}

		roleID, err := getRoleFromPath(r)
		if err != nil {
			msg := fmt.Sprintf("could not find role; encountered error: %s", err)
			http.Error(w, msg, http.StatusInternalServerError)
			return
		}

		operation := engine.OverwriteRoleWithJSON(roleID, body)
		operation.HandleResponseWriter(w)
	})
}

// Handle `DELETE` `/role/{role}`.
//
// Completely remove a role in the engine.
//
// NOTE: this will drop unused subroles out of the tree entirely. Use with
// caution.
func handleRoleDelete(engine *arborist.AuthEngine) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		roleID, err := getRoleFromPath(r)
		if err != nil {
			msg := fmt.Sprintf("could not find role; encountered error: %s", err)
			http.Error(w, msg, http.StatusInternalServerError)
			return
		}

		engine.DropRole(roleID)
	})
}

// handleListServices handles `GET` `/service/`.
//
// List the services that have been registered in the engine.
func handleListServices(engine *arborist.AuthEngine) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		services := struct {
			Services []string `json:"services"`
		}{
			Services: engine.ListServiceNames(),
		}
		bytes, err := json.MarshalIndent(services, "", "    ")
		if err != nil {
			msg := fmt.Sprintf("could not marshal services into json: %s", err)
			http.Error(w, msg, http.StatusInternalServerError)
			return
		}

		// Write out the service names.
		w.Header().Set("Content-Type", "application/json")
		w.Write(bytes)
	})
}

// handleServiceCreate handles `POST` `/service/`.
//
// Register a new service.
func handleServiceCreate(engine *arborist.AuthEngine) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get the service name from the URL.
		service_name, contains := mux.Vars(r)["service"]
		if !contains {
			msg := "path missing service component"
			http.Error(w, msg, http.StatusBadRequest)
			return
		}

		// Make sure service doesn't exist already.
		if engine.FindServiceNamed(service_name) != nil {
			response_json, err := json.Marshal(struct {
				Error string `json:"error"`
			}{
				Error: fmt.Sprintf("service already exists with name: %s", service_name),
			})
			if err != nil {
				msg := fmt.Sprintf("failed to write JSON: %s", err)
				http.Error(w, msg, http.StatusInternalServerError)
				return
			}
			w.Write(response_json)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
		}

		// TODO
	})
}

// handleListResources handles `GET` `/resource/`.
//
// List the resources that exist in the engine.
func handleListResources(engine *arborist.AuthEngine) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		operation := engine.ListResources()
		w.Header().Set("Content-Type", "application/json")
		w.Write(operation.JSON)
		w.WriteHeader(operation.Status)
	})
}

// handleCreateResource handles `POST` `/resource/`.
//
// Create a new resource.
func handleCreateResource(engine *arborist.AuthEngine) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// TODO
	})
}

//func handler(engine *arborist.AuthEngine) http.Handler {
//	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//	})
//}
