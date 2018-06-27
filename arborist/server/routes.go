package server

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/uc-cdis/arborist/arborist"
)

// writeJSON outputs some bytes encoding a JSON payload to the given
// ResponseWriter, settings the content type to `application/json` and
// returning a 200 code.
func writeJSON(w http.ResponseWriter, bytes []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.Write(bytes)
	w.WriteHeader(http.StatusOK)
}

// handleHealthCheck handles the health check route to indicate that the
// server is functioning. Just return a 200 code and no response.
func handleHealthCheck(w http.ResponseWriter, r *http.Request) {
	// Just return 200.
	w.WriteHeader(http.StatusOK)
}

// handleRoot returns information about the available endpoints.
//
// For the root endpoint `/`.
func handleRoot(config *ServerConfig) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		endpoints := config.EndpointInfo.fullURLs(config.BaseURL)
		responseJSON, err := json.MarshalIndent(endpoints, "", "    ")
		if err != nil {
			msg := "failed to marshal endpoint information"
			http.Error(w, msg, http.StatusInternalServerError)
			return
		}

		writeJSON(w, responseJSON)
	})
}

// handleAuth handles `POST` `/auth`.
//
// Issue an authorization decision.
func handleAuth(engine *arborist.Engine) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Try to read the request body.
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			msg := fmt.Sprintf("failed to read request body; encountered error: %s", err)
			http.Error(w, msg, http.StatusBadRequest)
			return
		}
		response := engine.HandleAuthRequestBytes(body)
		err = response.Write(w)
		if err != nil {
			http.Error(w, fmt.Sprintf("%s", err), http.StatusInternalServerError)
			return
		}
	})
}
