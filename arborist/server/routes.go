// server/routes.go contains miscellaneous utilities and routes which go
// immediately under the root and not under a different subrouter.

package server

import (
	"encoding/json"
	"net/http"
)

// writeJSON outputs some bytes encoding a JSON payload to the given
// ResponseWriter, settings the content type to `application/json` and
// returning a 200 code.
func writeJSON(w http.ResponseWriter, bytes []byte) {
	w.Header().Set("Content-Type", "application/json")
	_, err := w.Write(bytes)
	if err != nil {
		w.Header().Del("Content-Type")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func wantPrettyJSON(r *http.Request) bool {
	// url.Values.Get returns empty string if the parameter doesn't exist
	return r.URL.Query().Get("prettyJSON") == "true"
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
