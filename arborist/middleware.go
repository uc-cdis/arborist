package arborist

import (
	"net/http"
	"os"

	"github.com/gorilla/handlers"
)

// Add logging middleware onto the HTTP handler to output logs in the standard
// Apache format.
func loggingMiddleware(next http.Handler) http.Handler {
	return handlers.CombinedLoggingHandler(os.Stdout, next)
}

// Add all necessary middleware on top of the HTTP handler.
func ApplyMiddleware(next http.Handler) http.Handler {
	return loggingMiddleware(next)
}
