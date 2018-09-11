package server

import (
	"os"
	"testing"
)

func makeTestServer() *Server {
	// TODO
	return &Server{
		Engine: nil,
		JWTApp: nil,
		Config: nil,
		Log:    NewLogHandler(os.Stdout, 0),
	}
}

func TestReadPoliciesFromJWT(t *testing.T) {
	// TODO
}
