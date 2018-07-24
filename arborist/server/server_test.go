package server

import (
	"testing"
)

func makeTestServer() *Server {
	// TODO
	return &Server{
		Engine: nil,
		JWTApp: nil,
		Config: nil,
		Logger: nil,
	}
}

func TestReadPoliciesFromJWT(t *testing.T) {
	// TODO
}
