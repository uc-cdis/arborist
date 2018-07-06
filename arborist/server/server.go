package server

import (
	"fmt"
	"log"

	"github.com/uc-cdis/arborist/arborist"
	"github.com/uc-cdis/go-authutils/authutils"
)

type Server struct {
	engine *arborist.Engine
	jwtApp *authutils.JWTApplication
	config *ServerConfig
	logger *log.Logger
}

func typeError(field string, expectedType string) error {
	return fmt.Errorf(
		"token field %s has unexpected type; expected %s",
		field,
		expectedType,
	)
}

func (server *Server) readPoliciesFromJWT(token string) ([]string, error) {
	if server.jwtApp == nil {
		// should never happen; server initialization code is incorrect
		panic("jwtApp not initialized")
	}

	claims, err := server.jwtApp.Decode(token)
	if err != nil {
		return nil, err
	}
	context, casted := (*claims)["context"].(map[string]interface{})
	if !casted {
		return nil, typeError("context", "map")
	}
	contextUser, casted := context["user"].(map[string]interface{})
	if !casted {
		return nil, typeError("user", "map")
	}
	policies, casted := contextUser["policies"].([]string)
	if !casted {
		return nil, typeError("policies", "list of strings")
	}
	return policies, nil
}

type ServerConfig struct {
	StrictSlashes bool
	BaseURL       string
	EndpointInfo  EndpointInformation
}

type EndpointInformation struct {
	HealthCheckURL  string `json:"health_check_url"`
	AuthURL         string `json:"auth_url"`
	PolicyBaseURL   string `json:"policy_base_url"`
	RoleBaseURL     string `json:"role_base_url"`
	ResourceBaseURL string `json:"resource_base_url"`
	EngineURL       string `json:"engine_url"`
}

// fullURLs returns a copy of the endpoint information with the base URL
// included, suitable for returning functional links to actual API endpoints.
func (endpointInfo EndpointInformation) fullURLs(baseURL string) EndpointInformation {
	return EndpointInformation{
		HealthCheckURL: fmt.Sprintf("%s%s", baseURL, endpointInfo.HealthCheckURL),
		AuthURL:        fmt.Sprintf("%s%s", baseURL, endpointInfo.AuthURL),
		PolicyBaseURL:  fmt.Sprintf("%s%s", baseURL, endpointInfo.PolicyBaseURL),
		EngineURL:      fmt.Sprintf("%s%s", baseURL, endpointInfo.EngineURL),
	}
}

// Record the endpoints mapping so that the server can return some information
// about what endpoints are located at what URLs.
//
// This really should be a `const`.
var Endpoints EndpointInformation = EndpointInformation{
	HealthCheckURL: "/health",
	AuthURL:        "/auth",
	PolicyBaseURL:  "/policy/",
	EngineURL:      "/engine",
}
