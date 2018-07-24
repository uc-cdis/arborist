package server

import (
	"fmt"
	"log"

	"github.com/uc-cdis/arborist/arborist"
	"github.com/uc-cdis/go-authutils/authutils"
)

type Server struct {
	Engine *arborist.Engine
	JWTApp *authutils.JWTApplication
	Config *ServerConfig
	Logger *log.Logger
}

func typeError(field string, expectedType string) error {
	return fmt.Errorf(
		"token field %s has unexpected type; expected %s",
		field,
		expectedType,
	)
}

type ServerConfig struct {
	StrictSlashes bool   `toml:"strict_slashes"`
	BaseURL       string `toml:"base_url"`
}

type EndpointInformation struct {
	AuthURL         string `json:"auth_url"`
	EngineURL       string `json:"engine_url"`
	HealthCheckURL  string `json:"health_check_url"`
	PolicyBaseURL   string `json:"policy_base_url"`
	ResourceBaseURL string `json:"resource_base_url"`
	RoleBaseURL     string `json:"role_base_url"`
}

// fullURLs returns a copy of the endpoint information with the base URL
// included, suitable for returning functional links to actual API endpoints.
func fullURLs(baseURL string) EndpointInformation {
	return EndpointInformation{
		AuthURL:         fmt.Sprintf("%s%s", baseURL, ENDPOINTS.AuthURL),
		EngineURL:       fmt.Sprintf("%s%s", baseURL, ENDPOINTS.EngineURL),
		HealthCheckURL:  fmt.Sprintf("%s%s", baseURL, ENDPOINTS.HealthCheckURL),
		PolicyBaseURL:   fmt.Sprintf("%s%s", baseURL, ENDPOINTS.PolicyBaseURL),
		ResourceBaseURL: fmt.Sprintf("%s%s", baseURL, ENDPOINTS.ResourceBaseURL),
		RoleBaseURL:     fmt.Sprintf("%s%s", baseURL, ENDPOINTS.RoleBaseURL),
	}
}

// Record the endpoints mapping so that the server can return some information
// about what endpoints are located at what URLs.
//
// This really should be a `const`.
var ENDPOINTS EndpointInformation = EndpointInformation{
	AuthURL:         "/auth",
	EngineURL:       "/engine",
	HealthCheckURL:  "/health",
	PolicyBaseURL:   "/policy/",
	ResourceBaseURL: "/resource/",
	RoleBaseURL:     "/role/",
}
