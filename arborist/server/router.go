package server

import (
	"fmt"
	//"github.com/gorilla/mux"
	//"github.com/uc-cdis/arborist/arborist"
)

type EndpointInformation struct {
	HealthCheckURL  string `json:"health_check_url"`
	AuthURL         string `json:"auth_url"`
	PolicyBaseURL   string `json:"policy_base_url"`
	RoleBaseURL     string `json:"role_base_url"`
	ResourceBaseURL string `json:"resource_base_url"`
	EngineURL       string `json:"engine_url"`
}

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
var Endpoints EndpointInformation = EndpointInformation{
	HealthCheckURL: "/health",
	AuthURL:        "/auth",
	PolicyBaseURL:  "/policy/",
	EngineURL:      "/engine",
}
