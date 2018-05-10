package server

type ServerConfig struct {
	StrictSlashes bool
	BaseURL       string
	EndpointInfo  EndpointInformation
}
