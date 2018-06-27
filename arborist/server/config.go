package server

import (
	"log"
)

type ServerConfig struct {
	StrictSlashes bool
	BaseURL       string
	EndpointInfo  EndpointInformation
	Logger        *log.Logger
}
