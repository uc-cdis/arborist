package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/uc-cdis/arborist/arborist"
	"github.com/uc-cdis/arborist/arborist/server"
	"github.com/uc-cdis/go-authutils/authutils"
)

func main() {
	var port *uint = flag.Uint("port", 8000, "port on which to expose the API")
	var jwkEndpoint *string = flag.String(
		"jwks",
		"",
		"endpoint from which the application can fetch a JWKS",
	)
	if *jwkEndpoint == "" {
		print("WARNING: no JWKS endpoint specified; endpoints requiring JWT validation will error\n")
	}
	flag.Parse()
	addr := fmt.Sprintf(":%d", *port)

	config := &server.ServerConfig{
		BaseURL:       fmt.Sprintf("http://localhost%s", addr),
		EndpointInfo:  server.Endpoints,
		StrictSlashes: true,
	}
	engine := arborist.NewAuthEngine()
	logger := log.New(os.Stdout, "arborist: ", log.LstdFlags)
	jwtApp := authutils.NewJWTApplication(*jwkEndpoint)
	arboristServer := server.Server{
		Config: config,
		Engine: engine,
		Logger: logger,
		JWTApp: jwtApp,
	}

	router := arboristServer.MakeRouter()
	handler := server.ApplyMiddleware(router)

	httpServer := &http.Server{
		Addr:         addr,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		ErrorLog:     logger,
		Handler:      handler,
	}
	logger.Println(fmt.Sprintf("serving at %s", httpServer.Addr))
	logger.Fatal(httpServer.ListenAndServe())
}
