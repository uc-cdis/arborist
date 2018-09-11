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
	var jwkEndpointEnv string = os.Getenv("JWKS_ENDPOINT")

	var port *uint = flag.Uint("port", 80, "port on which to expose the API")
	var jwkEndpoint *string = flag.String(
		"jwks",
		jwkEndpointEnv,
		"endpoint from which the application can fetch a JWKS",
	)
	flag.Parse()

	if *jwkEndpoint == "" {
		print("WARNING: no $JWKS_ENDPOINT or --jwks specified; endpoints requiring JWT validation will error\n")
	}
	addr := fmt.Sprintf(":%d", *port)

	config := &server.ServerConfig{
		BaseURL:       fmt.Sprintf("http://localhost%s", addr),
		StrictSlashes: true,
	}
	engine := arborist.NewAuthEngine()
	jwtApp := authutils.NewJWTApplication(*jwkEndpoint)
	logHandler := server.NewLogHandler(os.Stdout, 0) // 0 for default log flags
	arboristServer := server.Server{
		Config: config,
		Engine: engine,
		JWTApp: jwtApp,
		Log:    logHandler,
	}

	router := arboristServer.MakeRouter()
	handler := server.ApplyMiddleware(router)

	httpLogger := log.New(os.Stdout, "", log.LstdFlags)
	httpServer := &http.Server{
		Addr:         addr,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		ErrorLog:     httpLogger,
		Handler:      handler,
	}
	httpLogger.Println(fmt.Sprintf("arborist serving at %s", httpServer.Addr))
	httpLogger.Fatal(httpServer.ListenAndServe())
}
