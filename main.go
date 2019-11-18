package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/uc-cdis/arborist/arborist"
	"github.com/uc-cdis/go-authutils/authutils"
)

func main() {
	var jwkEndpointEnv string = os.Getenv("JWKS_ENDPOINT")

	// Parse flags:
	//     - port (to serve on)
	//     - jwks (endpoint to get keys for JWT validation)
	var port *uint = flag.Uint("port", 80, "port on which to expose the API")
	var jwkEndpoint *string = flag.String(
		"jwks",
		jwkEndpointEnv,
		"endpoint from which the application can fetch a JWKS",
	)
	var dbUrl *string = flag.String(
		"db",
		"",
		"URL to connect to database: postgresql://user:password@netloc:port/dbname\n"+
			"can also be specified through the postgres\n"+
			"environment variables. If using the commandline argument, add\n"+
			"?sslmode=disable",
	)
	var fenceUrl *string = flag.String(
		"fence",
		"",
		"URL to connect to fence",
	)
	flag.Parse()

	if *jwkEndpoint == "" {
		print("WARNING: no $JWKS_ENDPOINT or --jwks specified; endpoints requiring JWT validation will error\n")
	}
	// if database URL is not provided it can use environment variables

	db, err := sqlx.Open("postgres", *dbUrl)
	if err != nil {
		panic(err)
	}
	defer db.Close()
	logFlags := log.Ldate | log.Ltime
	logger := log.New(os.Stdout, "", logFlags)
	jwtApp := authutils.NewJWTApplication(*jwkEndpoint)
	arboristServer, err := arborist.NewServer().
		WithLogger(logger).
		WithJWTApp(jwtApp).
		WithDB(db).
		WithFence(fenceUrl).
		Init()
	if err != nil {
		panic(err)
	}

	addr := fmt.Sprintf(":%d", *port)
	router := arboristServer.MakeRouter(os.Stdout)
	httpLogger := log.New(os.Stdout, "", log.LstdFlags)
	httpServer := &http.Server{
		Addr:         addr,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		ErrorLog:     httpLogger,
		Handler:      router,
	}
	httpLogger.Println(fmt.Sprintf("arborist serving at %s", httpServer.Addr))
	httpLogger.Fatal(httpServer.ListenAndServe())
}
