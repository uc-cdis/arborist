package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/uc-cdis/arborist/arborist"
	"github.com/uc-cdis/go-authutils/authutils"
)

// dbPoolSizeEnv names the environment variable which sets the maximum number of
// database connections each arborist process keeps open.
const dbPoolSizeEnv = "DB_POOL_SIZE"

// defaultDBPoolSize is the pool size used when `dbPoolSizeEnv` is not set.
const defaultDBPoolSize = 10

// dbPoolSizeFromEnv returns the configured database pool size, or
// `defaultDBPoolSize` if it's not set. It returns an error if the value is not
// a positive integer.
func dbPoolSizeFromEnv() (int, error) {
	value := os.Getenv(dbPoolSizeEnv)
	if value == "" {
		return defaultDBPoolSize, nil
	}
	size, err := strconv.Atoi(value)
	if err != nil || size < 1 {
		return 0, fmt.Errorf("$%s must be a positive integer, got %q", dbPoolSizeEnv, value)
	}
	return size, nil
}

// dbConnMaxLifetime is how long a database connection is used before it's
// closed and replaced, so that connections broken by a database restart,
// failover or proxy are eventually dropped.
const dbConnMaxLifetime = 30 * time.Minute

// dbConnMaxIdleTime is how long a database connection can sit unused before
// it's closed, so that idle pods release connections on a shared database.
const dbConnMaxIdleTime = 5 * time.Minute

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
	flag.Parse()

	if *jwkEndpoint == "" {
		print("WARNING: no $JWKS_ENDPOINT or --jwks specified; endpoints requiring JWT validation will error\n")
	}
	poolSize, err := dbPoolSizeFromEnv()
	if err != nil {
		panic(err)
	}
	// if database URL is not provided it can use environment variables

	db, err := sqlx.Open("postgres", *dbUrl)
	if err != nil {
		panic(err)
	}
	defer db.Close()
	// Keep as many idle connections as open ones, so that connections are
	// reused instead of opened and closed again for each request.
	db.SetMaxOpenConns(poolSize)
	db.SetMaxIdleConns(poolSize)
	db.SetConnMaxLifetime(dbConnMaxLifetime)
	db.SetConnMaxIdleTime(dbConnMaxIdleTime)
	logFlags := log.Ldate | log.Ltime
	logger := log.New(os.Stdout, "", logFlags)
	jwtApp := authutils.NewJWTApplication(*jwkEndpoint)
	arboristServer, err := arborist.NewServer().
		WithLogger(logger).
		WithJWTApp(jwtApp).
		WithDB(db).
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
	httpLogger.Println("arborist serving at", httpServer.Addr)
	httpLogger.Fatal(httpServer.ListenAndServe())
}
