package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/uc-cdis/arborist/arborist"
)

func main() {
	var port *uint = flag.Uint("port", 8080, "port on which to expose the API")
	flag.Parse()
	addr := fmt.Sprintf(":%d", *port)

	logger := log.New(os.Stdout, "arborist: ", log.LstdFlags)

	engine, err := arborist.NewAuthEngine()
	if err != nil {
		panic(fmt.Sprintf("failed to initialize auth engine: %s", err))
	}
	router := arborist.MakeRouter(&engine, false)

	handler := arborist.ApplyMiddleware(&router)

	server := &http.Server{
		Addr:         addr,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		ErrorLog:     logger,
		Handler:      handler,
	}
	logger.Println(fmt.Sprintf("serving at %s", server.Addr))
	server.ListenAndServe()
}
