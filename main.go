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

const ConfigFile string = "./credentials.json"
const LocalSavedModel string = "./model.json"

// startPolling periodically upload the model to S3
func startPolling(engine *arborist.Engine, bucketName string, keyName string) {
	for {
		time.Sleep(3600 * time.Second)
		err := engine.UploadModelToS3(ConfigFile, bucketName, keyName)
		if err != nil {
			fmt.Println("WARNING: Can not upload data model to S3. Continue anyway!!!")
		}
	}
}

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
		fmt.Println("WARNING: no $JWKS_ENDPOINT or --jwks specified; endpoints requiring JWT validation will error")
	}
	addr := fmt.Sprintf(":%d", *port)

	bucketName := ""
	data, err := arborist.GetKeyValueFromConfigFile(ConfigFile, []string{"bucket"})
	if err != nil {
		fmt.Println(err)
		fmt.Println("WARNING: There is no s3 bucket in config file")
	} else {
		bucketName = data.(string)
	}

	modelFileName := ""
	data, err = arborist.GetKeyValueFromConfigFile(ConfigFile, []string{"model_file_name"})
	if err != nil {
		fmt.Println(err)
		fmt.Println("WARNING: There is no data model name in config file")
	} else {
		modelFileName = data.(string)
	}

	config := &server.ServerConfig{
		BaseURL:       fmt.Sprintf("http://localhost%s", addr),
		StrictSlashes: true,
	}

	// Start a authentication engine
	engine := arborist.NewAuthEngine()

	// Try get updated model from S3
	err = engine.DownloadModelFromS3(ConfigFile, bucketName, modelFileName, LocalSavedModel)
	if err != nil {
		fmt.Println(err)
		fmt.Println("WARNING: Can not download the data model from S3. Continue anyway!!!")
	} else {
		engine, err = engine.LoadDataModelFromJSONFile(LocalSavedModel)
		if err != nil {
			fmt.Println(err)
			fmt.Println("WARNING: Can not load model from JSON file. Continue anyway!!!")
		}

	}

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

	// Periodically copy the data model to s3
	go startPolling(engine, bucketName, modelFileName)

	httpLogger.Println(fmt.Sprintf("arborist serving at %s", httpServer.Addr))
	httpLogger.Fatal(httpServer.ListenAndServe())
}
