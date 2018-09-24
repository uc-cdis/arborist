package main

import (
	"fmt"
)

//"os"
//"strconv"
//"reflect"

type S3Credentials struct {
	region                string
	aws_access_key_id     string
	aws_secret_access_key string
}

func (cred *S3Credentials) loadConfigFile(path string) {
	jsonBytes, _ := readFile(path)
	data, _ := getValue(jsonBytes, []string{"AWS", "region"})
	cred.region = data.(string)
	data, _ = getValue(jsonBytes, []string{"AWS", "aws_access_key_id"})
	cred.aws_access_key_id = data.(string)
	data, _ = getValue(jsonBytes, []string{"AWS", "aws_secret_access_key"})
	cred.aws_secret_access_key = data.(string)
}

func (cred *S3Credentials) printCreds() {
	fmt.Println(cred.region)
	fmt.Println(cred.aws_access_key_id)
	fmt.Println(cred.aws_secret_access_key)
}

/*
func main() {

	cred := S3Credentials{}
	cred.loadConfigFile("credentials.json")
	cred.printCreds()
	sess := cred.createNewSession()
	// Upload
	err := AddFileToS3(sess, "result.csv")
	if err != nil {
		log.Fatal(err)
	}

	//jsonBytes, _ := readCredentials("credentials.json")
	//printCredentials(jsonBytes)
	//fmt.Println(getValue(jsonBytes, []string{"AWS", "social", "facebook"}))
	//fmt.Println(getValue(jsonBytes, []string{"AWS", "age"}))
}
*/
