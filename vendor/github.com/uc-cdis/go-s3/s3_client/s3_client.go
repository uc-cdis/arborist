package main

import (
	"bytes"
	"fmt"
	"log"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
)

const (
	S3_REGION = "us-east-1"
	S3_BUCKET = "xssxs"
)

type AwsClient struct {
	credentials *S3Credentials
	session     *session.Session
}

func (client *AwsClient) createNewSession() {
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(client.credentials.region),
		Credentials: credentials.NewStaticCredentials(
			client.credentials.aws_access_key_id, client.credentials.aws_secret_access_key, ""),
	})
	if err != nil {
		panic("Can not establist aws client session")
	}
	client.session = sess
}

func exitErrorf(msg string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, msg+"\n", args...)
	os.Exit(1)
}

// AddFileToS3 add file to s3 bucket
func (client *AwsClient) AddFileToS3(buffer []byte, bucketName string, fileKey string) error {

	// Upload input parameters
	upParams := &s3manager.UploadInput{
		Bucket: &bucketName,
		Key:    &fileKey,
		Body:   bytes.NewReader(buffer),
	}

	size := int64(len(buffer))
	fmt.Println(size)

	sess := client.session

	// Create an uploader with the session and default options
	uploader := s3manager.NewUploader(sess)
	// Perform an upload.
	_, err := uploader.Upload(upParams)

	return err

}

func (client *AwsClient) DownloadDataS3(bucket string, key string, filename string) error {

	// The session the S3 Downloader will use
	sess := client.session

	// Create a downloader with the session and default options
	//downloader := s3manager.NewDownloader(sess)

	// Create a downloader with the session and custom options
	downloader := s3manager.NewDownloader(sess, func(d *s3manager.Downloader) {
		d.PartSize = 64 * 1024 * 1024 // 64MB per part
	})

	// Create a file to write the S3 Object contents to.
	f, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file %q, %v", filename, err)
	}

	// Write the contents of S3 Object to the file
	_, err = downloader.Download(f, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})

	return err

}

func main() {

	awsClient := AwsClient{}
	awsClient.credentials = new(S3Credentials)
	awsClient.credentials.loadConfigFile("credentials.json")
	awsClient.credentials.printCreds()
	awsClient.createNewSession()
	// Upload

	buff, _ := readFile("result.csv")

	err := awsClient.AddFileToS3(buff, "xssxs", "result3.txt")
	if err != nil {
		log.Fatal(err)
	}
	//awsClient.DownloadDataS3("xssxs", "result3.txt", "./test.txt")
}
