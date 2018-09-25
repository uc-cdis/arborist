package arborist

import (
	"bytes"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
)

type S3Credentials struct {
	region             string
	awsAccessKeyID     string
	awsSecretAccessKey string
}

type AwsClient struct {
	credentials S3Credentials
	bucket      string
	session     *session.Session
}

func (client *AwsClient) SetBucket(bucket string) {
	client.bucket = bucket
}

func (client *AwsClient) SetS3Credentials(cred S3Credentials) {
	client.credentials = cred
}

func (client *AwsClient) LoadConfigFile(path string) {
	jsonBytes, _ := readFile(path)
	data, _ := getValue(jsonBytes, []string{"AWS", "region"})
	client.credentials.region = data.(string)
	data, _ = getValue(jsonBytes, []string{"AWS", "aws_access_key_id"})
	client.credentials.awsAccessKeyID = data.(string)
	data, _ = getValue(jsonBytes, []string{"AWS", "aws_secret_access_key"})
	client.credentials.awsSecretAccessKey = data.(string)
}

func (client *AwsClient) createNewSession() {
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(client.credentials.region),
		Credentials: credentials.NewStaticCredentials(
			client.credentials.awsAccessKeyID, client.credentials.awsSecretAccessKey, ""),
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

// UploadObjectToS3 add file to s3 bucket
func (client *AwsClient) UploadObjectToS3(buffer []byte, bucketName string, fileKey string) error {

	if client.session == nil {
		client.createNewSession()
	}

	// Upload input parameters
	upParams := &s3manager.UploadInput{
		Bucket: &bucketName,
		Key:    &fileKey,
		Body:   bytes.NewReader(buffer),
	}

	size := int64(len(buffer))
	fmt.Println(size)

	// Create an uploader with the session and default options
	uploader := s3manager.NewUploader(client.session, func(u *s3manager.Uploader) {
		u.PartSize = 64 * 1024 * 1024 // 64MB per part
	})
	// Perform an upload.
	_, err := uploader.Upload(upParams)

	return err

}

// DownloadObjectFromS3 : Download an object from S3
func (client *AwsClient) DownloadObjectFromS3(bucket string, key string, filename string) error {
	if client.session == nil {
		client.createNewSession()
	}
	// The session the S3 Downloader will use
	sess := client.session

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
