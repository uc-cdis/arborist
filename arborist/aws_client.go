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

// S3Credentials contains AWS credentials
type S3Credentials struct {
	region             string
	awsAccessKeyID     string
	awsSecretAccessKey string
}

type AwsClient struct {
	credentials S3Credentials
	session     *session.Session
	bucket      string
}

func (client *AwsClient) SetS3Credentials(cred S3Credentials) {
	client.credentials = cred
}

// LoadCredentialFromConfigFile loads AWS credentials from the config file
func (client *AwsClient) LoadCredentialFromConfigFile(path string) error {
	// Read data file
	jsonBytes, err := ReadFile(path)
	if err != nil {
		return err
	}

	// Get AWS region
	data, err := GetValueFromKeys(jsonBytes, []string{"AWS", "region"})
	if err != nil {
		return err
	}
	client.credentials.region = data.(string)

	// Get AWS access key id
	data, err = GetValueFromKeys(jsonBytes, []string{"AWS", "aws_access_key_id"})
	if err != nil {
		return err
	}
	client.credentials.awsAccessKeyID = data.(string)

	// Get AWS secret access key
	data, err = GetValueFromKeys(jsonBytes, []string{"AWS", "aws_secret_access_key"})
	if err != nil {
		return err
	}
	client.credentials.awsSecretAccessKey = data.(string)

	return nil
}

// createNewSession creats a aws s3 session
func (client *AwsClient) createNewSession() error {

	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(client.credentials.region),
		Credentials: credentials.NewStaticCredentials(
			client.credentials.awsAccessKeyID, client.credentials.awsSecretAccessKey, ""),
	})
	client.session = sess

	return err
}

func (client *AwsClient) GetBucketName() string {
	return client.bucket
}

func (client *AwsClient) SetBucketName(name string) {
	client.bucket = name
}

// UploadObjectToS3 adds an object file to s3 bucket
func (client *AwsClient) UploadObjectToS3(buffer []byte, bucketName string, fileKey string) error {
	if client.session == nil {
		err := client.createNewSession()
		if err != nil {
			return nil
		}
	}

	// Upload input parameters
	upParams := &s3manager.UploadInput{
		Bucket: &bucketName,
		Key:    &fileKey,
		Body:   bytes.NewReader(buffer),
	}

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
		err := client.createNewSession()
		if err != nil {
			return err
		}
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
