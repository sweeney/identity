package backup

import (
	"context"
	"fmt"
	"io"
	"os"
	"sort"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// BackupEntry represents a backup object in R2.
type BackupEntry struct {
	Key          string
	Size         int64
	LastModified time.Time
}

// R2Uploader implements Uploader using Cloudflare R2 (S3-compatible).
type R2Uploader struct {
	client *s3.Client
	bucket string
}

// R2Config holds R2 credentials and bucket configuration.
type R2Config struct {
	AccountID       string
	AccessKeyID     string
	SecretAccessKey string
	BucketName      string
	DBPath          string // path of the SQLite DB to back up
}

// NewR2Uploader creates an R2Uploader configured with the given credentials.
func NewR2Uploader(cfg R2Config) (*R2Uploader, error) {
	endpoint := fmt.Sprintf("https://%s.r2.cloudflarestorage.com", cfg.AccountID)

	awsCfg, err := config.LoadDefaultConfig(
		context.Background(),
		config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(cfg.AccessKeyID, cfg.SecretAccessKey, ""),
		),
		config.WithRegion("auto"),
	)
	if err != nil {
		return nil, fmt.Errorf("load aws config: %w", err)
	}

	client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(endpoint)
		o.UsePathStyle = true // R2 requires path-style addressing
	})

	return &R2Uploader{
		client: client,
		bucket: cfg.BucketName,
	}, nil
}

// ListBackupsWithPrefix returns all backup objects matching the prefix, newest first.
func (u *R2Uploader) ListBackupsWithPrefix(ctx context.Context, prefix string) ([]BackupEntry, error) {
	var entries []BackupEntry
	paginator := s3.NewListObjectsV2Paginator(u.client, &s3.ListObjectsV2Input{
		Bucket: aws.String(u.bucket),
		Prefix: aws.String(prefix),
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list objects: %w", err)
		}
		for _, obj := range page.Contents {
			entries = append(entries, BackupEntry{
				Key:          aws.ToString(obj.Key),
				Size:         aws.ToInt64(obj.Size),
				LastModified: aws.ToTime(obj.LastModified),
			})
		}
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].LastModified.After(entries[j].LastModified)
	})
	return entries, nil
}

// Download downloads a backup object to a local file.
func (u *R2Uploader) Download(ctx context.Context, key, localPath string) error {
	out, err := u.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(u.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return fmt.Errorf("get object: %w", err)
	}
	defer out.Body.Close()

	f, err := os.Create(localPath)
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}
	defer f.Close()

	if _, err := io.Copy(f, out.Body); err != nil {
		return fmt.Errorf("write file: %w", err)
	}
	return f.Chmod(0600)
}

// Upload uploads the file at localPath to R2 at the given key.
func (u *R2Uploader) Upload(ctx context.Context, key, localPath string) error {
	f, err := os.Open(localPath)
	if err != nil {
		return fmt.Errorf("open backup file: %w", err)
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat backup file: %w", err)
	}

	_, err = u.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(u.bucket),
		Key:           aws.String(key),
		Body:          f,
		ContentLength: aws.Int64(stat.Size()),
		ContentType:   aws.String("application/octet-stream"),
	})
	if err != nil {
		return fmt.Errorf("put object: %w", err)
	}

	return nil
}
