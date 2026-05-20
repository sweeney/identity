package cli

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/sweeney/identity/common/backup"
)

// BackupConfig holds everything needed for backup CLI operations.
// Callers populate this from their own service config loader.
type BackupConfig struct {
	ServiceName       string
	DBPath            string
	Env               string
	R2AccountID       string
	R2AccessKeyID     string
	R2SecretAccessKey string
	R2BucketName      string
}

func (c BackupConfig) r2Configured() bool {
	return c.R2AccountID != "" && c.R2AccessKeyID != "" &&
		c.R2SecretAccessKey != "" && c.R2BucketName != ""
}

func (c BackupConfig) newUploader() (*backup.R2Uploader, error) {
	if !c.r2Configured() {
		return nil, fmt.Errorf("R2 not configured — set R2_ACCOUNT_ID, R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY, R2_BUCKET_NAME")
	}
	return backup.NewR2Uploader(backup.R2Config{
		AccountID:       c.R2AccountID,
		AccessKeyID:     c.R2AccessKeyID,
		SecretAccessKey: c.R2SecretAccessKey,
		BucketName:      c.R2BucketName,
	})
}

// ListBackups lists R2 backup objects belonging to the service in BackupConfig.
func ListBackups(cfg BackupConfig) error {
	uploader, err := cfg.newUploader()
	if err != nil {
		return err
	}

	prefix := cfg.Env + "/backups/"
	fmt.Printf("Listing %s backups for environment: %s\n\n", cfg.ServiceName, cfg.Env)

	entries, err := uploader.ListBackupsWithPrefix(context.Background(), prefix)
	if err != nil {
		return fmt.Errorf("list backups: %w", err)
	}

	filenamePrefix := cfg.ServiceName + "-"
	filtered := entries[:0]
	for _, e := range entries {
		if strings.HasPrefix(path.Base(e.Key), filenamePrefix) {
			filtered = append(filtered, e)
		}
	}

	if len(filtered) == 0 {
		fmt.Println("No backups found.")
		return nil
	}

	fmt.Printf("%-4s  %-20s  %8s  %s\n", "#", "Date", "Size", "Key")
	fmt.Println(strings.Repeat("─", 100))
	for i, e := range filtered {
		fmt.Printf("%-4d  %-20s  %6dKB  %s\n",
			i+1,
			e.LastModified.Format("2006-01-02 15:04:05"),
			e.Size/1024,
			e.Key,
		)
	}
	fmt.Printf("\n%d backup(s) found.\n", len(filtered))
	fmt.Printf("\nTo restore: ./identity-server %s --restore-backup <key>\n", cfg.ServiceName)
	return nil
}

// RestoreBackup downloads an R2 backup to the local DB file.
// If key is empty, the user is prompted to select from the filtered list.
func RestoreBackup(cfg BackupConfig, key string) error {
	uploader, err := cfg.newUploader()
	if err != nil {
		return err
	}

	if key != "" && !strings.HasPrefix(path.Base(key), cfg.ServiceName+"-") {
		return fmt.Errorf("key %q does not belong to service %q (filename must start with %q-)",
			key, cfg.ServiceName, cfg.ServiceName)
	}

	dbPath := cfg.DBPath
	if dbPath == "" {
		dbPath = cfg.ServiceName + ".db"
	}

	if key == "" {
		prefix := cfg.Env + "/backups/"
		fmt.Printf("Restoring %s backup for environment: %s\n\n", cfg.ServiceName, cfg.Env)
		entries, err := uploader.ListBackupsWithPrefix(context.Background(), prefix)
		if err != nil {
			return fmt.Errorf("list backups: %w", err)
		}

		filenamePrefix := cfg.ServiceName + "-"
		filtered := entries[:0]
		for _, e := range entries {
			if strings.HasPrefix(path.Base(e.Key), filenamePrefix) {
				filtered = append(filtered, e)
			}
		}
		if len(filtered) == 0 {
			return fmt.Errorf("no backups found for service %q", cfg.ServiceName)
		}

		fmt.Printf("%-4s  %-20s  %8s  %s\n", "#", "Date", "Size", "Key")
		fmt.Println(strings.Repeat("─", 100))
		limit := len(filtered)
		if limit > 20 {
			limit = 20
		}
		for i := 0; i < limit; i++ {
			e := filtered[i]
			fmt.Printf("%-4d  %-20s  %6dKB  %s\n",
				i+1,
				e.LastModified.Format("2006-01-02 15:04:05"),
				e.Size/1024,
				e.Key,
			)
		}

		reader := bufio.NewReader(os.Stdin)
		fmt.Printf("\nEnter backup number (1-%d): ", limit)
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		var idx int
		if _, err := fmt.Sscanf(input, "%d", &idx); err != nil || idx < 1 || idx > limit {
			return fmt.Errorf("invalid selection")
		}
		key = filtered[idx-1].Key
	}

	if _, err := os.Stat(dbPath); err == nil {
		reader := bufio.NewReader(os.Stdin)
		fmt.Printf("WARNING: This will overwrite %s\n", dbPath)
		fmt.Print("Type 'yes' to confirm: ")
		confirm, _ := reader.ReadString('\n')
		if strings.TrimSpace(confirm) != "yes" {
			fmt.Println("Aborted.")
			return nil
		}
	}

	fmt.Printf("Downloading %s ...\n", key)
	if err := uploader.Download(context.Background(), key, dbPath); err != nil {
		return fmt.Errorf("download: %w", err)
	}

	fmt.Printf("Restored %s from %s\n", dbPath, key)
	fmt.Println("Start the server to use the restored database.")
	return nil
}
