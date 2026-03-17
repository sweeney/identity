package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/sweeney/identity/internal/backup"
	"github.com/sweeney/identity/internal/config"
)

func newR2Uploader() (*backup.R2Uploader, *config.Config, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, nil, fmt.Errorf("config: %w", err)
	}
	if !cfg.R2Configured() {
		return nil, nil, fmt.Errorf("R2 not configured — set R2_ACCOUNT_ID, R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY, R2_BUCKET_NAME")
	}
	uploader, err := backup.NewR2Uploader(backup.R2Config{
		AccountID:       cfg.R2AccountID,
		AccessKeyID:     cfg.R2AccessKeyID,
		SecretAccessKey: cfg.R2SecretAccessKey,
		BucketName:      cfg.R2BucketName,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("create R2 client: %w", err)
	}
	return uploader, cfg, nil
}

func listBackups() error {
	uploader, cfg, err := newR2Uploader()
	if err != nil {
		return err
	}

	prefix := string(cfg.Env) + "/backups/"
	fmt.Printf("Listing backups for environment: %s\n\n", cfg.Env)

	entries, err := uploader.ListBackupsWithPrefix(context.Background(), prefix)
	if err != nil {
		return fmt.Errorf("list backups: %w", err)
	}

	if len(entries) == 0 {
		fmt.Println("No backups found.")
		return nil
	}

	fmt.Printf("%-4s  %-20s  %8s  %s\n", "#", "Date", "Size", "Key")
	fmt.Println(strings.Repeat("─", 100))
	for i, e := range entries {
		fmt.Printf("%-4d  %-20s  %6dKB  %s\n",
			i+1,
			e.LastModified.Format("2006-01-02 15:04:05"),
			e.Size/1024,
			e.Key,
		)
	}
	fmt.Printf("\n%d backup(s) found.\n", len(entries))
	fmt.Println("\nTo restore: ./identity-server --restore-backup <key>")
	return nil
}

func restoreBackup(key string) error {
	uploader, cfg, err := newR2Uploader()
	if err != nil {
		return err
	}

	if key == "" {
		// Interactive: list and let user pick
		prefix := string(cfg.Env) + "/backups/"
		fmt.Printf("Restoring from environment: %s\n\n", cfg.Env)
		entries, err := uploader.ListBackupsWithPrefix(context.Background(), prefix)
		if err != nil {
			return fmt.Errorf("list backups: %w", err)
		}
		if len(entries) == 0 {
			return fmt.Errorf("no backups found")
		}

		fmt.Printf("%-4s  %-20s  %8s  %s\n", "#", "Date", "Size", "Key")
		fmt.Println(strings.Repeat("─", 100))
		limit := len(entries)
		if limit > 20 {
			limit = 20
		}
		for i := 0; i < limit; i++ {
			e := entries[i]
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
		key = entries[idx-1].Key
	}

	dbPath := cfg.DBPath
	if dbPath == "" {
		dbPath = "identity.db"
	}

	// Safety check
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
