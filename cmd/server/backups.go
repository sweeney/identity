package main

import (
	"fmt"

	"github.com/sweeney/identity/common/cli"
	"github.com/sweeney/identity/internal/config"
)

func backupCfgForService(serviceName, dbPath string) (cli.BackupConfig, error) {
	cfg, err := config.Load()
	if err != nil {
		return cli.BackupConfig{}, fmt.Errorf("config: %w", err)
	}
	if dbPath == "" {
		dbPath = cfg.DBPath
	}
	return cli.BackupConfig{
		ServiceName:       serviceName,
		DBPath:            dbPath,
		Env:               string(cfg.Env),
		R2AccountID:       cfg.R2AccountID,
		R2AccessKeyID:     cfg.R2AccessKeyID,
		R2SecretAccessKey: cfg.R2SecretAccessKey,
		R2BucketName:      cfg.R2BucketName,
	}, nil
}

func listBackupsForService(serviceName string) error {
	bcfg, err := backupCfgForService(serviceName, "")
	if err != nil {
		return err
	}
	return cli.ListBackups(bcfg)
}

func listBackups() error {
	return listBackupsForService("identity")
}

func restoreBackupForService(serviceName, dbPath, key string) error {
	bcfg, err := backupCfgForService(serviceName, dbPath)
	if err != nil {
		return err
	}
	return cli.RestoreBackup(bcfg, key)
}

func restoreBackup(key string) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	return restoreBackupForService("identity", cfg.DBPath, key)
}
