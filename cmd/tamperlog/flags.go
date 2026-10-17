package main

import (
	"context"
	"encoding/asn1"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kastrul/tamperlog/seal"
	"github.com/kastrul/tamperlog/seal/sinks/fs"
	"github.com/kastrul/tamperlog/seal/sinks/s3lock"
	tlpgx "github.com/kastrul/tamperlog/store/pgx"
	"github.com/kastrul/tamperlog/store/sqlite"
)

// storeFlags select the database.
type storeFlags struct {
	Driver string `enum:"pgx,sqlite," default:"" help:"Database driver: pgx (PostgreSQL) or sqlite."`
	DSN    string `help:"Connection string (PostgreSQL URL, or a SQLite file path)."`
	Schema string `default:"public" help:"PostgreSQL schema holding the tables."`
}

// open returns a provider that implements both store interfaces.
func (f *storeFlags) open(ctx context.Context) (seal.Provider, func(), error) {
	switch f.Driver {
	case "pgx":
		if f.DSN == "" {
			return nil, nil, errors.New("--dsn is required")
		}
		pool, err := pgxpool.New(ctx, f.DSN)
		if err != nil {
			return nil, nil, err
		}
		if err := pool.Ping(ctx); err != nil {
			pool.Close()
			return nil, nil, fmt.Errorf("postgres: %w", err)
		}
		return tlpgx.New(pool, tlpgx.WithSchema(f.Schema)), pool.Close, nil
	case "sqlite":
		if f.DSN == "" {
			return nil, nil, errors.New("--dsn is required")
		}
		db, err := sqlite.Open(f.DSN)
		if err != nil {
			return nil, nil, err
		}
		return sqlite.New(db), func() { _ = db.Close() }, nil
	default:
		return nil, nil, errors.New("--driver is required (pgx or sqlite), or use --bundle")
	}
}

func (f *storeFlags) migrate(ctx context.Context) error {
	switch f.Driver {
	case "pgx":
		pool, err := pgxpool.New(ctx, f.DSN)
		if err != nil {
			return err
		}
		defer pool.Close()
		return tlpgx.Migrate(ctx, pool, tlpgx.WithSchema(f.Schema))
	case "sqlite":
		db, err := sqlite.Open(f.DSN)
		if err != nil {
			return err
		}
		defer db.Close() //nolint:errcheck // nothing left to do with it
		return sqlite.Migrate(ctx, db)
	default:
		return errors.New("--driver is required (pgx or sqlite)")
	}
}

// sinkFlags configure write-once sinks.
type sinkFlags struct {
	SinkDir    string `name:"sink-dir" help:"Filesystem sink directory."`
	S3Bucket   string `name:"s3-bucket" help:"S3 Object Lock bucket."`
	S3Prefix   string `name:"s3-prefix" help:"Key prefix inside the bucket."`
	S3Endpoint string `name:"s3-endpoint" help:"S3-compatible endpoint URL (Hetzner, MinIO); AWS when empty."`
	S3Region   string `name:"s3-region" default:"eu-central-1" help:"S3 region name."`
}

func (f *sinkFlags) sinks(ctx context.Context) ([]seal.Sink, error) {
	var out []seal.Sink
	if f.SinkDir != "" {
		s, err := fs.New(f.SinkDir)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	if f.S3Bucket != "" {
		cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(f.S3Region))
		if err != nil {
			return nil, fmt.Errorf("aws config: %w", err)
		}
		client := s3.NewFromConfig(cfg, func(o *s3.Options) {
			if f.S3Endpoint != "" {
				o.BaseEndpoint = aws.String(f.S3Endpoint)
				o.UsePathStyle = true
			}
		})
		out = append(out, s3lock.New(client, f.S3Bucket, s3lock.WithPrefix(f.S3Prefix)))
	}
	return out, nil
}

func parseOID(s string) (asn1.ObjectIdentifier, error) {
	var oid asn1.ObjectIdentifier
	for _, part := range strings.Split(s, ".") {
		n, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("oid %q: %w", s, err)
		}
		oid = append(oid, n)
	}
	return oid, nil
}

func sortedKeys[V any](m map[string]V) []string { return slices.Sorted(maps.Keys(m)) }
