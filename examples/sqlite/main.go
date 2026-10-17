// Command sqlite keeps an audit trail in a SQLite file: open, migrate,
// append, and show the triggers refusing a direct edit.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/kastrul/tamperlog"
	"github.com/kastrul/tamperlog/store/sqlite"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	ctx := context.Background()
	dir, err := os.MkdirTemp("", "tamperlog-sqlite")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir) //nolint:errcheck // temporary directory

	db, err := sqlite.Open("file:" + filepath.Join(dir, "audit.db"))
	if err != nil {
		return err
	}
	defer db.Close() //nolint:errcheck // read-only at this point
	if err := sqlite.Migrate(ctx, db); err != nil {
		return err
	}

	audit := tamperlog.NewLog(sqlite.New(db))
	rec, err := audit.Append(ctx, tamperlog.Event{Stream: "audit", Actor: "u1", Action: "login", Entity: "session", EntityID: "s1"})
	if err != nil {
		return err
	}
	fmt.Printf("appended %s/%d\n", rec.Stream, rec.Seq)

	_, err = db.ExecContext(ctx, `UPDATE tamperlog_event SET actor = 'mallory' WHERE seq = 1`)
	fmt.Println("direct UPDATE:", err)
	_, err = db.ExecContext(ctx, `DELETE FROM tamperlog_event`)
	fmt.Println("direct DELETE:", err)
	return nil
}
