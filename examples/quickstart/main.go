// Command quickstart appends events to an in-memory store, seals, verifies,
// then tampers with a record and shows the verifier catching it.
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/kastrul/tamperlog"
	"github.com/kastrul/tamperlog/seal"
	"github.com/kastrul/tamperlog/store/memory"
	"github.com/kastrul/tamperlog/verify"
)

func main() {
	ctx := context.Background()
	store := memory.New()
	audit := tamperlog.NewLog(store)

	for i := range 3 {
		rec, err := audit.Append(ctx, tamperlog.Event{
			Stream:     "audit",
			Actor:      "0199f5a0-0000-7000-8000-000000000001",
			Subject:    "0199f5a0-0000-7000-8000-000000000042",
			Action:     "record.read",
			Entity:     "patient_record",
			EntityID:   fmt.Sprintf("rec-%d", i),
			Attributes: map[string]string{"purpose": "treatment"},
		})
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("appended %s/%d hash=%x\n", rec.Stream, rec.Seq, rec.Hash[:8])
	}

	writer := seal.NewWriter(store, seal.WithWriterName("quickstart"))
	s, err := writer.Seal(ctx)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("seal %d: %s\n", s.Seq, s.Bytes)

	v := verify.New()
	fmt.Println("before tampering:", v.Verify(ctx, verify.FromProvider(store), nil).Summary())

	// A privileged user edits record 2 and recomputes its hash.
	recs := store.Records("audit")
	recs[1].Actor = "someone-else"
	recs[1].Hash, _ = audit.Appender().Chain().Link(recs[1])
	store.Replace("audit", recs)

	rep := v.Verify(ctx, verify.FromProvider(store), nil)
	fmt.Println("after tampering: ", rep.Summary())
	for _, f := range rep.Errors() {
		fmt.Println("  ", f)
	}
}
