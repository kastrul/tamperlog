package fs_test

import (
	"testing"

	"github.com/kastrul/tamperlog/seal"
	"github.com/kastrul/tamperlog/seal/sinks/fs"
	"github.com/kastrul/tamperlog/seal/sinktest"
)

func TestConformance(t *testing.T) {
	t.Parallel()
	sinktest.Run(t, func(t *testing.T) seal.Sink {
		s, err := fs.New(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		return s
	})
}
