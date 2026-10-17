package main

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/kastrul/tamperlog"
	"github.com/kastrul/tamperlog/anchor"
	"github.com/kastrul/tamperlog/anchor/rfc3161"
	"github.com/kastrul/tamperlog/anchor/rfc3161/eutl"
	"github.com/kastrul/tamperlog/bundle"
	"github.com/kastrul/tamperlog/seal"
	"github.com/kastrul/tamperlog/sign"
	"github.com/kastrul/tamperlog/verify"
)

// runContext is passed to every command.
type runContext struct {
	ctx    context.Context
	logger *slog.Logger
}

// exitError carries a process exit code.
type exitError struct {
	code int
	msg  string
}

func (e *exitError) Error() string { return e.msg }

func asExit(err error, target **exitError) bool { return errors.As(err, target) }

func newLogger(level string) (*slog.Logger, error) {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		return nil, fmt.Errorf("log level: %w", err)
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: l})), nil
}

// ---- migrate ----

type migrateCmd struct {
	storeFlags
}

func (c *migrateCmd) Run(rc *runContext) error {
	if err := c.migrate(rc.ctx); err != nil {
		return err
	}
	fmt.Println("schema installed")
	return nil
}

// ---- append ----

type appendCmd struct {
	storeFlags
	Stream   string            `required:"" help:"Stream name."`
	Action   string            `required:"" help:"Action, such as record.read."`
	Entity   string            `required:"" help:"Entity type, such as patient_record."`
	EntityID string            `name:"entity-id" help:"Entity identifier."`
	Actor    string            `help:"Actor identifier (a pseudonym, never a name)."`
	Subject  string            `help:"Subject identifier (a pseudonym)."`
	Attr     map[string]string `help:"Attributes, key=value." mapsep:","`
}

func (c *appendCmd) Run(rc *runContext) error {
	p, closeFn, err := c.open(rc.ctx)
	if err != nil {
		return err
	}
	defer closeFn()
	rec, err := tamperlog.NewLog(p, tamperlog.WithLogger(rc.logger)).Append(rc.ctx, tamperlog.Event{
		Stream: c.Stream, Actor: c.Actor, Subject: c.Subject, Action: c.Action, Entity: c.Entity, EntityID: c.EntityID, Attributes: c.Attr,
	})
	if err != nil {
		return err
	}
	fmt.Printf("%s/%d %s %x\n", rec.Stream, rec.Seq, rec.At.Format(time.RFC3339Nano), rec.Hash)
	return nil
}

// ---- seal ----

type sealCmd struct {
	storeFlags
	sinkFlags
	Interval   time.Duration `default:"1h" help:"Seal interval when running continuously."`
	Once       bool          `help:"Write one seal and exit."`
	WriterName string        `name:"writer-name" help:"Writer identifier recorded in every seal (default: tamperlog <version>)."`
	SignKey    string        `name:"sign-ed25519-key" type:"existingfile" help:"PEM or raw 64-byte Ed25519 private key file; enables seal signatures."`
	KeyID      string        `name:"key-id" help:"Key identifier written into signed seals."`
}

func (c *sealCmd) Run(rc *runContext) error {
	p, closeFn, err := c.open(rc.ctx)
	if err != nil {
		return err
	}
	defer closeFn()
	sinks, err := c.sinks(rc.ctx)
	if err != nil {
		return err
	}
	name := c.WriterName
	if name == "" {
		name = "tamperlog " + version
	}
	opts := []seal.WriterOption{seal.WithSinks(sinks...), seal.WithLogger(rc.logger), seal.WithWriterName(name)}
	if c.SignKey != "" {
		if c.KeyID == "" {
			return errors.New("--key-id is required with --sign-ed25519-key")
		}
		priv, err := loadEd25519Private(c.SignKey)
		if err != nil {
			return err
		}
		signer, err := sign.NewEd25519(c.KeyID, priv)
		if err != nil {
			return err
		}
		opts = append(opts, seal.WithSigner(signer))
	}
	w := seal.NewWriter(p, opts...)
	if c.Once {
		st, err := w.Seal(rc.ctx)
		if err != nil {
			return err
		}
		fmt.Printf("seal %d %x\n%s\n", st.Seq, st.Hash, st.Bytes)
		return nil
	}
	return ignoreCancel(w.Run(rc.ctx, c.Interval, func(err error) { rc.logger.Error("seal failed", "err", err) }))
}

// ---- anchor ----

type anchorCmd struct {
	storeFlags
	sinkFlags
	tsaFlags
	Once  bool          `help:"Anchor what is pending and exit."`
	Grace time.Duration `default:"4h" help:"How long a seal may stay unanchored before anchor.failed is recorded."`
}

func (c *anchorCmd) Run(rc *runContext) error {
	p, closeFn, err := c.open(rc.ctx)
	if err != nil {
		return err
	}
	defer closeFn()
	sinks, err := c.sinks(rc.ctx)
	if err != nil {
		return err
	}
	prov, err := c.provider(rc.ctx, true)
	if err != nil {
		return err
	}
	r := anchor.NewRunner(p, prov, anchor.WithSinks(sinks...), anchor.WithGrace(c.Grace), anchor.WithLogger(rc.logger),
		anchor.WithLog(tamperlog.NewLog(p, tamperlog.WithLogger(rc.logger))))
	if c.Once {
		n, err := r.Once(rc.ctx)
		fmt.Printf("anchored %d seal(s)\n", n)
		return err
	}
	return ignoreCancel(r.Run(rc.ctx))
}

// ---- verify ----

type verifyCmd struct {
	storeFlags
	sinkFlags
	tsaFlags
	Bundle          string            `type:"existingdir" help:"Verify an export bundle instead of a database."`
	NoAnchors       bool              `name:"no-anchors" help:"Explicitly skip proof verification (otherwise --tsa-roots is required)."`
	NoSinks         bool              `name:"no-sinks" help:"Explicitly skip sink comparison (otherwise a sink is required)."`
	NoFreshness     bool              `name:"no-freshness" help:"Explicitly skip the latest-seal age check (otherwise --max-seal-age is required)."`
	Pubkey          map[string]string `help:"Ed25519 seal signature keys, keyid=hex; when given every seal must be signed." mapsep:","`
	Interval        time.Duration     `help:"Run continuously every interval and record outcomes in the system stream; default is one run."`
	JSON            bool              `name:"json" help:"Print the report as JSON."`
	MaxSealAge      time.Duration     `name:"max-seal-age" help:"Latest seal older than this is an error."`
	MaxSealInterval time.Duration     `name:"max-seal-interval" help:"Longer gap between seals is an error."`
	AllowInnerGaps  bool              `name:"allow-inner-gaps" help:"Accept sealed drops inside a stream, not only at its start."`
	TimeTolerance   time.Duration     `name:"time-tolerance" default:"1s" help:"Allowed timestamp regression between records; use the appender's value."`
	Full            bool              `help:"Force full walks in continuous mode (default: daily full walk, incremental otherwise)."`
}

// scopeErrors returns the configuration mistakes that would make a run
// verify less than the operator thinks. Every external layer must be either
// configured or explicitly skipped.
func (c *verifyCmd) scopeErrors() error {
	var problems []string
	hasSink := c.SinkDir != "" || c.S3Bucket != ""
	switch {
	case c.TSARoots == "" && !c.NoAnchors:
		problems = append(problems, "proofs are not verified: pass --tsa-roots or --no-anchors")
	case c.TSARoots != "" && c.NoAnchors:
		problems = append(problems, "--tsa-roots and --no-anchors conflict")
	}
	if c.TSARoots == "" && (c.TSAPolicy != "" || c.EUTLCache != "" || c.TSAURL != "") {
		problems = append(problems, "--tsa-url, --tsa-policy and --eutl-cache have no effect without --tsa-roots")
	}
	switch {
	case !hasSink && !c.NoSinks:
		problems = append(problems, "no sink to compare against: pass --sink-dir or --s3-bucket, or --no-sinks")
	case hasSink && c.NoSinks:
		problems = append(problems, "a sink and --no-sinks conflict")
	}
	switch {
	case c.MaxSealAge <= 0 && !c.NoFreshness && c.Bundle == "":
		problems = append(problems, "latest-seal age is not checked: pass --max-seal-age (a few seal intervals) or --no-freshness")
	case c.MaxSealAge > 0 && c.NoFreshness:
		problems = append(problems, "--max-seal-age and --no-freshness conflict")
	}
	if len(problems) == 0 {
		return nil
	}
	return &exitError{code: 2, msg: "verification scope: " + strings.Join(problems, "; ")}
}

func (c *verifyCmd) Run(rc *runContext) error {
	if err := c.scopeErrors(); err != nil {
		return err
	}
	var src verify.Source
	var log *tamperlog.Log
	switch {
	case c.Bundle != "":
		b, err := bundle.Open(c.Bundle)
		if err != nil {
			return err
		}
		src = b
	default:
		p, closeFn, err := c.open(rc.ctx)
		if err != nil {
			return err
		}
		defer closeFn()
		src = verify.FromProvider(p)
		log = tamperlog.NewLog(p, tamperlog.WithLogger(rc.logger))
	}
	sinks, err := c.sinks(rc.ctx)
	if err != nil {
		return err
	}
	opts := []verify.Option{verify.WithSinks(sinks...), verify.WithLogger(rc.logger), verify.WithTimeTolerance(c.TimeTolerance)}
	if c.MaxSealAge > 0 {
		opts = append(opts, verify.WithMaxSealAge(c.MaxSealAge))
	}
	if c.MaxSealInterval > 0 {
		opts = append(opts, verify.WithMaxSealInterval(c.MaxSealInterval))
	}
	if c.AllowInnerGaps {
		opts = append(opts, verify.WithAllowInnerGaps())
	}
	if c.TSARoots != "" {
		prov, err := c.provider(rc.ctx, false)
		if err != nil {
			return err
		}
		opts = append(opts, verify.WithAnchors(prov))
	}
	if len(c.Pubkey) > 0 {
		keys := map[string]ed25519.PublicKey{}
		for id, h := range c.Pubkey {
			b, err := hex.DecodeString(h)
			if err != nil {
				return fmt.Errorf("--pubkey %s: %w", id, err)
			}
			keys[id] = b
		}
		sv, err := sign.NewEd25519Verifier(keys)
		if err != nil {
			return err
		}
		opts = append(opts, verify.WithSignatureVerifier(sv))
	}
	v := verify.New(opts...)
	if c.Interval > 0 {
		var last *verify.Report
		ropts := []verify.RunnerOption{verify.WithOnReport(func(_ context.Context, rep *verify.Report) {
			last = rep
			if err := c.print(rep); err != nil {
				rc.logger.Error("print report", "err", err)
			}
		})}
		if log != nil {
			ropts = append(ropts, verify.WithLog(log))
		}
		if !c.Full {
			ropts = append(ropts, verify.WithIncremental(24*time.Hour))
		}
		err := ignoreCancel(verify.NewRunner(v, src, ropts...).Run(rc.ctx, c.Interval))
		if err != nil {
			return err
		}
		// Continuous mode ends only when stopped; the exit status reflects
		// the last report so a supervisor sees a broken state.
		return exitFor(last)
	}
	rep := v.Verify(rc.ctx, src, nil)
	if err := c.print(rep); err != nil {
		return err
	}
	return exitFor(rep)
}

// exitFor maps a report to the documented exit status: 0 verified, 1 an
// integrity finding, 2 an operational failure (the evidence could not be
// read, so nothing is known either way).
func exitFor(rep *verify.Report) error {
	switch {
	case rep == nil:
		return nil
	case rep.Operational():
		return &exitError{code: 2, msg: "verification could not complete: " + firstError(rep)}
	case !rep.OK():
		return &exitError{code: 1, msg: "verification found errors: " + firstError(rep)}
	default:
		return nil
	}
}

func firstError(rep *verify.Report) string {
	if errs := rep.Errors(); len(errs) > 0 {
		return errs[0].String()
	}
	return ""
}

func (c *verifyCmd) print(rep *verify.Report) error {
	if c.JSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(rep)
	}
	fmt.Println(rep.Summary())
	for _, f := range rep.Findings {
		if f.Severity != verify.Info {
			fmt.Println(" ", f)
		}
	}
	for _, name := range sortedKeys(rep.Streams) {
		s := rep.Streams[name]
		state := "ok"
		if !s.Verified {
			state = "BROKEN"
		}
		fmt.Printf("  stream %-24s %s head=%d kept_from=%d records=%d sealed_head=%d unsealed=%d gaps=%d\n", name, state, s.HeadSeq, s.FirstKeptSeq, s.Records, s.SealedHead, s.Unsealed, len(s.Gaps))
	}
	return nil
}

// ---- export ----

type exportCmd struct {
	storeFlags
	Out     string   `required:"" help:"Destination directory (must not exist or be empty)."`
	Streams []string `help:"Only these streams." sep:","`
}

func (c *exportCmd) Run(rc *runContext) error {
	p, closeFn, err := c.open(rc.ctx)
	if err != nil {
		return err
	}
	defer closeFn()
	m, err := bundle.Export(rc.ctx, verify.FromProvider(p), c.Out, bundle.ExportOptions{Writer: "tamperlog " + version, Streams: c.Streams})
	if err != nil {
		return err
	}
	fmt.Printf("exported %d stream(s), %d seal(s) to %s\n", len(m.Streams), m.Seals.Count, c.Out)
	return nil
}

// ---- resync ----

type resyncCmd struct {
	storeFlags
	sinkFlags
}

func (c *resyncCmd) Run(rc *runContext) error {
	p, closeFn, err := c.open(rc.ctx)
	if err != nil {
		return err
	}
	defer closeFn()
	sinks, err := c.sinks(rc.ctx)
	if err != nil {
		return err
	}
	if len(sinks) == 0 {
		return errors.New("no sink configured")
	}
	n, err := seal.NewWriter(p, seal.WithSinks(sinks...), seal.WithLogger(rc.logger)).Resync(rc.ctx)
	fmt.Printf("wrote %d object(s)\n", n)
	return err
}

// ---- inspect ----

type inspectCmd struct {
	Seal  inspectSealCmd  `cmd:"" help:"Print a seal document and its hash."`
	Token inspectTokenCmd `cmd:"" help:"Print an RFC 3161 token (parsed, not verified)."`
}

type inspectSealCmd struct {
	File string `arg:"" type:"existingfile" help:"Seal file (canonical JSON)."`
}

func (c *inspectSealCmd) Run(*runContext) error {
	b, err := os.ReadFile(c.File)
	if err != nil {
		return err
	}
	s, err := seal.Parse(b)
	if err != nil {
		return err
	}
	fmt.Printf("seal %d at %s hash %x prev %x writer %q signed=%v\n", s.Seq, s.SealedAt.Format(time.RFC3339Nano), seal.Hash(b), s.PrevSealHash, s.Writer, s.KeyID != "")
	for _, h := range s.Streams {
		fmt.Printf("  %-24s %s/%s kept %d..%d head %x\n", h.Stream, h.Encoder, h.Hasher, h.FirstKeptSeq, h.HeadSeq, h.HeadHash)
	}
	for _, d := range s.Drops {
		fmt.Printf("  drop %x\n", d)
	}
	return nil
}

type inspectTokenCmd struct {
	File string `arg:"" type:"existingfile" help:"DER TimeStampToken (.proof or .tsr)."`
}

func (c *inspectTokenCmd) Run(*runContext) error {
	b, err := os.ReadFile(c.File)
	if err != nil {
		return err
	}
	t, err := rfc3161.ParseToken(b)
	if err != nil {
		return err
	}
	fmt.Printf("genTime %s accuracy %s policy %s serial %s\n", t.GenTime.Format(time.RFC3339Nano), t.Accuracy, t.Policy, t.SerialNumber)
	fmt.Printf("imprint %x\n", t.MessageImprint.HashedMessage)
	if t.SignerCertificate != nil {
		fmt.Printf("signer %s (issuer %s, not after %s)\n", t.SignerCertificate.Subject, t.SignerCertificate.Issuer, t.SignerCertificate.NotAfter.Format(time.RFC3339))
	}
	fmt.Println("parsed, not verified; use `tamperlog verify --tsa-roots` for verification")
	return nil
}

type versionCmd struct{}

func (versionCmd) Run(*runContext) error {
	fmt.Println("tamperlog", version)
	return nil
}

// ---- TSA flags ----

type tsaFlags struct {
	TSAURL      string `name:"tsa-url" help:"RFC 3161 endpoint, for example http://tsa.demo.sk.ee/tsa."`
	TSARoots    string `name:"tsa-roots" type:"existingfile" help:"PEM file with the TSA root certificate(s) to trust."`
	TSAPolicy   string `name:"tsa-policy" help:"Required TSA policy OID."`
	EUTLCache   string `name:"eutl-cache" help:"Directory caching the EU Trusted List; enables qualified-status checks."`
	EUTLOffline bool   `name:"eutl-offline" help:"Read the EU Trusted List from the cache only."`
}

// provider builds the rfc3161 anchor provider. needClient requires --tsa-url.
func (f *tsaFlags) provider(ctx context.Context, needClient bool) (anchor.Provider, error) {
	if f.TSARoots == "" {
		return nil, errors.New("--tsa-roots is required to verify tokens")
	}
	pemBytes, err := os.ReadFile(f.TSARoots)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("%s holds no certificates", f.TSARoots)
	}
	var vopts []rfc3161.Option
	if f.TSAPolicy != "" {
		oid, err := parseOID(f.TSAPolicy)
		if err != nil {
			return nil, err
		}
		vopts = append(vopts, rfc3161.WithRequiredPolicies(oid))
	}
	if f.EUTLCache != "" {
		lopts := []eutl.Option{eutl.WithCacheDir(f.EUTLCache)}
		if f.EUTLOffline {
			lopts = append(lopts, eutl.WithOffline())
		}
		list, err := eutl.NewLoader(lopts...).Load(ctx)
		if err != nil {
			return nil, fmt.Errorf("eu trusted list: %w", err)
		}
		vopts = append(vopts, rfc3161.WithQualifiedChecker(eutl.Checker(list, nil)))
	}
	verifier := rfc3161.NewVerifier(roots, vopts...)
	if needClient && f.TSAURL == "" {
		return nil, errors.New("--tsa-url is required")
	}
	var client *rfc3161.Client
	if f.TSAURL != "" {
		client = rfc3161.New(f.TSAURL, rfc3161.WithUserAgent("tamperlog/"+version))
	}
	return rfc3161.NewProvider(client, verifier), nil
}

func loadEd25519Private(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path) //nolint:gosec // operator-supplied key path
	if err != nil {
		return nil, err
	}
	if block, _ := pem.Decode(b); block != nil {
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		priv, ok := key.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%s: not an Ed25519 key", path)
		}
		return priv, nil
	}
	if len(b) == ed25519.PrivateKeySize {
		return ed25519.PrivateKey(b), nil
	}
	if len(b) == ed25519.SeedSize {
		return ed25519.NewKeyFromSeed(b), nil
	}
	return nil, fmt.Errorf("%s: not a PEM PKCS#8 key, a 64-byte private key or a 32-byte seed", path)
}

func ignoreCancel(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return nil
	}
	return err
}
