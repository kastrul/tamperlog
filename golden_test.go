package tamperlog_test

// Golden vectors shared with SPEC.md. They pin the shipped encoders and
// hashers: a change here is a wire-format change and needs a new identifier.

const goldenBinaryV1 = "0000000463686174" + // stream "chat"
	"0000000000000001" + // seq 1
	"00065db78dd3b240" + // at 1791892800123456 µs = 2026-10-13T12:00:00.123456Z
	"0000002430313939663561302d303030302d373030302d383030302d303030303030303030303031" + // actor
	"00000000" + // subject absent
	"0000000c6d6573736167652e72656164" + // action "message.read"
	"0000000c636861745f6d657373616765" + // entity "chat_message"
	"0000002430313939663561302d303030302d373030302d383030302d303030303030303030303032" + // entity_id
	"00000020aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" + // payload_hash
	"0000000000000002" + // 2 attributes
	"000000076368616e6e656c" + "00000003776562" + // channel=web
	"00000007707572706f7365" + "0000000974726561746d656e74" // purpose=treatment

var goldenHashes = map[string]string{
	"binary/v1 sha256":     "05442837467699a6f80ddecbe2411c1229d57eeeabdc31f14f4cab453df790a8",
	"binary/v1 sha3-256":   "1a5631c53e73c04f3e1b6ebcaabf95ae78d1f2f2d14c2c7763cb692fcee8f177",
	"binary/v1 sha512-256": "1d878357873dcf8f42aa467dbf49f43fc62fd0d86c299783075adedc4219457d",
	"jcs/v1 sha256":        "b64ded7ed62482209e126edabf485588d40175ca0825e4a8fb1691284a593bea",
	"jcs/v1 sha3-256":      "15b2c7818c12ce5b38b1594899354f925bfcead9fd254bb1eea6f53716448c12",
	"jcs/v1 sha512-256":    "951c040b8002b26f3f20eb8c1be28c19db2a5e1cef72471996151cafb74f0e33",
}

const (
	goldenCommit     = "a210c5e361d74c746baa8733b32260efa121a1c579a7361acbc08dd229daeea1"
	goldenDropDigest = "58d29f1d2731ffcac13c51658d408ba042f00a26d67adc516616c1dc52855cb2"
)
