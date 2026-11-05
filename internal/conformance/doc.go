// Package conformance holds the envelope cases that every relay
// implementation must agree on: the Go relay (through envelope.ParseEnvelope)
// and the Cloudflare Worker relay in relay-worker/.
//
// The cases live in testdata/conformance/envelopes.json at the repository
// root. Regenerate them with
//
//	POSTERN_WRITE_CONFORMANCE=1 go test ./internal/conformance -run TestWriteConformance
//
// The package has no non-test code. Its tests check that the committed file
// still matches the generator and that envelope.ParseEnvelope gives the
// expected outcome for every case.
package conformance
