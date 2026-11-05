package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// node is one line of a (block-style) YAML document: a mapping key with
// an inline value, or a list item ("-"), with the lines nested under it.
type node struct {
	key      string
	value    string
	indent   int
	line     int
	children []*node
}

func (n *node) child(key string) *node {
	for _, c := range n.children {
		if c.key == key {
			return c
		}
	}
	return nil
}

func (n *node) path(keys ...string) *node {
	cur := n
	for _, k := range keys {
		if cur = cur.child(k); cur == nil {
			return nil
		}
	}
	return cur
}

// items returns the entries of a list or mapping node: list items in
// block or flow style, or mapping keys.
func (n *node) items() []string {
	var out []string
	if v := strings.TrimSpace(n.value); strings.HasPrefix(v, "[") && strings.HasSuffix(v, "]") {
		for _, s := range strings.Split(strings.Trim(v, "[]"), ",") {
			if s = unquote(s); s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	for _, c := range n.children {
		if c.key == "-" {
			out = append(out, unquote(c.value))
		} else {
			out = append(out, c.key)
		}
	}
	return out
}

func unquote(s string) string {
	return strings.Trim(strings.TrimSpace(s), `"'`)
}

// stripComment removes a trailing comment that is not inside quotes.
func stripComment(s string) string {
	inS, inD := false, false
	for i, r := range s {
		switch {
		case r == '\'' && !inD:
			inS = !inS
		case r == '"' && !inS:
			inD = !inD
		case r == '#' && !inS && !inD && (i == 0 || s[i-1] == ' ' || s[i-1] == '\t'):
			return s[:i]
		}
	}
	return s
}

func parseYAML(t *testing.T, data []byte) *node {
	t.Helper()
	root := &node{indent: -1}
	stack := []*node{root}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for ln := 1; sc.Scan(); ln++ {
		raw := strings.TrimRight(stripComment(sc.Text()), " \t")
		if strings.TrimSpace(raw) == "" || strings.TrimSpace(raw) == "---" {
			continue
		}
		if strings.Contains(raw, "\t") {
			t.Fatalf("line %d: tab in YAML indentation", ln)
		}
		indent := len(raw) - len(strings.TrimLeft(raw, " "))
		text := strings.TrimSpace(raw)
		n := &node{indent: indent, line: ln}
		if text == "-" || strings.HasPrefix(text, "- ") {
			n.key, n.value = "-", strings.TrimSpace(strings.TrimPrefix(text, "-"))
		} else if k, v, ok := strings.Cut(text, ":"); ok {
			n.key, n.value = unquote(k), strings.TrimSpace(v)
		} else {
			t.Fatalf("line %d: not a key or list item: %q", ln, text)
		}
		for len(stack) > 1 {
			top := stack[len(stack)-1]
			// A list may sit at the same indent as its parent key.
			if top.indent < indent || (n.key == "-" && top.indent == indent && top.key != "-" && top.value == "") {
				break
			}
			stack = stack[:len(stack)-1]
		}
		parent := stack[len(stack)-1]
		parent.children = append(parent.children, n)
		stack = append(stack, n)
		// "- key: value" opens a mapping inside the list item.
		if n.key == "-" {
			if k, v, ok := strings.Cut(n.value, ":"); ok && !strings.HasPrefix(n.value, "[") && !strings.Contains(k, " ") {
				inner := &node{key: unquote(k), value: strings.TrimSpace(v), indent: indent + 2, line: ln}
				n.children = append(n.children, inner)
			}
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return root
}

func walk(n *node, fn func(*node)) {
	fn(n)
	for _, c := range n.children {
		walk(c, fn)
	}
}

func loadCompose(t *testing.T) *node {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "docker-compose.yml"))
	if err != nil {
		t.Fatal(err)
	}
	return parseYAML(t, data)
}

// TestComposePublishesNoPorts: nothing in the compose file publishes or
// exposes a port, or shares the host network, so the relay is reachable
// only through the tunnel.
func TestComposePublishesNoPorts(t *testing.T) {
	root := loadCompose(t)
	walk(root, func(n *node) {
		switch n.key {
		case "ports", "expose":
			t.Errorf("line %d: %q key is not allowed", n.line, n.key)
		case "network_mode", "ipc", "pid", "privileged", "devices", "extra_hosts":
			t.Errorf("line %d: %q is not allowed", n.line, n.key)
		}
	})
	services := root.child("services")
	if services == nil {
		t.Fatal("no services")
	}
	if got := services.items(); !slices.Equal(got, []string{"relay", "cloudflared"}) {
		t.Fatalf("services = %v, want [relay cloudflared]", got)
	}
}

// TestComposeRelayOnlyOnInternalNetwork: the relay is attached to one
// network, and that network is internal (no route out, no host access).
func TestComposeRelayOnlyOnInternalNetwork(t *testing.T) {
	root := loadCompose(t)
	nets := root.path("services", "relay", "networks")
	if nets == nil {
		t.Fatal("relay has no explicit networks (would join the default network)")
	}
	if got := nets.items(); !slices.Equal(got, []string{"relay-internal"}) {
		t.Fatalf("relay networks = %v, want only relay-internal", got)
	}
	internal := root.path("networks", "relay-internal", "internal")
	if internal == nil || internal.value != "true" {
		t.Fatal("networks.relay-internal must set internal: true")
	}
	cf := root.path("services", "cloudflared", "networks")
	if cf == nil {
		t.Fatal("cloudflared has no explicit networks")
	}
	for _, n := range cf.items() {
		if n != "relay-internal" && n != "egress" {
			t.Fatalf("cloudflared joins unexpected network %q", n)
		}
	}
}

func TestComposeContainersHardened(t *testing.T) {
	root := loadCompose(t)
	for _, svc := range []string{"relay", "cloudflared"} {
		s := root.path("services", svc)
		if s == nil {
			t.Fatalf("service %s missing", svc)
		}
		if ro := s.child("read_only"); ro == nil || ro.value != "true" {
			t.Errorf("%s: read_only must be true", svc)
		}
		if c := s.child("cap_drop"); c == nil || !slices.Contains(c.items(), "ALL") {
			t.Errorf("%s: cap_drop must include ALL", svc)
		}
		if c := s.child("cap_add"); c != nil {
			t.Errorf("%s: cap_add is not allowed", svc)
		}
		if so := s.child("security_opt"); so == nil || !slices.Contains(so.items(), "no-new-privileges:true") {
			t.Errorf("%s: security_opt must include no-new-privileges:true", svc)
		}
	}
	if u := root.path("services", "relay", "user"); u == nil || unquote(u.value) != "65532:65532" {
		t.Error("relay must run as 65532:65532")
	}
	hc := root.path("services", "relay", "healthcheck", "test")
	if hc == nil || !strings.Contains(hc.value, "healthcheck") {
		t.Error("relay healthcheck must use the postern-relay healthcheck subcommand")
	}
	img := root.path("services", "cloudflared", "image")
	if img == nil || strings.HasSuffix(img.value, ":latest") || !strings.Contains(img.value, ":") {
		t.Error("cloudflared image must be pinned to a version")
	}
	// The tunnel credentials arrive as a secret, not a bind-mounted file.
	if s := root.path("secrets", "tunnel_credentials", "file"); s == nil {
		t.Error("tunnel credentials must be a compose secret")
	}
}

// serviceSecrets returns source -> target for a service's secrets (long
// or short syntax; the target defaults to the source).
func serviceSecrets(root *node, svc string) map[string]string {
	out := map[string]string{}
	s := root.path("services", svc, "secrets")
	if s == nil {
		return out
	}
	for _, item := range s.children {
		if item.key != "-" {
			continue
		}
		src := item.child("source")
		if src == nil {
			out[unquote(item.value)] = unquote(item.value)
			continue
		}
		target := unquote(src.value)
		if tg := item.child("target"); tg != nil {
			target = unquote(tg.value)
		}
		out[unquote(src.value)] = target
	}
	return out
}

// TestComposeRelayGetsEdgeSecret: the relay, and only the relay, receives
// the edge secret as a compose secret from the gitignored deploy/secrets/
// directory, at the path the example relay.json reads.
func TestComposeRelayGetsEdgeSecret(t *testing.T) {
	root := loadCompose(t)
	f := root.path("secrets", "edge_secret", "file")
	if f == nil || unquote(f.value) != "./deploy/secrets/edge-secret" {
		t.Fatal("secrets.edge_secret.file must be ./deploy/secrets/edge-secret")
	}
	relaySecrets := serviceSecrets(root, "relay")
	target, ok := relaySecrets["edge_secret"]
	if !ok {
		t.Fatal("relay does not receive the edge_secret secret")
	}
	if _, ok := relaySecrets["tunnel_credentials"]; ok {
		t.Error("relay must not receive the tunnel credentials")
	}
	if _, ok := serviceSecrets(root, "cloudflared")["edge_secret"]; ok {
		t.Error("cloudflared must not receive the edge secret")
	}
	if _, ok := serviceSecrets(root, "cloudflared")["tunnel_credentials"]; !ok {
		t.Error("cloudflared lost the tunnel credentials secret")
	}

	example, err := os.ReadFile(filepath.Join("..", "..", "deploy", "relay.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		EdgeSecretFile string `json:"edge_secret_file"`
	}
	if err := json.Unmarshal(example, &cfg); err != nil {
		t.Fatal(err)
	}
	if want := "/run/secrets/" + target; cfg.EdgeSecretFile != want {
		t.Fatalf("relay.example.json edge_secret_file = %q, want %q", cfg.EdgeSecretFile, want)
	}

	// The secret file's directory must stay gitignored.
	gi, err := os.ReadFile(filepath.Join("..", "..", ".gitignore"))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(strings.Split(string(gi), "\n"), "deploy/secrets/") {
		t.Fatal(".gitignore must ignore deploy/secrets/")
	}
}

// TestComposeEdgeSecretNextOverlay: the rotation overlay adds only the
// optional next edge secret, only to the relay, from the gitignored
// secrets directory, at the path the docs tell the operator to put in
// relay.json. The base compose file does not need the next file, so
// normal operation works without it.
func TestComposeEdgeSecretNextOverlay(t *testing.T) {
	base := loadCompose(t)
	if base.path("secrets", "edge_secret_next") != nil {
		t.Fatal("docker-compose.yml must not require the next edge secret; it belongs in the overlay")
	}
	if _, ok := serviceSecrets(base, "relay")["edge_secret_next"]; ok {
		t.Fatal("docker-compose.yml relay must not mount the next edge secret")
	}

	data, err := os.ReadFile(filepath.Join("..", "..", "deploy", "compose.edge-secret-next.yml"))
	if err != nil {
		t.Fatal(err)
	}
	root := parseYAML(t, data)
	walk(root, func(n *node) {
		switch n.key {
		case "ports", "expose", "networks", "network_mode", "ipc", "pid", "privileged", "devices",
			"extra_hosts", "cap_add", "volumes", "image", "build", "command", "user", "read_only",
			"security_opt", "cap_drop", "environment", "env_file":
			t.Errorf("line %d: the overlay must not set %q", n.line, n.key)
		}
	})
	if got := root.child("services").items(); !slices.Equal(got, []string{"relay"}) {
		t.Fatalf("overlay services = %v, want only relay", got)
	}
	if got := root.path("services", "relay").items(); !slices.Equal(got, []string{"secrets"}) {
		t.Fatalf("overlay relay keys = %v, want only secrets", got)
	}
	if got := serviceSecrets(root, "relay"); len(got) != 1 || got["edge_secret_next"] != "edge_secret_next" {
		t.Fatalf("overlay relay secrets = %v, want only edge_secret_next", got)
	}
	if got := root.child("secrets").items(); !slices.Equal(got, []string{"edge_secret_next"}) {
		t.Fatalf("overlay top-level secrets = %v", got)
	}
	f := root.path("secrets", "edge_secret_next", "file")
	if f == nil || unquote(f.value) != "./deploy/secrets/edge-secret-next" {
		t.Fatal("secrets.edge_secret_next.file must be ./deploy/secrets/edge-secret-next")
	}

	// The documented relay.json line names the overlay's mount point.
	for _, doc := range []string{"docs/edge-setup.md", "deploy/compose.edge-secret-next.yml"} {
		b, err := os.ReadFile(filepath.Join("..", "..", doc))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), `"edge_secret_next_file": "/run/secrets/edge_secret_next"`) {
			t.Errorf("%s does not give the relay.json line for the next edge secret", doc)
		}
	}
}

func TestParseYAMLHelper(t *testing.T) {
	root := parseYAML(t, []byte(`
a:
  ports: ["80:80"] # comment
  networks: [x, "y"]
  list:
  - one
  - two
  secrets:
    - source: s
      target: t
`))
	if got := root.path("a", "networks").items(); !slices.Equal(got, []string{"x", "y"}) {
		t.Fatalf("flow list = %v", got)
	}
	if got := root.path("a", "list").items(); !slices.Equal(got, []string{"one", "two"}) {
		t.Fatalf("same-indent list = %v", got)
	}
	if root.path("a", "ports") == nil {
		t.Fatal("ports key not found")
	}
	if len(root.path("a", "secrets").children) != 1 {
		t.Fatal("list item mapping not nested")
	}
}

func TestDockerfileHardening(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	df := string(data)
	for _, want := range []string{
		"CGO_ENABLED=0",
		"-trimpath",
		`-ldflags "-s -w"`,
		"./cmd/postern-relay",
		"gcr.io/distroless/static-debian12:nonroot",
		"USER 65532:65532",
	} {
		if !strings.Contains(df, want) {
			t.Errorf("Dockerfile lacks %q", want)
		}
	}
	for _, line := range strings.Split(df, "\n") {
		if f := strings.Fields(line); len(f) > 1 && strings.EqualFold(f[0], "FROM") && !strings.Contains(f[1], "@sha256:") {
			t.Errorf("base image not pinned by digest: %s", line)
		}
		if f := strings.Fields(line); len(f) > 0 && strings.EqualFold(f[0], "EXPOSE") {
			t.Errorf("Dockerfile must not EXPOSE ports: %s", line)
		}
	}
}

func TestHealthcheckSubcommand(t *testing.T) {
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) }))
	defer ok.Close()
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) }))
	defer bad.Close()
	redirect := httptest.NewServer(http.RedirectHandler(ok.URL, http.StatusFound))
	defer redirect.Close()
	gone := httptest.NewServer(http.NotFoundHandler())
	goneURL := gone.URL
	gone.Close()

	var stderr bytes.Buffer
	cases := map[string]int{ok.URL: 0, bad.URL: 1, redirect.URL: 1, goneURL: 1}
	for url, want := range cases {
		if got := run([]string{"healthcheck", "-url", url}, &stderr); got != want {
			t.Errorf("healthcheck %s = %d, want %d", url, got, want)
		}
	}
}

func TestRunRejectsBadConfig(t *testing.T) {
	var stderr bytes.Buffer
	if got := run([]string{"-config", filepath.Join(t.TempDir(), "missing.json")}, &stderr); got != 1 {
		t.Fatalf("missing config: exit %d", got)
	}
	p := filepath.Join(t.TempDir(), "relay.json")
	if err := os.WriteFile(p, []byte(`{"identity":"header","db":"x","peers":{"peer-a":["<PEER_A_CERT_SHA256>"],"peer-b":["<PEER_B_CERT_SHA256>"]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := run([]string{"-config", p}, &stderr); got != 1 {
		t.Fatalf("placeholder config: exit %d", got)
	}
	if got := run([]string{"-nope"}, &stderr); got != 2 {
		t.Fatalf("bad flag: exit %d", got)
	}
}

// TestRunRejectsBadEdgeSecret: header mode does not start without a usable
// edge secret, and the startup error never prints the file's content.
func TestRunRejectsBadEdgeSecret(t *testing.T) {
	dir := t.TempDir()
	peers := `"peers":{"peer-a":["` + strings.Repeat("a", 64) + `"],"peer-b":["` + strings.Repeat("b", 64) + `"]}`
	const short = "0123456789abcdef0123456789abcde" // one byte short
	const placeholder = "<EDGE_SECRET_FROM_OPENSSL_RAND_HEX_32>"
	for name, content := range map[string]string{"short": short + "\n", "placeholder": placeholder + "\n", "none": ""} {
		t.Run(name, func(t *testing.T) {
			secretPath := filepath.Join(dir, name+"-secret")
			field := `"edge_secret_file":"` + secretPath + `",`
			if name == "none" {
				field = ""
			} else if err := os.WriteFile(secretPath, []byte(content), 0o400); err != nil {
				t.Fatal(err)
			}
			cfg := filepath.Join(dir, name+"-relay.json")
			body := `{"identity":"header","db":"` + filepath.Join(dir, name+".db") + `",` + field + peers + `}`
			if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			var stderr bytes.Buffer
			if got := run([]string{"-config", cfg}, &stderr); got != 1 {
				t.Fatalf("exit %d, want 1", got)
			}
			out := stderr.String()
			if !strings.Contains(out, "edge") {
				t.Fatalf("error does not mention the edge secret: %s", out)
			}
			for _, v := range []string{short, placeholder, "EDGE_SECRET_FROM"} {
				if strings.Contains(out, v) {
					t.Fatalf("stderr contains the secret file's content: %s", out)
				}
			}
		})
	}
}
