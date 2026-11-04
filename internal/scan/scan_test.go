package scan

import (
	"encoding/base64"
	"errors"
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"
	"time"
)

// Every secret-looking fixture is generated at runtime so no string in
// this file looks like a real credential to repository scanners.

const (
	upperDigits = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	digits      = "0123456789"
	hexChars    = "0123456789abcdef"
	b64Std      = alnum + "+/"
)

type gen struct{ r *rand.Rand }

func newGen(t *testing.T) *gen {
	t.Helper()
	return &gen{rand.New(rand.NewPCG(20261105, 7))}
}

func (g *gen) chars(alphabet string, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[g.r.IntN(len(alphabet))]
	}
	return string(b)
}

// mixed returns a random string with upper case, lower case and digits
// that contains no placeholder word.
func (g *gen) mixed(alphabet string, n int) string {
	for {
		s := g.chars(alphabet, n)
		if hasUpper(s) && hasLower(s) && hasDigit(s) && !isPlaceholderToken(s) && !isPlaceholder(s) {
			return s
		}
	}
}

type positive struct {
	name   string
	rule   string
	line   string
	secret string
}

func positives(t *testing.T) []positive {
	g := newGen(t)
	var ps []positive
	add := func(name, rule, line, secret string) {
		ps = append(ps, positive{name, rule, line, secret})
	}

	// private-key
	begin, end := "-----BEGIN ", "PRIVATE KEY-----"
	for _, kind := range []string{"", "RSA ", "EC ", "DSA ", "OPENSSH ", "ENCRYPTED "} {
		h := begin + kind + end
		add("pem "+kind, RulePrivateKey, h, h)
	}
	pgp := begin + "PGP PRIVATE KEY BLOCK-----"
	add("pgp", RulePrivateKey, pgp, pgp)
	inline := `key := "` + begin + end + `\n` + g.chars(b64Std, 64) + `"`
	add("pem in string literal", RulePrivateKey, inline, inline)
	ssh2 := "---- BEGIN SSH2 ENCRYPTED " + "PRIVATE KEY ----"
	add("ssh2", RulePrivateKey, ssh2, ssh2)
	putty := "PuTTY-User-Key-File-" + "3: ssh-ed25519"
	add("putty", RulePrivateKey, putty, putty)
	age := "AGE-SECRET-KEY-1" + g.chars(upperDigits, 58)
	add("age", RulePrivateKey, "identity: "+age, age)

	// aws-access-key-id
	k := "AKIA" + strings.Repeat("Q", 16)
	add("aws akia", RuleAWSAccessKeyID, "aws_access_key_id = "+k, k)
	k = "ASIA" + g.chars(upperDigits, 16)
	add("aws asia", RuleAWSAccessKeyID, "creds: id="+k+" (temporary)", k)

	// github-token
	for _, p := range []string{"ghp", "gho", "ghu", "ghs", "ghr"} {
		k = p + "_" + g.chars(alnum, 36)
		add("github "+p, RuleGitHubToken, "git clone https://"+k+"@git.example.test/x", k)
	}
	k = "github" + "_pat_" + g.chars(alnum, 22) + "_" + g.chars(alnum, 59)
	add("github fine-grained", RuleGitHubToken, "use "+k, k)

	// slack-token
	k = "xox" + "b-" + g.chars(digits, 12) + "-" + g.chars(digits, 13) + "-" + g.chars(alnum, 24)
	add("slack bot", RuleSlackToken, "SLACK_BOT="+k, k)
	k = "xox" + "p-" + g.chars(digits, 11) + "-" + g.chars(digits, 12) + "-" + g.chars(hexChars, 32)
	add("slack user", RuleSlackToken, k, k)
	k = "xapp-1-" + g.chars(upperDigits, 11) + "-" + g.chars(digits, 13) + "-" + g.chars(hexChars, 64)
	add("slack app", RuleSlackToken, k, k)
	k = "https://hooks.slack.com/services/T" + g.chars(upperDigits, 10) + "/B" + g.chars(upperDigits, 10) + "/" + g.chars(alnum, 24)
	add("slack webhook", RuleSlackToken, "post to "+k, k)

	// stripe-live-key
	k = "sk" + "_live_" + g.chars(alnum, 24)
	add("stripe secret", RuleStripeLiveKey, "stripe "+k, k)
	k = "rk" + "_live_" + g.chars(alnum, 24)
	add("stripe restricted", RuleStripeLiveKey, k, k)

	// google-api-key
	k = "AI" + "za" + g.chars(base64URLCh, 35)
	add("google", RuleGoogleAPIKey, "https://maps.example.test/api?key="+k+"&q=x", k)

	// api-key
	k = "sk-" + "ant-api03-" + g.mixed(base64URLCh, 80)
	add("sk-ant", RuleAPIKey, "the key is "+k, k)
	k = "sk-" + "proj-" + g.mixed(base64URLCh, 48)
	add("sk-proj", RuleAPIKey, k, k)
	k = "sk-" + g.mixed(alnum, 48)
	add("sk plain", RuleAPIKey, `"`+k+`"`, k)

	// jwt
	enc := base64.RawURLEncoding.EncodeToString
	k = enc([]byte(`{"alg":"HS256","typ":"JWT"}`)) + "." +
		enc([]byte(`{"sub":"peer-b","iat":1793824000}`)) + "." + g.chars(base64URLCh, 43)
	add("jwt", RuleJWT, "Authorization: Bearer "+k, k)
	add("jwt alone", RuleJWT, k, k)

	// url-credentials
	pw := g.mixed(alnum, 16)
	add("postgres url", RuleURLCredentials, "DATABASE_URL=postgres://app:"+pw+"@db.example.test:5432/app", pw)
	pw = g.mixed(alnum, 20)
	add("redis url no user", RuleURLCredentials, "redis://:"+pw+"@cache.example.test:6379/0", pw)
	pw = g.mixed(alnum, 12) + "!"
	add("https url", RuleURLCredentials, "git remote add origin https://deploy:"+pw+"@git.example.test/repo.git", pw)

	// credential-assignment
	ca := func(name, prefix, suffix string) {
		s := g.mixed(alnum, 16)
		add("assign "+name, RuleCredentialAssignment, prefix+s+suffix, s)
	}
	ca("env", "DB_PASSWORD=", "")
	ca("export", "export API_KEY=", "")
	ca("export quoted", `export API_KEY="`, `"`)
	ca("yaml", "client_secret: ", "")
	ca("yaml indented list", "  - POSTGRES_PASSWORD=", "")
	ca("json", `  "password": "`, `",`)
	ca("json camel", `{"apiKey": "`, `"}`)
	ca("cli flag", "mysql --user=app --password=", " db")
	ca("curl data", `curl -d "password=`, `" https://x.example.test`)
	ca("python", "password = '", "'")
	ca("js const", `const secretKey = "`, `";`)
	ca("go struct literal", `	Token: "`, `",`)
	ca("go short decl literal", `token := "`, `"`)
	ca("php", `'password' => '`, `'`)
	ca("pgpassword", "PGPASSWORD=", "")
	ca("properties", "spring.datasource.password=", "")
	ca("python environ", `os.environ["SECRET_KEY"] = "`, `"`)
	ca("db pass", "DB_PASS=", "")
	ca("smtp pass", "smtp_pass: ", "")
	ca("escaped quotes", `"password": "\"`, `\""`)
	ca("auth token yaml", "AUTH_TOKEN: ", "")
	ca("header", "x-api-key: ", "")
	ca("logfmt", "level=info user=app token=", " took=3ms")
	ca("toml", `access_key = "`, `"`)
	ca("crlf", "SECRET=", "\r")
	ca("diff added line", "+GITHUB_TOKEN=", "")
	ca("query string", "GET /v1/items?limit=5&access_token=", " HTTP/1.1")
	ca("bearer header", "Authorization: Bearer ", "")
	ca("bearer curl", `curl -H "Authorization: Bearer `, `" https://x.example.test`)
	ca("basic header", "Authorization: Basic ", "")
	s := g.chars(hexChars, 64)
	add("assign hex", RuleCredentialAssignment, "private_key = "+s, s)
	s = "0x" + g.chars(hexChars, 64)
	add("assign 0x hex", RuleCredentialAssignment, "PRIVATE_KEY="+s, s)
	s = base64.StdEncoding.EncodeToString([]byte("app:" + g.mixed(alnum, 12)))
	add("basic in go string", RuleCredentialAssignment, `fmt.Printf("Authorization: Basic `+s+`\n\n")`, s)
	s = "p@ss-" + g.mixed(alnum, 10) + "#!"
	add("assign symbols", RuleCredentialAssignment, `password: "`+s+`"`, s)
	// Letters only but not made of words (fixed so the generator cannot
	// produce a digit-free word by chance).
	s = "QwErTyUiOpAsDf"
	add("assign letters", RuleCredentialAssignment, "DB_PASSWORD="+s, s)

	// high-entropy-near-keyword
	s = g.mixed(alnum, 40)
	add("entropy token", RuleHighEntropyKeyword, "the deploy token is "+s, s)
	s = g.mixed(b64Std, 44)
	add("entropy secret b64", RuleHighEntropyKeyword, "here is the secret, "+s+" , keep it safe", s)
	s = g.mixed(base64URLCh, 64)
	add("entropy auth", RuleHighEntropyKeyword, "auth header value follows "+s, s)
	return ps
}

func wantText(rule string, line int) string {
	where := fmt.Sprintf("on line %d", line)
	if line == 0 {
		where = "in the subject"
	}
	return "possible " + rule + " " + where + "; remove it before sending (Postern blocks messages that look like secrets)"
}

func TestPositives(t *testing.T) {
	for _, p := range positives(t) {
		t.Run(p.name, func(t *testing.T) {
			body := "Hi,\n\nhere is the thing you asked for:\n" + p.line + "\nthanks"
			err := Check("status update", body)
			var f *Finding
			if !errors.As(err, &f) {
				t.Fatalf("no finding for %s", p.rule)
			}
			if f.Rule != p.rule || f.Line != 4 {
				t.Fatalf("got rule %s line %d, want %s line 4", f.Rule, f.Line, p.rule)
			}
			if err.Error() != wantText(p.rule, 4) {
				t.Fatalf("error text: %q", err.Error())
			}
			if strings.Contains(err.Error(), p.secret) || strings.Contains(err.Error(), strings.TrimSpace(p.line)) {
				t.Fatal("error text contains the secret")
			}
			for i := 0; i+8 <= len(p.secret); i++ {
				if strings.Contains(err.Error(), p.secret[i:i+8]) && !strings.Contains(wantText(p.rule, 4), p.secret[i:i+8]) {
					t.Fatal("error text contains part of the secret")
				}
			}

			// The same text in the subject reports line 0.
			if !strings.ContainsAny(p.line, "\r\n") {
				err = Check(p.line, "ordinary body")
				if !errors.As(err, &f) || f.Rule != p.rule || f.Line != 0 {
					t.Fatalf("subject: got %v", err)
				}
				if err.Error() != wantText(p.rule, 0) || strings.Contains(err.Error(), p.secret) {
					t.Fatalf("subject error text: %q", err.Error())
				}
			}
		})
	}
}

func TestEveryRuleHasPositive(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range positives(t) {
		seen[p.rule] = true
	}
	for _, r := range rules {
		if !seen[r.name] {
			t.Errorf("rule %s has no positive fixture", r.name)
		}
	}
}

func TestLineNumbers(t *testing.T) {
	g := newGen(t)
	pw := g.mixed(alnum, 16)
	body := "line one\nline two\n\nDB_PASSWORD=" + pw + "\nline five\nAPI_KEY=" + g.mixed(alnum, 16)
	var f *Finding
	if err := Check("hello", body); !errors.As(err, &f) || f.Line != 4 || f.Rule != RuleCredentialAssignment {
		t.Fatalf("got %+v", err)
	}
	// CRLF line endings count the same.
	crlf := strings.ReplaceAll(body, "\n", "\r\n")
	if err := Check("hello", crlf); !errors.As(err, &f) || f.Line != 4 {
		t.Fatalf("crlf: got %+v", err)
	}
	// First line.
	if err := Check("hello", "SECRET="+pw); !errors.As(err, &f) || f.Line != 1 {
		t.Fatalf("first line: got %+v", err)
	}
	// Subject wins over body.
	if err := Check("token "+g.mixed(alnum, 40), body); !errors.As(err, &f) || f.Line != 0 {
		t.Fatalf("subject: got %+v", err)
	}
	// Last line without trailing newline, and with one.
	if err := Check("x", "a\nb\nSECRET="+pw); !errors.As(err, &f) || f.Line != 3 {
		t.Fatalf("last line: got %+v", err)
	}
	if err := Check("x", "a\nb\nSECRET="+pw+"\n"); !errors.As(err, &f) || f.Line != 3 {
		t.Fatalf("last line with newline: got %+v", err)
	}
}

func negatives(t *testing.T) map[string]string {
	g := newGen(t)
	h1, h2, h3 := g.chars(hexChars, 40), g.chars(hexChars, 40), g.chars(hexChars, 40)
	raw := make([]byte, 300)
	for i := range raw {
		raw[i] = byte(g.r.IntN(256))
	}
	b64 := base64.StdEncoding.EncodeToString(raw)
	var wrapped strings.Builder
	for i := 0; i < len(b64); i += 76 {
		wrapped.WriteString(b64[i:min(i+76, len(b64))])
		wrapped.WriteByte('\n')
	}

	return map[string]string{
		"prose": `Thanks for the review. I rotated the session tokens on machine B and the
auth loop is gone. The secret to making this work was retrying with backoff;
the password prompt no longer appears. Next I will look at the token refresh
path and the API key rotation docs. Let me know if you want a call.`,

		"go code": "type Config struct {\n" +
			"\tPassword string `json:\"password\"`\n" +
			"\tAPIToken string `json:\"api_token,omitempty\"`\n" +
			"}\n\n" +
			"func refresh(ctx context.Context) error {\n" +
			"\ttoken := getToken()\n" +
			"\tif token == \"\" {\n" +
			"\t\treturn errors.New(\"token: empty\")\n" +
			"\t}\n" +
			"\tpassword := os.Getenv(\"DB_PASSWORD\")\n" +
			"\tsecret, err := store.Get(secrets.BoxPrivateKey)\n" +
			"\tcfg.Token = token\n" +
			"\tcfg.Password = password\n" +
			"\treq.Header.Set(\"Authorization\", \"Bearer \"+token)\n" +
			"\tconst BoxPrivateKey = \"box-private-key\"\n" +
			"\tvar apiKey = cfg.APIKey\n" +
			"\topts := Options{Token: tok, Secret: secret, Password: pw}\n" +
			"\treturn nil\n" +
			"}\n",

		"ts code": "interface Session {\n" +
			"  token: string;\n" +
			"  refreshToken?: string;\n" +
			"  apiKey: string | undefined;\n" +
			"  password: Promise<string>;\n" +
			"}\n" +
			"const auth = useAuth();\n" +
			"const { accessToken } = await auth.getSession();\n" +
			"const headers = { Authorization: `Bearer ${accessToken}` };\n" +
			"this.password = hashPassword(input.password);\n" +
			"export const API_KEY = process.env.API_KEY;\n" +
			"const secret = await vault.read(\"kv/app\");\n" +
			"tokens.map(token => token.trim());\n" +
			"if (password === confirmPassword) { submit(); }\n",

		"python code": "def login(username: str, password: str) -> Session:\n" +
			"    token = client.fetch_token(token_url, client_secret=settings.CLIENT_SECRET)\n" +
			"    api_key = os.environ[\"API_KEY\"]\n" +
			"    secret = None\n" +
			"    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())\n" +
			"    return Session(token=token, api_key=api_key)\n",

		"git diff": "diff --git a/internal/auth/token.go b/internal/auth/token.go\n" +
			"index " + h1[:7] + ".." + h2[:7] + " 100644\n" +
			"--- a/internal/auth/token.go\n" +
			"+++ b/internal/auth/token.go\n" +
			"@@ -12,7 +12,8 @@ func refreshToken(ctx context.Context) (string, error) {\n" +
			"-\ttoken := os.Getenv(\"TOKEN\")\n" +
			"+\ttoken, err := loadToken(ctx)\n" +
			"+\tif err != nil {\n" +
			"+\t\treturn \"\", fmt.Errorf(\"auth: load token: %w\", err)\n" +
			"+\t}\n" +
			" \treturn token, nil\n",

		"git log": "commit " + h1 + "\n" +
			"Author: Operator <operator@example.com>\n" +
			"Date:   Wed Nov 5 10:12:00 2026 +0000\n\n" +
			"    Rotate session tokens on reconnect\n\n" +
			"    Token refresh now retries with backoff. Fixes the auth loop seen\n" +
			"    when the relay restarts.\n\n" +
			"commit " + h2 + "\n" +
			"Merge: " + h2[:7] + " " + h3[:7] + "\n" +
			h3 + " fix token refresh and secret rotation\n" +
			h1[:7] + " auth: reseal on retry\n",

		"uuids": "request_id: 550e8400-e29b-41d4-a716-446655440000\n" +
			"trace 6ba7b810-9dad-11d1-80b4-00c04fd430c8 failed auth after token refresh\n" +
			"thread t-01JC9Z7Q3K8M2N4P6R8S0T2V4W session reviewer\n",

		"base64 data": "data: " + b64 + "\n" + wrapped.String() + "fixture := \"" + b64 + "\"\n",

		"go stack trace": "panic: runtime error: invalid memory address or nil pointer dereference\n" +
			"[signal SIGSEGV: segmentation violation code=0x2 addr=0x18 pc=0x1024a3f5c]\n\n" +
			"goroutine 42 [running]:\n" +
			"postern/internal/bridge.(*Bridge).refreshToken(0x14000126000, {0x102b8e0a8, 0x14000110050})\n" +
			"\t/home/operator/src/postern/internal/bridge/token.go:88 +0x2c\n" +
			"postern/internal/bridge.(*Bridge).Run(0x14000126000, {0x102b8e0a8, 0x14000110050})\n" +
			"\t/home/operator/src/postern/internal/bridge/bridge.go:141 +0x1a8\n" +
			"created by main.main in goroutine 1\n" +
			"\t/home/operator/src/postern/cmd/postern/main.go:57 +0x3c4\n",

		"python traceback": "Traceback (most recent call last):\n" +
			"  File \"/app/auth/session.py\", line 42, in refresh_token\n" +
			"    token = client.fetch_token(token_url, client_secret=settings.CLIENT_SECRET)\n" +
			"KeyError: 'access_token'\n",

		"markdown": "# Token rotation\n\n" +
			"- **Password**: at least 12 characters\n" +
			"- Set `API_KEY=<your-key>` in `.env`\n" +
			"- Use `DB_PASSWORD=changeme` locally\n\n" +
			"| Setting | Value |\n|---|---|\n| `token_ttl` | `3600` |\n\n" +
			"> Never paste secrets into a reply.\n\n" +
			"```sh\nexport GITHUB_TOKEN=$(gh auth token)\n```\n",

		"urls without credentials": "See https://docs.example.com/auth/tokens?view=reference#rotation\n" +
			"and https://user@git.example.test/repo.git or ssh://git@git.example.test:22/repo.git\n" +
			"and http://[::1]:8080/healthz\n",

		"non-secret settings": "TOKEN_URL=https://auth.example.com/oauth/token\n" +
			"SECRET_NAME=db-credentials-prod\n" +
			"PASSWORD_MIN_LENGTH=12\n" +
			"AUTH_PROVIDER=oidc-provider-2\n" +
			"max_tokens: 4096\n" +
			"TOKEN_TTL=86400\n" +
			"PWD=/home/operator/src/postern\n" +
			"OLDPWD=/home/operator\n" +
			"token_expires_at: 2026-11-05T10:00:00Z\n" +
			"SSH_PRIVATE_KEY=/home/operator/.ssh/id_ed25519\n" +
			"ACCESS_KEY_ID_FILE=/run/secrets/aws\n" +
			"grant_type: client_credentials\n" +
			`"token_type": "Bearer",` + "\n" +
			`"tokenExpired": "Your session token has expired. Please sign in again.",` + "\n" +
			"password: !vault |\n" +
			"password: *default_password\n" +
			"token: ${{ secrets.DEPLOY_TOKEN }}\n" +
			"DB_PASSWORD=postgres://...\n" +
			"API_KEY=sk-...\n" +
			"DATABASE_URL=postgres://postgres:" + "postgres@localhost:5432/app\n" +
			"REDIS_URL=redis://:${REDIS_PASSWORD}@cache:6379\n" +
			"MYSQL_URL=mysql://root:<password>@db/app\n" +
			"// \tgroupname:password:GID:user_list\n" +
			"const secretValue = 0x53c237_53c237\n" +
			"\tSIOCGLIFTOKEN                 = -0x3f879678\n" +
			"\tfmt.Printf(\"Authorization: Basic invalid\\n\\n\")\n" +
			"// JSON Web Tokens: base64url header and payload (both JSON objects,\n" +
			"Secret: sha256 of the key, then hex\n" +
			"token = base64url of the payload\n" +
			"\twwwAuth := \"Bearer resource_metadata=\" + url\n" +
			"\tTokenTypeSAML2 = \"urn:ietf:params:oauth:token-type:saml2\"\n" +
			"\tsecretPath := \"kv/data/app2/api-token\"\n" +
			"\tconst privateKeyAuthMagic = \"openssh-key-v1\\x00\"\n" +
			"\t\"secret\":                               \"\\u3299\\ufe0f\",\n" +
			"--- PASS: TestSeal/very/nested/s/u/b/t/e/s/t\n" +
			"PASS: very/nested/s/u/b/t/e/s/t\n",

		"llm usage": `{"usage": {"input_tokens": 1234, "output_tokens": 567}, "stop_reason": "end_turn"}` + "\n" +
			"The model used 12,345 tokens; request id req_011" + g.mixed(alnum, 21) + ".\n",

		"go test output": "--- FAIL: TestTokenRefresh_rejects_expired_tokens_after_rotation (0.00s)\n" +
			"    token_test.go:42: got status 401, want 200\n" +
			"FAIL\tpostern/internal/auth\t0.512s\n" +
			"ok  \tpostern/internal/secrets\t1.507s\n",

		"commit links near keywords": "* **api:** add token budgets ([6e758a9](https://git.example.test/org/sdk-go/commit/" + h1 + "))\n" +
			"* redact api-key headers in debug logs ([" + h2[:7] + "](https://git.example.test/org/sdk-go/commit/" + h2 + "))\n",

		"word-built tokens near keywords": "\t\"auth/2025-03-26-oauth-endpoint-fallback\",\n" +
			"The token [mitigation](https://spec.example.com/specification/2025-06-18/basic/security_best_practices#m-2)\n",

		"sk lookalikes": "the task-loading-spinner-container-item class and sk-loading-spinner-container-item\n" +
			"xoxb-your-token-here and ghp_" + strings.Repeat("x", 36) + "\n" +
			"AKIA" + "IOSFODNN7" + "EXAMPLE is the documented example id\n",
	}
}

func TestNegatives(t *testing.T) {
	for name, body := range negatives(t) {
		t.Run(name, func(t *testing.T) {
			if err := Check("status update", body); err != nil {
				lines := strings.Split(body, "\n")
				var f *Finding
				if errors.As(err, &f) && f.Line >= 1 && f.Line <= len(lines) {
					t.Fatalf("%v: %q", err, lines[f.Line-1])
				}
				t.Fatal(err)
			}
		})
	}
}

func TestPlaceholdersDoNotTrigger(t *testing.T) {
	values := []string{
		"", "changeme", "change-me", "change_me", "CHANGEME", "example", "example-password-1",
		"xxx", "xxxxxxxxxxxx", "XXXX-XXXX-XXXX", "***", "****", "************", "<your-key>",
		"<API_KEY>", "${API_KEY}", "${DB_PASSWORD:-dev}", "$API_KEY", "{{ .Values.apiKey }}",
		"{{apiKey}}", "your-api-key", "your_api_key_here", "YOUR_API_KEY", "redacted", "[REDACTED]",
		"placeholder", "dummy", "dummy-secret-123", "test", "none", "None", "null", "nil", "true",
		"false", "undefined", "short1", "abc123", "%API_KEY%", "sample-token-42", "00000000",
		"sk-...", "ghp_...abcd", "test-token-1234", "insert-your-key", "REPLACE_ME", "password",
	}
	formats := []string{
		"API_KEY=%s", `"password": "%s"`, "client_secret: %s", "export SECRET_TOKEN='%s'",
		"--password=%s", "Authorization: Bearer %s",
	}
	for _, v := range values {
		for _, f := range formats {
			line := fmt.Sprintf(f, v)
			if err := Check("x", line); err != nil {
				t.Errorf("%q: %v", line, err)
			}
		}
	}
}

func TestCleanReturnsUntypedNil(t *testing.T) {
	err := Check("hello", "world")
	if err != nil {
		t.Fatalf("got %#v", err)
	}
}

func TestPerformance(t *testing.T) {
	g := newGen(t)
	var mixedBody strings.Builder
	for _, b := range negatives(t) {
		mixedBody.WriteString(b)
	}
	base := mixedBody.String()
	for mixedBody.Len() < 32*1024 {
		mixedBody.WriteString(base)
	}
	bodies := map[string]string{
		"realistic":         mixedBody.String()[:32*1024],
		"one long token":    g.chars(b64Std, 32*1024),
		"one long word":     strings.Repeat("a", 32*1024),
		"many assignments":  strings.Repeat("a=", 16*1024),
		"keyword quotes":    strings.Repeat(`token:"`, 32*1024/7),
		"keyword values":    strings.Repeat("token=x", 32*1024/7),
		"open quotes":       strings.Repeat(`password="`+strings.Repeat("y", 1000), 32),
		"pem prefixes":      strings.Repeat("-----BEGIN ", 32*1024/11),
		"sk prefixes":       strings.Repeat("sk-", 32*1024/3),
		"jwt prefixes":      strings.Repeat("eyJ.", 32*1024/4),
		"url prefixes":      strings.Repeat("a://b:", 32*1024/6),
		"short lines":       strings.Repeat("token: v\n", 32*1024/9),
		"entropy + keyword": strings.Repeat("token "+g.chars(hexChars, 60)+" ", 32*1024/67),
	}
	for name, body := range bodies {
		start := time.Now()
		_ = Check("subject", body)
		d := time.Since(start)
		if d > 500*time.Millisecond*raceFactor {
			t.Errorf("%s: Check took %v on %d bytes", name, d, len(body))
		}
		t.Logf("%-18s %6d bytes %v", name, len(body), d)
	}
}

func TestSplitWords(t *testing.T) {
	cases := map[string]string{
		"APIKey":         "api key",
		"OAuth2Token":    "o auth 2 token",
		"GITHUB_TOKEN":   "github token",
		"hashedPassword": "hashed password",
		"x-api-key":      "x api key",
		"api03":          "api 03",
		"":               "",
	}
	for in, want := range cases {
		if got := strings.Join(splitWords(in), " "); got != want {
			t.Errorf("splitWords(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCredentialKeys(t *testing.T) {
	yes := []string{
		"password", "DB_PASSWORD", "PGPASSWORD", "passwd", "db_pwd", "secret", "CLIENT_SECRET",
		"clientsecret", "api_key", "APIKEY", "apiKey", "x-api-key", "private_key", "privateKey",
		"ACCESS_KEY", "aws_secret_access_key", "token", "GITHUB_TOKEN", "accessToken", "csrftoken",
		"auth", "AUTH_TOKEN", "basic_auth", "Authorization", "DB_PASS", "passphrase", "credentials",
	}
	no := []string{
		"author", "tokenizer", "secretary", "passwordless", "pwd", "PWD", "OLDPWD", "TOKEN_URL",
		"SECRET_NAME", "PASSWORD_FILE", "ACCESS_KEY_ID", "auth_provider", "token_type", "key",
		"bypass", "compass", "monkey", "name", "authorized_keys",
	}
	for _, k := range yes {
		if !isCredentialKey(k) {
			t.Errorf("%q should be a credential key", k)
		}
	}
	for _, k := range no {
		if isCredentialKey(k) {
			t.Errorf("%q should not be a credential key", k)
		}
	}
}
