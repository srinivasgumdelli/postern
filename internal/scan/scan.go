// Package scan checks outgoing messages for things that look like
// secrets: private keys, cloud and SaaS tokens, JWTs, credentials in
// URLs, credential assignments and long random strings next to words
// like "token" or "password".
//
// It blocks, never redacts: Check either passes a message unchanged or
// returns a *Finding naming the rule and line. A Finding never carries
// the matched text or anything around it, so it is safe to log and to
// show to the sending session.
//
// The scanner targets accidents (a session pasting an .env file, a key
// or a token into a reply). It is not a defence against a session that
// deliberately encodes a secret; the session guard's human approval
// covers that.
package scan

import (
	"math"
	"regexp"
	"strconv"
	"strings"
)

// Rule names reported in Finding.Rule.
const (
	RulePrivateKey           = "private-key"
	RuleAWSAccessKeyID       = "aws-access-key-id"
	RuleGitHubToken          = "github-token"
	RuleSlackToken           = "slack-token"
	RuleStripeLiveKey        = "stripe-live-key"
	RuleGoogleAPIKey         = "google-api-key"
	RuleAPIKey               = "api-key"
	RuleJWT                  = "jwt"
	RuleURLCredentials       = "url-credentials"
	RuleCredentialAssignment = "credential-assignment"
	RuleHighEntropyKeyword   = "high-entropy-near-keyword"
)

// Finding reports the first rule that matched. Line 0 is the subject;
// body lines are numbered from 1.
type Finding struct {
	Rule string
	Line int
}

// Error names the rule and line only, never the matched text.
func (f *Finding) Error() string {
	where := "on line " + strconv.Itoa(f.Line) + " of the body"
	if f.Line == 0 {
		where = "in the subject"
	}
	return "possible " + f.Rule + " " + where + "; remove it before sending"
}

// Check scans the subject (reported as line 0) and then each body line.
// It returns nil or a *Finding for the first match.
func Check(subject, body string) error {
	for rest := subject; rest != ""; {
		var line string
		line, rest, _ = strings.Cut(rest, "\n")
		if r := scanLine(line); r != "" {
			return &Finding{Rule: r, Line: 0}
		}
	}
	n := 0
	for rest := body; rest != ""; {
		var line string
		line, rest, _ = strings.Cut(rest, "\n")
		n++
		if r := scanLine(strings.TrimSuffix(line, "\r")); r != "" {
			return &Finding{Rule: r, Line: n}
		}
	}
	return nil
}

type rule struct {
	name  string
	match func(line string) bool
}

// rules run in order; the first match on a line wins. Specific token
// formats come before the generic heuristics so the reported rule is
// the most precise one.
var rules = []rule{
	{RulePrivateKey, privateKeyRe.MatchString},
	{RuleAWSAccessKeyID, awsKeyID.match},
	{RuleGitHubToken, githubToken.match},
	{RuleSlackToken, slackToken.match},
	{RuleStripeLiveKey, stripeLiveKey.match},
	{RuleGoogleAPIKey, googleAPIKey.match},
	{RuleAPIKey, apiKey.match},
	{RuleJWT, jwt.match},
	{RuleURLCredentials, urlCredentials},
	{RuleCredentialAssignment, credentialAssignment},
	{RuleHighEntropyKeyword, highEntropyNearKeyword},
}

func scanLine(line string) string {
	if len(line) < 8 {
		return ""
	}
	for _, r := range rules {
		if r.match(line) {
			return r.name
		}
	}
	return ""
}

// ---- private keys ----

// PEM and OpenSSH private key headers (RSA, EC, DSA, OPENSSH, ENCRYPTED,
// PKCS#8, PGP private key blocks, SSH2 "---- BEGIN ... ----"), PuTTY key
// files and age secret keys. The header alone is enough: a session has
// no reason to send one, and a key without its header is caught only by
// the entropy rule.
var privateKeyRe = regexp.MustCompile(
	`-{4,5} ?BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)? ?-{4,5}` +
		`|PuTTY-User-Key-File-[0-9]+:` +
		`|AGE-SECRET-KEY-1[0-9A-Z]{58}`)

// ---- prefixed token formats ----

const (
	alnum       = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	alnumUnder  = alnum + "_"
	base64URLCh = alnum + "_-"
)

// tokenRule matches a token format. A candidate counts only if the
// characters on either side are not in boundary (so the token is not a
// slice of a longer word), it is not an obvious placeholder, and ok
// (when set) accepts it.
type tokenRule struct {
	re       *regexp.Regexp
	boundary string
	ok       func(tok string) bool
}

func (r tokenRule) match(line string) bool {
	for _, loc := range r.re.FindAllStringIndex(line, -1) {
		if loc[0] > 0 && strings.IndexByte(r.boundary, line[loc[0]-1]) >= 0 {
			continue
		}
		if loc[1] < len(line) && strings.IndexByte(r.boundary, line[loc[1]]) >= 0 {
			continue
		}
		tok := line[loc[0]:loc[1]]
		if isPlaceholderToken(tok) {
			continue
		}
		if r.ok != nil && !r.ok(tok) {
			continue
		}
		return true
	}
	return false
}

var (
	// AWS long-term (AKIA) and temporary (ASIA) access key ids.
	awsKeyID = tokenRule{
		re:       regexp.MustCompile(`(?:AKIA|ASIA)[A-Z0-9]{16}`),
		boundary: alnum,
	}
	// GitHub classic tokens (personal, OAuth, user-to-server,
	// server-to-server, refresh) and fine-grained personal tokens.
	githubToken = tokenRule{
		re:       regexp.MustCompile(`(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,}`),
		boundary: alnumUnder,
	}
	// Slack bot, user, app-level and refresh tokens, and incoming
	// webhook URLs. Real tokens contain digits; "xoxb-your-token-here"
	// does not.
	slackToken = tokenRule{
		re: regexp.MustCompile(`xox[abeprs]-[A-Za-z0-9-]{10,}|xapp-[0-9]-[A-Za-z0-9-]{10,}` +
			`|hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]{8,}`),
		boundary: alnum,
		ok:       hasDigit,
	}
	// Stripe live secret and restricted keys.
	stripeLiveKey = tokenRule{
		re:       regexp.MustCompile(`(?:sk|rk)_live_[A-Za-z0-9]{16,}`),
		boundary: alnumUnder,
	}
	// Google API keys.
	googleAPIKey = tokenRule{
		re:       regexp.MustCompile(`AIza[A-Za-z0-9_-]{35}`),
		boundary: base64URLCh,
	}
	// "sk-" style API keys (including "sk-ant-", "sk-proj-"). The part
	// after "sk-" must mix upper case, lower case and digits, which
	// random keys do and kebab-case names ("sk-loading-spinner-...") do
	// not.
	apiKey = tokenRule{
		re:       regexp.MustCompile(`sk-[A-Za-z0-9_-]{20,}`),
		boundary: base64URLCh,
		ok: func(tok string) bool {
			b := tok[3:]
			return hasUpper(b) && hasLower(b) && hasDigit(b)
		},
	}
	// JSON Web Tokens: base64url header and payload (both JSON objects,
	// so both start "eyJ") and a signature.
	jwt = tokenRule{
		re:       regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{16,}`),
		boundary: base64URLCh,
	}
)

// placeholderTokenWords mark a prefixed token as documentation rather
// than a live credential (for example the well-known "...EXAMPLE" keys
// in vendor docs). Random tokens contain these with negligible odds.
var placeholderTokenWords = []string{
	"example", "xxxxxxxx", "placeholder", "redacted", "dummy", "sample", "your", "fake",
}

func isPlaceholderToken(tok string) bool {
	l := strings.ToLower(tok)
	for _, w := range placeholderTokenWords {
		if strings.Contains(l, w) {
			return true
		}
	}
	return false
}

// ---- credentials in URLs ----

// scheme://user:password@host. The user part may be empty
// ("redis://:password@host").
var urlCredRe = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://([^\s/:@]*):([^\s/@]+)@[^\s/@]`)

func urlCredentials(line string) bool {
	if !strings.Contains(line, "://") {
		return false
	}
	for _, m := range urlCredRe.FindAllStringSubmatch(line, -1) {
		user, pass := m[1], m[2]
		if pass == user || isPlaceholder(pass) || isWordLike(pass) || identHasKeywordPart(pass) {
			continue
		}
		return true
	}
	return false
}

// ---- credential assignments ----

// credentialAssignment finds KEY=value, KEY: value, "key": "value",
// key := "value", 'key' => 'value', export KEY=value, --key=value and
// similar, where the key names a credential and the value looks like a
// literal secret rather than code, a placeholder, a reference or prose.
func credentialAssignment(line string) bool {
	n := len(line)
	for i := 0; i < n; {
		if !isKeyChar(line[i]) {
			i++
			continue
		}
		j := i
		for j < n && isKeyChar(line[j]) {
			j++
		}
		run := line[i:j]
		i = j
		key := strings.TrimLeft(run, "-.0123456789")
		if key == "" || len(key) > 128 {
			continue
		}
		k := j
		if k < n && (line[k] == '"' || line[k] == '\'') {
			k++
		}
		if k < n && line[k] == ']' {
			k++
		}
		opAt := skipSpace(line, k)
		op, k := parseOp(line, opAt)
		if op == "" || !isCredentialKey(key) {
			continue
		}
		// "KEY = value" and "KEY: value" also appear in prose and code;
		// "KEY=value" (env files, logfmt, command prefixes) rarely does.
		spaced := opAt > j || (k < n && (line[k] == ' ' || line[k] == '\t'))
		if secretValue(parseValue(line, k), op, spaced) {
			return true
		}
	}
	return false
}

func isKeyChar(c byte) bool {
	return isAlnum(c) || c == '_' || c == '-' || c == '.'
}

func skipSpace(s string, k int) int {
	for k < len(s) && (s[k] == ' ' || s[k] == '\t') {
		k++
	}
	return k
}

// parseOp recognises an assignment operator at s[k:] and returns it and
// the index after it. Comparisons ("==", "=~") and scope separators
// ("::") are not assignments.
func parseOp(s string, k int) (string, int) {
	if k >= len(s) {
		return "", k
	}
	rest := s[k:]
	switch {
	case strings.HasPrefix(rest, ":="):
		return ":=", k + 2
	case strings.HasPrefix(rest, "=>"):
		return "=>", k + 2
	case strings.HasPrefix(rest, "=="), strings.HasPrefix(rest, "=~"), strings.HasPrefix(rest, "::"):
		return "", k
	case rest[0] == '=' || rest[0] == ':':
		return rest[:1], k + 1
	}
	return "", k
}

type value struct {
	text     string
	quoted   bool // was a string literal
	scheme   bool // followed an HTTP auth scheme ("Bearer ...")
	trailing bool // unquoted, and more text (not a comment) follows on the line
}

// maxValueScan bounds how far one value is read, keeping a line full of
// assignments linear in practice.
const maxValueScan = 1024

func parseValue(line string, k int) value {
	k = skipSpace(line, k)
	if k >= len(line) {
		return value{}
	}
	rest := line[k:]
	if len(rest) > maxValueScan {
		rest = rest[:maxValueScan]
	}
	if q := rest[0]; q == '"' || q == '\'' || q == '`' {
		body := rest[1:]
		if end := closingQuote(body, q); end >= 0 {
			body = body[:end]
		}
		if strings.Contains(body, "\\") {
			// "\u3299\ufe0f", "magic-v1\x00": judge the literal text,
			// not its escape sequences.
			body = escapeRe.ReplaceAllString(body, "")
		}
		if s, ok := cutAuthScheme(body); ok {
			return value{text: s, quoted: true, scheme: true}
		}
		return value{text: body, quoted: true}
	}
	word, after := cutUnquoted(rest)
	if isAuthScheme(word) {
		next, _ := cutUnquoted(strings.TrimLeft(after, " \t"))
		return value{text: trimUnquoted(next), scheme: true}
	}
	return value{text: trimUnquoted(word), trailing: moreText(after)}
}

// moreText reports whether s holds anything besides spaces and a
// trailing comment.
func moreText(s string) bool {
	s = strings.TrimLeft(s, " \t\r\f\v")
	return s != "" && !strings.HasPrefix(s, "#") && !strings.HasPrefix(s, "//")
}

// trimUnquoted drops trailing separators and the closing quote of a
// string the assignment sits in: -d "password=x" or -H "Authorization:
// Bearer x".
func trimUnquoted(s string) string {
	return strings.TrimRight(s, ",;\"'`")
}

// cutUnquoted ends an unquoted value at whitespace, a quote or a
// backslash. The last two end the string literal the assignment sits in
// (-d "password=x", "Authorization: Basic x\n").
func cutUnquoted(s string) (word, rest string) {
	if e := strings.IndexAny(s, " \t\r\f\v\"'`\\"); e >= 0 {
		return s[:e], s[e:]
	}
	return s, ""
}

func cutWord(s string) (word, rest string) {
	if e := strings.IndexAny(s, " \t\r\f\v"); e >= 0 {
		return s[:e], s[e:]
	}
	return s, ""
}

func closingQuote(s string, q byte) int {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case q:
			return i
		}
	}
	return -1
}

func isAuthScheme(w string) bool {
	switch strings.ToLower(w) {
	case "bearer", "basic", "token", "bot", "digest":
		return true
	}
	return false
}

func cutAuthScheme(s string) (string, bool) {
	word, rest := cutWord(s)
	if rest == "" || !isAuthScheme(word) {
		return "", false
	}
	return strings.TrimSpace(rest), true
}

var (
	escapeRe      = regexp.MustCompile(`\\(?:u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8}|x[0-9A-Fa-f]{2}|[0-7]{1,3}|.)`)
	dottedIdentRe = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)+$`)
	// Numbers, durations, versions, dates, times and integer-sized hex
	// constants. Longer hex ("0x" + 64 digits) stays a candidate: that is
	// how some private keys are written.
	numericRe   = regexp.MustCompile(`^-?(?:[0-9][0-9.:,_+\-TZ]*[A-Za-z]{0,3}|0[xX][0-9A-Fa-f_]{1,19})$`)
	nameCharsRe = regexp.MustCompile(`^[A-Za-z0-9_.:/-]+$`)
)

// secretValue decides whether an assigned value looks like a literal
// secret. The order matters: cheap placeholder checks first, then shape
// checks, then code heuristics for unquoted values.
func secretValue(v value, op string, spaced bool) bool {
	s := v.text
	if isPlaceholder(s) {
		return false
	}
	if v.scheme {
		// "Authorization: Bearer <x>": unless it is a name or a word,
		// what follows is a credential, whatever its shape.
		return !strings.ContainsAny(s, " \t") && !isWordLike(strings.TrimRight(s, "=")) &&
			!identHasKeywordPart(s)
	}
	if !v.quoted && (op == ":=" || op == "=>") {
		return false // Go short declarations, arrow functions: code
	}
	if v.trailing && (op == ":" || spaced) {
		return false // "Tokens: base64url header and payload": a sentence
	}
	if strings.ContainsAny(s, " \t") {
		return false // prose, messages, i18n strings
	}
	if strings.Contains(s, "://") || looksLikePath(s) || numericRe.MatchString(s) ||
		isWordLike(strings.TrimRight(s, "=")) || identHasKeywordPart(s) {
		return false
	}
	if !v.quoted {
		if strings.ContainsAny(s, "()[]{}<>|\"'`\\") {
			return false // calls, indexing, generics, types: code
		}
		switch s[0] {
		case '$', '%', '@', '&', '*', '!', '#', '?':
			return false // variables, references, YAML tags and anchors
		}
		if dottedIdentRe.MatchString(s) {
			return false // member access: cfg.Password, process.env.X
		}
	}
	return true
}

// metadataSuffixes are last key parts that describe a credential rather
// than hold one (TOKEN_URL, SECRET_NAME, PASSWORD_FILE, ACCESS_KEY_ID).
var metadataSuffixes = setOf(
	"url", "uri", "urls", "endpoint", "host", "hostname", "domain", "path", "file", "filename",
	"dir", "name", "id", "ids", "type", "method", "mode", "provider", "enabled", "enable",
	"disabled", "required", "expiry", "expires", "expiration", "exp", "ttl", "timeout",
	"length", "len", "size", "header", "prefix", "suffix", "format", "arn", "ref", "kind",
	"version", "algorithm", "alg", "scope", "scopes", "issuer", "audience", "port", "region",
	"count", "max", "min", "limit", "field", "param", "env", "var", "policy", "rotation",
	"hint", "label", "location", "store", "manager", "backend", "source", "mount", "cache",
	"duration", "lifetime", "interval", "age", "regex", "pattern", "strength", "at", "on",
	"time", "date", "timestamp", "schema", "help", "description", "message", "msg", "error",
	"text", "title", "placeholder", "link", "flag", "option", "options", "class", "style",
	"icon", "color", "status", "state", "usage", "details",
)

func isCredentialKey(key string) bool {
	if strings.EqualFold(key, "pwd") {
		return false // the shell's working directory
	}
	parts := splitWords(key)
	if len(parts) == 0 || metadataSuffixes[parts[len(parts)-1]] {
		return false
	}
	return hasKeyword(parts, true)
}

// strongKeywords match as a whole part or as the end of one, singular
// or plural: "password", "PGPASSWORD", "clientsecret", "csrftoken".
var strongKeywords = []string{"password", "passwd", "passphrase", "secret", "token"}

// hasKeyword reports whether word parts name a credential: SECRET,
// TOKEN, PASSWORD, PASSWD, PASSPHRASE, PWD, API_KEY/APIKEY,
// PRIVATE_KEY, ACCESS_KEY, CLIENT_SECRET, AUTH, AUTHORIZATION, BEARER,
// CREDENTIAL(S); and PASS as part of a key name (DB_PASS), but not alone
// ("--- PASS: TestX" in test output) and not in prose.
func hasKeyword(parts []string, keyName bool) bool {
	for i, p := range parts {
		for _, kw := range strongKeywords {
			if strings.HasSuffix(p, kw) || strings.HasSuffix(p, kw+"s") {
				return true
			}
		}
		switch p {
		case "pwd", "auth", "authorization", "bearer", "credential", "credentials":
			return true
		case "pass":
			if keyName && len(parts) > 1 {
				return true
			}
		case "api", "private", "access":
			if i+1 < len(parts) && (parts[i+1] == "key" || parts[i+1] == "keys") {
				return true
			}
		}
		if strings.HasSuffix(p, "apikey") || strings.HasSuffix(p, "privatekey") || strings.HasSuffix(p, "accesskey") {
			return true
		}
	}
	return false
}

// identHasKeywordPart reports whether s is a name that itself mentions a
// credential ("apiKeyV2", "GITHUB_TOKEN", "db-secret-2", "kv/app/token",
// "urn:ietf:params:oauth:token-type:jwt"): a reference to a secret, not
// the secret.
func identHasKeywordPart(s string) bool {
	if !nameCharsRe.MatchString(s) {
		return false
	}
	parts := splitWords(s)
	for _, p := range parts {
		if p == "key" || p == "keys" {
			return true
		}
	}
	return hasKeyword(parts, true)
}

// placeholderWords are values (compared case-insensitively) that stand
// in for a secret in docs and examples.
var placeholderWords = setOf(
	"changeme", "change-me", "change_me", "changeit", "example", "redacted", "placeholder",
	"dummy", "test", "none", "null", "nil", "true", "false", "undefined", "password",
	"passwd", "secret", "token",
)

var placeholderSubstrings = []string{
	"example", "placeholder", "redacted", "changeme", "change-me", "change_me", "dummy",
	"sample", "xxxxxxxx", "your-", "your_", "replace-me", "replace_me", "...", "\u2026",
}

var (
	dollarVarRe  = regexp.MustCompile(`^\$[A-Za-z_][A-Za-z0-9_]*$`)
	percentVarRe = regexp.MustCompile(`^%[A-Za-z_][A-Za-z0-9_]*%$`)
)

// isPlaceholder reports whether a value is empty, short or obviously a
// stand-in: changeme, example, xxx..., ***, <...>, ${...}, $VAR,
// {{...}}, your-..., redacted, placeholder, dummy, test, none, null,
// true/false, or shorter than 8 characters.
func isPlaceholder(v string) bool {
	if len(v) < 8 {
		return true
	}
	l := strings.ToLower(v)
	if placeholderWords[l] {
		return true
	}
	for _, s := range placeholderSubstrings {
		if strings.Contains(l, s) {
			return true
		}
	}
	switch {
	case strings.HasPrefix(l, "your"), strings.HasPrefix(l, "test-"), strings.HasPrefix(l, "test_"),
		strings.HasPrefix(l, "${"), strings.HasPrefix(l, "$("), strings.HasPrefix(l, "{{"),
		strings.HasPrefix(l, "<") && strings.HasSuffix(l, ">"),
		strings.HasPrefix(l, "[") && strings.HasSuffix(l, "]"),
		dollarVarRe.MatchString(v), percentVarRe.MatchString(v):
		return true
	}
	return isMask(v)
}

// isMask reports whether v is all one character ("00000000") or only
// mask characters ("xxxx-xxxx", "********").
func isMask(v string) bool {
	same, mask := true, true
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c != v[0] {
			same = false
		}
		if !strings.ContainsRune("xX*#._-", rune(c)) {
			mask = false
		}
	}
	return same || mask
}

func looksLikePath(s string) bool {
	switch {
	case strings.HasPrefix(s, "/"), strings.HasPrefix(s, "./"), strings.HasPrefix(s, "../"),
		strings.HasPrefix(s, "~/"):
		return true
	case len(s) > 2 && isLetter(s[0]) && s[1] == ':' && (s[2] == '\\' || s[2] == '/'):
		return true
	}
	return false
}

// isWordLike reports whether s is made of words: only letters and the
// separators _ - . : /, with at most one part shorter than three letters
// ("client_credentials", "AuthorizationCode", "DB_PASSWORD",
// "REPLACE_ME", "GID:user_list"). Random letter strings split into many
// short parts ("QwErTyUi") and are not word-like.
func isWordLike(s string) bool {
	for i := 0; i < len(s); i++ {
		if !isLetter(s[i]) && strings.IndexByte("_-.:/", s[i]) < 0 {
			return false
		}
	}
	parts := splitWords(s)
	if len(parts) == 0 {
		return false
	}
	short := 0
	for _, p := range parts {
		if len(p) < 3 {
			short++
		}
	}
	return short <= 1
}

// ---- high-entropy strings near a keyword ----

var longTokenRe = regexp.MustCompile(`[A-Za-z0-9+/=_-]{32,}`)

// entropyThreshold separates random base64 and alphanumeric strings of
// 32+ characters (typically 4.4 to 5.2 bits per character) from
// identifiers, paths and English (3.5 to 4.1). Hex never exceeds 4.
const entropyThreshold = 4.2

// urlRe finds URLs. Long strings inside URLs are mostly commit hashes,
// ids and paths; credentials in URLs are covered by url-credentials,
// query-string assignments and the token formats above.
var urlRe = regexp.MustCompile("[A-Za-z][A-Za-z0-9+.-]*://[^\\s<>\"'`)\\]]*")

func highEntropyNearKeyword(line string) bool {
	var urls [][]int
	if strings.Contains(line, "://") {
		urls = urlRe.FindAllStringIndex(line, -1)
	}
	found := false
	for _, loc := range longTokenRe.FindAllStringIndex(line, -1) {
		tok := line[loc[0]:loc[1]]
		if strings.HasPrefix(tok, "/") || !hasDigit(tok) || !hasLetter(tok) ||
			isPlaceholderToken(tok) || builtFromWords(tok) || within(loc, urls) {
			continue
		}
		if shannon(tok) > entropyThreshold {
			found = true
			break
		}
	}
	return found && hasKeyword(splitWords(line), false)
}

// builtFromWords reports whether most of tok is lower-case words with
// a natural share of vowels: paths, slugs and identifiers such as
// "auth/2025-03-26-oauth-endpoint-fallback". At least 60% of the
// characters must sit in parts of 3+ lower-case letters (optionally
// capitalised), with 30%+ vowels among them. Random base64 and mixed
// case strings almost never qualify (under 0.1%); random lower-case
// alphanumeric strings sometimes do (a few percent), an accepted miss.
func builtFromWords(tok string) bool {
	inWords, letters, vowels := 0, 0, 0
	for _, p := range splitWordsCase(tok) {
		w := p
		if isUpper(w[0]) {
			w = w[1:]
		}
		if len(w) < 3 || !isAllLower(w) {
			continue
		}
		inWords += len(p)
		letters += len(p)
		for i := 0; i < len(p); i++ {
			switch p[i] | 0x20 {
			case 'a', 'e', 'i', 'o', 'u':
				vowels++
			}
		}
	}
	return letters > 0 && 10*vowels >= 3*letters && 10*inWords >= 6*len(tok)
}

func isAllLower(s string) bool {
	for i := 0; i < len(s); i++ {
		if !isLower(s[i]) {
			return false
		}
	}
	return true
}

func within(loc []int, spans [][]int) bool {
	for _, sp := range spans {
		if loc[0] >= sp[0] && loc[1] <= sp[1] {
			return true
		}
	}
	return false
}

func shannon(s string) float64 {
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	n := float64(len(s))
	h := 0.0
	for _, c := range counts {
		if c > 0 {
			p := float64(c) / n
			h -= p * math.Log2(p)
		}
	}
	return h
}

// ---- helpers ----

// splitWords splits s into lower-case word parts at non-alphanumeric
// characters, camelCase boundaries and letter/digit boundaries:
// "APIKey" -> api, key; "OAuth2Token" -> o, auth, 2, token.
func splitWords(s string) []string {
	parts := splitWordsCase(s)
	for i, p := range parts {
		parts[i] = strings.ToLower(p)
	}
	return parts
}

// splitWordsCase is splitWords without lower-casing.
func splitWordsCase(s string) []string {
	var parts []string
	start := -1
	flush := func(end int) {
		if start >= 0 && end > start {
			parts = append(parts, s[start:end])
		}
		start = -1
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !isAlnum(c) {
			flush(i)
			continue
		}
		if start < 0 {
			start = i
			continue
		}
		p := s[i-1]
		switch {
		case isDigit(c) != isDigit(p), isUpper(c) && isLower(p):
			flush(i)
			start = i
		case isLower(c) && isUpper(p) && i-1 > start:
			flush(i - 1)
			start = i - 1
		}
	}
	flush(len(s))
	return parts
}

func setOf(words ...string) map[string]bool {
	m := make(map[string]bool, len(words))
	for _, w := range words {
		m[w] = true
	}
	return m
}

func isDigit(c byte) bool  { return c >= '0' && c <= '9' }
func isUpper(c byte) bool  { return c >= 'A' && c <= 'Z' }
func isLower(c byte) bool  { return c >= 'a' && c <= 'z' }
func isLetter(c byte) bool { return isUpper(c) || isLower(c) }
func isAlnum(c byte) bool  { return isLetter(c) || isDigit(c) }

func hasClass(s string, f func(byte) bool) bool {
	for i := 0; i < len(s); i++ {
		if f(s[i]) {
			return true
		}
	}
	return false
}

func hasDigit(s string) bool  { return hasClass(s, isDigit) }
func hasUpper(s string) bool  { return hasClass(s, isUpper) }
func hasLower(s string) bool  { return hasClass(s, isLower) }
func hasLetter(s string) bool { return hasClass(s, isLetter) }
