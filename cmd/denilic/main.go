// denilic is the deliberately network-free DeniLicense issuer and verifier CLI.
package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/deni336/DeniLicense/internal/claimcode"
	"github.com/deni336/DeniLicense/internal/license"
	"golang.org/x/term"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		usage(stderr)
		return errors.New("a command is required")
	}
	switch args[0] {
	case "keygen":
		return keygen(args[1:], stdout, stderr)
	case "public-key":
		return publicKey(args[1:], stdout, stderr)
	case "issue":
		return issue(args[1:], stdout, stderr)
	case "verify":
		return verify(args[1:], stdout, stderr)
	case "secret":
		return randomSecret(args[1:], stdout)
	case "help", "-h", "--help":
		usage(stdout)
		return nil
	default:
		usage(stderr)
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func usage(w io.Writer) {
	fmt.Fprintln(w, `DeniLicense offline issuer

Commands:
  keygen       Generate a passphrase-encrypted Ed25519 signing key
  public-key   Export the non-secret public-key document
  issue        Generate a claim code and signed offline grant
  verify       Verify and inspect a signed offline grant
  secret       Generate a 32-byte base64url configuration secret

Private-key passphrases are read from a terminal. For non-interactive use,
provide DENILICENSE_KEY_PASSPHRASE through a protected process environment.`)
}

func randomSecret(args []string, stdout io.Writer) error {
	if len(args) != 0 {
		return errors.New("secret does not accept arguments")
	}
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return err
	}
	fmt.Fprintln(stdout, base64.RawURLEncoding.EncodeToString(value))
	wipe(value)
	return nil
}

func keygen(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("keygen", flag.ContinueOnError)
	flags.SetOutput(stderr)
	purposeText := flags.String("purpose", "license", "license or activation")
	privatePath := flags.String("private", "issuer.key.json", "encrypted private-key output")
	publicPath := flags.String("public", "issuer.public.json", "public-key output")
	if err := flags.Parse(args); err != nil {
		return err
	}
	purpose, err := parsePurpose(*purposeText)
	if err != nil {
		return err
	}
	if samePath(*privatePath, *publicPath) {
		return errors.New("private and public paths must differ")
	}
	if pathExists(*privatePath) || pathExists(*publicPath) {
		return errors.New("refusing to overwrite an existing key file")
	}
	passphrase, err := readPassphrase("New key passphrase: ", true, stderr)
	if err != nil {
		return err
	}
	defer wipe(passphrase)
	key, err := license.GenerateSigningKey(purpose)
	if err != nil {
		return err
	}
	encrypted, err := license.EncryptSigningKey(key, passphrase, license.DefaultScryptParams())
	if err != nil {
		return err
	}
	public, err := license.MarshalPublicKey(key.VerificationKey())
	if err != nil {
		return err
	}
	if err := writeNewFile(*privatePath, encrypted, 0o600); err != nil {
		return err
	}
	if err := writeNewFile(*publicPath, public, 0o644); err != nil {
		_ = os.Remove(*privatePath)
		return err
	}
	fmt.Fprintf(stdout, "Key ID: %s\nPrivate key: %s\nPublic key: %s\n", key.KeyID(), *privatePath, *publicPath)
	return nil
}

func publicKey(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("public-key", flag.ContinueOnError)
	flags.SetOutput(stderr)
	privatePath := flags.String("private", "issuer.key.json", "encrypted private-key input")
	publicPath := flags.String("out", "issuer.public.json", "public-key output")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if pathExists(*publicPath) {
		return errors.New("refusing to overwrite an existing public-key file")
	}
	key, err := loadSigningKey(*privatePath, stderr)
	if err != nil {
		return err
	}
	encoded, err := license.MarshalPublicKey(key.VerificationKey())
	if err != nil {
		return err
	}
	if err := writeNewFile(*publicPath, encoded, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Key ID: %s\nPublic key: %s\n", key.KeyID(), *publicPath)
	return nil
}

type entitlementFlags map[string]any

func (e *entitlementFlags) String() string { return "key=value" }

func (e *entitlementFlags) Set(value string) error {
	parts := strings.SplitN(value, "=", 2)
	if len(parts) != 2 || parts[0] == "" {
		return errors.New("entitlement must use key=value")
	}
	if *e == nil {
		*e = make(map[string]any)
	}
	if _, exists := (*e)[parts[0]]; exists {
		return fmt.Errorf("duplicate entitlement %q", parts[0])
	}
	var parsed any
	switch parts[1] {
	case "true":
		parsed = true
	case "false":
		parsed = false
	default:
		if number, err := strconv.ParseInt(parts[1], 10, 64); err == nil {
			parsed = number
		} else {
			parsed = parts[1]
		}
	}
	(*e)[parts[0]] = parsed
	return nil
}

func issue(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("issue", flag.ContinueOnError)
	flags.SetOutput(stderr)
	privatePath := flags.String("key", "issuer.key.json", "encrypted issuer private key")
	issuer := flags.String("issuer", "", "stable issuer identifier")
	product := flags.String("product", "", "product code")
	subject := flags.String("subject", "unassigned", "non-secret customer reference")
	maxActivations := flags.Int("max-activations", 1, "maximum active installations")
	notBeforeText := flags.String("not-before", "", "RFC3339 start (default: now)")
	expiresText := flags.String("expires", "", "RFC3339 expiry")
	validFor := flags.Duration("valid-for", 0, "validity duration, for example 8760h")
	perpetual := flags.Bool("perpetual", false, "explicitly issue without an expiry")
	artifactPath := flags.String("out", "license.dlicense", "signed grant output")
	var entitlements entitlementFlags
	flags.Var(&entitlements, "entitlement", "typed key=value; repeat for multiple entries")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *issuer == "" || *product == "" {
		return errors.New("--issuer and --product are required")
	}
	if pathExists(*artifactPath) {
		return errors.New("refusing to overwrite an existing artifact")
	}
	if (*expiresText != "" && *validFor != 0) || (*perpetual && (*expiresText != "" || *validFor != 0)) {
		return errors.New("choose exactly one expiry mode: --expires, --valid-for, or --perpetual")
	}
	if !*perpetual && *expiresText == "" && *validFor == 0 {
		return errors.New("finite expiry is required unless --perpetual is explicit")
	}
	now := time.Now().UTC().Truncate(time.Second)
	notBefore := now
	var err error
	if *notBeforeText != "" {
		notBefore, err = time.Parse(time.RFC3339, *notBeforeText)
		if err != nil {
			return fmt.Errorf("parse not-before: %w", err)
		}
		notBefore = notBefore.UTC()
	}
	var expiresAt *time.Time
	if *expiresText != "" {
		parsed, err := time.Parse(time.RFC3339, *expiresText)
		if err != nil {
			return fmt.Errorf("parse expires: %w", err)
		}
		parsed = parsed.UTC()
		expiresAt = &parsed
	} else if *validFor != 0 {
		if *validFor < time.Hour || *validFor > 10*365*24*time.Hour {
			return errors.New("--valid-for must be between one hour and ten years")
		}
		parsed := notBefore.Add(*validFor)
		expiresAt = &parsed
	}
	key, err := loadSigningKey(*privatePath, stderr)
	if err != nil {
		return err
	}
	if key.Purpose() != license.PurposeOfflineLicenseIssuer {
		return errors.New("the supplied key is not an offline license issuer key")
	}
	claimCode, claimDigest, suffix, err := claimcode.Generate()
	if err != nil {
		return err
	}
	serial, err := license.GenerateSerial()
	if err != nil {
		return err
	}
	if entitlements == nil {
		entitlements = entitlementFlags{}
	}
	claims := license.Claims{
		Issuer:          *issuer,
		KeyID:           key.KeyID(),
		Audience:        strings.ToUpper(*product),
		Serial:          serial,
		Subject:         *subject,
		ClaimCodeSHA256: license.EncodeClaimCodeSHA256(claimDigest),
		ClaimCodeSuffix: suffix,
		IssuedAt:        now,
		NotBefore:       notBefore,
		ExpiresAt:       expiresAt,
		MaxActivations:  *maxActivations,
		Entitlements:    map[string]any(entitlements),
	}
	artifact, err := license.SignToken(claims, key)
	if err != nil {
		return err
	}
	if err := writeNewFile(*artifactPath, []byte(artifact+"\n"), 0o600); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Claim code (shown once): %s\nArtifact: %s\nSerial: %s\nKey ID: %s\n", claimCode, *artifactPath, serial, key.KeyID())
	return nil
}

func verify(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("verify", flag.ContinueOnError)
	flags.SetOutput(stderr)
	publicPath := flags.String("public", "issuer.public.json", "issuer public key")
	artifactPath := flags.String("artifact", "license.dlicense", "signed grant")
	expectedIssuer := flags.String("issuer", "", "required expected issuer")
	expectedProduct := flags.String("product", "", "required expected product code")
	ignoreTime := flags.Bool("ignore-time", false, "verify signature/schema but not validity window")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if !*ignoreTime && (*expectedIssuer == "" || *expectedProduct == "") {
		return errors.New("--issuer and --product are required unless --ignore-time is explicit")
	}
	publicBytes, err := readBoundedFile(*publicPath, license.MaxKeyFileBytes)
	if err != nil {
		return err
	}
	key, err := license.ParsePublicKey(publicBytes)
	if err != nil {
		return err
	}
	artifactBytes, err := readBoundedFile(*artifactPath, license.MaxTokenBytes+1)
	if err != nil {
		return err
	}
	artifact := strings.TrimSpace(string(artifactBytes))
	var claims license.Claims
	if *ignoreTime {
		claims, err = license.VerifyToken(artifact, key)
	} else {
		claims, err = license.VerifyTokenForUse(artifact, key, license.VerificationOptions{
			ExpectedIssuer: *expectedIssuer, ExpectedAudience: strings.ToUpper(*expectedProduct), Now: time.Now().UTC(), ClockSkew: time.Minute,
		})
	}
	if err != nil {
		return err
	}
	encoded, _ := json.MarshalIndent(claims, "", "  ")
	fmt.Fprintf(stdout, "VALID\n%s\n", encoded)
	return nil
}

func parsePurpose(value string) (license.KeyPurpose, error) {
	switch value {
	case "license":
		return license.PurposeOfflineLicenseIssuer, nil
	case "activation":
		return license.PurposeActivationReceiptSigner, nil
	default:
		return "", errors.New("purpose must be license or activation")
	}
}

func loadSigningKey(path string, stderr io.Writer) (*license.SigningKey, error) {
	encoded, err := readBoundedFile(path, license.MaxKeyFileBytes)
	if err != nil {
		return nil, err
	}
	passphrase, err := readPassphrase("Key passphrase: ", false, stderr)
	if err != nil {
		return nil, err
	}
	defer wipe(passphrase)
	return license.DecryptSigningKey(encoded, passphrase)
}

func readPassphrase(prompt string, confirm bool, stderr io.Writer) ([]byte, error) {
	if value := os.Getenv("DENILICENSE_KEY_PASSPHRASE"); value != "" {
		return []byte(value), nil
	}
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return nil, errors.New("no terminal available; set DENILICENSE_KEY_PASSPHRASE securely")
	}
	fmt.Fprint(stderr, prompt)
	value, err := term.ReadPassword(fd)
	fmt.Fprintln(stderr)
	if err != nil {
		return nil, err
	}
	if confirm {
		fmt.Fprint(stderr, "Confirm passphrase: ")
		repeated, err := term.ReadPassword(fd)
		fmt.Fprintln(stderr)
		if err != nil {
			wipe(value)
			return nil, err
		}
		defer wipe(repeated)
		if string(value) != string(repeated) {
			wipe(value)
			return nil, errors.New("passphrases did not match")
		}
	}
	return value, nil
}

func readBoundedFile(path string, limit int) ([]byte, error) {
	file, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	defer file.Close()
	value, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(value) > limit {
		return nil, errors.New("file exceeds size limit")
	}
	return value, nil
}

func writeNewFile(path string, value []byte, mode os.FileMode) error {
	cleaned := filepath.Clean(path)
	file, err := os.OpenFile(cleaned, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	remove := true
	defer func() {
		_ = file.Close()
		if remove {
			_ = os.Remove(cleaned)
		}
	}()
	if _, err := file.Write(value); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	remove = false
	return nil
}

func pathExists(path string) bool {
	_, err := os.Stat(filepath.Clean(path))
	return err == nil || !errors.Is(err, os.ErrNotExist)
}

func samePath(a, b string) bool {
	a, _ = filepath.Abs(filepath.Clean(a))
	b, _ = filepath.Abs(filepath.Clean(b))
	return strings.EqualFold(a, b)
}

func wipe(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
