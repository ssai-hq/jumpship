package canonical

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"
)

const (
	AlgorithmECDSAP256SHA256 = "ECDSA_P256_SHA256"
	AlgorithmRSAPSSSHA256    = "RSA_PSS_SHA256"
	sha256Size               = 32
)

var contractTimestampPattern = regexp.MustCompile(
	`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z$`,
)

var canonicalBase64Pattern = regexp.MustCompile(
	`^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$`,
)

// SignatureClaims, SignatureEnvelope, and PublicKeyRegistry are generated into
// contract_types.gen.go in this package. The verifier owns behavior and small
// internal projections, never a handwritten copy of a contract DTO.

type verificationKey struct {
	Algorithm    string
	PublicKeyPEM string
	Purposes     []string
	Environments []string
	TenantScope  *string
	ValidFrom    string
	ValidUntil   string
	Status       string
	RevokedAt    *string
}

// VerifyExpectation prevents schema/type/purpose/scope and registry replay.
type VerifyExpectation struct {
	ObjectType          string
	ObjectSchemaID      string
	ObjectSchemaVersion string
	Purpose             string
	Environment         string
	TenantScope         *string
	MigrationScope      *string
	RegistryHash        string
	At                  time.Time
}

// SignDetached creates an ECDSA P-256 or RSA-PSS detached envelope for an
// already schema-validated logical payload. Authority and key custody remain
// outside this dependency-free verification package.
func SignDetached(logicalPayload []byte, claims SignatureClaims, signer crypto.Signer) (SignatureEnvelope, error) {
	if claims.SchemaVersion != "1.0.0" || signer == nil {
		return SignatureEnvelope{}, errors.New("invalid signature envelope claims")
	}
	issuedAt, err := parseContractTime(claims.IssuedAt)
	if err != nil {
		return SignatureEnvelope{}, errors.New("invalid signature issuance time")
	}
	if claims.ExpiresAt != nil {
		expiresAt, expiryErr := parseContractTime(*claims.ExpiresAt)
		if expiryErr != nil || expiresAt.Before(issuedAt) {
			return SignatureEnvelope{}, errors.New("invalid signature expiry time")
		}
	}
	digest, err := TypedDigestHex(claims.ObjectType, claims.ObjectSchemaVersion, logicalPayload)
	if err != nil {
		return SignatureEnvelope{}, err
	}
	claims.PayloadDigest = digest
	canonicalClaims, err := canonicalClaimsBytes(claims)
	if err != nil {
		return SignatureEnvelope{}, err
	}
	claimsHash := sha256.Sum256(canonicalClaims)
	var signature []byte
	switch publicKey := signer.Public().(type) {
	case *ecdsa.PublicKey:
		if claims.Algorithm != AlgorithmECDSAP256SHA256 || publicKey.Curve.Params().Name != "P-256" {
			return SignatureEnvelope{}, errors.New("signature algorithm/key mismatch")
		}
		// crypto.Signer keeps key custody outside this package and permits KMS/HSM
		// implementations as well as local test keys.
		signature, err = signer.Sign(rand.Reader, claimsHash[:], crypto.SHA256)
	case *rsa.PublicKey:
		if claims.Algorithm != AlgorithmRSAPSSSHA256 || publicKey.N.BitLen() < 2048 {
			return SignatureEnvelope{}, errors.New("signature algorithm/key mismatch")
		}
		signature, err = signer.Sign(
			rand.Reader,
			claimsHash[:],
			&rsa.PSSOptions{SaltLength: sha256Size, Hash: crypto.SHA256},
		)
	default:
		return SignatureEnvelope{}, errors.New("unsupported signature key type")
	}
	if err != nil {
		return SignatureEnvelope{}, err
	}
	envelopeID, err := TypedDigestHex("signature_envelope", claims.SchemaVersion, canonicalClaims)
	if err != nil {
		return SignatureEnvelope{}, err
	}
	return SignatureEnvelope{
		SchemaVersion:       claims.SchemaVersion,
		EnvelopeID:          envelopeID,
		ObjectType:          claims.ObjectType,
		ObjectSchemaID:      claims.ObjectSchemaID,
		ObjectSchemaVersion: claims.ObjectSchemaVersion,
		PayloadDigest:       claims.PayloadDigest,
		Purpose:             claims.Purpose,
		Environment:         claims.Environment,
		TenantScope:         claims.TenantScope,
		MigrationScope:      claims.MigrationScope,
		Kid:                 claims.Kid,
		Algorithm:           claims.Algorithm,
		SignerID:            claims.SignerID,
		SignerRole:          claims.SignerRole,
		IssuedAt:            claims.IssuedAt,
		ExpiresAt:           claims.ExpiresAt,
		KeyRegistryID:       claims.KeyRegistryID,
		KeyRegistryHash:     claims.KeyRegistryHash,
		SignatureBase64:     base64.StdEncoding.EncodeToString(signature),
	}, nil
}

// VerifyDetached verifies logical identity, claims, registry scope and status,
// temporal validity, and the algorithm-specific signature bytes.
func VerifyDetached(logicalPayload []byte, envelope SignatureEnvelope, registry PublicKeyRegistry, expected VerifyExpectation) error {
	if err := validateRegistry(registry); err != nil {
		return err
	}
	claims := SignatureClaims{
		SchemaVersion:       envelope.SchemaVersion,
		ObjectType:          envelope.ObjectType,
		ObjectSchemaID:      envelope.ObjectSchemaID,
		ObjectSchemaVersion: envelope.ObjectSchemaVersion,
		PayloadDigest:       envelope.PayloadDigest,
		Purpose:             envelope.Purpose,
		Environment:         envelope.Environment,
		TenantScope:         envelope.TenantScope,
		MigrationScope:      envelope.MigrationScope,
		Kid:                 envelope.Kid,
		Algorithm:           envelope.Algorithm,
		SignerID:            envelope.SignerID,
		SignerRole:          envelope.SignerRole,
		IssuedAt:            envelope.IssuedAt,
		ExpiresAt:           envelope.ExpiresAt,
		KeyRegistryID:       envelope.KeyRegistryID,
		KeyRegistryHash:     envelope.KeyRegistryHash,
	}
	if claims.SchemaVersion != "1.0.0" || claims.ObjectType != expected.ObjectType || claims.ObjectSchemaID != expected.ObjectSchemaID || claims.ObjectSchemaVersion != expected.ObjectSchemaVersion || claims.Purpose != expected.Purpose {
		return errors.New("signature type/schema/purpose replay denied")
	}
	if claims.Environment != expected.Environment || !sameOptionalString(claims.TenantScope, expected.TenantScope) || !sameOptionalString(claims.MigrationScope, expected.MigrationScope) {
		return errors.New("signature scope mismatch")
	}
	if claims.KeyRegistryID != registry.RegistryID || claims.KeyRegistryHash != expected.RegistryHash {
		return errors.New("signature registry binding mismatch")
	}
	registryHash, err := registryDigest(registry)
	if err != nil || registryHash != expected.RegistryHash {
		return errors.New("supplied registry bytes do not match expected registry hash")
	}
	digest, err := TypedDigestHex(claims.ObjectType, claims.ObjectSchemaVersion, logicalPayload)
	if err != nil {
		return err
	}
	if claims.PayloadDigest != digest {
		return errors.New("payload digest mismatch")
	}
	if decoded, decodeErr := hex.DecodeString(claims.PayloadDigest); decodeErr != nil || len(decoded) != sha256Size {
		return errors.New("malformed payload digest")
	}
	issuedAt, err := parseContractTime(claims.IssuedAt)
	if err != nil {
		return errors.New("invalid signature issuance time")
	}
	at := expected.At
	if at.IsZero() {
		return errors.New("verification time is required")
	}
	registryIssuedAt, registryTimeErr := parseContractTime(registry.IssuedAt)
	if registryTimeErr != nil || registryIssuedAt.After(at) {
		return errors.New("registry issuance is after verification time")
	}
	if issuedAt.After(at) {
		return errors.New("signature issuance is after verification time")
	}
	if claims.ExpiresAt != nil {
		expiresAt, expiryErr := parseContractTime(*claims.ExpiresAt)
		if expiryErr != nil || expiresAt.Before(issuedAt) || at.After(expiresAt) {
			return errors.New("signature envelope expired")
		}
	}
	key, err := findEligibleKey(registry, claims, issuedAt, at)
	if err != nil {
		return err
	}
	canonicalClaims, err := canonicalClaimsBytes(claims)
	if err != nil {
		return err
	}
	envelopeID, err := TypedDigestHex("signature_envelope", claims.SchemaVersion, canonicalClaims)
	if err != nil || envelopeID != envelope.EnvelopeID {
		return errors.New("derived envelope identity mismatch")
	}
	if !canonicalBase64Pattern.MatchString(envelope.SignatureBase64) {
		return errors.New("invalid detached signature encoding")
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(envelope.SignatureBase64)
	if err != nil {
		return errors.New("invalid detached signature encoding")
	}
	claimsHash := sha256.Sum256(canonicalClaims)
	publicKey, err := parsePublicKey(key.PublicKeyPEM)
	if err != nil {
		return err
	}
	switch typed := publicKey.(type) {
	case *ecdsa.PublicKey:
		if claims.Algorithm != AlgorithmECDSAP256SHA256 || typed.Curve.Params().Name != "P-256" || !ecdsa.VerifyASN1(typed, claimsHash[:], signature) {
			return errors.New("detached ECDSA signature verification failed")
		}
	case *rsa.PublicKey:
		if claims.Algorithm != AlgorithmRSAPSSSHA256 || typed.N.BitLen() < 2048 || rsa.VerifyPSS(typed, crypto.SHA256, claimsHash[:], signature, &rsa.PSSOptions{SaltLength: sha256Size, Hash: crypto.SHA256}) != nil {
			return errors.New("detached RSA-PSS signature verification failed")
		}
	default:
		return errors.New("unsupported registry public key")
	}
	return nil
}

func canonicalClaimsBytes(claims SignatureClaims) ([]byte, error) {
	encoded, err := json.Marshal(claims)
	if err != nil {
		return nil, err
	}
	return CanonicalizeJSON(encoded)
}

func registryDigest(registry PublicKeyRegistry) (string, error) {
	encoded, err := json.Marshal(registry)
	if err != nil {
		return "", err
	}
	canonical, err := CanonicalizeJSON(encoded)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(canonical)
	return hex.EncodeToString(digest[:]), nil
}

func parsePublicKey(value string) (crypto.PublicKey, error) {
	block, remainder := pem.Decode([]byte(value))
	if block == nil || block.Type != "PUBLIC KEY" || len(remainder) != 0 {
		return nil, errors.New("invalid registry public-key PEM")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, errors.New("invalid registry public key")
	}
	return key, nil
}

func findEligibleKey(registry PublicKeyRegistry, claims SignatureClaims, issuedAt, at time.Time) (verificationKey, error) {
	for _, key := range registry.Keys {
		if key.Kid != claims.Kid {
			continue
		}
		if key.Status != "active" {
			return verificationKey{}, errors.New("key is not active")
		}
		if key.Algorithm != claims.Algorithm || !slices.Contains(key.Purposes, claims.Purpose) || !slices.Contains(key.Environments, claims.Environment) {
			return verificationKey{}, errors.New("key is ineligible for algorithm/purpose/environment")
		}
		if !sameOptionalString(key.TenantScope, claims.TenantScope) {
			return verificationKey{}, errors.New("key is ineligible for tenant")
		}
		validFrom, beforeErr := parseContractTime(key.ValidFrom)
		validUntil, afterErr := parseContractTime(key.ValidUntil)
		if beforeErr != nil || afterErr != nil || issuedAt.Before(validFrom) || issuedAt.After(validUntil) || at.Before(validFrom) || at.After(validUntil) {
			return verificationKey{}, errors.New("key outside validity interval")
		}
		if key.RevokedAt != nil {
			revokedAt, revokeErr := parseContractTime(*key.RevokedAt)
			if revokeErr != nil || !at.Before(revokedAt) {
				return verificationKey{}, errors.New("key revoked")
			}
		}
		return verificationKey{
			Algorithm:    key.Algorithm,
			PublicKeyPEM: key.PublicKeyPem,
			Purposes:     key.Purposes,
			Environments: key.Environments,
			TenantScope:  key.TenantScope,
			ValidFrom:    key.ValidFrom,
			ValidUntil:   key.ValidUntil,
			Status:       key.Status,
			RevokedAt:    key.RevokedAt,
		}, nil
	}
	return verificationKey{}, fmt.Errorf("unknown key %q", claims.Kid)
}

func validateRegistry(registry PublicKeyRegistry) error {
	if registry.SchemaVersion != "1.0.0" || registry.RegistryVersion == 0 || len(registry.Keys) == 0 {
		return errors.New("invalid public-key registry header")
	}
	for _, value := range []string{registry.RegistryID, registry.RootFingerprint, registry.PurposePolicyHash} {
		if decoded, err := hex.DecodeString(value); err != nil || len(decoded) != sha256Size {
			return errors.New("invalid public-key registry hash")
		}
	}
	_, err := parseContractTime(registry.IssuedAt)
	if err != nil {
		return errors.New("invalid public-key registry issuance time")
	}
	if registry.RegistryVersion == 1 && registry.PreviousRegistryHash != nil {
		return errors.New("genesis registry cannot have previous hash")
	}
	if registry.RegistryVersion > 1 {
		if registry.PreviousRegistryHash == nil {
			return errors.New("registry version requires previous hash")
		}
		if decoded, err := hex.DecodeString(*registry.PreviousRegistryHash); err != nil || len(decoded) != sha256Size {
			return errors.New("invalid previous registry hash")
		}
	}
	type keyChainState struct {
		algorithm string
		status    string
	}
	seen := make(map[string]keyChainState, len(registry.Keys))
	for _, key := range registry.Keys {
		if key.Kid == "" {
			return errors.New("registry key is missing kid")
		}
		if _, duplicate := seen[key.Kid]; duplicate {
			return errors.New("duplicate registry kid")
		}
		validFrom, fromErr := parseContractTime(key.ValidFrom)
		validUntil, untilErr := parseContractTime(key.ValidUntil)
		if fromErr != nil || untilErr != nil || validUntil.Before(validFrom) {
			return errors.New("invalid registry key validity interval")
		}
		switch key.Status {
		case "revoked":
			if key.RevokedAt == nil || key.RevocationReason == nil {
				return errors.New("revoked key is missing revocation metadata")
			}
			if revokedAt, revokeErr := parseContractTime(*key.RevokedAt); revokeErr != nil || revokedAt.Before(validFrom) {
				return errors.New("invalid registry key revocation time")
			}
		case "active", "superseded":
			if key.RevokedAt != nil || key.RevocationReason != nil {
				return errors.New("non-revoked key has revocation metadata")
			}
		default:
			return errors.New("unsupported registry key status")
		}
		publicKey, parseErr := parsePublicKey(key.PublicKeyPem)
		if parseErr != nil {
			return parseErr
		}
		switch key.Algorithm {
		case AlgorithmECDSAP256SHA256:
			typed, ok := publicKey.(*ecdsa.PublicKey)
			if !ok || typed.Curve.Params().Name != "P-256" {
				return errors.New("registry key algorithm/public-key mismatch")
			}
		case AlgorithmRSAPSSSHA256:
			typed, ok := publicKey.(*rsa.PublicKey)
			if !ok || typed.N.BitLen() < 2048 {
				return errors.New("registry key algorithm/public-key mismatch")
			}
		default:
			return errors.New("unsupported registry key algorithm")
		}
		seen[key.Kid] = keyChainState{algorithm: key.Algorithm, status: key.Status}
	}
	for _, key := range registry.Keys {
		if key.SupersedesKid != nil {
			if *key.SupersedesKid == key.Kid {
				return errors.New("key cannot supersede itself")
			}
			prior, exists := seen[*key.SupersedesKid]
			if !exists || prior.status != "superseded" || prior.algorithm != key.Algorithm {
				return errors.New("broken key supersession chain")
			}
		}
	}
	visiting := make(map[string]bool, len(registry.Keys))
	visited := make(map[string]bool, len(registry.Keys))
	var visit func(string) error
	visit = func(kid string) error {
		if visiting[kid] {
			return errors.New("cyclic key supersession chain")
		}
		if visited[kid] {
			return nil
		}
		visiting[kid] = true
		for _, key := range registry.Keys {
			if key.Kid == kid && key.SupersedesKid != nil {
				if err := visit(*key.SupersedesKid); err != nil {
					return err
				}
				break
			}
		}
		visiting[kid] = false
		visited[kid] = true
		return nil
	}
	for kid := range seen {
		if err := visit(kid); err != nil {
			return err
		}
	}
	return nil
}

// parseContractTime is the behavioral counterpart of timestamp_field. Contract
// timestamps are UTC-only RFC 3339 values and preserve at most nanosecond
// precision; offsets and over-precise fractions are rejected rather than
// silently normalized by time.Parse.
func parseContractTime(value string) (time.Time, error) {
	if !contractTimestampPattern.MatchString(value) {
		return time.Time{}, errors.New("invalid contract timestamp")
	}
	return time.Parse(time.RFC3339Nano, value)
}

func sameOptionalString(left, right *string) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}
