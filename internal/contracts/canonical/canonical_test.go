package canonical

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// wrappedSigner models a remote KMS/HSM signer: it satisfies crypto.Signer but
// deliberately does not expose a concrete local private-key type.
type wrappedSigner struct {
	crypto.Signer
}

type canonicalVector struct {
	Name          string `json:"name"`
	ObjectType    string `json:"object_type"`
	SchemaVersion string `json:"schema_version"`
	Input         string `json:"input"`
	Canonical     string `json:"canonical"`
	Digest        string `json:"digest"`
}

type signatureVerificationFixture struct {
	Payload      json.RawMessage   `json:"payload"`
	Registry     PublicKeyRegistry `json:"registry"`
	RegistryHash string            `json:"registry_hash"`
	Expected     struct {
		ObjectType          string  `json:"object_type"`
		ObjectSchemaID      string  `json:"object_schema_id"`
		ObjectSchemaVersion string  `json:"object_schema_version"`
		Purpose             string  `json:"purpose"`
		Environment         string  `json:"environment"`
		TenantScope         *string `json:"tenant_scope"`
		MigrationScope      *string `json:"migration_scope"`
		At                  string  `json:"at"`
	} `json:"expected"`
	Vectors []struct {
		Name     string            `json:"name"`
		Envelope SignatureEnvelope `json:"envelope"`
	} `json:"vectors"`
}

func loadSignatureVerificationFixture(t *testing.T) signatureVerificationFixture {
	t.Helper()
	fixturePath := filepath.Join("..", "..", "..", "contracts", "fixtures", "signature-verification-vectors.json")
	raw, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatal(err)
	}
	var fixture signatureVerificationFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func mutateAndReidentify(t *testing.T, document []byte, mutate func(map[string]any)) []byte {
	t.Helper()
	var object map[string]any
	if err := json.Unmarshal(document, &object); err != nil {
		t.Fatal(err)
	}
	mutate(object)
	projection, ok := object["logical_payload_projection"].(map[string]any)
	if !ok {
		t.Fatal("fixture has no logical payload projection")
	}
	objectType, _ := projection["object_type"].(string)
	version, _ := projection["object_schema_version"].(string)
	idField, _ := projection["id_field"].(string)
	excludedValues, _ := projection["excluded_fields"].([]any)
	projected := make(map[string]any, len(object))
	for field, value := range object {
		projected[field] = value
	}
	for _, value := range excludedValues {
		field, ok := value.(string)
		if !ok {
			t.Fatal("fixture has a non-string identity exclusion")
		}
		delete(projected, field)
	}
	projectedBytes, err := json.Marshal(projected)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := TypedDigestHex(objectType, version, projectedBytes)
	if err != nil {
		t.Fatal(err)
	}
	object[idField] = digest
	object["logical_payload_sha256"] = digest
	if fields, ok := projection["equivalent_digest_fields"].([]any); ok {
		for _, value := range fields {
			field, ok := value.(string)
			if !ok {
				t.Fatal("fixture has a non-string equivalent digest field")
			}
			object[field] = digest
		}
	}
	result, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestCanonicalVectors(t *testing.T) {
	fixture := filepath.Join("..", "..", "..", "contracts", "fixtures", "canonicalization-vectors.json")
	raw, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Vectors []canonicalVector `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	if len(document.Vectors) < 3 {
		t.Fatal("canonical fixture corpus is incomplete")
	}
	for _, vector := range document.Vectors {
		vector := vector
		t.Run(vector.Name, func(t *testing.T) {
			actual, err := CanonicalizeJSON([]byte(vector.Input))
			if err != nil {
				t.Fatal(err)
			}
			if string(actual) != vector.Canonical {
				t.Fatalf("canonical mismatch\nwant %s\n got %s", vector.Canonical, actual)
			}
			digest, err := TypedDigestHex(vector.ObjectType, vector.SchemaVersion, []byte(vector.Input))
			if err != nil {
				t.Fatal(err)
			}
			if digest != vector.Digest {
				t.Fatalf("digest mismatch: want %s got %s", vector.Digest, digest)
			}
		})
	}
}

func TestCanonicalRejectsUnsafeJSON(t *testing.T) {
	invalid := []string{
		`{"duplicate":1,"duplicate":2}`,
		`{"surrogate":"\ud800"}`,
		`{"number":1e999}`,
		`{"value":1} {"trailing":2}`,
		`{"value":1} trailing-junk`,
	}
	for _, input := range invalid {
		if _, err := CanonicalizeJSON([]byte(input)); err == nil {
			t.Fatalf("expected rejection for %s", input)
		}
	}
}

func TestSharedECDSAAndRSAPSSSignatureVectors(t *testing.T) {
	fixture := loadSignatureVerificationFixture(t)
	actualRegistryHash, err := registryDigest(fixture.Registry)
	if err != nil {
		t.Fatal(err)
	}
	if actualRegistryHash != fixture.RegistryHash {
		t.Fatalf("registry hash mismatch: want %s got %s", fixture.RegistryHash, actualRegistryHash)
	}
	at, err := parseContractTime(fixture.Expected.At)
	if err != nil {
		t.Fatal(err)
	}
	expected := VerifyExpectation{
		ObjectType: fixture.Expected.ObjectType, ObjectSchemaID: fixture.Expected.ObjectSchemaID,
		ObjectSchemaVersion: fixture.Expected.ObjectSchemaVersion, Purpose: fixture.Expected.Purpose,
		Environment: fixture.Expected.Environment, TenantScope: fixture.Expected.TenantScope,
		MigrationScope: fixture.Expected.MigrationScope, RegistryHash: fixture.RegistryHash, At: at,
	}
	algorithms := make(map[string]bool)
	for _, vector := range fixture.Vectors {
		algorithms[vector.Envelope.Algorithm] = true
		if err := VerifyDetached(fixture.Payload, vector.Envelope, fixture.Registry, expected); err != nil {
			t.Fatalf("%s: %v", vector.Name, err)
		}
	}
	if !algorithms[AlgorithmECDSAP256SHA256] || !algorithms[AlgorithmRSAPSSSHA256] || len(algorithms) != 2 {
		t.Fatalf("shared fixture does not cover both frozen algorithms: %v", algorithms)
	}
	for _, malformed := range []string{"AA-A", "AAAAA", "AB==", "AAAA\n"} {
		envelope := fixture.Vectors[0].Envelope
		envelope.SignatureBase64 = malformed
		if err := VerifyDetached(fixture.Payload, envelope, fixture.Registry, expected); err == nil {
			t.Fatalf("accepted malformed base64 signature %q", malformed)
		}
	}
}

func TestContractTimestampAndRegistrySupersessionValidation(t *testing.T) {
	validTimestamps := []string{
		"2026-07-18T01:00:00Z",
		"2026-07-18T01:00:00.1Z",
		"2026-07-18T01:00:00.123456789Z",
	}
	for _, value := range validTimestamps {
		if _, err := parseContractTime(value); err != nil {
			t.Fatalf("valid timestamp %q rejected: %v", value, err)
		}
	}
	invalidTimestamps := []string{
		"2026-07-18T01:00:00+00:00",
		"2026-07-18T01:00:00.1234567890Z",
		"2026-02-30T01:00:00Z",
		"2026-07-18t01:00:00Z",
	}
	for _, value := range invalidTimestamps {
		if _, err := parseContractTime(value); err == nil {
			t.Fatalf("invalid timestamp %q accepted", value)
		}
	}

	fixture := loadSignatureVerificationFixture(t)
	genesisWithParent := fixture.Registry
	genesisWithParent.PreviousRegistryHash = &fixture.RegistryHash
	if err := validateRegistry(genesisWithParent); err == nil {
		t.Fatal("genesis registry with previous hash accepted")
	}
	versionedWithoutParent := fixture.Registry
	versionedWithoutParent.RegistryVersion = 2
	versionedWithoutParent.PreviousRegistryHash = nil
	if err := validateRegistry(versionedWithoutParent); err == nil {
		t.Fatal("successor registry without previous hash accepted")
	}
	self := loadSignatureVerificationFixture(t).Registry
	self.Keys[0].Status = "superseded"
	self.Keys[0].SupersedesKid = &self.Keys[0].Kid
	if err := validateRegistry(self); err == nil {
		t.Fatal("self-superseding key accepted")
	}
	cycle := loadSignatureVerificationFixture(t).Registry
	firstKid := cycle.Keys[0].Kid
	cycleKid := "fixture-ecdsa-cycle"
	cycle.Keys[0].Status = "superseded"
	cycle.Keys[0].SupersedesKid = &cycleKid
	second := cycle.Keys[0]
	second.Kid = cycleKid
	second.SupersedesKid = &firstKid
	cycle.Keys = append(cycle.Keys, second)
	if err := validateRegistry(cycle); err == nil {
		t.Fatal("cyclic key supersession accepted")
	}
	malformedKey := loadSignatureVerificationFixture(t).Registry
	malformedKey.Keys[0].PublicKeyPem = "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n"
	if err := validateRegistry(malformedKey); err == nil {
		t.Fatal("malformed registry public key accepted")
	}
	mismatchedKey := loadSignatureVerificationFixture(t).Registry
	mismatchedKey.Keys[0].Algorithm = AlgorithmRSAPSSSHA256
	if err := validateRegistry(mismatchedKey); err == nil {
		t.Fatal("registry algorithm/public-key mismatch accepted")
	}
	revokedWithoutMetadata := loadSignatureVerificationFixture(t).Registry
	revokedWithoutMetadata.Keys[0].Status = "revoked"
	if err := validateRegistry(revokedWithoutMetadata); err == nil {
		t.Fatal("revoked key without revocation metadata accepted")
	}
	activeWithMetadata := loadSignatureVerificationFixture(t).Registry
	revokedAt := "2026-07-18T00:30:00Z"
	reason := "compromised"
	activeWithMetadata.Keys[0].RevokedAt = &revokedAt
	activeWithMetadata.Keys[0].RevocationReason = &reason
	if err := validateRegistry(activeWithMetadata); err == nil {
		t.Fatal("active key with revocation metadata accepted")
	}
	validRevoked := loadSignatureVerificationFixture(t).Registry
	validRevoked.Keys[0].Status = "revoked"
	validRevoked.Keys[0].RevokedAt = &revokedAt
	validRevoked.Keys[0].RevocationReason = &reason
	if err := validateRegistry(validRevoked); err != nil {
		t.Fatalf("well-formed revoked key rejected: %v", err)
	}
	unsupported := loadSignatureVerificationFixture(t).Registry
	unsupported.Keys[0].Algorithm = "UNSUPPORTED"
	if err := validateRegistry(unsupported); err == nil {
		t.Fatal("unsupported registry key algorithm accepted")
	}
	unsupported = loadSignatureVerificationFixture(t).Registry
	unsupported.Keys[0].Status = "unknown"
	if err := validateRegistry(unsupported); err == nil {
		t.Fatal("unsupported registry key status accepted")
	}
}

func TestSharedCatalogContentIdentityTamperDenial(t *testing.T) {
	fixturePath := filepath.Join("..", "..", "..", "contracts", "fixtures", "client", "valid-customer-incapability-catalog.json")
	raw, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatal(err)
	}
	var wrapper struct {
		Instance json.RawMessage `json:"instance"`
	}
	if err := json.Unmarshal(raw, &wrapper); err != nil {
		t.Fatal(err)
	}
	if err := VerifyContentIdentity(wrapper.Instance); err != nil {
		t.Fatalf("valid generated catalog identity rejected: %v", err)
	}
	if err := VerifyCustomerIncapabilityCatalog(wrapper.Instance); err != nil {
		t.Fatalf("valid generated catalog ordering rejected: %v", err)
	}
	original := []byte("Jumpship cannot perform customer-owned validation.")
	replacement := []byte("Semantically changed while holding every digest field fixed.")
	tampered := bytes.Replace(wrapper.Instance, original, replacement, 1)
	if bytes.Equal(tampered, wrapper.Instance) {
		t.Fatal("catalog tamper target was not present")
	}
	if err := VerifyContentIdentity(tampered); err == nil {
		t.Fatal("semantic catalog tamper with held content ID accepted")
	}
	reversed := mutateAndReidentify(t, wrapper.Instance, func(object map[string]any) {
		items := object["items"].([]any)
		items[0], items[1] = items[1], items[0]
	})
	if err := VerifyContentIdentity(reversed); err != nil {
		t.Fatalf("reidentified reversed catalog failed generic identity: %v", err)
	}
	if err := VerifyCustomerIncapabilityCatalog(reversed); err == nil {
		t.Fatal("reversed catalog sort order accepted")
	}
	duplicate := mutateAndReidentify(t, wrapper.Instance, func(object map[string]any) {
		items := object["items"].([]any)
		first := items[0].(map[string]any)
		second := items[1].(map[string]any)
		second["capability_id"] = first["capability_id"]
		second["incapability_id"] = first["incapability_id"]
	})
	if err := VerifyContentIdentity(duplicate); err != nil {
		t.Fatalf("reidentified duplicate-key catalog failed generic identity: %v", err)
	}
	if err := VerifyCustomerIncapabilityCatalog(duplicate); err == nil {
		t.Fatal("duplicate catalog sort key with distinct item content accepted")
	}
	attackerProjection := mutateAndReidentify(t, wrapper.Instance, func(object map[string]any) {
		projection := object["logical_payload_projection"].(map[string]any)
		projection["object_type"] = "attacker_catalog"
		projection["id_field"] = "attacker_id"
		projection["domain_separator"] = "jumpship:attacker_catalog:2.0.0\x00"
		projection["excluded_fields"] = []any{
			"attacker_id", "logical_payload_sha256", "logical_payload_projection",
		}
		projection["equivalent_digest_fields"] = []any{}
	})
	if err := VerifyContentIdentity(attackerProjection); err != nil {
		t.Fatalf("generic identity should remain generic: %v", err)
	}
	if err := VerifyCustomerIncapabilityCatalog(attackerProjection); err == nil {
		t.Fatal("attacker-controlled catalog projection accepted")
	}
	unknownItemField := mutateAndReidentify(t, wrapper.Instance, func(object map[string]any) {
		items := object["items"].([]any)
		items[0].(map[string]any)["unexpected_authority"] = true
	})
	if err := VerifyContentIdentity(unknownItemField); err != nil {
		t.Fatalf("generic identity rejected reidentified unknown-field witness: %v", err)
	}
	if err := VerifyCustomerIncapabilityCatalog(unknownItemField); err == nil {
		t.Fatal("catalog item with an unknown field accepted")
	}
	missingItemField := mutateAndReidentify(t, wrapper.Instance, func(object map[string]any) {
		items := object["items"].([]any)
		delete(items[0].(map[string]any), "reason_code")
	})
	if err := VerifyContentIdentity(missingItemField); err != nil {
		t.Fatalf("generic identity rejected reidentified missing-field witness: %v", err)
	}
	if err := VerifyCustomerIncapabilityCatalog(missingItemField); err == nil {
		t.Fatal("catalog item missing a required field accepted")
	}
	oversized := mutateAndReidentify(t, wrapper.Instance, func(object map[string]any) {
		items := object["items"].([]any)
		template := items[len(items)-1].(map[string]any)
		for index := 0; index < 300; index++ {
			raw, marshalErr := json.Marshal(template)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			var item map[string]any
			if unmarshalErr := json.Unmarshal(raw, &item); unmarshalErr != nil {
				t.Fatal(unmarshalErr)
			}
			item["capability_id"] = fmt.Sprintf("MVP-CAP-Z%04d", index)
			item["incapability_id"] = fmt.Sprintf("cannot-oversize-%04d", index)
			item["safe_explanation"] = strings.Repeat("x", 2048)
			item["safe_remediation"] = strings.Repeat("y", 2048)
			items = append(items, item)
		}
		object["items"] = items
	})
	if err := VerifyContentIdentity(oversized); err != nil {
		t.Fatalf("generic identity rejected reidentified oversized witness: %v", err)
	}
	if len(oversized) <= 1_048_576 {
		t.Fatalf("oversized witness is only %d bytes", len(oversized))
	}
	if err := VerifyCustomerIncapabilityCatalog(oversized); err == nil {
		t.Fatal("catalog above the frozen byte limit was accepted")
	}
}

func loadContractFixtureInstance(t *testing.T, name string) json.RawMessage {
	t.Helper()
	fixturePath := filepath.Join("..", "..", "..", "contracts", "fixtures", "client", name)
	raw, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatal(err)
	}
	var wrapper struct {
		Instance json.RawMessage `json:"instance"`
	}
	if err := json.Unmarshal(raw, &wrapper); err != nil {
		t.Fatal(err)
	}
	return wrapper.Instance
}

func TestCatalogOneWayBindingResponseAndDowngradeBoundaries(t *testing.T) {
	catalog := loadContractFixtureInstance(t, "valid-customer-incapability-catalog.json")
	binding := loadContractFixtureInstance(t, "valid-customer-incapability-catalog-binding.json")
	response := loadContractFixtureInstance(t, "valid-customer-incapability-catalog-response.json")
	if err := VerifyCustomerIncapabilityCatalogBinding(binding); err != nil {
		t.Fatalf("valid generated catalog binding rejected: %v", err)
	}
	if err := VerifyCustomerIncapabilityCatalogResponse(response); err != nil {
		t.Fatalf("valid generated catalog response rejected: %v", err)
	}

	var responseObject map[string]any
	if err := json.Unmarshal(response, &responseObject); err != nil {
		t.Fatal(err)
	}
	originalCatalog, marshalOriginalErr := json.Marshal(responseObject["catalog"])
	if marshalOriginalErr != nil {
		t.Fatal(marshalOriginalErr)
	}
	responseObject["selection_mode"] = "pinned_cell_release_binding"
	responseObject["migration_id"] = "018f0f7e-7b8a-7abc-8def-0123456789ab"
	responseObject["release_evidence_chain"] = []any{strings.Repeat("7", 64)}
	responseObject["served_at"] = "2026-07-19T00:00:00Z"
	metadataChanged, marshalResponseErr := json.Marshal(responseObject)
	if marshalResponseErr != nil {
		t.Fatal(marshalResponseErr)
	}
	if err := VerifyCustomerIncapabilityCatalogResponse(metadataChanged); err != nil {
		t.Fatalf("response-only metadata change altered catalog validity: %v", err)
	}
	retainedCatalog, marshalRetainedErr := json.Marshal(responseObject["catalog"])
	if marshalRetainedErr != nil {
		t.Fatal(marshalRetainedErr)
	}
	if !bytes.Equal(originalCatalog, retainedCatalog) {
		t.Fatal("response-only metadata change altered nested immutable catalog")
	}

	oldFlat := mutateAndReidentify(t, catalog, func(object map[string]any) {
		object["schema_version"] = "1.0.0"
		object["release_unit_id"] = strings.Repeat("2", 64)
	})
	if err := VerifyContentIdentity(oldFlat); err != nil {
		t.Fatalf("downgrade witness should retain a coherent generic identity: %v", err)
	}
	if err := VerifyCustomerIncapabilityCatalog(oldFlat); err == nil {
		t.Fatal("old flat catalog downgrade accepted")
	}
	if err := VerifyCustomerIncapabilityCatalog(response); err == nil {
		t.Fatal("response envelope accepted as immutable catalog")
	}

	var catalogObject map[string]any
	if err := json.Unmarshal(catalog, &catalogObject); err != nil {
		t.Fatal(err)
	}
	releaseSeed := map[string]any{
		"schema_version":         "1.0.0",
		"release_unit_id":        strings.Repeat("0", 64),
		"logical_payload_sha256": strings.Repeat("0", 64),
		"logical_payload_projection": map[string]any{
			"object_type":                      "release_unit",
			"id_field":                         "release_unit_id",
			"object_schema_version":            "1.0.0",
			"canonical_encoder":                "RFC8785_JCS",
			"domain_separator":                 "jumpship:release_unit:1.0.0\x00",
			"excluded_fields":                  []any{"release_unit_id", "logical_payload_sha256", "logical_payload_projection"},
			"equivalent_digest_fields":         []any{},
			"id_encoding":                      "lowercase_hex_sha256",
			"id_equals_logical_payload_sha256": true,
		},
		"customer_incapability_catalog_hash":         catalogObject["catalog_hash"],
		"customer_incapability_source_registry_hash": catalogObject["source_registry_hash"],
		"members": []any{map[string]any{
			"kind":           "customer_incapability_catalog",
			"object_id":      catalogObject["catalog_id"],
			"content_sha256": catalogObject["catalog_hash"],
		}},
	}
	releaseSeedBytes, marshalReleaseErr := json.Marshal(releaseSeed)
	if marshalReleaseErr != nil {
		t.Fatal(marshalReleaseErr)
	}
	releaseUnit := mutateAndReidentify(t, releaseSeedBytes, func(map[string]any) {})
	var releaseObject map[string]any
	if err := json.Unmarshal(releaseUnit, &releaseObject); err != nil {
		t.Fatal(err)
	}
	associationBinding := mutateAndReidentify(t, binding, func(object map[string]any) {
		object["release_unit_id"] = releaseObject["release_unit_id"]
		object["release_unit_hash"] = releaseObject["release_unit_id"]
	})
	if err := VerifyCustomerIncapabilityCatalogAssociation(catalog, associationBinding, releaseUnit); err != nil {
		t.Fatalf("valid catalog/ReleaseUnit binding association rejected: %v", err)
	}
	substitutedSource := mutateAndReidentify(t, associationBinding, func(object map[string]any) {
		object["source_registry_hash"] = strings.Repeat("8", 64)
	})
	if err := VerifyCustomerIncapabilityCatalogBinding(substitutedSource); err != nil {
		t.Fatalf("substitution witness should have a valid binding identity: %v", err)
	}
	if err := VerifyCustomerIncapabilityCatalogAssociation(catalog, substitutedSource, releaseUnit); err == nil {
		t.Fatal("cross-object source registry substitution accepted")
	}
}

func TestDetachedSignatureReplayTamperSupersessionAndResigning(t *testing.T) {
	privateOne, setupErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if setupErr != nil {
		t.Fatal(setupErr)
	}
	privateTwo, setupErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if setupErr != nil {
		t.Fatal(setupErr)
	}
	payload := []byte(`{"schema_version":"1.0.0","value":"stable"}`)
	issued := time.Date(2026, 7, 18, 1, 0, 0, 0, time.UTC)
	tenant := "018f1234-5678-7abc-8def-0123456789ab"
	registryID := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	claims := SignatureClaims{
		SchemaVersion: "1.0.0", ObjectType: "release_unit",
		ObjectSchemaID: "https://jumpship.dev/contracts/release/release-unit.schema.json", ObjectSchemaVersion: "1.0.0",
		Purpose: "release_evidence", Environment: "staging", TenantScope: &tenant,
		Kid: "release-2026-a", Algorithm: AlgorithmECDSAP256SHA256,
		SignerID: "release-workflow", SignerRole: "release-evidence", IssuedAt: issued.Format(time.RFC3339),
		KeyRegistryID: registryID,
	}
	publicDER, setupErr := x509.MarshalPKIXPublicKey(&privateOne.PublicKey)
	if setupErr != nil {
		t.Fatal(setupErr)
	}
	registryPayload, setupErr := json.Marshal(map[string]any{
		"schema_version": "1.0.0", "registry_id": registryID, "registry_version": 1,
		"previous_registry_hash": nil,
		"root_fingerprint":       "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		"purpose_policy_hash":    "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		"issued_at":              issued.Add(-time.Hour).Format(time.RFC3339),
		"keys": []map[string]any{{
			"kid": "release-2026-a", "algorithm": AlgorithmECDSAP256SHA256,
			"public_key_pem": string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})),
			"purposes":       []string{"release_evidence"}, "environments": []string{"staging"},
			"tenant_scope": &tenant, "valid_from": issued.Add(-time.Hour).Format(time.RFC3339),
			"valid_until": issued.Add(24 * time.Hour).Format(time.RFC3339), "status": "active",
			"supersedes_kid": nil, "revoked_at": nil, "revocation_reason": nil,
		}},
	})
	if setupErr != nil {
		t.Fatal(setupErr)
	}
	var registry PublicKeyRegistry
	if setupErr = json.Unmarshal(registryPayload, &registry); setupErr != nil {
		t.Fatal(setupErr)
	}
	registryHash, setupErr := registryDigest(registry)
	if setupErr != nil {
		t.Fatal(setupErr)
	}
	claims.KeyRegistryHash = registryHash
	envelope, setupErr := SignDetached(payload, claims, wrappedSigner{Signer: privateOne})
	if setupErr != nil {
		t.Fatal(setupErr)
	}
	expected := VerifyExpectation{
		ObjectType: "release_unit", ObjectSchemaID: claims.ObjectSchemaID, ObjectSchemaVersion: "1.0.0",
		Purpose: "release_evidence", Environment: "staging", TenantScope: &tenant,
		RegistryHash: registryHash, At: issued.Add(time.Minute),
	}
	if err := VerifyDetached(payload, envelope, registry, expected); err != nil {
		t.Fatal(err)
	}
	tamperedRegistry := registry
	tamperedRegistry.RootFingerprint = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	if err := VerifyDetached(payload, envelope, tamperedRegistry, expected); err == nil {
		t.Fatal("registry substitution accepted")
	}
	originalDigest := envelope.PayloadDigest

	if err := VerifyDetached([]byte(`{"schema_version":"1.0.0","value":"tampered"}`), envelope, registry, expected); err == nil {
		t.Fatal("payload tamper accepted")
	}
	tamperedEnvelope := envelope
	replacement := "A"
	if envelope.SignatureBase64[0] == 'A' {
		replacement = "B"
	}
	tamperedEnvelope.SignatureBase64 = replacement + envelope.SignatureBase64[1:]
	if err := VerifyDetached(payload, tamperedEnvelope, registry, expected); err == nil {
		t.Fatal("signature tamper accepted")
	}
	replayed := expected
	replayed.Purpose = "bundle_promotion"
	if err := VerifyDetached(payload, envelope, registry, replayed); err == nil {
		t.Fatal("purpose replay accepted")
	}
	replayed = expected
	replayed.ObjectType = "qualification_record"
	if err := VerifyDetached(payload, envelope, registry, replayed); err == nil {
		t.Fatal("type replay accepted")
	}
	replayed = expected
	replayed.ObjectSchemaVersion = "2.0.0"
	if err := VerifyDetached(payload, envelope, registry, replayed); err == nil {
		t.Fatal("schema-version replay accepted")
	}
	publicTwoDER, setupErr := x509.MarshalPKIXPublicKey(&privateTwo.PublicKey)
	if setupErr != nil {
		t.Fatal(setupErr)
	}
	priorKid := registry.Keys[0].Kid
	successor := registry
	successor.RegistryID = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	successor.RegistryVersion = 2
	successor.PreviousRegistryHash = &registryHash
	successor.Keys = append(successor.Keys[:0:0], registry.Keys...)
	successor.Keys[0].Status = "superseded"
	newKey := successor.Keys[0]
	newKey.Kid = "release-2026-b"
	newKey.PublicKeyPem = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicTwoDER}))
	newKey.ValidFrom = issued.Format(time.RFC3339)
	newKey.Status = "active"
	newKey.SupersedesKid = &priorKid
	successor.Keys = append(successor.Keys, newKey)
	successorHash, setupErr := registryDigest(successor)
	if setupErr != nil {
		t.Fatal(setupErr)
	}
	successorExpected := expected
	successorExpected.RegistryHash = successorHash
	successorExpected.At = issued.Add(time.Hour)
	oldKeyClaims := claims
	oldKeyClaims.KeyRegistryID = successor.RegistryID
	oldKeyClaims.KeyRegistryHash = successorHash
	oldKeyEnvelope, setupErr := SignDetached(payload, oldKeyClaims, wrappedSigner{Signer: privateOne})
	if setupErr != nil {
		t.Fatal(setupErr)
	}
	if err := VerifyDetached(payload, oldKeyEnvelope, successor, successorExpected); err == nil || err.Error() != "key is not active" {
		t.Fatalf("superseded key did not fail at key eligibility: %v", err)
	}
	newKeyClaims := oldKeyClaims
	newKeyClaims.Kid = newKey.Kid
	newKeyEnvelope, setupErr := SignDetached(payload, newKeyClaims, wrappedSigner{Signer: privateTwo})
	if setupErr != nil {
		t.Fatal(setupErr)
	}
	if err := VerifyDetached(payload, newKeyEnvelope, successor, successorExpected); err != nil {
		t.Fatalf("active successor key rejected: %v", err)
	}
	if newKeyEnvelope.PayloadDigest != originalDigest {
		t.Fatal("re-signing under successor registry changed logical identity")
	}
}
