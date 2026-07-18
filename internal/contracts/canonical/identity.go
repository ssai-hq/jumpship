package canonical

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"unicode/utf8"
)

// logicalPayloadProjection is the schema-frozen recipe carried by every P02
// content-addressed object. The object itself is expected to have passed its
// JSON Schema before this semantic equality check is invoked.
type logicalPayloadProjection struct {
	ObjectType                   string   `json:"object_type"`
	IDField                      string   `json:"id_field"`
	ObjectSchemaVersion          string   `json:"object_schema_version"`
	CanonicalEncoder             string   `json:"canonical_encoder"`
	DomainSeparator              string   `json:"domain_separator"`
	ExcludedFields               []string `json:"excluded_fields"`
	EquivalentDigestFields       []string `json:"equivalent_digest_fields"`
	IDEncoding                   string   `json:"id_encoding"`
	IDEqualsLogicalPayloadSHA256 bool     `json:"id_equals_logical_payload_sha256"`
}

type customerIncapabilityCatalogItem struct {
	CapabilityID                string   `json:"capability_id"`
	IncapabilityID              string   `json:"incapability_id"`
	OperationID                 string   `json:"operation_id"`
	ReasonCode                  string   `json:"reason_code"`
	SafeExplanation             string   `json:"safe_explanation"`
	SafeRemediation             string   `json:"safe_remediation"`
	RequiredHumanSurface        string   `json:"required_human_surface"`
	CodingAgentDenied           bool     `json:"coding_agent_denied"`
	StructuralDenialContractIDs []string `json:"structural_denial_contract_ids"`
	NegativeTestReceiptHashes   []string `json:"negative_test_receipt_hashes"`
}

type customerIncapabilityCatalog struct {
	SchemaVersion            string                            `json:"schema_version"`
	CatalogID                string                            `json:"catalog_id"`
	LogicalPayloadSHA256     string                            `json:"logical_payload_sha256"`
	LogicalPayloadProjection logicalPayloadProjection          `json:"logical_payload_projection"`
	CatalogHash              string                            `json:"catalog_hash"`
	SourceRegistryHash       string                            `json:"source_registry_hash"`
	Items                    []customerIncapabilityCatalogItem `json:"items"`
}

type customerIncapabilityCatalogBinding struct {
	SchemaVersion            string                   `json:"schema_version"`
	BindingID                string                   `json:"binding_id"`
	LogicalPayloadSHA256     string                   `json:"logical_payload_sha256"`
	LogicalPayloadProjection logicalPayloadProjection `json:"logical_payload_projection"`
	BindingHash              string                   `json:"binding_hash"`
	ReleaseUnitID            string                   `json:"release_unit_id"`
	ReleaseUnitHash          string                   `json:"release_unit_hash"`
	CatalogID                string                   `json:"catalog_id"`
	CatalogHash              string                   `json:"catalog_hash"`
	SourceRegistryHash       string                   `json:"source_registry_hash"`
}

type customerIncapabilityCatalogResponse struct {
	SchemaVersion        string          `json:"schema_version"`
	SelectionMode        string          `json:"selection_mode"`
	MigrationID          *string         `json:"migration_id"`
	ReleaseEvidenceChain []string        `json:"release_evidence_chain"`
	CatalogBinding       json.RawMessage `json:"catalog_binding"`
	Catalog              json.RawMessage `json:"catalog"`
	ServedAt             string          `json:"served_at"`
}

type releaseUnitCatalogAssociation struct {
	ReleaseUnitID                          string `json:"release_unit_id"`
	CustomerIncapabilityCatalogHash        string `json:"customer_incapability_catalog_hash"`
	CustomerIncapabilitySourceRegistryHash string `json:"customer_incapability_source_registry_hash"`
	Members                                []struct {
		Kind          string `json:"kind"`
		ObjectID      string `json:"object_id"`
		ContentSHA256 string `json:"content_sha256"`
	} `json:"members"`
}

var (
	catalogCapabilityIDPattern = regexp.MustCompile(`^MVP-CAP-[A-Z0-9][A-Z0-9-]+$`)
	catalogSafeTokenPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@+\-]*$`)
	catalogMigrationIDPattern  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
)

// VerifyContentIdentity applies the object's declared non-recursive projection
// and proves its content ID, logical_payload_sha256, and any explicitly
// equivalent digest fields all equal the recomputed typed JCS digest.
func VerifyContentIdentity(document []byte) error {
	canonical, err := CanonicalizeJSON(document)
	if err != nil {
		return err
	}
	var object map[string]json.RawMessage
	if decodeErr := json.Unmarshal(canonical, &object); decodeErr != nil || object == nil {
		return errors.New("content identity requires a JSON object")
	}
	var projection logicalPayloadProjection
	projectionRaw, exists := object["logical_payload_projection"]
	if !exists || json.Unmarshal(projectionRaw, &projection) != nil {
		return errors.New("missing logical payload projection")
	}
	if projection.CanonicalEncoder != "RFC8785_JCS" ||
		projection.IDEncoding != "lowercase_hex_sha256" ||
		!projection.IDEqualsLogicalPayloadSHA256 ||
		projection.DomainSeparator != fmt.Sprintf("jumpship:%s:%s\x00", projection.ObjectType, projection.ObjectSchemaVersion) {
		return errors.New("invalid logical payload projection")
	}
	if projection.IDField == "" {
		return errors.New("logical payload projection has no id field")
	}
	excluded := make(map[string]struct{}, len(projection.ExcludedFields))
	for _, field := range projection.ExcludedFields {
		if field == "" {
			return errors.New("logical payload projection has an empty exclusion")
		}
		if _, duplicate := excluded[field]; duplicate {
			return errors.New("logical payload projection has duplicate exclusions")
		}
		excluded[field] = struct{}{}
	}
	for _, field := range []string{
		projection.IDField,
		"logical_payload_sha256",
		"logical_payload_projection",
	} {
		if _, found := excluded[field]; !found {
			return fmt.Errorf("logical payload projection does not exclude %q", field)
		}
	}
	equivalent := make(map[string]struct{}, len(projection.EquivalentDigestFields))
	for _, field := range projection.EquivalentDigestFields {
		if field == "" {
			return errors.New("logical payload projection has an empty equivalent digest field")
		}
		if _, duplicate := equivalent[field]; duplicate {
			return errors.New("logical payload projection has duplicate equivalent digest fields")
		}
		if _, found := excluded[field]; !found {
			return fmt.Errorf("equivalent digest field %q is not excluded", field)
		}
		equivalent[field] = struct{}{}
	}
	projected := make(map[string]json.RawMessage, len(object)-len(excluded))
	for field, value := range object {
		if _, omit := excluded[field]; !omit {
			projected[field] = value
		}
	}
	projectedBytes, err := json.Marshal(projected)
	if err != nil {
		return err
	}
	digest, err := TypedDigestHex(
		projection.ObjectType,
		projection.ObjectSchemaVersion,
		projectedBytes,
	)
	if err != nil {
		return err
	}
	for _, field := range append(
		[]string{projection.IDField, "logical_payload_sha256"},
		projection.EquivalentDigestFields...,
	) {
		valueRaw, found := object[field]
		if !found {
			return fmt.Errorf("content identity field %q is missing", field)
		}
		var value string
		if json.Unmarshal(valueRaw, &value) != nil || !isSHA256Hex(value) || value != digest {
			return fmt.Errorf("content identity field %q does not match logical payload", field)
		}
	}
	return nil
}

// VerifyCustomerIncapabilityCatalog adds the catalog's executable ordering
// invariant to the generic content-identity proof. Schema validation freezes
// item shape; this semantic check makes duplicate or reordered capability /
// incapability keys fail closed in every runtime.
func VerifyCustomerIncapabilityCatalog(document []byte) error {
	canonical, err := CanonicalizeJSON(document)
	if err != nil {
		return err
	}
	if len(canonical) > 1_048_576 {
		return errors.New("customer incapability catalog exceeds the frozen byte limit")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(canonical, &fields); err != nil || len(fields) != 7 {
		return errors.New("customer incapability catalog has an invalid top-level shape")
	}
	for _, field := range []string{
		"schema_version", "catalog_id", "logical_payload_sha256",
		"logical_payload_projection", "catalog_hash", "source_registry_hash", "items",
	} {
		if _, found := fields[field]; !found {
			return fmt.Errorf("customer incapability catalog is missing %q", field)
		}
	}
	var catalog customerIncapabilityCatalog
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&catalog); err != nil {
		return fmt.Errorf("invalid customer incapability catalog: %w", err)
	}
	if err := validateCustomerIncapabilityCatalogShape(catalog); err != nil {
		return err
	}
	if err := VerifyContentIdentity(canonical); err != nil {
		return err
	}
	previousCapability := ""
	previousIncapability := ""
	for index, item := range catalog.Items {
		if item.CapabilityID == "" || item.IncapabilityID == "" {
			return errors.New("customer incapability catalog has an empty sort key")
		}
		if index > 0 && (item.CapabilityID < previousCapability ||
			(item.CapabilityID == previousCapability && item.IncapabilityID <= previousIncapability)) {
			return errors.New("customer incapability catalog keys are not strictly ascending and unique")
		}
		previousCapability = item.CapabilityID
		previousIncapability = item.IncapabilityID
	}
	return nil
}

func validateCustomerIncapabilityCatalogShape(catalog customerIncapabilityCatalog) error {
	projection := catalog.LogicalPayloadProjection
	if catalog.SchemaVersion != "2.0.0" ||
		projection.ObjectType != "customer_incapability_catalog" ||
		projection.IDField != "catalog_id" ||
		projection.ObjectSchemaVersion != "2.0.0" ||
		projection.CanonicalEncoder != "RFC8785_JCS" ||
		projection.DomainSeparator != "jumpship:customer_incapability_catalog:2.0.0\x00" ||
		projection.IDEncoding != "lowercase_hex_sha256" ||
		!projection.IDEqualsLogicalPayloadSHA256 ||
		!equalStringSlices(projection.ExcludedFields, []string{
			"catalog_id", "catalog_hash", "logical_payload_sha256", "logical_payload_projection",
		}) ||
		!equalStringSlices(projection.EquivalentDigestFields, []string{"catalog_hash"}) {
		return errors.New("customer incapability catalog projection is not the frozen catalog projection")
	}
	for _, value := range []string{
		catalog.CatalogID,
		catalog.LogicalPayloadSHA256,
		catalog.CatalogHash,
		catalog.SourceRegistryHash,
	} {
		if !isSHA256Hex(value) {
			return errors.New("customer incapability catalog contains an invalid hash")
		}
	}
	if len(catalog.Items) < 1 || len(catalog.Items) > 2048 {
		return errors.New("customer incapability catalog has an invalid item count")
	}
	allowedSurfaces := map[string]bool{
		"browser": true, "human_cli": true, "support": true, "unavailable": true,
	}
	for _, item := range catalog.Items {
		if !catalogCapabilityIDPattern.MatchString(item.CapabilityID) || utf8.RuneCountInString(item.CapabilityID) > 128 ||
			!validCatalogToken(item.IncapabilityID) || !validCatalogToken(item.OperationID) ||
			!validCatalogToken(item.ReasonCode) || !allowedSurfaces[item.RequiredHumanSurface] ||
			!item.CodingAgentDenied || !validCatalogText(item.SafeExplanation) ||
			!validCatalogText(item.SafeRemediation) {
			return errors.New("customer incapability catalog contains an invalid item")
		}
		if len(item.StructuralDenialContractIDs) < 1 || len(item.StructuralDenialContractIDs) > 32 ||
			!uniqueStrings(item.StructuralDenialContractIDs) {
			return errors.New("customer incapability catalog has invalid structural denials")
		}
		for _, value := range item.StructuralDenialContractIDs {
			if !validCatalogToken(value) {
				return errors.New("customer incapability catalog has an invalid structural denial")
			}
		}
		if len(item.NegativeTestReceiptHashes) < 1 || len(item.NegativeTestReceiptHashes) > 64 ||
			!uniqueStrings(item.NegativeTestReceiptHashes) {
			return errors.New("customer incapability catalog has invalid negative-test receipts")
		}
		for _, value := range item.NegativeTestReceiptHashes {
			if !isSHA256Hex(value) {
				return errors.New("customer incapability catalog has an invalid negative-test receipt")
			}
		}
	}
	return nil
}

// VerifyCustomerIncapabilityCatalogBinding proves the separate one-way
// registration identity. ReleaseUnit/catalog/source equality against the
// referenced objects is enforced by VerifyCustomerIncapabilityCatalogAssociation.
func VerifyCustomerIncapabilityCatalogBinding(document []byte) error {
	canonical, err := CanonicalizeJSON(document)
	if err != nil {
		return err
	}
	if len(canonical) > 16_384 {
		return errors.New("customer incapability catalog binding exceeds the frozen byte limit")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(canonical, &fields); err != nil || len(fields) != 10 {
		return errors.New("customer incapability catalog binding has an invalid top-level shape")
	}
	for _, field := range []string{
		"schema_version", "binding_id", "logical_payload_sha256", "logical_payload_projection",
		"binding_hash", "release_unit_id", "release_unit_hash", "catalog_id", "catalog_hash",
		"source_registry_hash",
	} {
		if _, found := fields[field]; !found {
			return fmt.Errorf("customer incapability catalog binding is missing %q", field)
		}
	}
	var binding customerIncapabilityCatalogBinding
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&binding); err != nil {
		return fmt.Errorf("invalid customer incapability catalog binding: %w", err)
	}
	projection := binding.LogicalPayloadProjection
	if binding.SchemaVersion != "1.0.0" ||
		projection.ObjectType != "customer_incapability_catalog_binding" ||
		projection.IDField != "binding_id" || projection.ObjectSchemaVersion != "1.0.0" ||
		projection.CanonicalEncoder != "RFC8785_JCS" ||
		projection.DomainSeparator != "jumpship:customer_incapability_catalog_binding:1.0.0\x00" ||
		projection.IDEncoding != "lowercase_hex_sha256" || !projection.IDEqualsLogicalPayloadSHA256 ||
		!equalStringSlices(projection.ExcludedFields, []string{
			"binding_id", "binding_hash", "logical_payload_sha256", "logical_payload_projection",
		}) || !equalStringSlices(projection.EquivalentDigestFields, []string{"binding_hash"}) {
		return errors.New("customer incapability catalog binding projection is not frozen")
	}
	for _, value := range []string{
		binding.BindingID, binding.LogicalPayloadSHA256, binding.BindingHash,
		binding.ReleaseUnitID, binding.ReleaseUnitHash, binding.CatalogID,
		binding.CatalogHash, binding.SourceRegistryHash,
	} {
		if !isSHA256Hex(value) {
			return errors.New("customer incapability catalog binding contains an invalid hash")
		}
	}
	if binding.ReleaseUnitID != binding.ReleaseUnitHash || binding.CatalogID != binding.CatalogHash {
		return errors.New("customer incapability catalog binding contains unequal identity aliases")
	}
	return VerifyContentIdentity(canonical)
}

// VerifyCustomerIncapabilityCatalogResponse validates the non-identity API
// envelope without allowing its selection, migration or evidence fields to
// become catalog content.
func VerifyCustomerIncapabilityCatalogResponse(document []byte) error {
	canonical, err := CanonicalizeJSON(document)
	if err != nil {
		return err
	}
	if len(canonical) > 1_081_344 {
		return errors.New("customer incapability catalog response exceeds the frozen byte limit")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(canonical, &fields); err != nil || len(fields) != 7 {
		return errors.New("customer incapability catalog response has an invalid top-level shape")
	}
	for _, field := range []string{
		"schema_version", "selection_mode", "migration_id", "release_evidence_chain",
		"catalog_binding", "catalog", "served_at",
	} {
		if _, found := fields[field]; !found {
			return fmt.Errorf("customer incapability catalog response is missing %q", field)
		}
	}
	var response customerIncapabilityCatalogResponse
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&response); err != nil {
		return fmt.Errorf("invalid customer incapability catalog response: %w", err)
	}
	if response.SchemaVersion != "1.0.0" ||
		(response.SelectionMode != "new_admission_release" && response.SelectionMode != "pinned_cell_release_binding") {
		return errors.New("customer incapability catalog response has invalid version or selection mode")
	}
	if response.MigrationID != nil && !catalogMigrationIDPattern.MatchString(*response.MigrationID) {
		return errors.New("customer incapability catalog response has an invalid migration id")
	}
	if _, err := parseContractTime(response.ServedAt); err != nil {
		return errors.New("customer incapability catalog response has an invalid served_at")
	}
	if len(response.ReleaseEvidenceChain) < 1 || len(response.ReleaseEvidenceChain) > 64 ||
		!uniqueStrings(response.ReleaseEvidenceChain) {
		return errors.New("customer incapability catalog response has an invalid release evidence chain")
	}
	for _, value := range response.ReleaseEvidenceChain {
		if !isSHA256Hex(value) {
			return errors.New("customer incapability catalog response has an invalid release evidence hash")
		}
	}
	if err := VerifyCustomerIncapabilityCatalog(response.Catalog); err != nil {
		return fmt.Errorf("response catalog: %w", err)
	}
	if err := VerifyCustomerIncapabilityCatalogBinding(response.CatalogBinding); err != nil {
		return fmt.Errorf("response catalog binding: %w", err)
	}
	var catalog customerIncapabilityCatalog
	var binding customerIncapabilityCatalogBinding
	if json.Unmarshal(response.Catalog, &catalog) != nil || json.Unmarshal(response.CatalogBinding, &binding) != nil {
		return errors.New("customer incapability catalog response contains undecodable nested objects")
	}
	if binding.CatalogID != catalog.CatalogID || binding.CatalogHash != catalog.CatalogHash ||
		binding.SourceRegistryHash != catalog.SourceRegistryHash {
		return errors.New("customer incapability catalog response has a catalog binding mismatch")
	}
	return nil
}

// VerifyCustomerIncapabilityCatalogAssociation validates the exact three-object
// relation after ReleaseUnit identity/signature verification and before
// registrar persistence.
func VerifyCustomerIncapabilityCatalogAssociation(catalogDocument, bindingDocument, releaseUnitDocument []byte) error {
	if err := VerifyCustomerIncapabilityCatalog(catalogDocument); err != nil {
		return err
	}
	if err := VerifyCustomerIncapabilityCatalogBinding(bindingDocument); err != nil {
		return err
	}
	if err := VerifyContentIdentity(releaseUnitDocument); err != nil {
		return fmt.Errorf("release unit identity: %w", err)
	}
	var catalog customerIncapabilityCatalog
	var binding customerIncapabilityCatalogBinding
	var releaseUnit releaseUnitCatalogAssociation
	if json.Unmarshal(catalogDocument, &catalog) != nil || json.Unmarshal(bindingDocument, &binding) != nil ||
		json.Unmarshal(releaseUnitDocument, &releaseUnit) != nil {
		return errors.New("customer incapability catalog association contains undecodable objects")
	}
	if binding.ReleaseUnitID != releaseUnit.ReleaseUnitID || binding.ReleaseUnitHash != releaseUnit.ReleaseUnitID ||
		binding.CatalogID != catalog.CatalogID || binding.CatalogHash != catalog.CatalogHash ||
		binding.SourceRegistryHash != catalog.SourceRegistryHash ||
		releaseUnit.CustomerIncapabilityCatalogHash != catalog.CatalogHash ||
		releaseUnit.CustomerIncapabilitySourceRegistryHash != catalog.SourceRegistryHash {
		return errors.New("customer incapability catalog association has a cross-object hash mismatch")
	}
	matchedMembers := 0
	for _, member := range releaseUnit.Members {
		if member.Kind != "customer_incapability_catalog" {
			continue
		}
		matchedMembers++
		if member.ObjectID != catalog.CatalogID || member.ContentSHA256 != catalog.CatalogHash {
			return errors.New("release unit customer incapability catalog member does not match catalog")
		}
	}
	if matchedMembers != 1 {
		return errors.New("release unit must contain exactly one customer incapability catalog member")
	}
	return nil
}

func validCatalogToken(value string) bool {
	return utf8.RuneCountInString(value) >= 1 && utf8.RuneCountInString(value) <= 128 &&
		catalogSafeTokenPattern.MatchString(value)
}

func validCatalogText(value string) bool {
	length := utf8.RuneCountInString(value)
	return length >= 1 && length <= 2048
}

func uniqueStrings(values []string) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if _, found := seen[value]; found {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func equalStringSlices(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func isSHA256Hex(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256Size && value == fmt.Sprintf("%x", decoded)
}
