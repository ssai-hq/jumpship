// Package canonical implements the single P02-owned canonical JSON and typed
// digest construction used by every hash-addressed Jumpship JSON contract.
package canonical

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

var (
	// ErrInvalidJSON is returned when input is not strict I-JSON suitable for JCS.
	ErrInvalidJSON = errors.New("invalid canonical JSON input")
	// ErrUnsupportedNumber is returned for a value outside the finite IEEE-754 domain.
	ErrUnsupportedNumber = errors.New("number is not representable as finite IEEE-754")
)

// CanonicalizeJSON applies RFC 8785 JSON Canonicalization Scheme rules to one
// strict JSON value. Duplicate object names, trailing values and lone UTF-16
// surrogate escapes are rejected before hashing.
func CanonicalizeJSON(input []byte) ([]byte, error) {
	if !utf8.Valid(input) || hasLoneSurrogateEscape(input) {
		return nil, ErrInvalidJSON
	}
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.UseNumber()
	value, err := decodeValue(decoder)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidJSON, err)
	}
	if decoder.More() {
		return nil, fmt.Errorf("%w: trailing value", ErrInvalidJSON)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: trailing value", ErrInvalidJSON)
	}
	var output bytes.Buffer
	if err := appendCanonical(&output, value); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

// TypedDigest returns SHA-256("jumpship:<object-type>:<schema-version>\x00" ||
// canonical_payload). Object type and schema version are validated to prevent
// ambiguous or attacker-controlled domain strings.
func TypedDigest(objectType, schemaVersion string, logicalPayload []byte) ([32]byte, error) {
	var zero [32]byte
	if !validDomainToken(objectType) || !validSchemaVersion(schemaVersion) {
		return zero, errors.New("invalid typed-digest domain")
	}
	canonical, err := CanonicalizeJSON(logicalPayload)
	if err != nil {
		return zero, err
	}
	hasher := sha256.New()
	_, _ = fmt.Fprintf(hasher, "jumpship:%s:%s", objectType, schemaVersion)
	_, _ = hasher.Write([]byte{0})
	_, _ = hasher.Write(canonical)
	copy(zero[:], hasher.Sum(nil))
	return zero, nil
}

// TypedDigestHex is the lowercase hexadecimal form used in JSON contracts.
func TypedDigestHex(objectType, schemaVersion string, logicalPayload []byte) (string, error) {
	digest, err := TypedDigest(objectType, schemaVersion, logicalPayload)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(digest[:]), nil
}

func validDomainToken(value string) bool {
	if value == "" || len(value) > 96 {
		return false
	}
	for _, r := range value {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '_' && r != '-' {
			return false
		}
	}
	return true
}

func validSchemaVersion(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts {
		if part == "" || (len(part) > 1 && part[0] == '0') {
			return false
		}
		for _, r := range part {
			if r < '0' || r > '9' {
				return false
			}
		}
	}
	return true
}

func decodeValue(decoder *json.Decoder) (any, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		switch value := token.(type) {
		case nil, bool, string, json.Number:
			return value, nil
		default:
			return nil, fmt.Errorf("unsupported token %T", token)
		}
	}
	switch delimiter {
	case '{':
		result := make(map[string]any)
		for decoder.More() {
			keyToken, keyErr := decoder.Token()
			if keyErr != nil {
				return nil, keyErr
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil, errors.New("object member name is not a string")
			}
			if _, duplicate := result[key]; duplicate {
				return nil, fmt.Errorf("duplicate object member %q", key)
			}
			child, childErr := decodeValue(decoder)
			if childErr != nil {
				return nil, childErr
			}
			result[key] = child
		}
		closing, closeErr := decoder.Token()
		if closeErr != nil || closing != json.Delim('}') {
			return nil, errors.New("unterminated object")
		}
		return result, nil
	case '[':
		result := make([]any, 0)
		for decoder.More() {
			child, childErr := decodeValue(decoder)
			if childErr != nil {
				return nil, childErr
			}
			result = append(result, child)
		}
		closing, closeErr := decoder.Token()
		if closeErr != nil || closing != json.Delim(']') {
			return nil, errors.New("unterminated array")
		}
		return result, nil
	default:
		return nil, fmt.Errorf("unexpected delimiter %q", delimiter)
	}
}

func appendCanonical(output *bytes.Buffer, value any) error {
	switch typed := value.(type) {
	case nil:
		output.WriteString("null")
	case bool:
		if typed {
			output.WriteString("true")
		} else {
			output.WriteString("false")
		}
	case string:
		return appendString(output, typed)
	case json.Number:
		number, err := canonicalNumber(typed.String())
		if err != nil {
			return err
		}
		output.WriteString(number)
	case []any:
		output.WriteByte('[')
		for index, child := range typed {
			if index > 0 {
				output.WriteByte(',')
			}
			if err := appendCanonical(output, child); err != nil {
				return err
			}
		}
		output.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Slice(keys, func(left, right int) bool { return utf16Less(keys[left], keys[right]) })
		output.WriteByte('{')
		for index, key := range keys {
			if index > 0 {
				output.WriteByte(',')
			}
			if err := appendString(output, key); err != nil {
				return err
			}
			output.WriteByte(':')
			if err := appendCanonical(output, typed[key]); err != nil {
				return err
			}
		}
		output.WriteByte('}')
	default:
		return fmt.Errorf("%w: unsupported value %T", ErrInvalidJSON, value)
	}
	return nil
}

func appendString(output *bytes.Buffer, value string) error {
	if !utf8.ValidString(value) {
		return ErrInvalidJSON
	}
	output.WriteByte('"')
	for _, r := range value {
		switch r {
		case '"', '\\':
			output.WriteByte('\\')
			output.WriteRune(r)
		case '\b':
			output.WriteString("\\b")
		case '\t':
			output.WriteString("\\t")
		case '\n':
			output.WriteString("\\n")
		case '\f':
			output.WriteString("\\f")
		case '\r':
			output.WriteString("\\r")
		default:
			if r < 0x20 {
				_, _ = fmt.Fprintf(output, "\\u%04x", r)
			} else if r >= 0xD800 && r <= 0xDFFF {
				return ErrInvalidJSON
			} else {
				output.WriteRune(r)
			}
		}
	}
	output.WriteByte('"')
	return nil
}

func canonicalNumber(raw string) (string, error) {
	value, err := strconv.ParseFloat(raw, 64)
	if err != nil || math.IsInf(value, 0) || math.IsNaN(value) {
		return "", ErrUnsupportedNumber
	}
	if value == 0 {
		return "0", nil
	}
	absolute := math.Abs(value)
	if absolute >= 1e-6 && absolute < 1e21 {
		return strconv.FormatFloat(value, 'f', -1, 64), nil
	}
	rendered := strconv.FormatFloat(value, 'e', -1, 64)
	parts := strings.SplitN(rendered, "e", 2)
	if len(parts) != 2 {
		return "", ErrUnsupportedNumber
	}
	exponent, parseErr := strconv.Atoi(parts[1])
	if parseErr != nil {
		return "", ErrUnsupportedNumber
	}
	sign := ""
	if exponent >= 0 {
		sign = "+"
	}
	return parts[0] + "e" + sign + strconv.Itoa(exponent), nil
}

func utf16Less(left, right string) bool {
	leftUnits := utf16.Encode([]rune(left))
	rightUnits := utf16.Encode([]rune(right))
	limit := len(leftUnits)
	if len(rightUnits) < limit {
		limit = len(rightUnits)
	}
	for index := 0; index < limit; index++ {
		if leftUnits[index] != rightUnits[index] {
			return leftUnits[index] < rightUnits[index]
		}
	}
	return len(leftUnits) < len(rightUnits)
}

func hasLoneSurrogateEscape(input []byte) bool {
	inString := false
	escaped := false
	for index := 0; index < len(input); index++ {
		current := input[index]
		if !inString {
			if current == '"' {
				inString = true
			}
			continue
		}
		if escaped {
			escaped = false
			if current != 'u' || index+4 >= len(input) {
				continue
			}
			unit, err := strconv.ParseUint(string(input[index+1:index+5]), 16, 16)
			if err != nil {
				continue
			}
			index += 4
			if unit >= 0xD800 && unit <= 0xDBFF {
				if index+6 >= len(input) || input[index+1] != '\\' || input[index+2] != 'u' {
					return true
				}
				low, lowErr := strconv.ParseUint(string(input[index+3:index+7]), 16, 16)
				if lowErr != nil || low < 0xDC00 || low > 0xDFFF {
					return true
				}
				index += 6
			} else if unit >= 0xDC00 && unit <= 0xDFFF {
				return true
			}
			continue
		}
		switch current {
		case '\\':
			escaped = true
		case '"':
			inString = false
		}
	}
	return false
}
