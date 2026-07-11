package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"reflect"
	"strings"
)

const maxJSONBody = 64 * 1024

func decodeJSON(w http.ResponseWriter, r *http.Request, destination any) error {
	if contentType := r.Header.Get("Content-Type"); contentType != "" {
		mediaType, _, err := mime.ParseMediaType(contentType)
		if err != nil || mediaType != "application/json" {
			return errBadRequest
		}
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBody)
	encoded, err := io.ReadAll(r.Body)
	if err != nil || len(bytes.TrimSpace(encoded)) == 0 {
		return errBadRequest
	}
	if err := rejectDuplicateKeys(encoded); err != nil {
		return errBadRequest
	}
	if err := requireExactTopLevelFields(encoded, destination); err != nil {
		return errBadRequest
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return errBadRequest
	}
	if err := requireJSONEOF(decoder); err != nil {
		return errBadRequest
	}
	return nil
}

func requireExactTopLevelFields(encoded []byte, destination any) error {
	typeOf := reflect.TypeOf(destination)
	if typeOf == nil || typeOf.Kind() != reflect.Pointer || typeOf.Elem().Kind() != reflect.Struct {
		return nil
	}
	allowed := make(map[string]struct{})
	structType := typeOf.Elem()
	for index := 0; index < structType.NumField(); index++ {
		field := structType.Field(index)
		name := strings.Split(field.Tag.Get("json"), ",")[0]
		if name != "" && name != "-" {
			allowed[name] = struct{}{}
		}
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &object); err != nil || object == nil {
		return errors.New("request must be a JSON object")
	}
	for name := range object {
		if _, ok := allowed[name]; !ok {
			return errors.New("unknown or incorrectly cased JSON field")
		}
	}
	return nil
}

func rejectDuplicateKeys(encoded []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	if err := scanJSONValue(decoder, 0); err != nil {
		return err
	}
	return requireJSONEOF(decoder)
}

func scanJSONValue(decoder *json.Decoder, depth int) error {
	if depth > 32 {
		return errors.New("JSON nesting limit exceeded")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("object key is not a string")
			}
			comparisonKey := strings.ToLower(key)
			if _, duplicate := seen[comparisonKey]; duplicate {
				return errors.New("duplicate JSON object key")
			}
			seen[comparisonKey] = struct{}{}
			if err := scanJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("invalid object terminator")
		}
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("invalid array terminator")
		}
	default:
		return errors.New("invalid JSON delimiter")
	}
	return nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("request must contain one JSON value")
	}
	return nil
}
