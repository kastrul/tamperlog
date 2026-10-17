// Package jcs serialises values per RFC 8785, the JSON Canonicalization
// Scheme, for the subset the library needs: objects with string keys, arrays,
// strings, booleans, null and integers whose magnitude is below 2^53. It is
// shared by the jcs/v1 record encoder and the seal and bundle formats.
package jcs

import (
	"errors"
	"fmt"
	"math"
	"slices"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
)

// MaxInt is the largest integer magnitude the serialiser accepts. RFC 8785
// requires numbers to be IEEE-754 doubles; integers up to 2^53-1 serialise as
// plain digits, which is all this package supports.
const MaxInt = 1<<53 - 1

// ErrUnsupported is returned for values outside the supported subset.
var ErrUnsupported = errors.New("jcs: unsupported value")

// Marshal returns the canonical serialisation of v. Supported Go values:
// map[string]any, []any, string, bool, nil, int, int64, uint64, and the
// typed helpers in this package. Object members are sorted by the UTF-16 code
// units of their keys; no whitespace is emitted; strings are escaped
// minimally.
func Marshal(v any) ([]byte, error) {
	return appendValue(make([]byte, 0, 256), v)
}

func appendValue(b []byte, v any) ([]byte, error) {
	switch x := v.(type) {
	case nil:
		return append(b, "null"...), nil
	case bool:
		if x {
			return append(b, "true"...), nil
		}
		return append(b, "false"...), nil
	case string:
		return appendString(b, x)
	case int:
		return appendInt(b, int64(x))
	case int64:
		return appendInt(b, x)
	case uint64:
		if x > MaxInt {
			return nil, fmt.Errorf("%w: integer %d exceeds 2^53-1", ErrUnsupported, x)
		}
		return strconv.AppendUint(b, x, 10), nil
	case float64:
		if x != math.Trunc(x) || math.Abs(x) > MaxInt {
			return nil, fmt.Errorf("%w: non-integer or large number %v", ErrUnsupported, x)
		}
		return appendInt(b, int64(x))
	case []any:
		b = append(b, '[')
		for i, e := range x {
			if i > 0 {
				b = append(b, ',')
			}
			var err error
			if b, err = appendValue(b, e); err != nil {
				return nil, err
			}
		}
		return append(b, ']'), nil
	case []string:
		arr := make([]any, len(x))
		for i, s := range x {
			arr[i] = s
		}
		return appendValue(b, arr)
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		slices.SortFunc(keys, compareUTF16)
		b = append(b, '{')
		for i, k := range keys {
			if i > 0 {
				b = append(b, ',')
			}
			var err error
			if b, err = appendString(b, k); err != nil {
				return nil, err
			}
			b = append(b, ':')
			if b, err = appendValue(b, x[k]); err != nil {
				return nil, err
			}
		}
		return append(b, '}'), nil
	case map[string]string:
		m := make(map[string]any, len(x))
		for k, s := range x {
			m[k] = s
		}
		return appendValue(b, m)
	default:
		return nil, fmt.Errorf("%w: %T", ErrUnsupported, v)
	}
}

func appendInt(b []byte, x int64) ([]byte, error) {
	if x > MaxInt || x < -MaxInt {
		return nil, fmt.Errorf("%w: integer %d exceeds 2^53-1", ErrUnsupported, x)
	}
	return strconv.AppendInt(b, x, 10), nil
}

// appendString escapes per RFC 8785 section 3.2.2.2: only '"', '\' and
// control characters below 0x20 are escaped, the latter with the short forms
// \b \f \n \r \t where they exist and lowercase \u00xx otherwise.
func appendString(b []byte, s string) ([]byte, error) {
	if !utf8.ValidString(s) {
		return nil, fmt.Errorf("%w: string is not valid UTF-8", ErrUnsupported)
	}
	b = append(b, '"')
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == '"':
			b = append(b, '\\', '"')
		case c == '\\':
			b = append(b, '\\', '\\')
		case c == '\b':
			b = append(b, '\\', 'b')
		case c == '\f':
			b = append(b, '\\', 'f')
		case c == '\n':
			b = append(b, '\\', 'n')
		case c == '\r':
			b = append(b, '\\', 'r')
		case c == '\t':
			b = append(b, '\\', 't')
		case c < 0x20:
			b = append(b, '\\', 'u', '0', '0', hexDigit(c>>4), hexDigit(c&0xf))
		case c < utf8.RuneSelf:
			b = append(b, c)
		default:
			_, n := utf8.DecodeRuneInString(s[i:])
			b = append(b, s[i:i+n]...)
			i += n
			continue
		}
		i++
	}
	return append(b, '"'), nil
}

func hexDigit(x byte) byte { return "0123456789abcdef"[x] }

// compareUTF16 orders keys by their UTF-16 code units, as RFC 8785 requires.
func compareUTF16(a, b string) int {
	ua, ub := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			if ua[i] < ub[i] {
				return -1
			}
			return 1
		}
	}
	return len(ua) - len(ub)
}
