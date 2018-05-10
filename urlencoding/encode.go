package urlencoding

import (
	"fmt"
	"net/url"
	"reflect"
	"strconv"
	"strings"
)

// isEmptyValue checks for an unset value in the context of 'omitempty' being set
func isEmptyValue(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.String:
		return v.String() == ""
	case reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Int() == 0
	case reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return v.Uint() == 0
	case reflect.Bool:
		return v.Bool() == false
	}
	return false
}

// encode takes a value and casts it to a string
func encode(v reflect.Value) (string, error) {
	switch v.Kind() {
	case reflect.String:
		return v.String(), nil
	case reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return strconv.FormatInt(v.Int(), 10), nil
	case reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return strconv.FormatUint(v.Uint(), 10), nil
	case reflect.Bool:
		return strconv.FormatBool(v.Bool()), nil
	}
	return "", fmt.Errorf("unsupported type %s", v.Type().Name())
}

// options is an array of options
type tagOptions []string

// parseTag splits up an options string into a field name and list of options
func parseTag(t string) (string, tagOptions) {
	fields := strings.Split(t, ",")
	if len(fields) == 0 {
		return "", nil
	}
	return fields[0], fields[1:]
}

// contains returns whether an option is specified in an option list
func (o tagOptions) contains(option string) bool {
	for _, opt := range o {
		if opt == option {
			return true
		}
	}
	return false
}

// Marshal takes an anonymous struct and returns a URL encoded key/value mapping.
// Much like json encoding the struct is tagged to indicate that the field should
// be marshaled into a mapping.
//
// The tag used by this module is 'url'.  The first tag value is the encoded key name.
//
// The 'omitempty' option causes the encoder to ignore type specific zero values e.g.
// empty strings or integers set to zero
//
// Fields if anonymously tagged (typically structs) are recursively marshalled in
// depth first order, with key-value pairs flattened.
func Marshal(m interface{}) ([]byte, error) {
	// Buffer for building a key/value mapping
	data := &url.Values{}
	if err := marshal(m, data); err != nil {
		return nil, err
	}
	return []byte(data.Encode()), nil
}

// marshal is the internal recursive encoding function
func marshal(m interface{}, data *url.Values) error {
	// If this is a pointer to a struct dereference it.  The value gives us
	// access to the individual field values
	v := reflect.ValueOf(m)
	if v.Kind() == reflect.Ptr {
		v = reflect.Indirect(v)
	}

	// From the type we can access the tags of individual fields within
	// a struct
	t := v.Type()

	for i := 0; i < t.NumField(); i++ {
		st := t.Field(i)
		fv := v.FieldByName(st.Name)

		// Discard fields who aren't tagged as URL encoded
		tag, ok := st.Tag.Lookup("url")
		if !ok {
			continue
		}

		// Parse the tag extracting encoded field name and any options
		name, options := parseTag(tag)
		if name == "" {
			// Handle depth first recursion for nested structs
			switch fv.Kind() {
			case reflect.Struct:
				if err := marshal(fv.Interface(), data); err != nil {
					return err
				}
			default:
				return fmt.Errorf("unhandled anonymous type for field %s", st.Name)
			}
			continue
		}

		// Ignore empty values
		if options.contains("omitempty") && isEmptyValue(fv) {
			continue
		}

		// Finally encode the struct value
		encoded, err := encode(fv)
		if err != nil {
			return fmt.Errorf("urlencode: %v", err)
		}

		data.Set(name, encoded)
	}

	return nil
}
