package cbmgr

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

const (
	ContentTypeUrlEncoded string = "application/x-www-form-urlencoded"

	HeaderAuthorization string = "Authorization"
	HeaderContentType   string = "Content-Type"
	HeaderUserAgent     string = "User-Agent"
)

type couchbaseErrorType int

const (
	clientError  couchbaseErrorType = 0
	networkError couchbaseErrorType = 0
	serverError  couchbaseErrorType = 0
)

type CouchbaseError struct {
	httpcode  int
	api       string
	errorType couchbaseErrorType
	errors    map[string]string
}

func (e CouchbaseError) ClientError() bool {
	return e.errorType == clientError
}

func (e CouchbaseError) NetworkError() bool {
	return e.errorType == networkError
}

func (e CouchbaseError) ServerError() bool {
	return e.errorType == serverError
}

func (e CouchbaseError) Error() string {
	all := []string{}
	for k, v := range e.errors {
		all = append(all, k+" - "+v)
	}

	return fmt.Sprintf("Code: %d, Error: %v", e.httpcode, strings.Join(all, ","))
}

func (c *Couchbase) n_get(path string, result interface{}, headers http.Header) error {
	req, err := http.NewRequest("GET", c.URL.String()+path, nil)
	if err != nil {
		return CouchbaseError{0, path, clientError, map[string]string{"request_creation": err.Error()}}
	}

	req.Header = headers

	client := http.Client{}
	response, err := client.Do(req)
	if err != nil {
		return CouchbaseError{0, path, networkError, map[string]string{"send": err.Error()}}
	}

	return c.n_handleResponse(response, result)
}

func (c *Couchbase) n_post(path string, data []byte, headers http.Header) error {
	req, err := http.NewRequest("POST", c.URL.String()+path, bytes.NewBuffer(data))
	if err != nil {
		return CouchbaseError{0, path, clientError, map[string]string{"request_creation": err.Error()}}
	}
	req.Header = headers

	client := http.Client{}
	response, err := client.Do(req)
	if err != nil {
		return CouchbaseError{0, path, networkError, map[string]string{"send": err.Error()}}
	}

	return c.n_handleResponse(response, nil)
}

func (c *Couchbase) n_delete(path string, headers http.Header) error {
	req, err := http.NewRequest("DELETE", c.URL.String()+path, nil)
	if err != nil {
		return CouchbaseError{0, path, clientError, map[string]string{"request_creation": err.Error()}}
	}
	req.Header = headers

	client := http.Client{}
	response, err := client.Do(req)
	if err != nil {
		return CouchbaseError{0, path, networkError, map[string]string{"send": err.Error()}}
	}

	return c.n_handleResponse(response, nil)
}

func (c *Couchbase) n_handleResponse(response *http.Response, result interface{}) error {
	if response.StatusCode == http.StatusOK || response.StatusCode == http.StatusAccepted || response.StatusCode == http.StatusCreated {
		defer response.Body.Close()
		if result != nil {
			decoder := json.NewDecoder(response.Body)
			decoder.UseNumber()
			err := decoder.Decode(result)
			if err != nil {
				return CouchbaseError{response.StatusCode, "", clientError, map[string]string{"response": err.Error()}}
			}
		}

		return nil
	} else if response.StatusCode == http.StatusBadRequest {
		defer response.Body.Close()
		data, err := ioutil.ReadAll(response.Body)
		if err != nil {
			return CouchbaseError{response.StatusCode, "", clientError, map[string]string{"response": err.Error()}}
		}

		type errMapoverlay struct {
			Errors map[string]string
		}

		var errMapData errMapoverlay
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.UseNumber()
		err = decoder.Decode(&errMapData)
		if err == nil {
			return CouchbaseError{response.StatusCode, "", serverError, errMapData.Errors}
		}

		var listData []string
		decoder = json.NewDecoder(bytes.NewReader(data))
		err = decoder.Decode(&listData)
		if err == nil {
			return CouchbaseError{response.StatusCode, "", serverError, map[string]string{"error": listData[0]}}
		}

		return CouchbaseError{response.StatusCode, "", clientError, map[string]string{"body": "Error processing response"}}
	} else if response.StatusCode == http.StatusUnauthorized {
		return CouchbaseError{response.StatusCode, "", serverError, map[string]string{"auth": "Invalid username and password"}}
	} else if response.StatusCode == http.StatusForbidden {
		defer response.Body.Close()
		type overlay struct {
			Message     string
			Permissions []string
		}

		var data overlay
		decoder := json.NewDecoder(response.Body)
		decoder.UseNumber()
		err := decoder.Decode(&data)
		if err != nil {
			return CouchbaseError{response.StatusCode, "", clientError, map[string]string{"body": err.Error()}}
		}

		msg := data.Message + ": " + strings.Join(data.Permissions, ", ")
		return CouchbaseError{response.StatusCode, "", serverError, map[string]string{"permissions": msg}}
	} else {
		return CouchbaseError{response.StatusCode, "", serverError, map[string]string{}}
	}
}

func (c *Couchbase) defaultHeaders() http.Header {
	auth := "Basic " + base64.StdEncoding.EncodeToString([]byte(c.Username+":"+c.Password))

	headers := http.Header{}
	headers.Set(HeaderAuthorization, auth)
	headers.Set(HeaderUserAgent, "gocbmgr")

	return headers
}
