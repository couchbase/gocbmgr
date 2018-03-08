package cbmgr

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
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

type BulkError struct {
	errs []error
}

func (e BulkError) Error() string {
	rv := ""
	for i, err := range e.errs {
		rv += "[" + err.Error() + "]"
		if i != (len(e.errs) - 1) {
			rv += ", "
		}
	}
	return rv
}

type ClientError struct {
	reason string
	err    error
}

func (e ClientError) Error() string {
	return fmt.Sprintf("Client error `%s`: %s", e.reason, e.err.Error())
}

type NetworkError struct {
	endpoint string
	path     string
	err      error
}

func (e NetworkError) Error() string {
	return fmt.Sprintf("Network Error (%s%s): %s", e.endpoint, e.path, e.err.Error())
}

type ServerError struct {
	errors   map[string]string
	endpoint string
	path     string
	code     int
}

func (e ServerError) Error() string {
	all := []string{}
	for k, v := range e.errors {
		all = append(all, k+" - "+v)
	}

	return fmt.Sprintf("Server Error %d (%s%s): %s", e.code, e.endpoint, e.path, all)
}

// Check whether the endpoint is using TLS or not
func (c *Couchbase) getScheme(endpoint string) string {
	if strings.HasPrefix(endpoint, "https://") {
		return "https"
	}
	return "http"
}

func (c *Couchbase) getClient(endpoint string) (*http.Client, error) {
	client := &http.Client{
		Timeout: c.timeout,
	}
	if c.getScheme(endpoint) == "https" && c.tls != nil {
		tlsClientConfig := &tls.Config{
			RootCAs: x509.NewCertPool(),
		}
		// At the very least we need a CA certificate to attain trust in the remote end
		if ok := tlsClientConfig.RootCAs.AppendCertsFromPEM(c.tls.CACert); !ok {
			return nil, ClientError{"client create", fmt.Errorf("failed to append CA certificate")}
		}
		// If the remote end needs to trust us too we add a client certificate and key pair
		if c.tls.ClientAuth != nil {
			cert, err := tls.X509KeyPair(c.tls.ClientAuth.Cert, c.tls.ClientAuth.Key)
			if err != nil {
				return nil, err
			}
			tlsClientConfig.Certificates = append(tlsClientConfig.Certificates, cert)
		}
		transport := &http.Transport{
			TLSClientConfig: tlsClientConfig,
		}
		client.Transport = transport
	}
	return client, nil
}

func (c *Couchbase) n_get(path string, result interface{}, headers http.Header) error {
	errs := []error{}
	for _, endpoint := range c.endpoints {
		req, err := http.NewRequest("GET", endpoint+path, nil)
		if err != nil {
			return ClientError{"request creation", err}
		}

		req.Header = headers

		client, err := c.getClient(endpoint)
		if err != nil {
			return ClientError{"client create", err}
		}
		response, err := client.Do(req)
		if err != nil {
			errs = append(errs, err)
		} else {
			if rerr := c.n_handleResponse(response, result); rerr != nil {
				errs = append(errs, rerr)
			} else {
				return nil
			}
		}

	}

	return BulkError{errs}
}

func (c *Couchbase) n_post(path string, data []byte, headers http.Header) error {
	errs := []error{}
	for _, endpoint := range c.endpoints {
		req, err := http.NewRequest("POST", endpoint+path, bytes.NewBuffer(data))
		if err != nil {
			return ClientError{"request creation", err}
		}
		req.Header = headers

		client, err := c.getClient(endpoint)
		if err != nil {
			return ClientError{"client create", err}
		}
		response, err := client.Do(req)
		if err != nil {
			errs = append(errs, err)
		} else {
			if rerr := c.n_handleResponse(response, nil); rerr != nil {
				errs = append(errs, rerr)
			} else {
				return nil
			}
		}
	}

	return BulkError{errs}
}

func (c *Couchbase) n_delete(path string, headers http.Header) error {
	errs := []error{}
	for _, endpoint := range c.endpoints {
		req, err := http.NewRequest("DELETE", endpoint+path, nil)
		if err != nil {
			return ClientError{"request creation", err}
		}
		req.Header = headers

		client, err := c.getClient(endpoint)
		if err != nil {
			return ClientError{"client create", err}
		}
		response, err := client.Do(req)
		if err != nil {
			errs = append(errs, err)
		} else {
			if rerr := c.n_handleResponse(response, nil); rerr != nil {
				errs = append(errs, rerr)
			} else {
				return nil
			}
		}
	}

	return BulkError{errs}
}

func (c *Couchbase) n_handleResponse(response *http.Response, result interface{}) error {
	host := response.Request.Host
	path := response.Request.URL.Path
	if response.StatusCode == http.StatusOK || response.StatusCode == http.StatusAccepted || response.StatusCode == http.StatusCreated {
		defer response.Body.Close()
		if result != nil {
			decoder := json.NewDecoder(response.Body)
			decoder.UseNumber()
			err := decoder.Decode(result)
			if err != nil {
				return ClientError{"unmarshal json response", err}
			}
		}

		return nil
	} else if response.StatusCode == http.StatusBadRequest {
		defer response.Body.Close()
		data, err := ioutil.ReadAll(response.Body)
		if err != nil {
			return ClientError{"unmarshal json response", err}
		}

		type errMapoverlay struct {
			Errors map[string]string
		}

		var errMapData errMapoverlay
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.UseNumber()
		err = decoder.Decode(&errMapData)
		if err == nil {
			return ServerError{errMapData.Errors, host, path, response.StatusCode}
		}

		var listData []string
		decoder = json.NewDecoder(bytes.NewReader(data))
		err = decoder.Decode(&listData)
		if err == nil {
			return ServerError{map[string]string{"error": listData[0]}, host, path, response.StatusCode}
		}

		return ServerError{map[string]string{"body": "Client error processing response"}, host, path, response.StatusCode}
	} else if response.StatusCode == http.StatusUnauthorized {
		return ServerError{map[string]string{"auth": "Invalid username and password"}, host, path, response.StatusCode}
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
			return ServerError{map[string]string{"body": err.Error()}, host, path, response.StatusCode}
		}

		msg := data.Message + ": " + strings.Join(data.Permissions, ", ")
		return ServerError{map[string]string{"permissions": msg}, host, path, response.StatusCode}
	} else {
		return ServerError{map[string]string{}, host, path, response.StatusCode}
	}
}

func (c *Couchbase) defaultHeaders() http.Header {
	auth := "Basic " + base64.StdEncoding.EncodeToString([]byte(c.username+":"+c.password))

	headers := http.Header{}
	headers.Set(HeaderAuthorization, auth)
	headers.Set(HeaderUserAgent, "gocbmgr")

	return headers
}
