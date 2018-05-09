package cbmgr

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"reflect"
	"strings"
	"time"
)

const (
	ContentTypeUrlEncoded string = "application/x-www-form-urlencoded"
	ContentTypeJSON       string = "application/json"

	HeaderAuthorization string = "Authorization"
	HeaderContentType   string = "Content-Type"
	HeaderUserAgent     string = "User-Agent"

	tcpConnectTimeout = 5 * time.Second
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

// newClient creates a new HTTP client which offers connection persistence and
// also checks that the UUID of a host is what we expect when dialing before
// allowing further HTTP requests.
//
// Here be dragons!  You have been warned...
func (c *Couchbase) makeClient() {
	// uuidCheck is a closure which binds basic HTTP authorization and cluster
	// UUID to the configuration.  It is responsible for doing a HTTP GET from
	// a new network connection and verifying that the UUID matches what we
	// expect before allowing the http.Client to be used.
	uuidCheck := func(addr string, conn net.Conn) error {
		// Checks not enabled yet i.e. cluster initialization
		if c.uuid == "" {
			return nil
		}

		// Construct a HTTP request
		req, err := http.NewRequest("GET", "/pools", nil)
		if err != nil {
			return fmt.Errorf("uuid check: %s", err.Error())
		}
		req.URL.Host = addr
		req.Header.Set("Accept-Encoding", "application/json")
		req.SetBasicAuth(c.username, c.password)

		// Perform the transaction
		if err = req.Write(conn); err != nil {
			return fmt.Errorf("uuid check: %s", err.Error())
		}
		resp, err := http.ReadResponse(bufio.NewReader(conn), req)
		if err != nil {
			return fmt.Errorf("uuid check: %s", err.Error())
		}

		// Check the status code was 2XX
		if resp.StatusCode/100 != 2 {
			return fmt.Errorf("uuid check: unexpected status code '%s' from %s", resp.Status, addr)
		}
		defer resp.Body.Close()

		// Read the body
		buffer, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("uuid check: %s", err.Error())
		}

		// Parse the JSON body into our anonymous struct, we only care about the UUID
		var body struct {
			UUID interface{}
		}
		if err = json.Unmarshal(buffer, &body); err != nil {
			return fmt.Errorf("uuid check: json error '%s' from %s", err.Error(), addr)
		}

		// UUID is a string if set or an empty array otherwise :/
		var uuid string
		switch t := body.UUID.(type) {
		case string:
			uuid = t
		case []interface{}:
			return fmt.Errorf("uuid is unset")
		default:
			return fmt.Errorf("uuid is unexpected type: %s", reflect.TypeOf(t))
		}

		// Finally check the UUID is as we expect.  Will be empty if no body was found
		if uuid != c.uuid {
			return fmt.Errorf("uuid check: wanted %s got %s from %s", c.uuid, uuid, addr)
		}
		return nil
	}

	// dialContext is a closure which binds to the uuidCheck closure which
	// is specific to the username/password/uuid of the cluster.  It is called
	// when a HTTP client first dials a host and verifies the UUID is as expected.
	dialContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
		// Establish a TCP connection
		dialer := &net.Dialer{
			Timeout:   tcpConnectTimeout,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}
		conn, err := dialer.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}

		// Check the UUID of the host matches our configuration before
		// allowing use of this connection
		if err = uuidCheck(addr, conn); err != nil {
			return nil, err
		}

		return conn, nil
	}

	// dialTLS is a closure which binds to the uuidCheck closure which
	// is specific to the username/password/uuid of the cluster.  It is called
	// when a HTTPS client first dials a host and verifies the UUID is as expected.
	dialTLS := func(network, addr string) (net.Conn, error) {
		// If the TLS configuration is explicilty set use that, otherwise
		// use a basic configuration (which won't ever work unless your cluster
		// is signed by a CA defined in the ca-certificates package)
		var tlsClientConfig *tls.Config = nil
		if c.tls != nil {
			tlsClientConfig = &tls.Config{
				RootCAs: x509.NewCertPool(),
			}
			// At the very least we need a CA certificate to attain trust in the remote end
			if ok := tlsClientConfig.RootCAs.AppendCertsFromPEM(c.tls.CACert); !ok {
				return nil, fmt.Errorf("failed to append CA certificate")
			}
			// If the remote end needs to trust us too we add a client certificate and key pair
			if c.tls.ClientAuth != nil {
				cert, err := tls.X509KeyPair(c.tls.ClientAuth.Cert, c.tls.ClientAuth.Key)
				if err != nil {
					return nil, err
				}
				tlsClientConfig.Certificates = append(tlsClientConfig.Certificates, cert)
			}
		}

		// Establish a TCP connection with TLS transport
		dialer := &net.Dialer{
			Timeout:   tcpConnectTimeout,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}
		conn, err := tls.DialWithDialer(dialer, network, addr, tlsClientConfig)
		if err != nil {
			return nil, err
		}

		// Check the UUID of the host matches our configuration before
		// allowing use of this connection
		if err = uuidCheck(addr, conn); err != nil {
			return nil, err
		}
		return conn, nil
	}

	// Create the basic client configuration to support HTTP
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext:  dialContext,
			DialTLS:      dialTLS,
			MaxIdleConns: 100,
		},
	}

	c.client = client
}

func (c *Couchbase) n_get(path string, result interface{}, headers http.Header) error {
	errs := []error{}
	for _, endpoint := range c.endpoints {
		req, err := http.NewRequest("GET", endpoint+path, nil)
		if err != nil {
			return ClientError{"request creation", err}
		}

		req.Header = headers

		response, err := c.client.Do(req)
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

		response, err := c.client.Do(req)
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

func (c *Couchbase) n_put(path string, data []byte, headers http.Header) error {
	errs := []error{}
	for _, endpoint := range c.endpoints {
		req, err := http.NewRequest("PUT", endpoint+path, bytes.NewBuffer(data))
		if err != nil {
			return ClientError{"request creation", err}
		}
		req.Header = headers

		response, err := c.client.Do(req)
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

		response, err := c.client.Do(req)
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

	userAgent := "gocbmgr"
	if c.userAgent != nil {
		userAgent = c.userAgent.Name + "/" + c.userAgent.Version
		if c.userAgent.UUID != "" {
			userAgent += " (" + c.userAgent.UUID + ")"
		}
	}
	headers.Set(HeaderUserAgent, userAgent)

	return headers
}
