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
	"time"

	logf "sigs.k8s.io/controller-runtime/pkg/runtime/log"
)

const (
	ContentTypeUrlEncoded string = "application/x-www-form-urlencoded"
	ContentTypeJSON       string = "application/json"

	HeaderAuthorization string = "Authorization"
	HeaderContentType   string = "Content-Type"
	HeaderUserAgent     string = "User-Agent"

	tcpConnectTimeout = 5 * time.Second
)

var log = logf.Log.WithName("client")

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
		// If the TLS configuration is explicitly set use that, otherwise
		// use a basic configuration (which won't ever work unless your cluster
		// is signed by a CA defined in the ca-certificates package)
		var tlsClientConfig *tls.Config = nil
		if c.tls != nil {
			tlsClientConfig = &tls.Config{
				RootCAs:            x509.NewCertPool(),
				InsecureSkipVerify: c.tls.Insecure,
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

// doRequest is the generic request handler for all client calls.
func (c *Couchbase) doRequest(request *http.Request, result interface{}) error {
	// Do the request recording the time taken.
	start := time.Now()
	response, err := c.client.Do(request)
	if err != nil {
		return err
	}
	delta := time.Since(start)

	// Read the body so we can display it for really verbose debugging.
	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return err
	}

	// Log the request.  Careful here, higher levels of verbosity generate a huge
	// amount more log traffic.
	log.V(1).Info("http",
		"method", request.Method,
		"url", request.URL.String(),
		"status", response.Status,
		"time_ms", float64(delta.Nanoseconds())/1000000.0,
	)
	log.V(2).Info("http",
		"body", string(body),
	)

	// Anything outside of a 2XX we regard as an error.
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("request failed %v %v %v: %v", request.Method, request.URL.String(), response.Status, body)
	}

	// Don't care about the returned data, just report success.
	if result == nil {
		return nil
	}

	// Handle the content types we expect.
	switch contentType := response.Header.Get("Content-Type"); contentType {
	case "application/json":
		if err := json.Unmarshal(body, result); err != nil {
			return err
		}
	case "text/plain":
		s, ok := result.(*string)
		if !ok {
			return fmt.Errorf("unexpected type decode for text/plain")
		}
		*s = string(body)
	default:
		fmt.Errorf("unexpected content type %s", contentType)
	}

	return nil
}

func (c *Couchbase) n_get(path string, result interface{}, headers http.Header) error {
	errs := []error{}
	for _, endpoint := range c.endpoints {
		req, err := http.NewRequest("GET", endpoint+path, nil)
		if err != nil {
			return ClientError{"request creation", err}
		}
		req.Header = headers
		if err := c.doRequest(req, result); err != nil {
			errs = append(errs, err)
			continue
		}
		return nil
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
		if err := c.doRequest(req, nil); err != nil {
			errs = append(errs, err)
			continue
		}
		return nil
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
		if err := c.doRequest(req, nil); err != nil {
			errs = append(errs, err)
			continue
		}
		return nil
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
		if err := c.doRequest(req, nil); err != nil {
			errs = append(errs, err)
			continue
		}
		return nil
	}

	return BulkError{errs}
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
	headers.Set("Accept-Encoding", "application/json, text/plain, */*")

	return headers
}
