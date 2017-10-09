package cbmgr

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

type Couchbase struct {
	URL      *url.URL
	Username string
	Password string
	info     *Node
	cluster  *Cluster
}

type Node struct {
	Uptime               string   `json:"uptime,omitempty"`
	CouchApiBase         string   `json:"couchApiBase,omitempty"`
	ClusterMembership    string   `json:"clusterMembership,omitempty"`
	ClusterCompatibility int      `json:"clusterCompatibility,omitempty"`
	Status               string   `json:"status,omitempty"`
	ThisNode             bool     `json:"thisNode,omitempty"`
	Hostname             string   `json:"hostname,omitempty"`
	Version              string   `json:"version,omitempty"`
	OS                   string   `json:"os,omitempty"`
	Services             []string `json:"services,omitempty"`
	IndexMemoryQuota     int      `json:"indexMemoryQuota,omitempty"`
	MemoryQuota          int      `json:"memoryQuota,omitempty"`
	RebalanceStatus      string   `json:"rebalanceStatus,omitempty"`
	OTPCookie            string   `json:"otpCookie,omitempty"`
	OTPNode              string   `json:"otpNode,omitempty"`
}

type Cluster struct {
	IsAdminCreds bool   `json:"isAdminCreds,omitempty"`
	IsEnterprise bool   `json:"isEnterprise,omitempty"`
	UUID         string `json:"uuid,omitempty"`
}

type Pool struct {
	Nodes []Node `json:"nodes,omitempty"`
}

func New(rawURL string) (*Couchbase, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	return &Couchbase{
		URL: u,
	}, nil
}

func (c *Couchbase) Request(method, path string, body []byte, header *http.Header) (resp *http.Response, err error) {

	c.URL.User = url.UserPassword(c.Username, c.Password)
	resp, err = c.request(method, path, bytes.NewReader(body), header)
	if err != nil {
		return nil, fmt.Errorf("Error while connecting with auth: %s", err)
	}
	if resp.StatusCode == 401 {
		return nil, fmt.Errorf("Error authenticating. Check user/password")
	}

	return resp, nil
}

func strSliceContains(slice []string, item string) bool {
	for _, elem := range slice {
		if stripPort(item) == stripPort(elem) {
			return true
		}
	}
	return false
}

func stripPort(str string) string {
	return strings.Split(str, ":")[0]
}

// rest request with url from client
func (c *Couchbase) request(method, path string, body io.Reader, header *http.Header) (resp *http.Response, err error) {
	url := *c.URL
	url.Path = path
	c.Log().Debugf("method=%s url=%s", method, url.String())
	return requestUrl(url.String(), method, path, body, header, 0)
}

// generic rest request with provided url
func requestUrl(reqUrl, method, path string, body io.Reader, header *http.Header, timeout time.Duration) (resp *http.Response, err error) {
	client := &http.Client{
		Timeout: timeout,
	}
	req, err := http.NewRequest(method, reqUrl, body)
	if err != nil {
		return nil, err
	}
	if header != nil {
		req.Header = *header
	}
	return client.Do(req)
}

func (c *Couchbase) Form(method string, path string, data url.Values) (resp *http.Response, err error) {
	headers := make(http.Header)
	headers.Set("Content-Type", "application/x-www-form-urlencoded")
	return c.Request(method, path, []byte(data.Encode()), &headers)
}

func (c *Couchbase) PostForm(path string, data url.Values) (resp *http.Response, err error) {
	return c.Form("POST", path, data)
}

func (c *Couchbase) CheckStatusCode(resp *http.Response, validStatusCodes []int) error {
	validStatusCodesString := make([]string, len(validStatusCodes))

	for i, statusCode := range validStatusCodes {
		if statusCode == resp.StatusCode {
			return nil
		}
		validStatusCodesString[i] = fmt.Sprintf("%d", statusCode)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf(
			"expected statusCode '%s', got %d: %s",
			strings.Join(validStatusCodesString, ", "),
			resp.StatusCode,
			err,
		)
	}

	return fmt.Errorf(
		"expected statusCode '%s', got %d: %s",
		strings.Join(validStatusCodesString, ", "),
		resp.StatusCode,
		string(body),
	)
}

func (c *Couchbase) Connect() error {
	_, err := c.Info()
	return err
}

func (c *Couchbase) Nodes() (nodes []Node, err error) {
	// connect without auth
	c.Log().Debugf("getting node information")
	resp, err := c.Request("GET", "/pools/default", nil, nil)
	if err != nil {
		return nodes, fmt.Errorf("Error while connecting: %s", err)
	}

	// uninitialized
	if resp.StatusCode == 404 {
		return nodes, ErrorNodeUninitialized
	}

	err = c.CheckStatusCode(resp, []int{200})
	if err != nil {
		return nodes, err
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nodes, err
	}

	// parse json
	pool := Pool{}
	err = json.Unmarshal(body, &pool)
	if err != nil {
		return nodes, err
	}

	return pool.Nodes, nil
}

func (c *Couchbase) getInfo(nodes []Node) (*Node, error) {
	for _, node := range nodes {
		if node.ThisNode {
			return &node, nil
		}
	}
	return nil, fmt.Errorf("No node info found")
}

func (c *Couchbase) Info() (*Node, error) {
	if c.info == nil {
		nodes, err := c.Nodes()
		if err != nil {
			return nil, err
		}
		info, err := c.getInfo(nodes)
		if err != nil {
			return nil, err
		}
		c.info = info
	}
	return c.info, nil
}

func (c *Couchbase) Port() uint16 {
	hostParts := strings.Split(c.URL.Host, ":")
	if len(hostParts) < 2 {
		return uint16(80)
	}

	port, err := strconv.ParseInt(hostParts[len(hostParts)-1], 10, 16)
	if err != nil {
		return uint16(80)
	}
	return uint16(port)
}

func (c *Couchbase) ClusterID() (string, error) {
	cluster, err := c.Cluster()
	if err != nil {
		return "", err
	}
	return cluster.UUID, nil
}

func (c *Couchbase) Cluster() (*Cluster, error) {
	if c.cluster == nil {
		resp, err := c.Request("GET", "/pools", nil, nil)
		if err != nil {
			return nil, fmt.Errorf("Error while connecting: %s", err)
		}

		err = c.CheckStatusCode(resp, []int{200})
		if err != nil {
			return nil, err
		}

		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}

		// parse json
		cluster := Cluster{}
		err = json.Unmarshal(body, &cluster)
		if err != nil {
			return nil, err
		}
		c.cluster = &cluster
	}

	return c.cluster, nil

}

func (c *Couchbase) updateMemoryQuota(key string, quota int) error {
	c.Log().Debugf("update quota %s to %d", key, quota)
	data := url.Values{}
	data.Set(key, fmt.Sprintf("%d", quota))
	resp, err := c.PostForm("/pools/default", data)
	if err != nil {
		return err
	}
	return c.CheckStatusCode(resp, []int{200})
}

func (c *Couchbase) Log() *logrus.Entry {
	return logrus.WithField("component", "couchbase")
}

func (c *Couchbase) Ping(rawURL string) error {
	resp, err := requestUrl(rawURL, "GET", "/", nil, nil, 3*time.Second)
	if err != nil {
		return err
	}
	return c.CheckStatusCode(resp, []int{200})
}

// wait for node to become ready to accept requests
func (c *Couchbase) IsReady(rawURL string, timeout time.Duration) (bool, error) {

	interval := time.Tick(1 * time.Second)

	// Keep trying until we're timed out or got a result or got an error
	for {
		select {
		// timed out
		case <-time.After(timeout):
			return false, NewErrorWaitNodeTimeout(rawURL)
		case <-interval:
			if err := c.Ping(rawURL); err == nil {
				// ok, node is ready
				return true, nil
			}
		}
	}

	return false, NewErrorWaitNodeUnexpected(rawURL)
}

// check wether a node is within a cluster and has healthy status
func (c *Couchbase) Healthy(timeout time.Duration) error {
	interval := time.Tick(1 * time.Second)

	// Keep trying until we're timed out or got a result or got an error
	for {
		select {
		// timed out
		case <-time.After(timeout):
			return NewErrorHealthyTimedOut(c.URL.String())
		case <-interval:
			err := c.healthy()
			if err == nil {
				// node has joined cluster
				return nil
			}
		}
	}

	return nil
}

func (c *Couchbase) healthy() error {
	nodes, err := c.Nodes()
	if err != nil {
		return err
	}

	// TODO: This should involve a clusterID comparison
	if len(nodes) < 2 {
		return fmt.Errorf("Node hasn't joined the cluster yet")
	}

	info, err := c.getInfo(nodes)
	if err != nil {
		return err
	}

	if got, expected := info.Status, "healthy"; got != expected {
		return fmt.Errorf("status of node is '%s', expected '%s'", got, expected)
	}

	return nil
}

// Check wether bucket is ready
func (c *Couchbase) BucketReady(name string) (bool, error) {

	// get bucket info
	resp, err := c.request("GET", "/pools/default/buckets/"+name, nil, nil)
	defer resp.Body.Close()

	if (err != nil) || (resp.StatusCode != 200) {
		return false, err
	}

	// convert to status
	body, err := ioutil.ReadAll(resp.Body)
	status := BucketStatus{}
	if err = json.Unmarshal(body, &status); err != nil {
		return false, err
	}

	// check bucket health on all nodes
	if len(status.Nodes) == 0 {
		return false, nil
	}
	for _, node := range status.Nodes {
		if node.Status != "healthy" {
			// bucket still creating on node
			return false, nil
		}
	}

	return true, nil
}

func (c *Couchbase) BucketDelete(name string) error {
	c.Log().Debugf("delete bucket %s", name)
	path := fmt.Sprintf("/pools/default/buckets/%s", name)
	resp, err := c.Request("DELETE", path, nil, nil)
	if err != nil {
		return NewErrorDeleteBucket(name, err)
	}

	return c.CheckStatusCode(resp, []int{200})
}
