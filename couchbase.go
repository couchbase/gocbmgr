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

type Bucket struct {
	BucketName         string  `json:"name"`
	BucketType         string  `json:"type"`
	BucketMemoryQuota  int     `json:"memoryQuota"`
	BucketReplicas     int     `json:"replicas"`
	IoPriority         *string `json:"ioPriority"`
	EvictionPolicy     *string `json:"evictionPolicy"`
	ConflictResolution *string `json:"conflictResolution"`
	EnableFlush        *bool   `json:"enableFlush"`
	EnableIndexReplica *bool   `json:"enableIndexReplica"`
	BucketPassword     *string `json:"password"`
}

type BucketStatus struct {
	Bucket
	Nodes []Node `json:"nodes,omitempty"`
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

func (c *Couchbase) RemoveNodes(removeNodes []string) error {
	ejectNodes, _, _, allNodes, err := c.GetOTPNodes(removeNodes, []string{}, []string{})
	if err != nil {
		return err
	}

	if len(ejectNodes) != len(removeNodes) {
		return fmt.Errorf("Some nodes specified to be removed are not part of the cluster")
	}

	err = c.Rebalance(allNodes, ejectNodes)
	if err != nil {
		return err
	}

	var minSleep = time.Second * 2
	var sleep time.Duration = 0
	var nodeInClusterCount = 0
	for {
		time.Sleep(sleep)

		status, err := c.RebalanceStatus()
		if err != nil {
			sleep = 500 * time.Millisecond
			c.Log().Warnf("Error while checking rebalance status: %s", err)
			continue
		}
		sleep = time.Duration(int64(status.RecommendedRefreshPeriod * float64(time.Second)))
		if sleep < minSleep {
			sleep = minSleep
		}

		nodeInRebalance := false
		for _, node := range ejectNodes {
			if strSliceContains(status.Nodes, node) {
				nodeInRebalance = true
			}
		}

		if nodeInRebalance {
			nodeInClusterCount = 0
			continue
		}

		nodes, err := c.Nodes()
		if err != nil {
			c.Log().Warnf("Error while getting nodes: %s", err)
			continue
		}

		nodeInCluster := false
		for _, node := range nodes {
			if strSliceContains(ejectNodes, node.OTPNode) {
				nodeInCluster = true
			}
		}

		if nodeInCluster {
			if nodeInClusterCount > 10 {
				// better handling would probably be to prevent further scaling down / pod termination
				c.Log().Fatalf("rebalance finished, but node is still in the cluster. Rebalance failed")
				break
			}
			nodeInClusterCount++
			continue
		}

		c.Log().Infof("rebalance finished")
		break
	}

	return nil

}

func (c *Couchbase) GetOTPNodes(ejectNodes, failoverNode, reAddNode []string) (outEjectNodes, outFailoverNodes, outReAddNodes, outAllNodes []string, err error) {

	nodes, err := c.Nodes()
	if err != nil {
		return
	}

	for _, node := range nodes {
		if node.OTPNode == "" {
			err = fmt.Errorf("Unable to get OTP name for %+v", node)
			return
		}
		outAllNodes = append(outAllNodes, node.OTPNode)
		if strSliceContains(ejectNodes, node.Hostname) {
			outEjectNodes = append(outEjectNodes, node.OTPNode)
		}
	}

	return outEjectNodes, outFailoverNodes, outReAddNodes, outAllNodes, nil
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

func (c *Couchbase) KnownOTPNodes() ([]string, error) {
	otpNodes := []string{}
	nodes, err := c.Nodes()
	if err != nil {
		return otpNodes, err
	}

	for _, node := range nodes {
		otpNodes = append(otpNodes, node.OTPNode)
	}
	return otpNodes, nil

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

func (c *Couchbase) UpdateServices(services []string) error {
	c.Log().Debugf("update services to '%+v'", services)
	data := url.Values{}
	data.Set("services", strings.Join(services, ","))
	resp, err := c.PostForm("/node/controller/setupServices", data)
	if err != nil {
		return err
	}
	return c.CheckStatusCode(resp, []int{200})
}

func (c *Couchbase) EnsureMemoryQuota(dataQuota int, indexQuota int) error {
	info, err := c.Info()
	if err != nil {
		return err
	}

	if info.MemoryQuota != dataQuota {
		err := c.updateMemoryQuota("memoryQuota", dataQuota)
		if err != nil {
			return err
		}
		c.info = nil
	}

	if info.IndexMemoryQuota != indexQuota {
		err := c.updateMemoryQuota("indexMemoryQuota", indexQuota)
		if err != nil {
			return err
		}
		c.info = nil
	}

	return nil
}

func (c *Couchbase) ClusterID() (string, error) {
	cluster, err := c.Cluster()
	if err != nil {
		return "", err
	}
	return cluster.UUID, nil
}

func (c *Couchbase) Rebalance(knownNodes, ejectedNodes []string) error {
	c.Log().Debugf("rebalance nodes ejected=%+v known=%+v", ejectedNodes, knownNodes)
	data := url.Values{}
	data.Set("ejectedNodes", strings.Join(ejectedNodes, ","))
	data.Set("knownNodes", strings.Join(knownNodes, ","))
	resp, err := c.PostForm("/controller/rebalance", data)
	if err != nil {
		return err
	}
	return c.CheckStatusCode(resp, []int{200})
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

func (c *Couchbase) UpdateHostname(hostname string) error {
	c.Log().Debugf("update hostname to '%s'", hostname)
	data := url.Values{}
	data.Set("hostname", hostname)
	resp, err := c.PostForm("/node/controller/rename", data)
	if err != nil {
		return err
	}
	return c.CheckStatusCode(resp, []int{200})
}

func (c *Couchbase) Ping(rawURL string) error {
	resp, err := requestUrl(rawURL, "GET", "/", nil, nil, 3*time.Second)
	if err != nil {
		return err
	}
	return c.CheckStatusCode(resp, []int{200})
}

func (c *Couchbase) SetupAuth() error {
	resp, err := c.Request("GET", "/settings/web", nil, nil)
	if err != nil {
		return fmt.Errorf("Error while checking login: %s", err)
	}

	if resp.StatusCode == 200 {
		data := url.Values{}
		data.Set("username", c.Username)
		data.Set("password", c.Password)
		data.Set("port", fmt.Sprintf("%d", c.Port()))
		resp, err := c.PostForm("/settings/web", data)
		if err != nil {
			return err
		}
		err = c.CheckStatusCode(resp, []int{200})
		if err != nil {
			return err
		}
	} else if resp.StatusCode != 401 {
		return fmt.Errorf("Expected couchbase to respond with either 401 or 200")
	}

	return nil
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

func (c *Couchbase) Initialize(hostname string, services []string, dataQuota int, indexQuota int, searchQuota int) error {

	// TODO: set data + index path

	err := c.UpdateHostname(hostname)
	if err != nil {
		return err
	}

	err = c.UpdateServices(services)
	if err != nil {
		return err
	}

	err = c.SetupAuth()
	if err != nil {
		return err
	}

	// TODO: searchQuota
	err = c.EnsureMemoryQuota(dataQuota, indexQuota)
	if err != nil {
		return err
	}

	return nil
}

// Add node with retry for robustness as
// join sometimes fails due to non server errors
// such as client EOF
func (c *Couchbase) RetryableAddNode(nodeName, username, password string, services []string, serverGroup string, tries int) error {
	var err error
	for i := 0; i < tries; i++ {
		err = c.AddNode(nodeName, username, password, services, serverGroup)
		if err == nil {
			return nil
		} else {
			// log error as warning
			c.Log().Warnf("attempt to add node failed...retrying %s", err)
		}

		time.Sleep(1 * time.Second)
	}
	return err
}

func (c *Couchbase) AddNode(nodeName, username, password string, services []string, serverGroup string) error {

	data := url.Values{}
	data.Set("hostname", nodeName)
	data.Set("user", username)
	data.Set("password", password)
	data.Set("services", strings.Join(services, ","))
	c.Log().Debugf(
		"adding node hostname='%s' username='%s' password='%s' services='%s'",
		nodeName,
		username,
		password,
		strings.Join(services, ","),
	)
	resp, err := c.PostForm("/controller/addNode", data)
	if err != nil {
		return err
	}
	return c.CheckStatusCode(resp, []int{200})
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

// create bucket from json spec by unmarshalling to
// native bucket type
func (c *Couchbase) CreateBucketFromSpec(data []byte) error {

	// parse bucket json spec
	bucket := Bucket{}
	if err := json.Unmarshal(data, &bucket); err != nil {
		return err
	}

	// create
	return c.CreateBucket(&bucket, true)

}

func (c *Couchbase) CreateBucket(bucket *Bucket, sync bool) error {

	c.Log().Debugf("create bucket %+v", bucket)
	data := url.Values{}
	data.Set("name", bucket.BucketName)
	data.Set("bucketType", bucket.BucketType)
	data.Set("ramQuotaMB", strconv.Itoa(bucket.BucketMemoryQuota))
	data.Set("replicaNumber", strconv.Itoa(bucket.BucketReplicas))
	data.Set("proxyPort", "8091")
	data.Set("authType", "sasl")
	if bucket.BucketPassword != nil {
		data.Set("saslPassword", *bucket.BucketPassword)
	} else {
		data.Set("authType", "none")
	}
	if bucket.EvictionPolicy != nil {
		data.Set("evictionPolicy", *bucket.EvictionPolicy)
	}
	if bucket.IoPriority != nil {
		if *bucket.IoPriority == "high" {
			data.Set("threadsNumber", "8")
		}
		if *bucket.IoPriority == "low" {
			data.Set("threadsNumber", "2")
		}
	}
	if bucket.ConflictResolution != nil {
		data.Set("conflictResolutionType", *bucket.ConflictResolution)
	}
	if bucket.EnableFlush != nil {
		data.Set("flushEnabled", BoolToStr(*bucket.EnableFlush))
	}
	if bucket.EnableIndexReplica != nil {
		data.Set("replicaIndex", BoolToStr(*bucket.EnableIndexReplica))
	}

	// post
	resp, err := c.PostForm("/pools/default/buckets", data)
	if err != nil {
		return err
	}
	return c.CheckStatusCode(resp, []int{202})
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

func BoolToInt(b bool) int {
	return map[bool]int{false: 0, true: 1}[b]
}

func BoolToStr(b bool) string {
	return strconv.Itoa(BoolToInt(b))
}
