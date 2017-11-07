package cbmgr

import (
	"net/url"
	"strconv"
	"strings"
)

func (c *Couchbase) addNode(hostname, username, password string, services ServiceList) error {
	data := url.Values{}
	data.Set("hostname", hostname)
	data.Set("user", username)
	data.Set("password", password)
	data.Set("services", services.String())

	headers := c.defaultHeaders()
	headers.Set("Content-Type", ContentTypeUrlEncoded)

	return c.n_post("/controller/addNode", []byte(data.Encode()), headers)
}

func (c *Couchbase) cancelAddNode(otpNode string) error {
	data := url.Values{}
	data.Set("otpNode", otpNode)

	headers := c.defaultHeaders()
	headers.Set("Content-Type", ContentTypeUrlEncoded)

	return c.n_post("/controller/ejectNode", []byte(data.Encode()), headers)
}

func (c *Couchbase) getPools() (*PoolsInfo, error) {
	info := &PoolsInfo{}
	err := c.n_get("/pools", info, c.defaultHeaders())
	if err != nil {
		return nil, err
	}

	return info, nil
}

func (c *Couchbase) getPoolsDefault() (*ClusterInfo, error) {
	clusterInfo := &ClusterInfo{}
	err := c.n_get("/pools/default", clusterInfo, c.defaultHeaders())
	if err != nil {
		return nil, err
	}

	return clusterInfo, nil
}

func (c *Couchbase) getTasks() ([]*Task, error) {
	tasks := []*Task{}
	err := c.n_get("/pools/default/tasks", &tasks, c.defaultHeaders())
	if err != nil {
		return nil, err
	}

	return tasks, nil
}

func (c *Couchbase) rebalance(allNodes, ejectNodes []string) error {
	data := url.Values{}
	data.Set("ejectedNodes", strings.Join(ejectNodes, ","))
	data.Set("knownNodes", strings.Join(allNodes, ","))

	headers := c.defaultHeaders()
	headers.Set("Content-Type", ContentTypeUrlEncoded)

	return c.n_post("/controller/rebalance", []byte(data.Encode()), headers)
}

func (c *Couchbase) setPoolsDefault(name string, dataMemQuotaMB, indexMemQuotaMB, searchMemQuotaMB int) error {
	data := url.Values{}
	data.Set("memoryQuota", strconv.Itoa(dataMemQuotaMB))
	data.Set("indexMemoryQuota", strconv.Itoa(indexMemQuotaMB))
	data.Set("ftsMemoryQuota", strconv.Itoa(searchMemQuotaMB))
	data.Set("clusterName", name)

	headers := c.defaultHeaders()
	headers.Set(HeaderContentType, ContentTypeUrlEncoded)

	return c.n_post("/pools/default", []byte(data.Encode()), headers)
}

func (c *Couchbase) setStoragePaths(dataPath, indexPath string) error {
	data := url.Values{}
	data.Set("path", dataPath)
	data.Set("indexPath", indexPath)

	headers := c.defaultHeaders()
	headers.Set("Content-Type", ContentTypeUrlEncoded)

	return c.n_post("/nodes/self/controller/settings", []byte(data.Encode()), headers)
}

func (c *Couchbase) setHostname(hostname string) error {
	data := url.Values{}
	data.Set("hostname", hostname)

	headers := c.defaultHeaders()
	headers.Set("Content-Type", ContentTypeUrlEncoded)

	return c.n_post("/node/controller/rename", []byte(data.Encode()), headers)
}

func (c *Couchbase) getIndexSettings() (*IndexSettings, error) {
	settings := &IndexSettings{}
	err := c.n_get("/settings/indexes", settings, c.defaultHeaders())
	if err != nil {
		return nil, err
	}

	return settings, nil
}

func (c *Couchbase) setIndexSettings(mode IndexStorageMode, threads, memSnapInterval,
	stableSnapInterval, maxRollbackPoints int, logLevel IndexLogLevel) error {
	data := url.Values{}
	data.Set("storageMode", string(mode))
	data.Set("indexerThreads", strconv.Itoa(threads))
	data.Set("memorySnapshotInterval", strconv.Itoa(memSnapInterval))
	data.Set("stableSnapshotInterval", strconv.Itoa(stableSnapInterval))
	data.Set("maxRollbackPoints", strconv.Itoa(maxRollbackPoints))
	data.Set("logLevel", string(logLevel))

	headers := c.defaultHeaders()
	headers.Set(HeaderContentType, ContentTypeUrlEncoded)

	return c.n_post("/settings/indexes", []byte(data.Encode()), headers)

	return nil
}

func (c *Couchbase) setServices(services ServiceList) error {
	data := url.Values{}
	data.Set("services", services.String())

	headers := c.defaultHeaders()
	headers.Set(HeaderContentType, ContentTypeUrlEncoded)

	return c.n_post("/node/controller/setupServices", []byte(data.Encode()), headers)
}

func (c *Couchbase) setWebSettings(username, password string, port int) error {
	data := url.Values{}
	data.Set("username", username)
	data.Set("password", password)
	data.Set("port", strconv.Itoa(port))

	headers := c.defaultHeaders()
	headers.Set(HeaderContentType, ContentTypeUrlEncoded)

	return c.n_post("/settings/web", []byte(data.Encode()), headers)
}

func (c *Couchbase) createBucket(bucket *Bucket) error {
	params := bucket.FormEncode()
	headers := c.defaultHeaders()
	headers.Set(HeaderContentType, ContentTypeUrlEncoded)
	return c.n_post("/pools/default/buckets", params, headers)
}

func (c *Couchbase) deleteBucket(name string) error {
	headers := c.defaultHeaders()
	headers.Set(HeaderContentType, ContentTypeUrlEncoded)

	path := "/pools/default/buckets/" + name
	return c.n_delete(path, headers)
}

func (c *Couchbase) editBucket(bucket *Bucket) error {
	params := bucket.FormEncode()
	headers := c.defaultHeaders()
	headers.Set(HeaderContentType, ContentTypeUrlEncoded)
	return c.n_post("/pools/default/buckets/"+bucket.BucketName, params, headers)
}

func (c *Couchbase) getBucketStatus(name string) (*BucketStatus, error) {
	status := &BucketStatus{}
	path := "/pools/default/buckets/" + name
	err := c.n_get(path, status, c.defaultHeaders())
	if err != nil {
		return nil, err
	}
	return status, nil
}

func (c *Couchbase) getBuckets() ([]*Bucket, error) {
	buckets := []*Bucket{}
	path := "/pools/default/buckets/"
	err := c.n_get(path, &buckets, c.defaultHeaders())
	if err != nil {
		return nil, err
	}
	return buckets, nil
}

// Autofailover settings with specified timeout
func (c *Couchbase) setAutoFailoverTimeout(enabled bool, timeout uint64) error {

	data := url.Values{}
	data.Set("enabled", BoolAsStr(enabled))
	if enabled {
		data.Set("timeout", strconv.FormatUint(timeout, 10))
	}

	headers := c.defaultHeaders()
	headers.Set(HeaderContentType, ContentTypeUrlEncoded)

	return c.n_post("/settings/autoFailover", []byte(data.Encode()), headers)
}

func (c *Couchbase) getAutoFailoverSettings() (*AutoFailoverSettings, error) {
	settings := &AutoFailoverSettings{}
	err := c.n_get("/settings/autoFailover", settings, c.defaultHeaders())
	if err != nil {
		return nil, err
	}

	return settings, nil
}
