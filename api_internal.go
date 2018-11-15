package cbmgr

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/couchbase/gocbmgr/urlencoding"
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

func (c *Couchbase) cancelAddBackNode(otpNode string) error {
	data := url.Values{}
	data.Set("otpNode", otpNode)

	headers := c.defaultHeaders()
	headers.Set("Content-Type", ContentTypeUrlEncoded)

	return c.n_post("/controller/reFailOver", []byte(data.Encode()), headers)
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

func (c *Couchbase) stopRebalance() error {
	data := url.Values{}
	data.Set("allowUnsafe", "true")
	headers := c.defaultHeaders()
	headers.Set("Content-Type", ContentTypeUrlEncoded)

	return c.n_post("/controller/stopRebalance", []byte(data.Encode()), headers)
}

func (c *Couchbase) failover(otpNode string) error {
	data := url.Values{}
	data.Set("otpNode", otpNode)

	headers := c.defaultHeaders()
	headers.Set("Content-Type", ContentTypeUrlEncoded)

	return c.n_post("/controller/failOver", []byte(data.Encode()), headers)
}

func (c *Couchbase) setPoolsDefault(defaults *PoolsDefaults) error {
	headers := c.defaultHeaders()
	headers.Set(HeaderContentType, ContentTypeUrlEncoded)

	data, err := urlencoding.Marshal(defaults)
	if err != nil {
		return err
	}

	return c.n_post("/pools/default", data, headers)
}

func (c *Couchbase) setMemoryQuota(id string, quota int) error {
	data := url.Values{}
	data.Set(id, strconv.Itoa(quota))
	headers := c.defaultHeaders()
	headers.Set(HeaderContentType, ContentTypeUrlEncoded)
	return c.n_post("/pools/default", []byte(data.Encode()), headers)
}

func (c *Couchbase) setStoragePaths(dataPath, indexPath string, analyticsPaths []string) error {
	data := url.Values{}
	data.Set("path", dataPath)
	data.Set("index_path", indexPath)
	if len(analyticsPaths) > 0 {
		data.Set("cbas_path", analyticsPaths[0])
		for _, path := range analyticsPaths[1:] {
			data.Add("cbas_path", path)
		}
	}
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
	// bucket params cannot include conflict resolution field
	// during edit.  TODO: fix for couchbase rest API
	bucket.ConflictResolution = nil

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

func (c *Couchbase) insertDoc(bucket *Bucket, docKey string, docData []byte) error {
	docUrl := "/pools/default/buckets/" + bucket.BucketName + "/docs/" + docKey
	headers := c.defaultHeaders()
	headers.Set(HeaderContentType, "application/x-www-form-urlencoded")
	return c.n_post(docUrl, docData, headers)
}

// Autofailover settings with specified timeouts
func (c *Couchbase) setAutoFailoverSettings(settings *AutoFailoverSettings) error {
	headers := c.defaultHeaders()
	headers.Set(HeaderContentType, ContentTypeUrlEncoded)

	data, err := urlencoding.Marshal(settings)
	if err != nil {
		return err
	}

	return c.n_post("/settings/autoFailover", data, headers)
}

func (c *Couchbase) getAutoFailoverSettings() (*AutoFailoverSettings, error) {
	settings := &AutoFailoverSettings{}
	err := c.n_get("/settings/autoFailover", settings, c.defaultHeaders())
	if err != nil {
		return nil, err
	}

	return settings, nil
}

func (c *Couchbase) resetCount() error {

	data := url.Values{}
	headers := c.defaultHeaders()
	headers.Set(HeaderContentType, ContentTypeUrlEncoded)
	return c.n_post("/settings/autoFailover/resetCount", []byte(data.Encode()), headers)
}

func (c *Couchbase) getNodeInfo() (*NodeInfo, error) {
	node := &NodeInfo{}
	err := c.n_get("/nodes/self", node, c.defaultHeaders())
	if err != nil {
		return nil, err
	}

	return node, nil
}

func (c *Couchbase) uploadClusterCACert(pem []byte) error {
	headers := c.defaultHeaders()
	return c.n_post("/controller/uploadClusterCA", pem, headers)
}

func (c *Couchbase) reloadNodeCert() error {
	headers := c.defaultHeaders()
	return c.n_post("/node/controller/reloadCertificate", []byte{}, headers)
}

func (c *Couchbase) setClientCertAuth(settings *ClientCertAuth) error {
	data, err := json.Marshal(settings)
	if err != nil {
		return err
	}
	headers := c.defaultHeaders()
	return c.n_post("/settings/clientCertAuth", data, headers)
}

func (c *Couchbase) getUpdatesEnabled() (bool, error) {
	settingsStats := &SettingsStats{}
	if err := c.n_get("/settings/stats", settingsStats, c.defaultHeaders()); err != nil {
		return false, err
	}
	return settingsStats.SendStats, nil
}

func (c *Couchbase) setUpdatesEnabled(enabled bool) error {
	data := url.Values{}
	data.Set("sendStats", BoolAsStr(enabled))
	headers := c.defaultHeaders()
	headers.Set(HeaderContentType, ContentTypeUrlEncoded)
	return c.n_post("/settings/stats", []byte(data.Encode()), headers)
}

func (c *Couchbase) getAlternateAddressesExternal() (*AlternateAddressesExternal, error) {
	nodeServices := &NodeServices{}
	if err := c.n_get("/pools/default/nodeServices", nodeServices, c.defaultHeaders()); err != nil {
		return nil, err
	}
	for _, node := range nodeServices.NodesExt {
		if !node.ThisNode {
			continue
		}
		if node.AlternateAddresses == nil {
			return nil, nil
		}
		return node.AlternateAddresses.External, nil
	}
	return nil, fmt.Errorf("unable to locate alternate addresses for this node")
}

func (c *Couchbase) setAlternateAddressesExternal(addresses *AlternateAddressesExternal) error {
	headers := c.defaultHeaders()
	headers.Set(HeaderContentType, ContentTypeUrlEncoded)
	data, err := urlencoding.Marshal(addresses)
	if err != nil {
		return err
	}
	return c.n_put("/node/controller/setupAlternateAddresses/external", data, headers)
}

func (c *Couchbase) deleteAlternateAddressesExternal() error {
	headers := c.defaultHeaders()
	return c.n_delete("/node/controller/setupAlternateAddresses/external", headers)
}

func (c *Couchbase) getLogs() (LogList, error) {
	body := make(map[string]LogList)
	if err := c.n_get("/logs", &body, c.defaultHeaders()); err != nil {
		return nil, err
	}

	if logs, ok := body["list"]; ok {
		return logs, nil
	}
	return nil, NewErrorInvalidLogList()
}

func (c *Couchbase) logClientError(msg string) error {
	data := url.Values{}
	data.Set("error", msg)

	headers := c.defaultHeaders()
	headers.Set("Content-Type", ContentTypeUrlEncoded)

	return c.n_post("/logClientError", []byte(data.Encode()), headers)
}

func (c *Couchbase) getServerGroups() (*ServerGroups, error) {
	serverGroups := &ServerGroups{}
	if err := c.n_get("/pools/default/serverGroups", serverGroups, c.defaultHeaders()); err != nil {
		return nil, err
	}
	return serverGroups, nil
}

func (c *Couchbase) createServerGroup(name string) error {
	data := url.Values{}
	data.Set("name", name)
	headers := c.defaultHeaders()
	headers.Set(HeaderContentType, ContentTypeUrlEncoded)
	return c.n_post("/pools/default/serverGroups", []byte(data.Encode()), headers)
}

func (c *Couchbase) updateServerGroups(revision string, groups *ServerGroupsUpdate) error {
	data, err := json.Marshal(groups)
	if err != nil {
		return err
	}
	uri := "/pools/default/serverGroups?rev=" + revision
	headers := c.defaultHeaders()
	headers.Set(HeaderContentType, ContentTypeJSON)
	return c.n_put(uri, data, headers)
}

func (c *Couchbase) setRecoveryType(otpNode string, recoveryType RecoveryType) error {

	data := url.Values{}
	data.Set("otpNode", otpNode)
	data.Set("recoveryType", string(recoveryType))
	headers := c.defaultHeaders()
	headers.Set("Content-Type", ContentTypeUrlEncoded)

	return c.n_post("/controller/setRecoveryType", []byte(data.Encode()), headers)
}
