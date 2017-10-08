package cbmgr

import (
	"net/url"
	"strconv"
)

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
