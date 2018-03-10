package cbmgr

import (
	"fmt"
	"net/http"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/sirupsen/logrus"
)

// Certificate and key used by TLS client authentication
type TLSClientAuth struct {
	// PEM encoded certificate
	Cert []byte
	// PEM encoded private key
	Key []byte
}

// TLS Authentication parameters
type TLSAuth struct {
	// PEM encoded CA certificate
	CACert []byte
	// Optional client authentication
	ClientAuth *TLSClientAuth
}

// Client certificate authentication prefixes, used to extract the user name
type ClientCertAuthPrefix struct {
	Path      string `json:"path"`
	Prefix    string `json:"prefix"`
	Delimiter string `json:"delimiter"`
}

// Client certificate authentication settings
type ClientCertAuth struct {
	// Must be 'disable', 'enable', 'mandatory'
	State string `json:"state"`
	// Maximum of 10
	Prefixes []ClientCertAuthPrefix `json:"prefixes"`
}

// Couchbase is a structure which encapsulates HTTP API access to a
// Couchbase cluster
type Couchbase struct {
	// endpoints is a list of URIs to try when performing and operation
	endpoints []string
	// username is used in basic HTTP authorization
	username string
	// password is used in basic HTTP authorization
	password string
	// uuid, when set, is used to verify that endpoints we are connecting
	// to are part of the specified cluster and will return reliable
	// responses
	uuid string
	// tls, if set, specifies the client certificate chain and private keys
	// for mutual verification.  It also contains at least a CA certificate
	// to authenticate the server is trustworthy
	tls *TLSAuth
	// client is a persistent connection pool to be used by all endpoints
	// associated with this connection context.  It will become invalid
	// if any parameters used in the TLS handshake, or HTTP UUID check
	// are updated.
	client *http.Client
}

// New creates a new Couchbase HTTP(S) API client and initializes the
// HTTP connection pool.
func New(username, password string) *Couchbase {
	c := &Couchbase{
		endpoints: []string{},
		username:  username,
		password:  password,
	}
	c.makeClient()
	return c
}

// SetEndpoints sets the current working set of endpoints to try API requests
// against in the event of failure.  The endpoint host and port will be used
// to lookup a persistent connection in the http.Client.
func (c *Couchbase) SetEndpoints(endpoints []string) {
	c.endpoints = endpoints
}

// SetUUID updates the cluster UUID to check new connections against.  Creates
// a new client object to flush existing persistent connections.
func (c *Couchbase) SetUUID(uuid string) {
	c.uuid = uuid
	c.makeClient()
}

// SetTLS updates the client TLS settings.  Creates a new client object to
// flush existing persistent connections.
func (c *Couchbase) SetTLS(tls *TLSAuth) {
	c.tls = tls
	c.makeClient()
}

type RebalanceProgress struct {
	client    *Couchbase
	cancelled *atomicBool
	logger    *logrus.Entry
	interval  time.Duration
}

func (r *RebalanceProgress) Wait() error {
	isRunning := true
	for isRunning && !r.cancelled.Load() {
		tasks, err := r.client.getTasks()
		if err != nil {
			return err
		}

		for _, task := range tasks {
			if task.Type == "rebalance" {
				if task.Status == RebalanceStatusNotRunning || task.Status == RebalanceStatusStale {
					isRunning = false
				} else if task.Status == RebalanceStatusRunning {
					logger := (*logrus.Entry)(atomic.LoadPointer((*unsafe.Pointer)((unsafe.Pointer)(&r.logger))))
					if logger != nil {
						logger.Infof("Rebalance progress: %f", task.Progress)
					}
				}
			}
		}
		time.Sleep(r.interval)
	}

	return nil
}

func (r *RebalanceProgress) SetLogger(logger *logrus.Entry) {
	atomic.SwapPointer((*unsafe.Pointer)((unsafe.Pointer)(&r.logger)), unsafe.Pointer(logger))
}

func (r *RebalanceProgress) Cancel() {
	r.cancelled.Store(true)
}

func (c *Couchbase) AddNode(hostname, username, password string, services ServiceList) error {
	return c.addNode(hostname, username, password, services)
}

func (c *Couchbase) CancelAddNode(hostname string) error {
	cluster, err := c.getPoolsDefault()
	if err != nil {
		return err
	}

	for _, node := range cluster.Nodes {
		if node.HostName == hostname {
			return c.cancelAddNode(node.OTPNode)
		}
	}

	return fmt.Errorf("Hostname %s is not part of the cluster", hostname)
}

func (c *Couchbase) ClusterInfo() (*ClusterInfo, error) {
	return c.getPoolsDefault()
}

func (c *Couchbase) SetPoolsDefault(name string, dataMemQuotaMB, indexMemQuotaMB, searchMemQuotaMB int) error {
	return c.setPoolsDefault(name, dataMemQuotaMB, indexMemQuotaMB, searchMemQuotaMB)
}

func (c *Couchbase) ClusterInitialize(username, password, name string, dataMemQuotaMB, indexMemQuotaMB,
	searchMemQuotaMB, port int, services []ServiceName, mode IndexStorageMode) error {

	if err := c.setPoolsDefault(name, dataMemQuotaMB, indexMemQuotaMB, searchMemQuotaMB); err != nil {
		return err
	}

	settings, err := c.getIndexSettings()
	if err != nil {
		return err
	}

	if err := c.setIndexSettings(mode, settings.Threads, settings.MemSnapInterval,
		settings.StableSnapInterval, settings.MaxRollbackPoints, settings.LogLevel); err != nil {
		return err
	}

	if err := c.setServices(services); err != nil {
		return err
	}

	if err := c.setWebSettings(username, password, port); err != nil {
		return err
	}

	return nil
}

func (c *Couchbase) ClusterUUID() (string, error) {
	if info, err := c.getPools(); err != nil {
		return "", err
	} else {
		if uuid, ok := info.UUID.(string); ok {
			return uuid, nil
		}

		return "", nil
	}
}

func (c *Couchbase) NodeInitialize(hostname, dataPath, indexPath string) error {
	if err := c.setHostname(hostname); err != nil {
		return err
	}

	if err := c.setStoragePaths(dataPath, indexPath); err != nil {
		return err
	}

	return nil
}

func (c *Couchbase) Rebalance(nodesToRemove []string) (*RebalanceProgress, error) {
	cluster, err := c.getPoolsDefault()
	if err != nil {
		return nil, err
	}

	all := []string{}
	eject := []string{}
	for _, node := range cluster.Nodes {
		all = append(all, node.OTPNode)
		for _, toRemove := range nodesToRemove {
			if node.HostName == toRemove {
				eject = append(eject, node.OTPNode)
			}
		}
	}

	err = c.rebalance(all, eject)
	if err != nil {
		return nil, err
	}

	return &RebalanceProgress{c, newAtomicBool(false), nil, 4 * time.Second}, nil
}

func (c *Couchbase) Failover(nodeToRemove string) error {
	cluster, err := c.getPoolsDefault()
	if err != nil {
		return err
	}

	for _, node := range cluster.Nodes {
		if node.HostName == nodeToRemove {
			return c.failover(node.OTPNode)
		}
	}

	return NewErrorClusterNodeNotFound(nodeToRemove)
}

func (c *Couchbase) CreateBucket(bucket *Bucket) error {
	return c.createBucket(bucket)
}

func (c *Couchbase) DeleteBucket(name string) error {
	return c.deleteBucket(name)
}

func (c *Couchbase) EditBucket(bucket *Bucket) error {
	return c.editBucket(bucket)
}

// Determine wether bucket is ready based on status resolving
// to healthy across all nodes
func (c *Couchbase) BucketReady(name string) (bool, error) {

	status, err := c.getBucketStatus(name)
	if err != nil {
		return false, err
	}

	// check bucket health on all nodes
	if len(status.Nodes) == 0 {
		return false, NewErrorBucketNotReady(name, "creation pending")
	}
	for _, node := range status.Nodes {
		if node.Status != "healthy" {
			return false, NewErrorBucketNotReady(name, node.Status)
		}
	}

	return true, nil
}

func (c *Couchbase) GetBucketStatus(name string) (*BucketStatus, error) {

	status, err := c.getBucketStatus(name)
	if err != nil {
		return nil, err
	}

	return status, nil
}

func (c *Couchbase) GetBucketStats(name string) (map[string]BucketStat, error) {

	status, err := c.getBucketStats(name)
	if err != nil {
		return nil, err
	}

	return status, nil
}
func (c *Couchbase) GetBuckets() ([]*Bucket, error) {
	return c.getBuckets()
}

func (c *Couchbase) SetAutoFailoverTimeout(enabled bool, timeout uint64) error {
	return c.setAutoFailoverTimeout(enabled, timeout)
}

func (c *Couchbase) GetAutoFailoverSettings() (*AutoFailoverSettings, error) {
	return c.getAutoFailoverSettings()
}

func (c *Couchbase) SetDataMemoryQuota(quota int) error {
	return c.setDataMemoryQuota(quota)
}

func (c *Couchbase) SetIndexMemoryQuota(quota int) error {
	return c.setIndexMemoryQuota(quota)
}

func (c *Couchbase) SetSearchMemoryQuota(quota int) error {
	return c.setSearchMemoryQuota(quota)
}

func (c *Couchbase) GetIndexSettings() (*IndexSettings, error) {
	return c.getIndexSettings()
}

func (c *Couchbase) GetNodeInfo() (*NodeInfo, error) {
	return c.getNodeInfo()
}

func (c *Couchbase) UploadClusterCACert(pem []byte) error {
	return c.uploadClusterCACert(pem)
}

func (c *Couchbase) ReloadNodeCert() error {
	return c.reloadNodeCert()
}

func (c *Couchbase) SetClientCertAuth(settings *ClientCertAuth) error {
	return c.setClientCertAuth(settings)
}
