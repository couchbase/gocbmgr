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

// UserAgent defines the HTTP User-Agent header string
type UserAgent struct {
	// Name is the unique name of the client e.g. couchbase-operator
	Name string
	// Version is the release version of the client
	Version string
	// UUID is a unique identifier of the client to differentiate it from
	// other clients of the same Name e.g. a FQDN.  This field is optional
	UUID string
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
	// userAgent is sent to the server for all API requests and allows us
	// to uniquely identify the client e.g. differentiates from other go
	// tools or even instances of couchbase-operator
	userAgent *UserAgent
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

// SetUserAgent sets the User-Agent header to be sent in subsequent HTTP
// requests
func (c *Couchbase) SetUserAgent(userAgent *UserAgent) {
	c.userAgent = userAgent
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

func (c *Couchbase) SetPoolsDefault(defaults *PoolsDefaults) error {
	return c.setPoolsDefault(defaults)
}

func (c *Couchbase) ClusterInitialize(username, password string, defaults *PoolsDefaults,
	port int, services []ServiceName, mode IndexStorageMode) error {

	if err := c.setPoolsDefault(defaults); err != nil {
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

func (c *Couchbase) NodeInitialize(hostname, dataPath, indexPath string, analyticsPaths []string) error {
	if err := c.setHostname(hostname); err != nil {
		return err
	}

	if err := c.setStoragePaths(dataPath, indexPath, analyticsPaths); err != nil {
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

func (c *Couchbase) GetBuckets() ([]*Bucket, error) {
	return c.getBuckets()
}

func (c *Couchbase) SetAutoFailoverSettings(settings *AutoFailoverSettings) error {
	return c.setAutoFailoverSettings(settings)
}

func (c *Couchbase) GetAutoFailoverSettings() (*AutoFailoverSettings, error) {
	return c.getAutoFailoverSettings()
}

func (c *Couchbase) ResetFailoverCounter() error {
	return c.resetCount()
}

func (c *Couchbase) GetIndexSettings() (*IndexSettings, error) {
	return c.getIndexSettings()
}

func (c *Couchbase) SetIndexSettings(settings *IndexSettings) error {
	return c.setIndexSettings(settings.StorageMode, settings.Threads, settings.MemSnapInterval,
		settings.StableSnapInterval, settings.MaxRollbackPoints, settings.LogLevel)
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

func (c *Couchbase) GetUpdatesEnabled() (bool, error) {
	return c.getUpdatesEnabled()
}

func (c *Couchbase) SetUpdatesEnabled(enabled bool) error {
	return c.setUpdatesEnabled(enabled)
}

func (c *Couchbase) GetAlternateAddressesExternal() (*AlternateAddressesExternal, error) {
	return c.getAlternateAddressesExternal()
}

func (c *Couchbase) SetAlternateAddressesExternal(addresses *AlternateAddressesExternal) error {
	return c.setAlternateAddressesExternal(addresses)
}

func (c *Couchbase) DeleteAlternateAddressesExternal() error {
	return c.deleteAlternateAddressesExternal()
}

func (c *Couchbase) GetLogs() ([]*LogMessage, error) {
	return c.getLogs()
}

func (c *Couchbase) LogClientError(msg string) error {
	return c.logClientError(msg)
}

func (c *Couchbase) GetServerGroups() (*ServerGroups, error) {
	return c.getServerGroups()
}

func (c *Couchbase) CreateServerGroup(name string) error {
	return c.createServerGroup(name)
}

func (c *Couchbase) UpdateServerGroups(revision string, groups *ServerGroupsUpdate) error {
	return c.updateServerGroups(revision, groups)
}

func (c *Couchbase) SetRecoveryType(hostname string, recoveryType RecoveryType) error {
	cluster, err := c.getPoolsDefault()
	if err != nil {
		return err
	}

	for _, node := range cluster.Nodes {
		if node.HostName == hostname {
			return c.setRecoveryType(node.OTPNode, recoveryType)
		}
	}
	return fmt.Errorf("Hostname %s is not part of the cluster", hostname)
}
