package cbmgr

import (
	"fmt"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/sirupsen/logrus"
)

type Couchbase struct {
	endpoints []string
	username  string
	password  string
}

func New(endpoints []string, username, password string) *Couchbase {
	return &Couchbase{
		endpoints: endpoints,
		username:  username,
		password:  password,
	}
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
		return false, nil
	}
	for _, node := range status.Nodes {
		if node.Status != "healthy" {
			return false, nil
		}
	}

	return true, nil
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
