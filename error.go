package cbmgr

import (
	"fmt"
	"strings"
)

var (
	ErrorNodeUninitialized error = fmt.Errorf("Node uninitialized")
)

func NewErrorWaitNodeTimeout(hostname string) error {
	emsg := fmt.Errorf("timed out waiting for node %s", hostname)
	return emsg
}
func NewErrorWaitNodeUnexpected(hostname string) error {
	emsg := fmt.Errorf("unexpected error while waiting for node %s", hostname)
	return emsg
}

func NewErrorHealthyTimedOut(url string) error {
	emsg := fmt.Errorf("timed out waiting for unhealthy node %s", url)
	return emsg
}

func NewErrorDeleteBucket(name string, err error) error {
	emsg := fmt.Errorf("unable to delete bucket %s %v", name, err)
	return emsg
}

func NewErrorBucketNotReady(name, reason string) error {
	emsg := fmt.Errorf("bucket %s is not ready: %s", name, reason)
	return emsg
}

func NewErrorClusterNodeNotFound(name string) error {
	emsg := fmt.Errorf("unable to find cluster node: %s", name)
	return emsg
}

func NewErrorInvalidLogList() error {
	return fmt.Errorf("cluster logs missing 'list' key")
}

// Returns true if two errors are equal
func ErrCompare(e1, e2 error) bool {
	return strings.Compare(e1.Error(), e2.Error()) == 0
}
