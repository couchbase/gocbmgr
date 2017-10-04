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

// Returns true if two errors are equal
func ErrCompare(e1, e2 error) bool {
	return strings.Compare(e1.Error(), e2.Error()) == 0
}
