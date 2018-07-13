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

type BulkError struct {
	errs []error
}

func (e BulkError) Error() string {
	rv := ""
	for i, err := range e.errs {
		rv += "[" + err.Error() + "]"
		if i != (len(e.errs) - 1) {
			rv += ", "
		}
	}
	return rv
}

type ClientError struct {
	reason string
	err    error
}

func (e ClientError) Error() string {
	return fmt.Sprintf("Client error `%s`: %s", e.reason, e.err.Error())
}

type NetworkError struct {
	endpoint string
	path     string
	err      error
}

func (e NetworkError) Error() string {
	return fmt.Sprintf("Network Error (%s%s): %s", e.endpoint, e.path, e.err.Error())
}

type ServerError struct {
	errors   map[string]string
	endpoint string
	path     string
	code     int
}

func (e ServerError) Error() string {
	all := []string{}
	for k, v := range e.errors {
		all = append(all, k+" - "+v)
	}

	return fmt.Sprintf("Server Error %d (%s%s): %s", e.code, e.endpoint, e.path, all)
}

// IsServerError returns true if all errors are the same code
func IsServerError(err error, code int) bool {
	bulk, ok := err.(BulkError)
	if !ok {
		return false
	}
	for _, err := range bulk.errs {
		serverError, ok := err.(ServerError)
		if !ok {
			return false
		}
		if serverError.code != code {
			return false
		}
	}
	return true
}
