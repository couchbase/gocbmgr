package cbmgr

import (
	"fmt"
	"strings"
)

var (
	ErrorNodeUninitialized error = fmt.Errorf("Node uninitialized")
)

// Errors resulting from sending BadRequests to rebalance API
const (
	DeltaRecoveryNotPossible string = "deltaRecoveryNotPossible"
	EmptyKnownNodes                 = "empty_known_nodes"
	Mismatch                        = "mismatch"
)

// Rebalance API will set an int flag to indicate
// the type of BadRequest that has occurred
const errRebalanceRequestFlag int = 1

// errMapoverlay represents possible error responses from couchbase server
type errMapoverlay struct {
	Errors                 map[string]string
	DeltaRecoveryErrFlag   int `json:"deltaRecoveryNotPossible"`
	EmptyKnownNodesErrFlag int `json:"empty_known_nodes"`
	MismatchErrFlag        int `json:"mismatch"`
}

// ErrorMap combines all error responses into
// single map with readable descriptions
func (e errMapoverlay) ErrorMap() map[string]string {
	m := e.Errors
	if m == nil {
		m = make(map[string]string)
	}

	// Detect type of error that cased a BadRequest to
	// be returned and create a readable error output
	switch errRebalanceRequestFlag {
	case e.DeltaRecoveryErrFlag:
		m[DeltaRecoveryNotPossible] = "requireDeltaRecovery was set to true but delta recovery cannot be performed"
	case e.MismatchErrFlag:
		m[Mismatch] = "either knownNodes didn't match the set of nodes known to the cluster or ejectedNodes listed an unknown node"
	case e.EmptyKnownNodesErrFlag:
		m[EmptyKnownNodes] = "knownNodes was either omitted or empty"
	}

	return m
}

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

// Check for a specific error key within an arbitrary error type
func HasErrorOccured(err error, key string) bool {

	switch err.(type) {

	case ServerError:
		// Check as single SeverError
		return HasServerError(err, key)

	case BulkError:
		// Check as BulkErrors
		for _, e := range err.(BulkError).errs {
			if HasServerError(e, key) {
				return true
			}
		}
	}

	return false
}

// Check if a specific error has occurred
// within the map of ServerErrors
func HasServerError(err error, key string) bool {
	if serverError, ok := err.(ServerError); ok {
		_, ok := serverError.errors[key]
		return ok
	}
	return false
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
