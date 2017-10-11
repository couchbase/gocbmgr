package cbmgr

import (
	"fmt"
	"strings"
)

type IndexStorageMode string

const (
	IndexStorageNone   IndexStorageMode = ""
	IndexStoragePlasma IndexStorageMode = "plasma"
	IndexStorageMOI    IndexStorageMode = "memory_optimized"
)

type IndexLogLevel string

const (
	IndexLogLevelDebug   IndexLogLevel = "debug"
	IndexLogLevelError   IndexLogLevel = "error"
	IndexLogLevelFatal   IndexLogLevel = "fatal"
	IndexLogLevelInfo    IndexLogLevel = "info"
	IndexLogLevelSilent  IndexLogLevel = "silent"
	IndexLogLevelTiming  IndexLogLevel = "timing"
	IndexLogLevelTrace   IndexLogLevel = "trace"
	IndexLogLevelVerbose IndexLogLevel = "verbose"
	IndexLogLevelWarn    IndexLogLevel = "warn"
)

type ServiceName string

const (
	DataService   ServiceName = "kv"
	IndexService  ServiceName = "index"
	QueryService  ServiceName = "n1ql"
	SearchService ServiceName = "fts"
)

type ServiceList []ServiceName

func ServiceListFromStringArray(arr []string) (ServiceList, error) {
	list := []ServiceName{}
	for _, svc := range arr {
		if svc == "kv" || svc == "data" {
			list = append(list, DataService)
		} else if svc == "index" {
			list = append(list, IndexService)
		} else if svc == "n1ql" || svc == "query" {
			list = append(list, QueryService)
		} else if svc == "fts" || svc == "search" {
			list = append(list, SearchService)
		} else {
			return list, fmt.Errorf("Invalid service name: %s", svc)
		}
	}

	return list, nil
}

func (s ServiceList) String() string {
	strs := []string{}
	for _, svc := range s {
		strs = append(strs, (string)(svc))
	}
	return strings.Join(strs, ",")
}

type ClusterInfo struct {
	SearchMemoryQuotaMB int        `json:"ftsMemoryQuota"`
	IndexMemoryQuotaMB  int        `json:"indexMemoryQuota"`
	DataMemoryQuotaMB   int        `json:"memoryQuota"`
	Nodes               []NodeInfo `json:"nodes"`
	RebalanceStatus     string     `json:"rebalanceStatus"`
	ClusterName         string     `json:"clusterName"`
	Balanced            bool       `json:"balanced"`
}

type IndexSettings struct {
	StorageMode        IndexStorageMode `json:"storageMode"`
	Threads            int              `json:"indexerThreads"`
	MemSnapInterval    int              `json:"memorySnapshotInterval"`
	StableSnapInterval int              `json:"stableSnapshotInterval"`
	MaxRollbackPoints  int              `json:"maxRollbackPoints"`
	LogLevel           IndexLogLevel    `json:"logLevel"`
}

type NodeInfo struct {
	ThisNode     bool     `json:"thisNode"`
	Uptime       string   `json:"uptime"`
	Membership   string   `json:"clusterMembership"`
	RecoveryType string   `json:"recoveryType"`
	Status       string   `json:"status"`
	OTPNode      string   `json:"otpNode"`
	HostName     string   `json:"hostname"`
	Services     []string `json:"services"`
}

type PoolsInfo struct {
	Enterprise bool        `json:"isEnterprise"`
	UUID       interface{} `json:"uuid"`
}

type IoPriorityType string
type IoPriorityThreadCount int

const (
	IoPriorityTypeLow         IoPriorityType        = "low"
	IoPriorityTypeHigh        IoPriorityType        = "high"
	IoPriorityThreadCountLow  IoPriorityThreadCount = 2
	IoPriorityThreadCountHigh IoPriorityThreadCount = 8
)

type Bucket struct {
	BucketName         string          `json:"name"`
	BucketType         string          `json:"type"`
	BucketMemoryQuota  int             `json:"memoryQuota"`
	BucketReplicas     int             `json:"replicas"`
	IoPriority         *IoPriorityType `json:"ioPriority"`
	EvictionPolicy     *string         `json:"evictionPolicy"`
	ConflictResolution *string         `json:"conflictResolution"`
	EnableFlush        *bool           `json:"enableFlush"`
	EnableIndexReplica *bool           `json:"enableIndexReplica"`
	BucketPassword     *string         `json:"password"`
}

type BucketStatus struct {
	Bucket
	Nodes []Node `json:"nodes,omitempty"`
}
