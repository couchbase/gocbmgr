package cbmgr

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

const (
	RebalanceStatusNotRunning string = "notRunning"
	RebalanceStatusRunning    string = "running"
	RebalanceStatusStale      string = "stale"
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

type AutoFailoverSettings struct {
	Enabled bool   `json:"enabled"`
	Timeout uint64 `json:"timeout"`
	Count   uint8  `json:"count"`
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

type Task struct {
	Progress float64 `json:"progress"`
	Type     string  `json:"type"`
	Status   string  `json:"status"`
}

type IoPriorityType string
type IoPriorityThreadCount int

const (
	IoPriorityTypeLow         IoPriorityType        = "low"
	IoPriorityTypeHigh        IoPriorityType        = "high"
	IoPriorityThreadCountLow  IoPriorityThreadCount = 3
	IoPriorityThreadCountHigh IoPriorityThreadCount = 8
)

type Bucket struct {
	BucketName         string         `json:"name"`
	BucketType         string         `json:"type"`
	BucketMemoryQuota  int            `json:"memoryQuota"`
	BucketReplicas     int            `json:"replicas"`
	IoPriority         IoPriorityType `json:"ioPriority"`
	EvictionPolicy     *string        `json:"evictionPolicy"`
	ConflictResolution *string        `json:"conflictResolution"`
	EnableFlush        *bool          `json:"enableFlush"`
	EnableIndexReplica *bool          `json:"enableIndexReplica"`
	BucketPassword     *string        `json:"password"`
}

type BucketStatus struct {
	Nodes                  []NodeInfo            `json:"nodes"`
	BucketName             string                `json:"name"`
	BucketType             string                `json:"bucketType"`
	EvictionPolicy         string                `json:"evictionPolicy"`
	EnableIndexReplica     bool                  `json:"replicaIndex"`
	AutoCompactionSettings interface{}           `json:"autoCompactionSettings"`
	ReplicaNumber          int                   `json:"replicaNumber"`
	ThreadsNumber          IoPriorityThreadCount `json:"threadsNumber"`
	Controllers            map[string]string     `json:"controllers"`
	Quota                  map[string]int        `json:"quota"`
	Stats                  map[string]string     `json:"stats"`
	VBServerMap            VBucketServerMap      `json:"vBucketServerMap"`
}

type VBucketServerMap struct {
	ServerList []string   `json:"serverList"`
	VBMap      VBucketMap `json:"vBucketMap"`
}

type VBucketMap [][]int

func (s *BucketStatus) GetIoPriority() IoPriorityType {
	threadCount := s.ThreadsNumber

	if threadCount <= IoPriorityThreadCountLow {
		return IoPriorityTypeLow
	}
	return IoPriorityTypeHigh
}

// Unmarshall from json representation of
// type Bucket or BucketStatus
func (b *Bucket) UnmarshalJSON(data []byte) error {

	// unmarshal as generic json
	var jsonData map[string]interface{}
	if err := json.Unmarshal(data, &jsonData); err != nil {
		return err
	}

	// unmarshal as BucketStatus if nodes key exists
	if _, ok := jsonData["nodes"]; ok {
		return b.unmarshalFromStatus(data)
	} else {

		// unmarshal as standard bucket type
		type BucketAlias Bucket
		bucket := BucketAlias{}
		if err := json.Unmarshal(data, &bucket); err != nil {
			return err
		}
		*b = Bucket(bucket)
		return nil
	}

}

func (b *Bucket) unmarshalFromStatus(data []byte) error {

	// unmarshalling data as bucket status
	status := BucketStatus{}
	if err := json.Unmarshal(data, &status); err != nil {
		return err
	}

	b.BucketName = status.BucketName
	b.BucketType = status.BucketType
	b.EvictionPolicy = &status.EvictionPolicy
	b.EnableIndexReplica = &status.EnableIndexReplica
	b.BucketReplicas = status.ReplicaNumber

	if _, ok := status.Controllers["flush"]; ok {
		b.EnableFlush = &ok
	}

	if ramQuotaBytes, ok := status.Quota["ram"]; ok {
		b.BucketMemoryQuota = ramQuotaBytes >> 20
	}

	b.IoPriority = status.GetIoPriority()
	return nil
}

func (b *Bucket) FormEncode() []byte {
	data := url.Values{}
	data.Set("name", b.BucketName)
	data.Set("bucketType", b.BucketType)
	data.Set("ramQuotaMB", strconv.Itoa(b.BucketMemoryQuota))
	data.Set("replicaNumber", strconv.Itoa(b.BucketReplicas))
	data.Set("authType", "sasl")
	if b.EvictionPolicy != nil {
		data.Set("evictionPolicy", *b.EvictionPolicy)
	}
	if b.IoPriority == IoPriorityTypeLow {
		data.Set("threadsNumber", strconv.Itoa(int(IoPriorityThreadCountLow)))
	}
	if b.IoPriority == IoPriorityTypeHigh {
		data.Set("threadsNumber", strconv.Itoa(int(IoPriorityThreadCountHigh)))
	}
	if b.ConflictResolution != nil {
		data.Set("conflictResolution", *b.ConflictResolution)
	}
	if b.EnableFlush != nil {
		data.Set("flushEnabled", BoolToStr(*b.EnableFlush))
	}
	if b.EnableIndexReplica != nil {
		data.Set("replicaIndex", BoolToStr(*b.EnableIndexReplica))
	}

	return []byte(data.Encode())
}
