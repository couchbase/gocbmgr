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

type AvailableStorageType string

const (
	StorageTypeHDD AvailableStorageType = "hdd"
	StorageTypeSSD AvailableStorageType = "ssd"
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
	DataService      ServiceName = "kv"
	IndexService     ServiceName = "index"
	QueryService     ServiceName = "n1ql"
	SearchService    ServiceName = "fts"
	EventingService  ServiceName = "eventing"
	AnalyticsService ServiceName = "cbas"
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
		} else if svc == "eventing" {
			list = append(list, EventingService)
		} else if svc == "cbas" || svc == "analytics" {
			list = append(list, AnalyticsService)
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

type RecoveryType string

const (
	RecoveryTypeDelta RecoveryType = "delta"
	RecoveryTypeFull               = "full"
)

type ClusterInfo struct {
	SearchMemoryQuotaMB    uint64     `json:"ftsMemoryQuota"`
	IndexMemoryQuotaMB     uint64     `json:"indexMemoryQuota"`
	DataMemoryQuotaMB      uint64     `json:"memoryQuota"`
	EventingMemoryQuotaMB  uint64     `json:"eventingMemoryQuota"`
	AnalyticsMemoryQuotaMB uint64     `json:"cbasMemoryQuota"`
	Nodes                  []NodeInfo `json:"nodes"`
	RebalanceStatus        string     `json:"rebalanceStatus"`
	ClusterName            string     `json:"clusterName"`
	Balanced               bool       `json:"balanced"`
}

// PoolsDefaults returns a struct which could be used with the /pools/default API
func (c *ClusterInfo) PoolsDefaults() *PoolsDefaults {
	return &PoolsDefaults{
		ClusterName:          c.ClusterName,
		DataMemoryQuota:      c.DataMemoryQuotaMB,
		IndexMemoryQuota:     c.IndexMemoryQuotaMB,
		SearchMemoryQuota:    c.SearchMemoryQuotaMB,
		EventingMemoryQuota:  c.EventingMemoryQuotaMB,
		AnalyticsMemoryQuota: c.AnalyticsMemoryQuotaMB,
	}
}

type IndexSettings struct {
	StorageMode        IndexStorageMode `json:"storageMode"`
	Threads            int              `json:"indexerThreads"`
	MemSnapInterval    int              `json:"memorySnapshotInterval"`
	StableSnapInterval int              `json:"stableSnapshotInterval"`
	MaxRollbackPoints  int              `json:"maxRollbackPoints"`
	LogLevel           IndexLogLevel    `json:"logLevel"`
}

type FailoverOnDiskFailureSettings struct {
	Enabled    bool   `url:"failoverOnDataDiskIssues[enabled]" json:"enabled"`
	TimePeriod uint64 `url:"failoverOnDataDiskIssues[timePeriod]" json:"timePeriod"`
}

type AutoFailoverSettings struct {
	Enabled                  bool                          `url:"enabled" json:"enabled"`
	Timeout                  uint64                        `url:"timeout" json:"timeout"`
	Count                    uint8                         `json:"count"`
	FailoverOnDataDiskIssues FailoverOnDiskFailureSettings `url:"" json:"failoverOnDataDiskIssues"`
	FailoverServerGroup      bool                          `url:"failoverServerGroup" json:"failoverServerGroup"`
	MaxCount                 uint64                        `url:"maxCount" json:"maxCount"`
}

type AlternateAddressesExternalPorts struct {
	// AdminPort is the admin service K8S node port (mapped to 8091)
	AdminServicePort int32 `url:"mgmt,omitempty" json:"mgmt"`
	// AdminPortSSL is the admin service K8S node port (mapped to 18091)
	AdminServicePortTLS int32 `url:"mgmtSSL,omitempty" json:"mgmtSSL"`
	// ViewServicePort is the view service K8S node port (mapped to 8092)
	ViewServicePort int32 `url:"capi,omitempty" json:"capi"`
	// ViewServicePortSSL is the view service K8S node port (mapped to 8092)
	ViewServicePortTLS int32 `url:"capiSSL,omitempty" json:"capiSSL"`
	// QueryServicePort is the query service K8S node port (mapped to 8093)
	QueryServicePort int32 `url:"n1ql,omitempty" json:"n1ql"`
	// QueryServicePortTLS is the query service K8S node port (mapped to 18093)
	QueryServicePortTLS int32 `url:"n1qlSSL,omitempty" json:"n1qlSSL"`
	// FtsServicePort is the full text search service K8S node port (mapped to 8094)
	FtsServicePort int32 `url:"fts,omitempty" json:"fts"`
	// FtsServicePortTLS is the full text search service K8S node port (mapped to 18094)
	FtsServicePortTLS int32 `url:"ftsSSL,omitempty" json:"ftsSSL"`
	// AnalyticsServicePort is the analytics service K8S node port (mapped to 8095)
	AnalyticsServicePort int32 `url:"cbas,omitempty" json:"cbas"`
	// AnalyticsServicePortTLS is the analytics service K8S node port (mapped to 18095)
	AnalyticsServicePortTLS int32 `url:"cbasSSL,omitempty" json:"cbasSSL"`
	// DataServicePort is the data service K8S node port (mapped to 11210)
	DataServicePort int32 `url:"kv,omitempty" json:"kv"`
	// DataServicePortSSL is the data service K8S node port (mapped to 11207)
	DataServicePortTLS int32 `url:"kvSSL,omitempty" json:"kvSSL"`
}

// AlternateAddresses defines a K8S node address and port mapping for
// use by clients outside of the pod network.  Hostname must be set,
// ports are ignored if zero.
type AlternateAddressesExternal struct {
	// Hostname is the host name to connect to (typically a L3 address)
	Hostname string `url:"hostname" json:"hostname"`
	// Ports is the map of service to external ports
	Ports AlternateAddressesExternalPorts `url:"" json:"ports"`
}

type AlternateAddresses struct {
	External AlternateAddressesExternal `json:"external"`
}

type NodeInfo struct {
	ThisNode           bool                 `json:"thisNode"`
	Uptime             string               `json:"uptime"`
	Membership         string               `json:"clusterMembership"`
	RecoveryType       string               `json:"recoveryType"`
	Status             string               `json:"status"`
	OTPNode            string               `json:"otpNode"`
	HostName           string               `json:"hostname"`
	Services           []string             `json:"services"`
	AvailableStorage   AvailableStorageInfo `json:"storage"`
	AlternateAddresses AlternateAddresses   `json:"alternateAddresses"`
}

type AvailableStorageInfo map[AvailableStorageType][]StorageInfo

type StorageInfo struct {
	Path      string `json:"path"`
	IndexPath string `json:"index_path"`
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

// PoolsDefaults is the data that may be posted via the /pools/default API
type PoolsDefaults struct {
	ClusterName          string `url:"clusterName,omitempty"`
	DataMemoryQuota      uint64 `url:"memoryQuota,omitempty"`
	IndexMemoryQuota     uint64 `url:"indexMemoryQuota,omitempty"`
	SearchMemoryQuota    uint64 `url:"ftsMemoryQuota,omitempty"`
	EventingMemoryQuota  uint64 `url:"eventingMemoryQuota,omitempty"`
	AnalyticsMemoryQuota uint64 `url:"cbasMemoryQuota,omitempty"`
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
	ConflictResolution     string                `json:"conflictResolutionType"`
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

type LogMessage struct {
	Node       string `json:"node"`
	Type       string `json:"type"`
	Code       uint8  `json:"code"`
	Module     string `json:"module"`
	Tstamp     uint64 `json:"tstamp"`
	ShortText  string `json:"shortText"`
	Text       string `json:"text"`
	ServerTime string `json:"serverTime"`
}
type LogList []*LogMessage

func (li LogList) Len() int {
	return len(li)
}

func (li LogList) Less(i, j int) bool {
	return li[i].Tstamp < li[j].Tstamp
}

func (li LogList) Swap(i, j int) {
	li[i], li[j] = li[j], li[i]
}

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
	b.ConflictResolution = &status.ConflictResolution
	b.EnableIndexReplica = &status.EnableIndexReplica
	b.BucketReplicas = status.ReplicaNumber

	if _, ok := status.Controllers["flush"]; ok {
		b.EnableFlush = &ok
	} else {
		disabled := false
		b.EnableFlush = &disabled
	}

	if ramQuotaBytes, ok := status.Quota["rawRAM"]; ok {
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
		data.Set("conflictResolutionType", *b.ConflictResolution)
	}
	if b.EnableFlush != nil {
		data.Set("flushEnabled", BoolToStr(*b.EnableFlush))
	}
	if b.EnableIndexReplica != nil {
		data.Set("replicaIndex", BoolToStr(*b.EnableIndexReplica))
	}

	return []byte(data.Encode())
}

// SettingsStats is the data structure returned by /settings/stats
type SettingsStats struct {
	// SendStats actually indicates whether to perform software update checks
	SendStats bool `json:"sendStats"`
}

// ServerGroup is a map from name to a list of nodes
type ServerGroup struct {
	// Name is the human readable server group name
	Name string `json:"name"`
	// Nodes is a list of nodes who are members of the server group
	Nodes []NodeInfo `json:"nodes"`
	// URI is used to refer to a server group
	URI string `json:"uri"`
}

// ServerGroups is returned by /nodes/default/serverGroups
type ServerGroups struct {
	// Groups is a list of ServerGroup objects
	Groups []ServerGroup `json:"groups"`
	// URI is the URI used to update server groups
	URI string `json:"uri"`
}

// GetRevision returns the server group revision ID (for CAS)
func (groups ServerGroups) GetRevision() string {
	// Expected to be /pools/default/serverGroups?rev=13585112
	return strings.Split(groups.URI, "=")[1]
}

// GetServerGroup looks up a server group by name
func (groups ServerGroups) GetServerGroup(name string) *ServerGroup {
	for _, group := range groups.Groups {
		if group.Name == name {
			return &group
		}
	}
	return nil
}

// ServerGroupUpdateOTPNode defines a single node is OTP notation
type ServerGroupUpdateOTPNode struct {
	OTPNode string `json:"otpNode"`
}

// ServerGroupUpdate defines a server group and its nodes
type ServerGroupUpdate struct {
	// Name is the group name and must match the existing one
	Name string `json:"name",omitempty`
	// URI is the same as returned in ServerGroup
	URI string `json:"uri"`
	// Nodes is a list of OTP nodes
	Nodes []ServerGroupUpdateOTPNode `json:"nodes"`
}

// ServerGroupsUpdate is used to move nodes between server groups
type ServerGroupsUpdate struct {
	Groups []ServerGroupUpdate `json:"groups"`
}
