package cbmgr

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

type RebalanceStatus string

const (
	RebalanceStatusNotRunning RebalanceStatus = "notRunning"
	RebalanceStatusRunning    RebalanceStatus = "running"
	RebalanceStatusUnknown    RebalanceStatus = "unknown"
	RebalanceStatusNone       RebalanceStatus = "none"
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
			return list, fmt.Errorf("invalid service name: %s", svc)
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
	RecoveryTypeFull  RecoveryType = "full"
)

type ClusterInfo struct {
	SearchMemoryQuotaMB    int64      `json:"ftsMemoryQuota"`
	IndexMemoryQuotaMB     int64      `json:"indexMemoryQuota"`
	DataMemoryQuotaMB      int64      `json:"memoryQuota"`
	EventingMemoryQuotaMB  int64      `json:"eventingMemoryQuota"`
	AnalyticsMemoryQuotaMB int64      `json:"cbasMemoryQuota"`
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
	Enabled    bool  `url:"failoverOnDataDiskIssues[enabled]" json:"enabled"`
	TimePeriod int64 `url:"failoverOnDataDiskIssues[timePeriod]" json:"timePeriod"`
}

type AutoFailoverSettings struct {
	Enabled                  bool                          `url:"enabled" json:"enabled"`
	Timeout                  int64                         `url:"timeout" json:"timeout"`
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
	// IndexServicePort is the view service K8S node port (mapped to 8092)
	IndexServicePort int32 `url:"capi,omitempty" json:"capi"`
	// IndexServicePortSSL is the view service K8S node port (mapped to 8092)
	IndexServicePortTLS int32 `url:"capiSSL,omitempty" json:"capiSSL"`
	// QueryServicePort is the query service K8S node port (mapped to 8093)
	QueryServicePort int32 `url:"n1ql,omitempty" json:"n1ql"`
	// QueryServicePortTLS is the query service K8S node port (mapped to 18093)
	QueryServicePortTLS int32 `url:"n1qlSSL,omitempty" json:"n1qlSSL"`
	// SearchServicePort is the full text search service K8S node port (mapped to 8094)
	SearchServicePort int32 `url:"fts,omitempty" json:"fts"`
	// SearchServicePortTLS is the full text search service K8S node port (mapped to 18094)
	SearchServicePortTLS int32 `url:"ftsSSL,omitempty" json:"ftsSSL"`
	// AnalyticsServicePort is the analytics service K8S node port (mapped to 8095)
	AnalyticsServicePort int32 `url:"cbas,omitempty" json:"cbas"`
	// AnalyticsServicePortTLS is the analytics service K8S node port (mapped to 18095)
	AnalyticsServicePortTLS int32 `url:"cbasSSL,omitempty" json:"cbasSSL"`
	// EventingServicePort is the eventing service K8S node port (mapped to 8096)
	EventingServicePort int32 `url:"eventingAdminPort,omitempty" json:"eventingAdminPort"`
	// EventingServicePortTLS is the eventing service K8S node port (mapped to 18096)
	EventingServicePortTLS int32 `url:"eventingSSL,omitempty" json:"eventingSSL"`
	// DataServicePort is the data service K8S node port (mapped to 11210)
	DataServicePort int32 `url:"kv,omitempty" json:"kv"`
	// DataServicePortTLS is the data service K8S node port (mapped to 11207)
	DataServicePortTLS int32 `url:"kvSSL,omitempty" json:"kvSSL"`
}

// AlternateAddresses defines a K8S node address and port mapping for
// use by clients outside of the pod network.  Hostname must be set,
// ports are ignored if zero.
type AlternateAddressesExternal struct {
	// Hostname is the host name to connect to (typically a L3 address)
	Hostname string `url:"hostname" json:"hostname"`
	// Ports is the map of service to external ports
	Ports *AlternateAddressesExternalPorts `url:"" json:"ports,omitempty"`
}

type AlternateAddresses struct {
	External *AlternateAddressesExternal `json:"external,omitempty"`
}

type NodeService struct {
	ThisNode           bool                `json:"thisNode"`
	AlternateAddresses *AlternateAddresses `json:"alternateAddresses,omitempty"`
}

// NodeServices is returned by the /pools/default/nodeServices API
type NodeServices struct {
	NodesExt []NodeService `json:"nodesExt"`
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
	AlternateAddresses *AlternateAddresses  `json:"alternateAddresses,omitempty"`
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

// Task is a base object to describe the very unfriendly polymorphic
// task struct.
type Task struct {
	// Common attributes.
	Type   string `json:"type"`
	Status string `json:"status"`

	// Rebalance attributes.
	Progress float64 `json:"progress"`
	Stale    bool    `json:"statusIsStale"`
	Timeout  bool    `json:"masterRequestTimedOut"`

	// Replication attributes.
	Source           string `json:"source"`
	Target           string `json:"target"`
	ReplicationType  string `url:"replicationType"`
	FilterExpression string `url:"filterExpression"`
}

// PoolsDefaults is the data that may be posted via the /pools/default API
type PoolsDefaults struct {
	ClusterName          string `url:"clusterName,omitempty"`
	DataMemoryQuota      int64  `url:"memoryQuota,omitempty"`
	IndexMemoryQuota     int64  `url:"indexMemoryQuota,omitempty"`
	SearchMemoryQuota    int64  `url:"ftsMemoryQuota,omitempty"`
	EventingMemoryQuota  int64  `url:"eventingMemoryQuota,omitempty"`
	AnalyticsMemoryQuota int64  `url:"cbasMemoryQuota,omitempty"`
}

type IoPriorityType string
type IoPriorityThreadCount int

const (
	IoPriorityTypeLow         IoPriorityType        = "low"
	IoPriorityTypeHigh        IoPriorityType        = "high"
	IoPriorityThreadCountLow  IoPriorityThreadCount = 3
	IoPriorityThreadCountHigh IoPriorityThreadCount = 8
)

type CompressionMode string

const (
	CompressionModeOff     CompressionMode = "off"
	CompressionModePassive CompressionMode = "passive"
	CompressionModeActive  CompressionMode = "active"
)

type Bucket struct {
	BucketName         string          `json:"name"`
	BucketType         string          `json:"type"`
	BucketMemoryQuota  int64           `json:"memoryQuota"`
	BucketReplicas     int             `json:"replicas"`
	IoPriority         IoPriorityType  `json:"ioPriority"`
	EvictionPolicy     string          `json:"evictionPolicy"`
	ConflictResolution string          `json:"conflictResolution"`
	EnableFlush        bool            `json:"enableFlush"`
	EnableIndexReplica bool            `json:"enableIndexReplica"`
	BucketPassword     string          `json:"password"`
	CompressionMode    CompressionMode `json:"compressionMode"`
}

type BucketBasicStats struct {
	DataUsed         int     `json:"dataUsed"`
	DiskFetches      float64 `json:"diskFetches"`
	DiskUsed         int     `json:"diskUsed"`
	ItemCount        int     `json:"itemCount"`
	MemUsed          int     `json:"memUsed"`
	OpsPerSec        float64 `json:"opsPerSec"`
	QuotaPercentUsed float64 `json:"quotaPercentUsed"`
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
	Quota                  map[string]int64      `json:"quota"`
	Stats                  map[string]string     `json:"stats"`
	VBServerMap            VBucketServerMap      `json:"vBucketServerMap"`
	CompressionMode        CompressionMode       `json:"compressionMode"`
	BasicStats             BucketBasicStats      `json:"basicStats"`
}

type VBucketServerMap struct {
	ServerList []string   `json:"serverList"`
	VBMap      VBucketMap `json:"vBucketMap"`
}

type VBucketMap [][]int

type AuthDomain string

const (
	InternalAuthDomain AuthDomain = "local"
	LDAPAuthDomain     AuthDomain = "ldap"
)

type User struct {
	Name     string     `json:"name"`
	FullName string     `json:"fullName"`
	Password string     `json:"password"`
	Domain   AuthDomain `json:"domain"`
	ID       string     `json:"id"`
	Roles    []UserRole `json:"roles"`
}

type Group struct {
	ID           string     `json:"id"`
	Roles        []UserRole `json:"roles"`
	Description  string     `json:"description"`
	LDAPGroupRef string     `json:"ldapGroupRef"`
}

type LDAPEncryption string

const (
	LDAPEncryptionNone     LDAPEncryption = "false"
	LDAPEncryptionStartTLS                = "StartTLSExtension"
	LDAPEncryptionTLS                     = "TLS"
)

type LDAPSettings struct {
	// Enables using LDAP to authenticate users.
	AuthenticationEnabled bool `json:"authenticationEnabled"`
	// Enables use of LDAP groups for authorization.
	AuthorizationEnabled bool `json:"authorizationEnabled"`
	// List of LDAP hosts.
	Hosts []string `json:"hosts"`
	// LDAP port
	Port int `json:"port"`
	// Encryption method to communicate with LDAP servers.
	// Can be StartTLSExtension, TLS, or false.
	Encryption LDAPEncryption `json:"encryption,omitempty"`
	// Whether server certificate validation be enabled
	EnableCertValidation bool `json:"serverCertValidation"`
	// Certificate in PEM format to be used in LDAP server certificate validation
	CACert string `json:"cacert"`
	// LDAP query, to get the users' groups by username in RFC4516 format.
	GroupsQuery string `json:"groupsQuery,omitempty"`
	// DN to use for searching users and groups synchronization.
	BindDN string `json:"bindDN,omitempty"`
	// Password for query_dn user.
	BindPass string `json:"bindPass,omitempty"`
	// User to distinguished name (DN) mapping. If none is specified,
	// the username is used as the user’s distinguished name.
	UserDNMapping *[]LDAPUserDNMapping `json:"userDNMapping,omitempty"`
	// If enabled Couchbase server will try to recursively search for groups
	// for every discovered ldap group. groupsQuery will be user for the search.
	NestedGroupsEnabled bool `json:"nestedGroupsEnabled,omitempty"`
	// Maximum number of recursive groups requests the server is allowed to perform.
	// Requires NestedGroupsEnabled.  Values between 1 and 100: the default is 10.
	NestedGroupsMaxDepth uint64 `json:"nestedGroupsMaxDepth,omitempty"`
	// Lifetime of values in cache in milliseconds. Default 300000 ms.
	CacheValueLifetime uint64 `json:"cacheValueLifetime,omitempty"`
}

type LDAPUserDNMapping struct {
	Regex    string `json:"re"`
	Template string `json:"template"`
}

type LDAPStatusResult string

const (
	LDAPStatusResultSuccess LDAPStatusResult = "success"
	LDAPStatusResultError   LDAPStatusResult = "error"
)

type LDAPStatus struct {
	Result LDAPStatusResult `json:result`
	Reason string           `json:reason`
}

type UserRole struct {
	Role       string `json:"role"`
	BucketName string `json:"bucket_name"`
}

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

	// Generic things across all bucket types
	b.BucketName = status.BucketName
	b.BucketType = status.BucketType
	if b.BucketType == "membase" {
		b.BucketType = "couchbase"
	}
	if ramQuotaBytes, ok := status.Quota["rawRAM"]; ok {
		b.BucketMemoryQuota = ramQuotaBytes >> 20
	}
	b.EnableFlush = false
	if _, ok := status.Controllers["flush"]; ok {
		b.EnableFlush = ok
	}
	if b.BucketType == "memcached" {
		return nil
	}

	// Generic things across couchbase/ephemeral
	b.EvictionPolicy = status.EvictionPolicy
	b.ConflictResolution = status.ConflictResolution
	b.BucketReplicas = status.ReplicaNumber
	b.CompressionMode = status.CompressionMode
	b.IoPriority = status.GetIoPriority()
	if b.BucketType == "ephemeral" {
		return nil
	}

	// Couchbase only things
	b.EnableIndexReplica = status.EnableIndexReplica

	return nil
}

func (b *Bucket) FormEncode() []byte {
	data := url.Values{}
	data.Set("name", b.BucketName)
	data.Set("bucketType", b.BucketType)
	data.Set("ramQuotaMB", strconv.Itoa(int(b.BucketMemoryQuota)))
	if b.BucketType != "memcached" {
		data.Set("replicaNumber", strconv.Itoa(b.BucketReplicas))
	}
	data.Set("authType", "sasl")
	data.Set("compressionMode", string(b.CompressionMode))
	data.Set("flushEnabled", BoolToStr(b.EnableFlush))
	if b.EvictionPolicy != "" {
		data.Set("evictionPolicy", b.EvictionPolicy)
	}
	if b.IoPriority == IoPriorityTypeLow {
		data.Set("threadsNumber", strconv.Itoa(int(IoPriorityThreadCountLow)))
	}
	if b.IoPriority == IoPriorityTypeHigh {
		data.Set("threadsNumber", strconv.Itoa(int(IoPriorityThreadCountHigh)))
	}
	if b.ConflictResolution != "" {
		data.Set("conflictResolutionType", b.ConflictResolution)
	}
	if b.BucketType == "couchbase" {
		data.Set("replicaIndex", BoolToStr(b.EnableIndexReplica))
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
	Name string `json:"name,omitempty"`
	// URI is the same as returned in ServerGroup
	URI string `json:"uri"`
	// Nodes is a list of OTP nodes
	Nodes []ServerGroupUpdateOTPNode `json:"nodes"`
}

// ServerGroupsUpdate is used to move nodes between server groups
type ServerGroupsUpdate struct {
	Groups []ServerGroupUpdate `json:"groups"`
}

// AutoCompactionDatabaseFragmentationThreshold indicates the percentage or size before a bucket
// compaction is triggered.
type AutoCompactionDatabaseFragmentationThreshold struct {
	Percentage int   `json:"percentage" url:"databaseFragmentationThreshold[percentage],omitempty"`
	Size       int64 `json:"size" url:"databaseFragmentationThreshold[size],omitempty"`
}

// UnmarshalJSON handles some *&$^ing moron's decision to have size as either an
// integer or "undefined".  Way to go!
func (r *AutoCompactionDatabaseFragmentationThreshold) UnmarshalJSON(b []byte) error {
	type t AutoCompactionDatabaseFragmentationThreshold
	var s struct {
		t
		Percentage interface{} `json:"percentage"`
		Size       interface{} `json:"size"`
	}

	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}

	*r = AutoCompactionDatabaseFragmentationThreshold(s.t)
	if i, ok := s.Size.(float64); ok {
		r.Size = int64(i)
	}
	if i, ok := s.Percentage.(float64); ok {
		r.Percentage = int(i)
	}

	return nil
}

// AutoCompactionViewFragmentationThreshold indicates the percentage or size before a view
// compaction is triggered.
type AutoCompactionViewFragmentationThreshold struct {
	Percentage int   `json:"percentage" url:"viewFragmentationThreshold[percentage],omitempty"`
	Size       int64 `json:"size" url:"viewFragmentationThreshold[size],omitempty"`
}

// UnmarshalJSON handles some *&$^ing moron's decision to have size as either an
// integer or "undefined".  Way to go!
func (r *AutoCompactionViewFragmentationThreshold) UnmarshalJSON(b []byte) error {
	type t AutoCompactionViewFragmentationThreshold
	var s struct {
		t
		Percentage interface{} `json:"percentage"`
		Size       interface{} `json:"size"`
	}

	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}

	*r = AutoCompactionViewFragmentationThreshold(s.t)
	if i, ok := s.Size.(float64); ok {
		r.Size = int64(i)
	}
	if i, ok := s.Percentage.(float64); ok {
		r.Percentage = int(i)
	}

	return nil
}

type AutoCompactionInterval struct {
	FromHour     int  `json:"fromHour" url:"indexCircularCompaction[interval][fromHour]"`
	FromMinute   int  `json:"fromMinute" url:"indexCircularCompaction[interval][fromMinute]"`
	ToHour       int  `json:"toHour" url:"indexCircularCompaction[interval][toHour]"`
	ToMinute     int  `json:"toMinute" url:"indexCircularCompaction[interval][toMinute]"`
	AbortOutside bool `json:"abortOutside" url:"indexCircularCompaction[interval][abortOutside]"`
}

type AutoCompactionIndexCircularCompaction struct {
	DaysOfWeek string                 `json:"daysOfWeek" url:"indexCircularCompaction[daysOfWeek]"`
	Interval   AutoCompactionInterval `json:"interval" url:""`
}

type AutoCompactionAutoCompactionSettings struct {
	DatabaseFragmentationThreshold AutoCompactionDatabaseFragmentationThreshold `json:"databaseFragmentationThreshold" url:""`
	ViewFragmentationThreshold     AutoCompactionViewFragmentationThreshold     `json:"viewFragmentationThreshold" url:""`
	ParallelDBAndViewCompaction    bool                                         `json:"parallelDBAndViewCompaction" url:"parallelDBAndViewCompaction"`
	IndexCompactionMode            string                                       `json:"indexCompactionMode" url:"indexCompactionMode"`
	IndexCircularCompaction        AutoCompactionIndexCircularCompaction        `json:"indexCircularCompaction" url:""`
}

// AutoCompactionSettings is the cluster wide auto-compaction settings for a
// Couchbase cluster.
type AutoCompactionSettings struct {
	AutoCompactionSettings AutoCompactionAutoCompactionSettings `json:"autoCompactionSettings" url:""`
	PurgeInterval          float64                              `json:"purgeInterval" url:"purgeInterval"`
}

// RemoteClusters is returned by
//   GET /pools/default/remoteClusters
type RemoteClusters []RemoteCluster

// RemoteCluster describes an XDCR remote cluster.
type RemoteCluster struct {
	Name       string `json:"name" url:"name"`
	Hostname   string `json:"hostname"  url:"hostname"`
	Username   string `json:"username"  url:"username"`
	Password   string `json:"password"  url:"password"`
	UUID       string `json:"uuid"  url:"uuid"`
	Deleted    bool   `json:"deleted"`
	SecureType string `json:"secureType" url:"secureType,omitempty"`

	// These are here for convenience and should only be populated
	// after comparison as they are not supplied by the API.
	CA          string `json:"-" url:"certificate,omitempty"`
	Certificate string `json:"-" url:"clientCertificate,omitempty"`
	Key         string `json:"-" url:"clientKey,omitempty"`
}

// Replication describes an XDCR replication as set with
//   POST /controller/createReplication
type Replication struct {
	FromBucket       string `url:"fromBucket"`
	ToCluster        string `url:"toCluster"`
	ToBucket         string `url:"toBucket"`
	Type             string `url:"type"`
	ReplicationType  string `url:"replicationType"`
	CompressionType  string `url:"compressionType,omitempty"`
	FilterExpression string `url:"filterExpression,omitempty"`
	PauseRequested   bool   `url:"pauseRequested"`
}

// ReplicationSettings describes an XDCR replication settings as returned by
//   GET /settings/replications/<remote UUID>/<local bucket>/<remote bucket>
type ReplicationSettings struct {
	CompressionType string `json:"compressionType" url:"compressionType,omitempty"`
	PauseRequested  bool   `json:"pauseRequested" url:"pauseRequested"`
}

// FormEncode represents user type in api compatible form
func (u *User) FormEncode() []byte {
	data := url.Values{}
	if u.Password != "" {
		data.Set("password", u.Password)
	}

	roles := RolesToStr(u.Roles)
	data.Set("roles", strings.Join(roles, ","))
	return []byte(data.Encode())
}

// RoleToStr translates roles to string array
func RolesToStr(userRoles []UserRole) []string {
	roles := []string{}
	for _, role := range userRoles {
		if role.BucketName != "" {
			// bucket roles are enclosed in brackets
			roles = append(roles, fmt.Sprintf("%s[%s]", role.Role, role.BucketName))
		} else {
			roles = append(roles, role.Role)
		}
	}
	sort.Strings(roles)
	return roles
}

// Normal unmarshlling doesn't work because
// LDAP DN Mapping returns a string when unset
func (s *LDAPSettings) UnmarshalJSON(data []byte) error {

	var jsonData map[string]interface{}
	err := json.Unmarshal(data, &jsonData)
	if err != nil {
		return err
	}

	// Remove dnMapping if it cannot be properly cast
	if dnMap, ok := jsonData["userDNMapping"]; ok {
		if _, ok := dnMap.(*[]LDAPUserDNMapping); !ok {
			delete(jsonData, "userDNMapping")
			data, err = json.Marshal(jsonData)
			if err != nil {
				return err
			}
		}
	}

	type LDAPSettingsAlias LDAPSettings
	settings := LDAPSettingsAlias{}

	if err := json.Unmarshal(data, &settings); err != nil {
		return err
	}

	*s = LDAPSettings(settings)
	return nil
}

func (s *LDAPSettings) FormEncode() ([]byte, error) {
	data := url.Values{}
	data.Set("hosts", strings.Join(s.Hosts, ","))
	data.Set("port", strconv.Itoa(s.Port))
	data.Set("bindDN", s.BindDN)
	data.Set("bindPass", s.BindPass)
	data.Set("authenticationEnabled", strconv.FormatBool(s.AuthenticationEnabled))
	data.Set("authorizationEnabled", strconv.FormatBool(s.AuthorizationEnabled))
	data.Set("encryption", string(s.Encryption))
	data.Set("serverCertValidation", strconv.FormatBool(s.EnableCertValidation))
	if s.EnableCertValidation {
		data.Set("cacert", string(s.CACert))
	}

	if s.AuthorizationEnabled && (s.UserDNMapping != nil) {
		dnData, err := json.Marshal(*s.UserDNMapping)
		if err != nil {
			return []byte{}, err
		}
		data.Set("userDNMapping", string(dnData))
	}

	if s.AuthorizationEnabled {
		data.Set("groupsQuery", s.GroupsQuery)
	}

	if s.NestedGroupsEnabled {
		data.Set("nestedGroupsEnabled", BoolToStr(s.NestedGroupsEnabled))
		data.Set("nestedGroupsMaxDepth", strconv.FormatUint(s.NestedGroupsMaxDepth, 10))
	}

	if s.CacheValueLifetime > 0 {
		data.Set("cacheValueLifetime", strconv.FormatUint(s.CacheValueLifetime, 10))
	}
	return []byte(data.Encode()), nil
}
