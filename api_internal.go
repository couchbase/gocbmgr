package cbmgr

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/couchbase/gocbmgr/urlencoding"
)

const version71Compatibility = 458753

func (c *Couchbase) addNode(hostname, username, password string, services ServiceList) error {
	data := url.Values{}
	data.Set("hostname", hostname)
	data.Set("user", username)
	data.Set("password", password)
	data.Set("services", services.String())

	headers := c.defaultHeaders()
	headers.Set("Content-Type", ContentTypeUrlEncoded)

	return c.n_post("/controller/addNode", []byte(data.Encode()), nil, headers)
}

func (c *Couchbase) cancelAddNode(otpNode string) error {
	data := url.Values{}
	data.Set("otpNode", otpNode)

	headers := c.defaultHeaders()
	headers.Set("Content-Type", ContentTypeUrlEncoded)

	return c.n_post("/controller/ejectNode", []byte(data.Encode()), nil, headers)
}

func (c *Couchbase) cancelAddBackNode(otpNode string) error {
	data := url.Values{}
	data.Set("otpNode", otpNode)

	headers := c.defaultHeaders()
	headers.Set("Content-Type", ContentTypeUrlEncoded)

	return c.n_post("/controller/reFailOver", []byte(data.Encode()), nil, headers)
}

func (c *Couchbase) getPools() (*PoolsInfo, error) {
	info := &PoolsInfo{}
	err := c.n_get("/pools", info, c.defaultHeaders())
	if err != nil {
		return nil, err
	}

	return info, nil
}

func (c *Couchbase) getPoolsDefault() (*ClusterInfo, error) {
	clusterInfo := &ClusterInfo{}
	err := c.n_get("/pools/default", clusterInfo, c.defaultHeaders())
	if err != nil {
		return nil, err
	}

	return clusterInfo, nil
}

func (c *Couchbase) getTasks() ([]*Task, error) {
	tasks := []*Task{}
	err := c.n_get("/pools/default/tasks", &tasks, c.defaultHeaders())
	if err != nil {
		return nil, err
	}

	return tasks, nil
}

func (c *Couchbase) rebalance(allNodes, ejectNodes []string) error {
	data := url.Values{}
	data.Set("ejectedNodes", strings.Join(ejectNodes, ","))
	data.Set("knownNodes", strings.Join(allNodes, ","))

	headers := c.defaultHeaders()
	headers.Set("Content-Type", ContentTypeUrlEncoded)

	return c.n_post("/controller/rebalance", []byte(data.Encode()), nil, headers)
}

func (c *Couchbase) stopRebalance() error {
	data := url.Values{}
	data.Set("allowUnsafe", "true")
	headers := c.defaultHeaders()
	headers.Set("Content-Type", ContentTypeUrlEncoded)

	return c.n_post("/controller/stopRebalance", []byte(data.Encode()), nil, headers)
}

func (c *Couchbase) failover(otpNodes []string) error {
	data := url.Values{}
	for _, otpNode := range otpNodes {
		data.Add("otpNode", otpNode)
	}

	headers := c.defaultHeaders()
	headers.Set("Content-Type", ContentTypeUrlEncoded)

	return c.n_post("/controller/failOver", []byte(data.Encode()), nil, headers)
}

func (c *Couchbase) setPoolsDefault(defaults *PoolsDefaults) error {
	headers := c.defaultHeaders()
	headers.Set(HeaderContentType, ContentTypeUrlEncoded)

	data, err := urlencoding.Marshal(defaults)
	if err != nil {
		return err
	}

	return c.n_post("/pools/default", data, nil, headers)
}

func (c *Couchbase) setStoragePaths(dataPath, indexPath string, analyticsPaths []string) error {
	data := url.Values{}
	data.Set("path", dataPath)
	data.Set("index_path", indexPath)
	if len(analyticsPaths) > 0 {
		data.Set("cbas_path", analyticsPaths[0])
		for _, path := range analyticsPaths[1:] {
			data.Add("cbas_path", path)
		}
	}
	headers := c.defaultHeaders()
	headers.Set("Content-Type", ContentTypeUrlEncoded)

	return c.n_post("/nodes/self/controller/settings", []byte(data.Encode()), nil, headers)
}

func (c *Couchbase) setHostname(hostname string) error {
	data := url.Values{}
	data.Set("hostname", hostname)

	headers := c.defaultHeaders()
	headers.Set("Content-Type", ContentTypeUrlEncoded)

	return c.n_post("/node/controller/rename", []byte(data.Encode()), nil, headers)
}

func (c *Couchbase) getIndexSettings() (*IndexSettings, error) {
	settings := &IndexSettings{}
	err := c.n_get("/settings/indexes", settings, c.defaultHeaders())
	if err != nil {
		return nil, err
	}

	return settings, nil
}

func (c *Couchbase) GetSecuritySettings() (*SecuritySettings, error) {
	s := &SecuritySettings{}

	if err := c.n_get("/settings/security", s, c.defaultHeaders()); err != nil {
		return nil, err
	}

	return s, nil
}

func (c *Couchbase) SetSecuritySettings(s *SecuritySettings) error {
	data, err := urlencoding.Marshal(s)
	if err != nil {
		return err
	}

	headers := c.defaultHeaders()
	headers.Set(HeaderContentType, ContentTypeUrlEncoded)

	return c.n_post("/settings/security", data, nil, headers)
}

func (c *Couchbase) GetNodeNetworkConfiguration() (*NodeNetworkConfiguration, error) {
	// And yet again, the CRUD is completely ignored!
	node, err := c.getNodeInfo()
	if err != nil {
		return nil, err
	}

	onOrOff := Off
	if node.NodeEncryption {
		onOrOff = On
	}

	s := &NodeNetworkConfiguration{
		NodeEncryption: onOrOff,
	}

	return s, nil
}

func (c *Couchbase) SetNodeNetworkConfiguration(s *NodeNetworkConfiguration) error {
	data, err := urlencoding.Marshal(s)
	if err != nil {
		return err
	}

	headers := c.defaultHeaders()
	headers.Set(HeaderContentType, ContentTypeUrlEncoded)

	return c.n_post("/node/controller/setupNetConfig", data, nil, headers)
}

func (c *Couchbase) EnableExternalListener(s *NodeNetworkConfiguration) error {
	data, err := urlencoding.Marshal(s)
	if err != nil {
		return err
	}

	headers := c.defaultHeaders()
	headers.Set(HeaderContentType, ContentTypeUrlEncoded)

	return c.n_post("/node/controller/enableExternalListener", data, nil, headers)
}

func (c *Couchbase) DisableExternalListener(s *NodeNetworkConfiguration) error {
	data, err := urlencoding.Marshal(s)
	if err != nil {
		return err
	}

	headers := c.defaultHeaders()
	headers.Set(HeaderContentType, ContentTypeUrlEncoded)

	return c.n_post("/node/controller/disableExternalListener", data, nil, headers)
}

func (c *Couchbase) setIndexSettings(mode IndexStorageMode, threads, memSnapInterval,
	stableSnapInterval, maxRollbackPoints int, logLevel IndexLogLevel) error {
	data := url.Values{}
	data.Set("storageMode", string(mode))
	data.Set("indexerThreads", strconv.Itoa(threads))
	data.Set("memorySnapshotInterval", strconv.Itoa(memSnapInterval))
	data.Set("stableSnapshotInterval", strconv.Itoa(stableSnapInterval))
	data.Set("maxRollbackPoints", strconv.Itoa(maxRollbackPoints))
	data.Set("logLevel", string(logLevel))

	headers := c.defaultHeaders()
	headers.Set(HeaderContentType, ContentTypeUrlEncoded)

	return c.n_post("/settings/indexes", []byte(data.Encode()), nil, headers)
}

func (c *Couchbase) setServices(services ServiceList) error {
	data := url.Values{}
	data.Set("services", services.String())

	headers := c.defaultHeaders()
	headers.Set(HeaderContentType, ContentTypeUrlEncoded)

	return c.n_post("/node/controller/setupServices", []byte(data.Encode()), nil, headers)
}

func (c *Couchbase) setWebSettings(username, password string, port int) error {
	data := url.Values{}
	data.Set("username", username)
	data.Set("password", password)
	data.Set("port", strconv.Itoa(port))

	headers := c.defaultHeaders()
	headers.Set(HeaderContentType, ContentTypeUrlEncoded)

	return c.n_post("/settings/web", []byte(data.Encode()), nil, headers)
}

func (c *Couchbase) createBucket(bucket *Bucket) error {
	params := bucket.FormEncode()
	headers := c.defaultHeaders()
	headers.Set(HeaderContentType, ContentTypeUrlEncoded)
	return c.n_post("/pools/default/buckets", params, nil, headers)
}

func (c *Couchbase) deleteBucket(name string) error {
	headers := c.defaultHeaders()
	headers.Set(HeaderContentType, ContentTypeUrlEncoded)

	path := "/pools/default/buckets/" + name
	return c.n_delete(path, headers)
}

func (c *Couchbase) editBucket(bucket *Bucket) error {
	// bucket params cannot include conflict resolution field
	// during edit.  TODO: fix for couchbase rest API
	bucket.ConflictResolution = ""

	params := bucket.FormEncode()
	headers := c.defaultHeaders()
	headers.Set(HeaderContentType, ContentTypeUrlEncoded)
	return c.n_post("/pools/default/buckets/"+bucket.BucketName, params, nil, headers)
}

func (c *Couchbase) getBucketStatus(name string) (*BucketStatus, error) {
	status := &BucketStatus{}
	path := "/pools/default/buckets/" + name
	err := c.n_get(path, status, c.defaultHeaders())
	if err != nil {
		return nil, err
	}
	return status, nil
}

func (c *Couchbase) getBuckets() ([]*Bucket, error) {
	buckets := []*Bucket{}
	path := "/pools/default/buckets/"
	err := c.n_get(path, &buckets, c.defaultHeaders())
	if err != nil {
		return nil, err
	}
	return buckets, nil
}

func (c *Couchbase) insertDoc(bucket *Bucket, docKey string, docData []byte) error {
	docUrl := "/pools/default/buckets/" + bucket.BucketName + "/docs/" + docKey
	headers := c.defaultHeaders()
	headers.Set(HeaderContentType, "application/x-www-form-urlencoded")
	return c.n_post(docUrl, docData, nil, headers)
}

// Autofailover settings with specified timeouts
func (c *Couchbase) setAutoFailoverSettings(settings *AutoFailoverSettings) error {
	headers := c.defaultHeaders()
	headers.Set(HeaderContentType, ContentTypeUrlEncoded)

	data, err := urlencoding.Marshal(settings)
	if err != nil {
		return err
	}

	return c.n_post("/settings/autoFailover", data, nil, headers)
}

func (c *Couchbase) getAutoFailoverSettings() (*AutoFailoverSettings, error) {
	settings := &AutoFailoverSettings{}
	err := c.n_get("/settings/autoFailover", settings, c.defaultHeaders())
	if err != nil {
		return nil, err
	}

	return settings, nil
}

func (c *Couchbase) resetCount() error {

	data := url.Values{}
	headers := c.defaultHeaders()
	headers.Set(HeaderContentType, ContentTypeUrlEncoded)
	return c.n_post("/settings/autoFailover/resetCount", []byte(data.Encode()), nil, headers)
}

func (c *Couchbase) getNodeInfo() (*NodeInfo, error) {
	node := &NodeInfo{}
	err := c.n_get("/nodes/self", node, c.defaultHeaders())
	if err != nil {
		return nil, err
	}

	return node, nil
}

func (c *Couchbase) uploadClusterCACert(pem []byte) error {
	headers := c.defaultHeaders()
	return c.n_post("/controller/uploadClusterCA", pem, nil, headers)
}

func (c *Couchbase) getClusterCompatibility() (compat int, err error) {
	info, err := c.getPoolsDefault()
	if err != nil {
		return
	}
	if len(info.Nodes) == 0 {
		err = fmt.Errorf("no nodes found to get cluster compatibility")
		return
	}
	compat = info.Nodes[0].ClusterCompatibility
	return
}

func (c *Couchbase) getClusterCert71() (certs []TrustedCA, err error) {
	certs = []TrustedCA{}
	err = c.n_get("/pools/default/trustedCAs", &certs, c.defaultHeaders())
	return
}

func (c *Couchbase) getClusterCACert() ([]byte, error) {
	certs, err := c.getClusterCACertAll()
	if err != nil {
		return nil, err
	}

	if len(certs) == 0 {
		err = fmt.Errorf("no certificates found")
		return nil, err
	}

	return []byte(certs[len(certs)-1].PEM), nil
}

func (c *Couchbase) getClusterCACertAll() (certs []TrustedCA, err error) {
	compat, err := c.getClusterCompatibility()
	if err != nil {
		return nil, err
	}

	if compat >= version71Compatibility {
		cert, err := c.getClusterCert71()
		if err != nil {
			return nil, err
		}
		return cert, nil
	}

	var cert string
	err = c.n_get("/pools/default/certificate", &cert, c.defaultHeaders())
	if err != nil {
		return
	}
	return []TrustedCA{
		{PEM: cert},
	}, err
}

func (c *Couchbase) reloadNodeCert() error {
	headers := c.defaultHeaders()
	return c.n_post("/node/controller/reloadCertificate", []byte{}, nil, headers)
}

func (c *Couchbase) getClientCertAuth() (*ClientCertAuth, error) {
	clientAuth := &ClientCertAuth{}
	if err := c.n_get("/settings/clientCertAuth", clientAuth, c.defaultHeaders()); err != nil {
		return nil, err
	}
	return clientAuth, nil
}

func (c *Couchbase) setClientCertAuth(settings *ClientCertAuth) error {
	data, err := json.Marshal(settings)
	if err != nil {
		return err
	}
	headers := c.defaultHeaders()
	return c.n_post("/settings/clientCertAuth", data, nil, headers)
}

func (c *Couchbase) getUpdatesEnabled() (bool, error) {
	settingsStats := &SettingsStats{}
	if err := c.n_get("/settings/stats", settingsStats, c.defaultHeaders()); err != nil {
		return false, err
	}
	return settingsStats.SendStats, nil
}

func (c *Couchbase) setUpdatesEnabled(enabled bool) error {
	data := url.Values{}
	data.Set("sendStats", BoolAsStr(enabled))
	headers := c.defaultHeaders()
	headers.Set(HeaderContentType, ContentTypeUrlEncoded)
	return c.n_post("/settings/stats", []byte(data.Encode()), nil, headers)
}

func (c *Couchbase) getAlternateAddressesExternal() (*AlternateAddressesExternal, error) {
	nodeServices := &NodeServices{}
	if err := c.n_get("/pools/default/nodeServices", nodeServices, c.defaultHeaders()); err != nil {
		return nil, err
	}
	for _, node := range nodeServices.NodesExt {
		if !node.ThisNode {
			continue
		}
		if node.AlternateAddresses == nil {
			return nil, nil
		}
		return node.AlternateAddresses.External, nil
	}
	// The absence of this node is probably due to it not being balanced in yet.
	// /pools/default/nodeServices apparently only shows nodes when the rebalance
	// starts.  Don't raise an error.
	return nil, nil
}

func (c *Couchbase) setAlternateAddressesExternal(addresses *AlternateAddressesExternal) error {
	headers := c.defaultHeaders()
	headers.Set(HeaderContentType, ContentTypeUrlEncoded)
	data, err := urlencoding.Marshal(addresses)
	if err != nil {
		return err
	}
	return c.n_put("/node/controller/setupAlternateAddresses/external", data, headers)
}

func (c *Couchbase) deleteAlternateAddressesExternal() error {
	headers := c.defaultHeaders()
	return c.n_delete("/node/controller/setupAlternateAddresses/external", headers)
}

func (c *Couchbase) getLogs() (LogList, error) {
	body := make(map[string]LogList)
	if err := c.n_get("/logs", &body, c.defaultHeaders()); err != nil {
		return nil, err
	}

	if logs, ok := body["list"]; ok {
		return logs, nil
	}
	return nil, NewErrorInvalidLogList()
}

func (c *Couchbase) logClientError(msg string) error {
	data := url.Values{}
	data.Set("error", msg)

	headers := c.defaultHeaders()
	headers.Set("Content-Type", ContentTypeUrlEncoded)

	return c.n_post("/logClientError", []byte(data.Encode()), nil, headers)
}

func (c *Couchbase) getServerGroups() (*ServerGroups, error) {
	serverGroups := &ServerGroups{}
	if err := c.n_get("/pools/default/serverGroups", serverGroups, c.defaultHeaders()); err != nil {
		return nil, err
	}
	return serverGroups, nil
}

func (c *Couchbase) createServerGroup(name string) error {
	data := url.Values{}
	data.Set("name", name)
	headers := c.defaultHeaders()
	headers.Set(HeaderContentType, ContentTypeUrlEncoded)
	return c.n_post("/pools/default/serverGroups", []byte(data.Encode()), nil, headers)
}

func (c *Couchbase) updateServerGroups(revision string, groups *ServerGroupsUpdate) error {
	data, err := json.Marshal(groups)
	if err != nil {
		return err
	}
	uri := "/pools/default/serverGroups?rev=" + revision
	headers := c.defaultHeaders()
	headers.Set(HeaderContentType, ContentTypeJSON)
	return c.n_put(uri, data, headers)
}

func (c *Couchbase) setRecoveryType(otpNode string, recoveryType RecoveryType) error {

	data := url.Values{}
	data.Set("otpNode", otpNode)
	data.Set("recoveryType", string(recoveryType))
	headers := c.defaultHeaders()
	headers.Set("Content-Type", ContentTypeUrlEncoded)

	return c.n_post("/controller/setRecoveryType", []byte(data.Encode()), nil, headers)
}

func (c *Couchbase) getAutoCompactionSettings() (*AutoCompactionSettings, error) {
	r := &AutoCompactionSettings{}
	if err := c.n_get("/settings/autoCompaction", r, c.defaultHeaders()); err != nil {
		return nil, err
	}
	return r, nil
}

func (c *Couchbase) setAutoCompactionSettings(r *AutoCompactionSettings) error {
	headers := c.defaultHeaders()
	headers.Set(HeaderContentType, ContentTypeUrlEncoded)

	data, err := urlencoding.Marshal(r)
	if err != nil {
		return err
	}

	return c.n_post("/controller/setAutoCompaction", data, nil, headers)
}

// listRemoteClusters lists remote clusters for use by XDCR.
func (c *Couchbase) listRemoteClusters() (RemoteClusters, error) {
	r := RemoteClusters{}
	if err := c.n_get("/pools/default/remoteClusters", &r, c.defaultHeaders()); err != nil {
		return nil, err
	}

	// God only knows what this means, but lets assume we discard things
	// that are "deleted".
	filtered := RemoteClusters{}
	for _, cluster := range r {
		if !cluster.Deleted {
			filtered = append(filtered, cluster)
		}
	}

	return filtered, nil
}

// createRemoteCluster creates a new XDCR remote cluster.
func (c *Couchbase) createRemoteCluster(r *RemoteCluster) error {
	headers := c.defaultHeaders()
	headers.Set(HeaderContentType, ContentTypeUrlEncoded)

	data, err := urlencoding.Marshal(r)
	if err != nil {
		return err
	}

	return c.n_post("/pools/default/remoteClusters", data, nil, headers)
}

// deleteRemoteCluster deletes an existing XDCR remote cluster.
func (c *Couchbase) deleteRemoteCluster(r *RemoteCluster) error {
	return c.n_delete("/pools/default/remoteClusters/"+r.Name, c.defaultHeaders())
}

// getRemoteClusterByUUID helps manage the utter horror show that is XDCR
// replications.
func (c *Couchbase) getRemoteClusterByUUID(uuid string) (*RemoteCluster, error) {
	clusters, err := c.listRemoteClusters()
	if err != nil {
		return nil, err
	}

	for _, cluster := range clusters {
		if cluster.UUID == uuid {
			return &cluster, nil
		}
	}

	return nil, fmt.Errorf("lookupClusterForUUID: no cluster found for uuid %v", uuid)
}

// getRemoteClusterByName helps manage the utter horror show that is XDCR
// replications.
func (c *Couchbase) getRemoteClusterByName(name string) (*RemoteCluster, error) {
	clusters, err := c.listRemoteClusters()
	if err != nil {
		return nil, err
	}

	for _, cluster := range clusters {
		if cluster.Name == name {
			return &cluster, nil
		}
	}

	return nil, fmt.Errorf("lookupUUIDForCluster: no cluster found for name %v", name)
}

// getReplicationSettings helps manage the utter horror show that is XDCR
// replications.
func (c *Couchbase) getReplicationSettings(uuid, from, to string) (*ReplicationSettings, error) {
	s := &ReplicationSettings{}
	if err := c.n_get("/settings/replications/"+url.PathEscape(uuid+"/"+from+"/"+to), s, c.defaultHeaders()); err != nil {
		return nil, err
	}
	return s, nil
}

// listReplications lists all replications in the cluster.  To make the Operator
// code a million times simpler we do a lot of post processing and table joins
// just to recover the same information used to create a replication.
func (c *Couchbase) listReplications() ([]Replication, error) {
	tasks, err := c.getXDCRTasks()
	if err != nil {
		return nil, err
	}

	replications := []Replication{}
	for _, task := range tasks {
		// Parse the target to recover lost information.
		// Should be in the form /remoteClusters/c4c9af9ad62d8b5f665edac5ffc9c1be/buckets/default
		if task.Target == "" {
			return nil, fmt.Errorf("listReplications: target not populated")
		}

		parts := strings.Split(task.Target, "/")
		if len(parts) != 5 {
			return nil, fmt.Errorf("listReplications: target incorrectly formatted: %v", task.Target)
		}

		uuid := parts[2]
		to := parts[4]

		// Lookup the UUID to recover the cluster name.
		cluster, err := c.getRemoteClusterByUUID(uuid)
		if err != nil {
			return nil, err
		}

		// Lookup the settings to recover the compression type.
		settings, err := c.getReplicationSettings(uuid, task.Source, to)
		if err != nil {
			return nil, err
		}

		// By now your eyeballs will be dry from all the rolling they are doing.
		replications = append(replications, Replication{
			FromBucket:       task.Source,
			ToCluster:        cluster.Name,
			ToBucket:         to,
			Type:             task.ReplicationType,
			ReplicationType:  "continuous",
			CompressionType:  settings.CompressionType,
			FilterExpression: task.FilterExpression,
			PauseRequested:   settings.PauseRequested,
		})
	}

	return replications, nil
}

// createReplication creates an XDCR replication between clusters.
func (c *Couchbase) createReplication(r *Replication) error {
	headers := c.defaultHeaders()
	headers.Set(HeaderContentType, ContentTypeUrlEncoded)

	data, err := urlencoding.Marshal(r)
	if err != nil {
		return err
	}

	return c.n_post("/controller/createReplication", data, nil, headers)
}

// updateReplication updates the parts of an XDCR replication that can be updated.
func (c *Couchbase) updateReplication(r *Replication) error {
	cluster, err := c.getRemoteClusterByName(r.ToCluster)
	if err != nil {
		return err
	}

	headers := c.defaultHeaders()
	headers.Set(HeaderContentType, ContentTypeUrlEncoded)

	data, err := urlencoding.Marshal(r)
	if err != nil {
		return err
	}

	return c.n_post("/settings/replications/"+url.PathEscape(cluster.UUID+"/"+r.FromBucket+"/"+r.ToBucket), data, nil, headers)
}

// deleteReplication deletes an existing XDCR replication between clusters.
func (c *Couchbase) deleteReplication(r *Replication) error {
	cluster, err := c.getRemoteClusterByName(r.ToCluster)
	if err != nil {
		return err
	}

	// WHAT IS THIS MADNESS?!??!?!?!?!??!
	return c.n_delete("/controller/cancelXDCR/"+url.PathEscape(cluster.UUID+"/"+r.FromBucket+"/"+r.ToBucket), c.defaultHeaders())
}

func (c *Couchbase) getUsers() ([]*User, error) {
	users := []*User{}
	path := "/settings/rbac/users"
	err := c.n_get(path, &users, c.defaultHeaders())
	if err != nil {
		return nil, err
	}
	return users, nil
}

func (c *Couchbase) createUser(user *User) error {
	params := user.FormEncode()
	headers := c.defaultHeaders()
	headers.Set(HeaderContentType, ContentTypeUrlEncoded)

	path := strings.Join([]string{"/settings/rbac/users", string(user.Domain), user.ID}, "/")
	return c.n_put(path, params, headers)
}

func (c *Couchbase) deleteUser(user *User) error {
	headers := c.defaultHeaders()
	headers.Set(HeaderContentType, ContentTypeUrlEncoded)

	path := strings.Join([]string{"/settings/rbac/users", string(user.Domain), user.ID}, "/")
	return c.n_delete(path, headers)
}

func (c *Couchbase) getUser(id string, domain AuthDomain) (*User, error) {
	headers := c.defaultHeaders()
	headers.Set(HeaderContentType, ContentTypeUrlEncoded)

	user := &User{}
	path := strings.Join([]string{"/settings/rbac/users", string(domain), id}, "/")
	err := c.n_get(path, user, c.defaultHeaders())
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (c *Couchbase) getGroups() ([]*Group, error) {
	groups := []*Group{}
	path := "/settings/rbac/groups"
	err := c.n_get(path, &groups, c.defaultHeaders())
	if err != nil {
		return nil, err
	}
	return groups, nil
}

func (c *Couchbase) createGroup(group *Group) error {
	data := url.Values{}
	roles := RolesToStr(group.Roles)
	data.Set("roles", strings.Join(roles, ","))
	data.Set("description", group.Description)
	data.Set("ldap_group_ref", group.LDAPGroupRef)

	headers := c.defaultHeaders()
	headers.Set(HeaderContentType, ContentTypeUrlEncoded)

	path := "/settings/rbac/groups/" + group.ID
	return c.n_put(path, []byte(data.Encode()), headers)
}

func (c *Couchbase) deleteGroup(group *Group) error {
	headers := c.defaultHeaders()
	headers.Set(HeaderContentType, ContentTypeUrlEncoded)

	path := "/settings/rbac/groups/" + group.ID
	return c.n_delete(path, headers)
}

func (c *Couchbase) getGroup(id string) (*Group, error) {
	headers := c.defaultHeaders()
	headers.Set(HeaderContentType, ContentTypeUrlEncoded)

	path := "/settings/rbac/groups/" + id
	group := &Group{}
	err := c.n_get(path, group, c.defaultHeaders())
	if err != nil {
		return nil, err
	}

	return group, nil
}

func (c *Couchbase) getLDAPSettings() (*LDAPSettings, error) {
	settings := &LDAPSettings{}
	err := c.n_get("/settings/ldap", settings, c.defaultHeaders())
	if err != nil {
		return nil, err
	}
	return settings, nil
}

func (c *Couchbase) setLDAPSettings(settings *LDAPSettings) error {
	params, err := settings.FormEncode()
	if err != nil {
		return err
	}
	headers := c.defaultHeaders()
	headers.Set(HeaderContentType, ContentTypeUrlEncoded)
	return c.n_post("/settings/ldap", params, nil, headers)
}

func (c *Couchbase) getLDAPConnectivityStatus() (*LDAPStatus, error) {
	data := url.Values{}
	headers := c.defaultHeaders()
	headers.Set(HeaderContentType, ContentTypeJSON)
	status := &LDAPStatus{}
	err := c.n_post("/settings/ldap/validate/connectivity", []byte(data.Encode()), status, headers)
	if err != nil {
		return nil, err
	}
	return status, nil
}
