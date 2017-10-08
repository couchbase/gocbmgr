package cbmgr

func (c *Couchbase) AddNode(hostname, username, password string, services ServiceList) error {
	return c.addNode(hostname, username, password, services)
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

func (c *Couchbase) NodeInitialize(hostname, dataPath, indexPath string) error {
	if err := c.setHostname(hostname); err != nil {
		return err
	}

	if err := c.setStoragePaths(dataPath, indexPath); err != nil {
		return err
	}

	return nil
}
