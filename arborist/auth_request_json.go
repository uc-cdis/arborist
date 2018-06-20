package arborist

type AuthRequestJSON struct {
	PolicyIDs    []string    `json:"policy_ids"`
	ResourcePath string      `json:"resource_path"`
	Action       Action      `json:"action"`
	Constraints  Constraints `json:"constraints"`
}

type BulkAuthRequestJSON struct {
	Requests []AuthRequestJSON `json:"requests"`
}
