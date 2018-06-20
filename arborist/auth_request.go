package arborist

type AuthRequest struct {
	policies    map[*Policy]struct{}
	resource    *Resource
	action      *Action
	constraints Constraints
}

type BulkAuthRequest struct {
	requests []*AuthRequest
}
