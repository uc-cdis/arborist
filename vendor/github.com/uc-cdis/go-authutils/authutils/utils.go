package authutils

import ()

// TODO: move to more general utils package
// (rudyardrichter 2018-06-18)
func contains(searchValue string, collection []string) bool {
	for _, value := range collection {
		if searchValue == value {
			return true
		}
	}
	return false
}
