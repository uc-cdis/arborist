package authutils

import ()

// Claims is a type alias for the values of the claims from a decoded token.
//
// Because it's a map, it must be created with `make(Claims)`.
type Claims = map[string]interface{}

type EncodedToken = string
