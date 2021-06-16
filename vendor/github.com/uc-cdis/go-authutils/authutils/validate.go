package authutils

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"gopkg.in/square/go-jose.v2/jwt"
)

// `fence`-specific: the `pur` field indicates the purpose for the token, which
// may also be validated. If used, it must take one of these values.
var ALLOWED_PURPOSES []string = []string{"id", "access", "refresh", "session", "api_key"}

// JWTApplication stores the state for an application needing to validate JWTs.
type JWTApplication struct {
	// KeyKeys for looking up RSA public keys by ID for token validation.
	Keys *KeysManager
}

// NewJWTApplication initializes a new application.
func NewJWTApplication(jwkURL string) *JWTApplication {
	keysManager := NewKeysManager(jwkURL)
	return &JWTApplication{
		Keys: &keysManager,
	}
}

// Decode takes an encoded token, finds the key suitable for validating this
// token, and returns the decoded token claims.
//
// NOTE that this does NOT validate the claims, only the signature.
func (application *JWTApplication) Decode(encodedToken EncodedToken) (*Claims, error) {
	decodedToken, err := jwt.ParseSigned(encodedToken)
	if err != nil {
		return nil, err
	}

	// Get the key used to sign this token.
	//
	// There will be multiple headers in the case of multiple signatures. This
	// doesn't apply to our use case, so make sure there is only one signature.
	if len(decodedToken.Headers) > 1 {
		return nil, validationError("token has multiple headers; expected exactly 1")
	}
	header := decodedToken.Headers[0]
	kid := header.KeyID
	key, err := application.Keys.Lookup(kid)
	if err != nil {
		return nil, err
	}

	claims := make(Claims)
	if err := decodedToken.Claims(key, &claims); err != nil {
		return nil, err
	}

	return &claims, nil
}

// checkExpiration validates the `exp` field in the claims.
func checkExpiration(claims *Claims, now int64) error {
	// `now` should be set with something like this:
	//
	//     now := time.Now().Unix()
	tokenExp, exists := (*claims)["exp"]
	if !exists {
		return missingField("exp")
	}
	var exp int64
	switch e := tokenExp.(type) {
	case float32:
		exp = int64(e)
	case float64:
		exp = int64(e)
	case int:
		exp = int64(e)
	case int32:
		exp = int64(e)
	case int64:
		exp = int64(e)
	default:
		return fieldTypeError("exp", tokenExp, "numeric type")
	}
	if exp < now {
		return expired(exp)
	}
	return nil
}

// checkIssuer validates the `iss` field in the claims.
func checkIssuer(claims *Claims, allowed []string) error {
	if allowed == nil {
		return nil
	}
	tokenIss, exists := (*claims)["iss"]
	if !exists {
		return missingField("iss")
	}
	iss, casted := tokenIss.(string)
	if !casted {
		return fieldTypeError("iss", iss, "string")
	}
	if !contains(iss, allowed) {
		return invalidIssuer(iss)
	}
	return nil
}

// checkScope validates the `scope` field in the claims.
func checkScope(claims *Claims, expected []string) error {
	// if token has a scope field but no scopes are expected this is fine
	if len(expected) == 0 {
		return nil
	}
	tokenScope, exists := (*claims)["scope"]
	if !exists {
		return missingField("scope")
	}
	var scope []string
	switch a := tokenScope.(type) {
	case []string:
		scope = a
	case []interface{}:
		for _, value := range a {
			valueString, casted := value.(string)
			if !casted {
				return fieldTypeError("scope", tokenScope, "[]string")
			}
			scope = append(scope, valueString)
		}
	default:
		return fieldTypeError("scope", tokenScope, "[]string")
	}
	for _, expectedScope := range expected {
		if !contains(expectedScope, scope) {
			return missingScope(expectedScope, scope)
		}
	}
	return nil
}

func checkPurpose(claims *Claims, expected *string) error {
	if expected != nil {
		tokenPur, exists := (*claims)["pur"]
		if !exists {
			return missingField("pur")
		}
		pur, casted := tokenPur.(string)
		if !casted {
			return fieldTypeError("pur", tokenPur, "string")
		}
		if *expected != pur {
			return invalidPurpose(pur, *expected)
		}
	}
	return nil
}

// Expected represents some values which are used to validate the claims in a
// token.
type Expected struct {
	// Scopes is a list of expected uses of the token.
	Scopes []string `json:"scope"`
	// Expiration is the Unix timestamp at which the token becomes expired.
	Expiration *int64 `json:"exp"`
	// Issuers is a list of acceptable issuers to expect tokens to contain.
	Issuers []string `json:"iss"`
	// Purpose is an optional field indicating the type of the token (access,
	// refresh, etc.)
	Purpose *string `json:"pur"`
}

// See https://tools.ietf.org/html/rfc7519 for general information on JWTs and
// basic validation, and see https://tools.ietf.org/html/rfc7523 for
// considerations for validation specific to using JWTs for the OAuth2 flow.
func (expected *Expected) selfValidate() error {
	if expected.Purpose != nil {
		// Must expect one of these given purposes.
		if !contains(*expected.Purpose, ALLOWED_PURPOSES) {
			allowed := strings.Join(ALLOWED_PURPOSES, ", ")
			msg := fmt.Sprintf("purpose \"%s\" not in valid values: %s", *expected.Purpose, allowed)
			return validationError(msg)
		}
	}

	return nil
}

// Validate checks the Expected fields against the provided Claims to make sure
// the claims are valid, returning an error if any fail to validate. On success
// return nil.
func (expected *Expected) Validate(claims *Claims) error {
	if err := expected.selfValidate(); err != nil {
		return err
	}

	exp := expected.Expiration
	if exp == nil {
		now := time.Now().Unix()
		exp = &now
	}
	if err := checkExpiration(claims, *exp); err != nil {
		return err
	}
	if err := checkIssuer(claims, expected.Issuers); err != nil {
		return err
	}
	if err := checkScope(claims, expected.Scopes); err != nil {
		return err
	}
	if err := checkPurpose(claims, expected.Purpose); err != nil {
		return err
	}

	return nil
}

// ValidateRequest takes an http.Request and some expectations for the claims
// in a token, looks for an encoded JWT in the `Authorization` header, and
// validates and decodes the JWT header to return the claims it contains.
func (application *JWTApplication) ValidateRequest(r *http.Request, expected *Expected) (*Claims, error) {
	encodedToken := r.Header.Get("Authorization")
	claims, err := application.Decode(encodedToken)
	if err != nil {
		return nil, err
	}
	err = expected.Validate(claims)
	if err != nil {
		return nil, err
	}
	return claims, nil
}
