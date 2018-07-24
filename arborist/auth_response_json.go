package arborist

func (response AuthResponse) toJSON() AuthResponseJSON {
	return AuthResponseJSON{
		Auth: response.auth,
	}
}

type AuthResponseJSON struct {
	Auth bool `json:"auth"`
}
