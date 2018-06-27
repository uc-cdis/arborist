package arborist

type AuthResponseJSON struct {
	Auth bool `json:"auth"`
}

func (response AuthResponse) toJSON() AuthResponseJSON {
	return AuthResponseJSON{
		Auth: response.auth,
	}
}
