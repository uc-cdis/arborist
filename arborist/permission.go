package arborist

type Permission struct {
	id          string
	description string
	action      Action
	constraints map[string]string
}

func (permission *Permission) equals(other *Permission) bool {
	return permission.id == other.id
}

func (permission *Permission) allows(action *Action, constraints Constraints) bool {
	correctMethod := action.Method == permission.action.Method
	correctService := action.Service == permission.action.Service
	if !correctService || !correctMethod {
		return false
	}

	for requiredKey, requiredVal := range constraints {
		val, exists := permission.constraints[requiredKey]
		if !exists {
			return false
		}
		if val != requiredVal {
			return false
		}
	}

	return true
}
