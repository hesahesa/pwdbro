package checker

type Pwnedpasswords struct {
}

func (pp *Pwnedpasswords) MethodName() string {
	return "Pwnedpasswords API"
}

func (pp *Pwnedpasswords) CheckPassword(pwd string) (bool, string, error) {
	return false, "", nil
}
