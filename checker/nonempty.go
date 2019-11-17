package checker

import "unicode/utf8"

type NonEmpty struct {
}

func (n *NonEmpty) MethodName() string {
	return "Non Empty String"
}

func (n *NonEmpty) CheckPassword(pwd string) (bool, string, error) {
	if utf8.RuneCountInString(pwd) > 0 {
		return true, "", nil
	}

	return false, "Character count should be more than 0", nil
}
