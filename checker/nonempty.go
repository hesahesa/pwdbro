package checker

import "unicode/utf8"

// NonEmpty is an example on how to create a checker for pwdbro
// This simple checker will return safe == true if the password
// string that is supplied have a character count more than one
type NonEmpty struct {
}

// MethodName returns the method name of this checker
func (n *NonEmpty) MethodName() string {
	return "Non Empty String"
}

// CheckPassword returns true if the character count of a string
// is more than or equal to one
func (n *NonEmpty) CheckPassword(pwd string) (bool, string, error) {
	if utf8.RuneCountInString(pwd) > 0 {
		return true, "", nil
	}

	return false, "Character count should be more than 0", nil
}
