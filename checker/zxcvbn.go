package checker

import (
	"strconv"

	"github.com/trustelem/zxcvbn"
)

// Zxcvbn is a checker struct that will calculate a password
// strength using Dropbox's zxcvbn algorithm
type Zxcvbn struct {
}

// MethodName returns the method name of the checker
func (z *Zxcvbn) MethodName() string {
	return "zxcvbn password strength (+ Indonesian wordlist)"
}

// CheckPassword computes a zxcvbn password strength of a given
// string, and return Safe == true if the score is more than or
// equal to three
func (z *Zxcvbn) CheckPassword(pwd string) (bool, string, error) {
	res := zxcvbn.PasswordStrength(pwd, nil)

	// password is safe if the zxcvbn score is >= 3
	if res.Score >= 3 {
		return true, "the score is " + strconv.Itoa(res.Score), nil
	}

	return false, "the score is " + strconv.Itoa(res.Score), nil
}
