package checker

import (
	"strconv"

	"github.com/trustelem/zxcvbn"
)

type Zxcvbn struct {
}

func (z *Zxcvbn) MethodName() string {
	return "zxcvbn password strength (+ Indonesian wordlist)"
}

func (z *Zxcvbn) CheckPassword(pwd string) (bool, string, error) {
	res := zxcvbn.PasswordStrength(pwd, nil)

	// password is safe if the zxcvbn score is >= 3
	if res.Score >= 3 {
		return true, "the score is " + strconv.Itoa(res.Score), nil
	}

	return false, "the score is " + strconv.Itoa(res.Score), nil
}
