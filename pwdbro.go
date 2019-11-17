package pwdbro

import (
	"sync"

	"github.com/hesahesa/pwdbro/checker"
)

// PwdStatus is a struct to hold password status after check
type PwdStatus struct {
	Method  string
	Safe    bool
	Message string
	Error   error
}

// NewPwdStatus construct a new PwdStatus struct
func NewPwdStatus(safe bool, message string, err error) *PwdStatus {
	return &PwdStatus{
		Safe:    safe,
		Message: message,
		Error:   err,
	}
}

// PwdChecker is an interface to check password strength
type PwdChecker interface {
	// The method name used, it should return a string denoting the method identifier
	MethodName() string
	// The method that is called when checking password, it accept a password string
	// and should return a boolean denoting whether the password is safe/not, a string
	// denoting additional message, and an error denoting if there is any error when
	// running the method
	CheckPassword(string) (bool, string, error)
}

// PwdBro is a struct to hold pwdbro instance
type PwdBro struct {
	pwdCheckers []PwdChecker
}

// NewDefaultPwdBro return an instance of PwdBro with default checking mechanisms
func NewDefaultPwdBro() *PwdBro {
	pwdb := &PwdBro{
		pwdCheckers: make([]PwdChecker, 0),
	}
	pwdb.AddChecker(&checker.NonEmpty{})
	pwdb.AddChecker(&checker.Pwnedpasswords{})
	pwdb.AddChecker(&checker.Zxcvbn{})

	return pwdb
}

// AddChecker add a PwdChecker to the list of method of pwdbro
func (pwdb *PwdBro) AddChecker(c PwdChecker) error {
	pwdb.pwdCheckers = append(pwdb.pwdCheckers, c)
	return nil
}

// RunChecks run all checks for a password string
func (pwdb *PwdBro) RunChecks(pwd string) ([]*PwdStatus, error) {
	result := make([]*PwdStatus, 0)
	for _, checker := range pwdb.pwdCheckers {
		status := NewPwdStatus(checker.CheckPassword(pwd))
		status.Method = checker.MethodName()

		result = append(result, status)
	}
	return result, nil
}

// RunParallelChecks run all checks for a password string in parallel
func (pwdb *PwdBro) RunParallelChecks(pwd string) ([]*PwdStatus, error) {
	result := make([]*PwdStatus, 0)
	wg := &sync.WaitGroup{}
	mtx := &sync.Mutex{}
	for _, checker := range pwdb.pwdCheckers {
		wg.Add(1)
		go func(c PwdChecker, wg *sync.WaitGroup) {
			status := NewPwdStatus(c.CheckPassword(pwd))
			status.Method = c.MethodName()

			mtx.Lock()
			result = append(result, status)
			mtx.Unlock()
			wg.Done()
		}(checker, wg)
	}
	wg.Wait()
	return result, nil
}
