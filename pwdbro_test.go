package pwdbro_test

import (
	"testing"

	"github.com/hesahesa/pwdbro"
	"github.com/hesahesa/pwdbro/mocks"
	"github.com/stretchr/testify/assert"
)

func TestRunChecks(t *testing.T) {
	pwdbro := pwdbro.NewEmptyPwdBro()

	checker := new(mocks.PwdChecker)
	checker.On("CheckPassword", "password").Return(true, "", nil)
	checker.On("MethodName").Return("mock checker")

	pwdbro.AddChecker(checker)

	status, _ := pwdbro.RunChecks("password")
	assert.True(t, status[0].Safe)
}

func TestRunParallelChecks(t *testing.T) {
	pwdbro := pwdbro.NewEmptyPwdBro()

	checker := new(mocks.PwdChecker)
	checker.On("CheckPassword", "password").Return(true, "", nil)
	checker.On("MethodName").Return("mock checker")

	pwdbro.AddChecker(checker)

	status, _ := pwdbro.RunParallelChecks("password")
	assert.True(t, status[0].Safe)
}
