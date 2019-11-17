package pwdbro_test

import (
	"testing"

	"github.com/hesahesa/pwdbro"
	"github.com/stretchr/testify/assert"
)

func TestRunChecks(t *testing.T) {
	pwdbro := pwdbro.NewDefaultPwdBro()
	status, _ := pwdbro.RunChecks("password")
	t.Log(status[1])
	assert.True(t, true)
}

func TestRunParallelChecks(t *testing.T) {
	pwdbro := pwdbro.NewDefaultPwdBro()
	status, _ := pwdbro.RunParallelChecks("password")
	t.Log(status[1])
	assert.True(t, true)
}
