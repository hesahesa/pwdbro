// Code generated by mockery v1.0.0. DO NOT EDIT.

package mocks

import mock "github.com/stretchr/testify/mock"

// PwdChecker is an autogenerated mock type for the PwdChecker type
type PwdChecker struct {
	mock.Mock
}

// CheckPassword provides a mock function with given fields: _a0
func (_m *PwdChecker) CheckPassword(_a0 string) (bool, string, error) {
	ret := _m.Called(_a0)

	var r0 bool
	if rf, ok := ret.Get(0).(func(string) bool); ok {
		r0 = rf(_a0)
	} else {
		r0 = ret.Get(0).(bool)
	}

	var r1 string
	if rf, ok := ret.Get(1).(func(string) string); ok {
		r1 = rf(_a0)
	} else {
		r1 = ret.Get(1).(string)
	}

	var r2 error
	if rf, ok := ret.Get(2).(func(string) error); ok {
		r2 = rf(_a0)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// MethodName provides a mock function with given fields:
func (_m *PwdChecker) MethodName() string {
	ret := _m.Called()

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}
