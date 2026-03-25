// Code generated manually. Based on service.TokenIssuer interface.
package mocks

import (
	"reflect"
	"time"

	domain "github.com/sweeney/identity/internal/domain"
	gomock "go.uber.org/mock/gomock"
)

// MockTokenIssuer is a mock of service.TokenIssuer interface.
type MockTokenIssuer struct {
	ctrl     *gomock.Controller
	recorder *MockTokenIssuerMockRecorder
	isgomock struct{}
}

// MockTokenIssuerMockRecorder is the mock recorder for MockTokenIssuer.
type MockTokenIssuerMockRecorder struct {
	mock *MockTokenIssuer
}

// NewMockTokenIssuer creates a new mock instance.
func NewMockTokenIssuer(ctrl *gomock.Controller) *MockTokenIssuer {
	mock := &MockTokenIssuer{ctrl: ctrl}
	mock.recorder = &MockTokenIssuerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockTokenIssuer) EXPECT() *MockTokenIssuerMockRecorder {
	return m.recorder
}

// MintServiceToken mocks base method.
func (m *MockTokenIssuer) MintServiceToken(claims domain.ServiceTokenClaims, ttl time.Duration) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "MintServiceToken", claims, ttl)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// MintServiceToken indicates an expected call of MintServiceToken.
func (mr *MockTokenIssuerMockRecorder) MintServiceToken(claims, ttl any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "MintServiceToken", reflect.TypeOf((*MockTokenIssuer)(nil).MintServiceToken), claims, ttl)
}
