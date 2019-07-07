// Code generated by moq; DO NOT EDIT.
// github.com/matryer/moq

package mocks

import (
	"github.com/johanbrandhorst/certify"
	"sync"
)

var (
	lockLoggerMockDebug sync.RWMutex
	lockLoggerMockError sync.RWMutex
	lockLoggerMockInfo  sync.RWMutex
	lockLoggerMockTrace sync.RWMutex
	lockLoggerMockWarn  sync.RWMutex
)

// Ensure, that LoggerMock does implement Logger.
// If this is not the case, regenerate this file with moq.
var _ certify.Logger = &LoggerMock{}

// LoggerMock is a mock implementation of Logger.
//
//     func TestSomethingThatUsesLogger(t *testing.T) {
//
//         // make and configure a mocked Logger
//         mockedLogger := &LoggerMock{
//             DebugFunc: func(msg string, fields ...map[string]interface{})  {
// 	               panic("mock out the Debug method")
//             },
//             ErrorFunc: func(msg string, fields ...map[string]interface{})  {
// 	               panic("mock out the Error method")
//             },
//             InfoFunc: func(msg string, fields ...map[string]interface{})  {
// 	               panic("mock out the Info method")
//             },
//             TraceFunc: func(msg string, fields ...map[string]interface{})  {
// 	               panic("mock out the Trace method")
//             },
//             WarnFunc: func(msg string, fields ...map[string]interface{})  {
// 	               panic("mock out the Warn method")
//             },
//         }
//
//         // use mockedLogger in code that requires Logger
//         // and then make assertions.
//
//     }
type LoggerMock struct {
	// DebugFunc mocks the Debug method.
	DebugFunc func(msg string, fields ...map[string]interface{})

	// ErrorFunc mocks the Error method.
	ErrorFunc func(msg string, fields ...map[string]interface{})

	// InfoFunc mocks the Info method.
	InfoFunc func(msg string, fields ...map[string]interface{})

	// TraceFunc mocks the Trace method.
	TraceFunc func(msg string, fields ...map[string]interface{})

	// WarnFunc mocks the Warn method.
	WarnFunc func(msg string, fields ...map[string]interface{})

	// calls tracks calls to the methods.
	calls struct {
		// Debug holds details about calls to the Debug method.
		Debug []struct {
			// Msg is the msg argument value.
			Msg string
			// Fields is the fields argument value.
			Fields []map[string]interface{}
		}
		// Error holds details about calls to the Error method.
		Error []struct {
			// Msg is the msg argument value.
			Msg string
			// Fields is the fields argument value.
			Fields []map[string]interface{}
		}
		// Info holds details about calls to the Info method.
		Info []struct {
			// Msg is the msg argument value.
			Msg string
			// Fields is the fields argument value.
			Fields []map[string]interface{}
		}
		// Trace holds details about calls to the Trace method.
		Trace []struct {
			// Msg is the msg argument value.
			Msg string
			// Fields is the fields argument value.
			Fields []map[string]interface{}
		}
		// Warn holds details about calls to the Warn method.
		Warn []struct {
			// Msg is the msg argument value.
			Msg string
			// Fields is the fields argument value.
			Fields []map[string]interface{}
		}
	}
}

// Debug calls DebugFunc.
func (mock *LoggerMock) Debug(msg string, fields ...map[string]interface{}) {
	if mock.DebugFunc == nil {
		panic("LoggerMock.DebugFunc: method is nil but Logger.Debug was just called")
	}
	callInfo := struct {
		Msg    string
		Fields []map[string]interface{}
	}{
		Msg:    msg,
		Fields: fields,
	}
	lockLoggerMockDebug.Lock()
	mock.calls.Debug = append(mock.calls.Debug, callInfo)
	lockLoggerMockDebug.Unlock()
	mock.DebugFunc(msg, fields...)
}

// DebugCalls gets all the calls that were made to Debug.
// Check the length with:
//     len(mockedLogger.DebugCalls())
func (mock *LoggerMock) DebugCalls() []struct {
	Msg    string
	Fields []map[string]interface{}
} {
	var calls []struct {
		Msg    string
		Fields []map[string]interface{}
	}
	lockLoggerMockDebug.RLock()
	calls = mock.calls.Debug
	lockLoggerMockDebug.RUnlock()
	return calls
}

// Error calls ErrorFunc.
func (mock *LoggerMock) Error(msg string, fields ...map[string]interface{}) {
	if mock.ErrorFunc == nil {
		panic("LoggerMock.ErrorFunc: method is nil but Logger.Error was just called")
	}
	callInfo := struct {
		Msg    string
		Fields []map[string]interface{}
	}{
		Msg:    msg,
		Fields: fields,
	}
	lockLoggerMockError.Lock()
	mock.calls.Error = append(mock.calls.Error, callInfo)
	lockLoggerMockError.Unlock()
	mock.ErrorFunc(msg, fields...)
}

// ErrorCalls gets all the calls that were made to Error.
// Check the length with:
//     len(mockedLogger.ErrorCalls())
func (mock *LoggerMock) ErrorCalls() []struct {
	Msg    string
	Fields []map[string]interface{}
} {
	var calls []struct {
		Msg    string
		Fields []map[string]interface{}
	}
	lockLoggerMockError.RLock()
	calls = mock.calls.Error
	lockLoggerMockError.RUnlock()
	return calls
}

// Info calls InfoFunc.
func (mock *LoggerMock) Info(msg string, fields ...map[string]interface{}) {
	if mock.InfoFunc == nil {
		panic("LoggerMock.InfoFunc: method is nil but Logger.Info was just called")
	}
	callInfo := struct {
		Msg    string
		Fields []map[string]interface{}
	}{
		Msg:    msg,
		Fields: fields,
	}
	lockLoggerMockInfo.Lock()
	mock.calls.Info = append(mock.calls.Info, callInfo)
	lockLoggerMockInfo.Unlock()
	mock.InfoFunc(msg, fields...)
}

// InfoCalls gets all the calls that were made to Info.
// Check the length with:
//     len(mockedLogger.InfoCalls())
func (mock *LoggerMock) InfoCalls() []struct {
	Msg    string
	Fields []map[string]interface{}
} {
	var calls []struct {
		Msg    string
		Fields []map[string]interface{}
	}
	lockLoggerMockInfo.RLock()
	calls = mock.calls.Info
	lockLoggerMockInfo.RUnlock()
	return calls
}

// Trace calls TraceFunc.
func (mock *LoggerMock) Trace(msg string, fields ...map[string]interface{}) {
	if mock.TraceFunc == nil {
		panic("LoggerMock.TraceFunc: method is nil but Logger.Trace was just called")
	}
	callInfo := struct {
		Msg    string
		Fields []map[string]interface{}
	}{
		Msg:    msg,
		Fields: fields,
	}
	lockLoggerMockTrace.Lock()
	mock.calls.Trace = append(mock.calls.Trace, callInfo)
	lockLoggerMockTrace.Unlock()
	mock.TraceFunc(msg, fields...)
}

// TraceCalls gets all the calls that were made to Trace.
// Check the length with:
//     len(mockedLogger.TraceCalls())
func (mock *LoggerMock) TraceCalls() []struct {
	Msg    string
	Fields []map[string]interface{}
} {
	var calls []struct {
		Msg    string
		Fields []map[string]interface{}
	}
	lockLoggerMockTrace.RLock()
	calls = mock.calls.Trace
	lockLoggerMockTrace.RUnlock()
	return calls
}

// Warn calls WarnFunc.
func (mock *LoggerMock) Warn(msg string, fields ...map[string]interface{}) {
	if mock.WarnFunc == nil {
		panic("LoggerMock.WarnFunc: method is nil but Logger.Warn was just called")
	}
	callInfo := struct {
		Msg    string
		Fields []map[string]interface{}
	}{
		Msg:    msg,
		Fields: fields,
	}
	lockLoggerMockWarn.Lock()
	mock.calls.Warn = append(mock.calls.Warn, callInfo)
	lockLoggerMockWarn.Unlock()
	mock.WarnFunc(msg, fields...)
}

// WarnCalls gets all the calls that were made to Warn.
// Check the length with:
//     len(mockedLogger.WarnCalls())
func (mock *LoggerMock) WarnCalls() []struct {
	Msg    string
	Fields []map[string]interface{}
} {
	var calls []struct {
		Msg    string
		Fields []map[string]interface{}
	}
	lockLoggerMockWarn.RLock()
	calls = mock.calls.Warn
	lockLoggerMockWarn.RUnlock()
	return calls
}
