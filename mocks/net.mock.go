package mocks

import (
	"net"
	"time"
)

type ConnMock struct {
	Remote net.Addr
}

func (c ConnMock) Read(b []byte) (n int, err error) {
	panic("not implemented")
}

func (c ConnMock) Write(b []byte) (n int, err error) {
	panic("not implemented")
}

func (c ConnMock) Close() error {
	panic("not implemented")
}

func (c ConnMock) LocalAddr() net.Addr {
	panic("not implemented")
}

func (c ConnMock) RemoteAddr() net.Addr {
	return c.Remote
}

func (c ConnMock) SetDeadline(t time.Time) error {
	panic("not implemented")
}

func (c ConnMock) SetReadDeadline(t time.Time) error {
	panic("not implemented")
}

func (c *ConnMock) SetWriteDeadline(t time.Time) error {
	panic("not implemented")
}

type AddrMock struct {
	S string
}

func (a AddrMock) Network() string {
	panic("not implemented")
}

func (a AddrMock) String() string {
	return a.S
}
