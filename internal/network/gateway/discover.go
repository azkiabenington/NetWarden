// Package gateway discovers the operating system's default IPv4 route.
package gateway

import (
	"context"
	"errors"
	"net/netip"
)

var (
	ErrNoDefaultRoute = errors.New("no default IPv4 route")
	ErrRouteQuery     = errors.New("default route query failed")
)

type Route struct {
	GatewayIP   netip.Addr
	InterfaceIP netip.Addr
}

type Discoverer interface {
	Discover(context.Context) (Route, error)
}

type SystemDiscoverer struct{}

func (SystemDiscoverer) Discover(ctx context.Context) (Route, error) {
	if err := ctx.Err(); err != nil {
		return Route{}, err
	}
	return discoverSystemRoute(ctx)
}
