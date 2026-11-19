package main

const (
	applicationName = "NetWarden"
)

// Release builds override these values with -ldflags. The defaults keep local
// development builds useful without requiring a generated source file.
var (
	applicationVersion = "2.4.0"
	buildVersion       = "v2.4.0"
)
