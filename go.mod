module github.com/sbezverk/srpolicy-injector

go 1.15

replace github.com/osrg/gobgp => ../gobgp

require (
	github.com/golang/protobuf v1.4.3
	github.com/osrg/gobgp v0.0.0-00010101000000-000000000000
	google.golang.org/grpc v1.33.2
)
