module github.com/sbezverk/srpolicy-injector

go 1.15

require (
	github.com/golang/protobuf v1.4.3
	github.com/osrg/gobgp v0.0.0-20201125222948-c5dcfb72a847
	github.com/sbezverk/gobgptoolbox v0.0.0-20201126160106-069765be96a1
	google.golang.org/grpc v1.33.2
	google.golang.org/protobuf v1.25.0
)

replace github.com/osrg/gobgp => ../gobgp
