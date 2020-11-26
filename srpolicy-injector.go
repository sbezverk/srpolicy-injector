package main

import (
	"context"
	"fmt"
	"net"
	"os"

	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/any"
	api "github.com/osrg/gobgp/api"
	"google.golang.org/grpc"
)

func AddSRPolicy() error {
	if p == nil {
		return fmt.Errorf("prefix is nil")
	}

	nlrivpn, _ := ptypes.MarshalAny(&api.LabeledVPNIPAddressPrefix{
		Labels:    []uint32{uint32(p.Label)},
		Rd:        p.Rd,
		PrefixLen: p.Prefix.MaskLength,
		Prefix:    net.IP(p.Prefix.Address).To4().String(),
	})
	// Origin attribute
	origin, _ := ptypes.MarshalAny(&api.OriginAttribute{
		Origin: 0,
	})
	// Next hop attribute
	nh, _ := ptypes.MarshalAny(&api.NextHopAttribute{
		NextHop: net.IP(p.NhAddress).To16().String(),
	})
	// Extended communities attribute
	rt, _ := ptypes.MarshalAny(&api.ExtendedCommunitiesAttribute{
		Communities: p.Rt,
	})
	// Inject Prefix SID attribute
	prefixSID, _ := ptypes.MarshalAny(&api.PrefixSID{
		Tlvs: p.PrefixSid.Tlvs,
	})
	attrs := []*any.Any{origin, nh, rt, prefixSID}
	if _, err := bgp.client.AddPath(context.TODO(), &api.AddPathRequest{
		TableType: api.TableType_GLOBAL,
		Path: &api.Path{
			Nlri:      nlrivpn,
			Pattrs:    attrs,
			Family:    &api.Family{Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_MPLS_VPN},
			Best:      true,
			SourceAsn: p.Asn,
		},
	}); err != nil {
		return fmt.Errorf("failed to run AddPath call with error: %v", err)
	}

	return nil
}

func main() {
	conn, err := grpc.DialContext(context.TODO(), "192.168.20.201:40404", grpc.WithInsecure())
	if err != nil {
		fmt.Printf("fail to connect to gobgp with error: %+v\n", err)
		os.Exit(1)
	}
	client := api.NewGobgpApiClient(conn)
	// Testing connection to gobgp by requesting its global config
	if _, err := client.GetBgp(context.TODO(), &api.GetBgpRequest{}); err != nil {
		fmt.Printf("fail to get gobgp info with error: %+v\n", err)
		os.Exit(1)
	}

	if err := AddSRPolicy(); err != nil {
		fmt.Printf("fail to add SR policy to gobgp with error: %+v\n", err)
		os.Exit(1)
	}
}
