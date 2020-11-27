package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"

	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/any"
	api "github.com/osrg/gobgp/api"
	toolbox "github.com/sbezverk/gobgptoolbox"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/anypb"
)

func AddSRPolicy(client api.GobgpApiClient) error {

	nlrisr, _ := ptypes.MarshalAny(&api.SRPolicyNLRI{
		Length:        96,
		Distinguisher: 2,
		Color:         99,
		Endpoint:      net.ParseIP("10.0.0.15").To4(),
	})
	// Origin attribute
	origin, _ := ptypes.MarshalAny(&api.OriginAttribute{
		Origin: 0,
	})
	// Next hop attribute
	nh, _ := ptypes.MarshalAny(&api.NextHopAttribute{
		NextHop: net.ParseIP("192.168.20.1").To4().String(),
	})
	// Extended communities attribute
	toolbox.MarshalRTFromString("")
	rtm, err := toolbox.MarshalRTFromString("10.0.0.8:0")
	if err != nil {
		return err
	}
	rt, _ := ptypes.MarshalAny(&api.ExtendedCommunitiesAttribute{
		Communities: []*any.Any{rtm},
	})
	sid := make([]byte, 4)
	binary.BigEndian.PutUint32(sid, 24321)
	bsid, err := ptypes.MarshalAny(&api.SRBindingSID{
		Flags: 0,
		Sid:   sid,
	})
	if err != nil {
		return err
	}
	segment, err := ptypes.MarshalAny(&api.SegmentTypeA{
		Flags: &api.SegmentFlags{
			SFlag: true,
		},
		Label: 10203,
	})
	if err != nil {
		return err
	}
	tunTlvs, err := ptypes.MarshalAny(&api.TunnelEncapSubTLVSRPolicy{
		Bsid:              bsid,
		CandidatePathName: "CandidatePathName",
		Priority:          10,
		Enlp: &api.TunnelEncapSubTLVSRENLP{
			Flags: 0,
			Enlp:  api.ENLPType_Type4,
		},
		Preference: &api.TunnelEncapSubTLVSRPreference{
			Flags:      0,
			Preference: 11,
		},
		SegmentList: []*api.SegmentList{
			{
				Weight: &api.SRWeight{
					Flags:  0,
					Weight: 12,
				},
				Segments: []*any.Any{segment},
			},
		},
	})
	if err != nil {
		return err
	}
	// Tunnel Encapsulation attribute for SR Policy
	tun, err := ptypes.MarshalAny(&api.TunnelEncapAttribute{
		Tlvs: []*api.TunnelEncapTLV{
			{
				Type: 15,
				Tlvs: []*anypb.Any{tunTlvs},
			},
		},
	})
	if err != nil {
		return err
	}
	attrs := []*any.Any{origin, nh, rt, tun}
	if _, err := client.AddPath(context.TODO(), &api.AddPathRequest{
		TableType: api.TableType_GLOBAL,
		Path: &api.Path{
			Nlri:      nlrisr,
			Pattrs:    attrs,
			Family:    &api.Family{Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_SR_POLICY},
			Best:      true,
			SourceAsn: 65000,
		},
	}); err != nil {
		return fmt.Errorf("failed to run AddPath call with error: %v", err)
	}

	return nil
}

func main() {
	conn, err := grpc.DialContext(context.TODO(), "192.168.20.201:50051", grpc.WithInsecure())
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

	if err := AddSRPolicy(client); err != nil {
		fmt.Printf("fail to add SR policy to gobgp with error: %+v\n", err)
		os.Exit(1)
	}
}
