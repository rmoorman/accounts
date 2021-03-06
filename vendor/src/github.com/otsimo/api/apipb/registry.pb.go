// Code generated by protoc-gen-gogo.
// source: registry.proto
// DO NOT EDIT!

package apipb

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

import (
	context "golang.org/x/net/context"
	grpc "google.golang.org/grpc"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// Client API for RegistryService service

type RegistryServiceClient interface {
	// Publish tries to create a new GameRelease by given manifest
	Publish(ctx context.Context, in *GameManifest, opts ...grpc.CallOption) (*PublishResponse, error)
	// ChangeReleaseState changes state of a release, If user is admin than s/he can change
	// from WAITING to REJECTED or VALIDATED, developers can change to any except VALIDATED
	ChangeReleaseState(ctx context.Context, in *ValidateRequest, opts ...grpc.CallOption) (*Response, error)
	// GetLatestVersions retusn latest versions of given game ids
	GetLatestVersions(ctx context.Context, in *GetLatestVersionsRequest, opts ...grpc.CallOption) (*GameVersionsResponse, error)
	// GetLatestVersionsStream returns versions of given game ids by steam
	GetLatestVersionsStream(ctx context.Context, in *GetLatestVersionsRequest, opts ...grpc.CallOption) (RegistryService_GetLatestVersionsStreamClient, error)
	// Search does search
	Search(ctx context.Context, in *SearchRequest, opts ...grpc.CallOption) (*SearchResponse, error)
}

type registryServiceClient struct {
	cc *grpc.ClientConn
}

func NewRegistryServiceClient(cc *grpc.ClientConn) RegistryServiceClient {
	return &registryServiceClient{cc}
}

func (c *registryServiceClient) Publish(ctx context.Context, in *GameManifest, opts ...grpc.CallOption) (*PublishResponse, error) {
	out := new(PublishResponse)
	err := grpc.Invoke(ctx, "/apipb.RegistryService/Publish", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *registryServiceClient) ChangeReleaseState(ctx context.Context, in *ValidateRequest, opts ...grpc.CallOption) (*Response, error) {
	out := new(Response)
	err := grpc.Invoke(ctx, "/apipb.RegistryService/ChangeReleaseState", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *registryServiceClient) GetLatestVersions(ctx context.Context, in *GetLatestVersionsRequest, opts ...grpc.CallOption) (*GameVersionsResponse, error) {
	out := new(GameVersionsResponse)
	err := grpc.Invoke(ctx, "/apipb.RegistryService/GetLatestVersions", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *registryServiceClient) GetLatestVersionsStream(ctx context.Context, in *GetLatestVersionsRequest, opts ...grpc.CallOption) (RegistryService_GetLatestVersionsStreamClient, error) {
	stream, err := grpc.NewClientStream(ctx, &_RegistryService_serviceDesc.Streams[0], c.cc, "/apipb.RegistryService/GetLatestVersionsStream", opts...)
	if err != nil {
		return nil, err
	}
	x := &registryServiceGetLatestVersionsStreamClient{stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type RegistryService_GetLatestVersionsStreamClient interface {
	Recv() (*GameAndVersion, error)
	grpc.ClientStream
}

type registryServiceGetLatestVersionsStreamClient struct {
	grpc.ClientStream
}

func (x *registryServiceGetLatestVersionsStreamClient) Recv() (*GameAndVersion, error) {
	m := new(GameAndVersion)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *registryServiceClient) Search(ctx context.Context, in *SearchRequest, opts ...grpc.CallOption) (*SearchResponse, error) {
	out := new(SearchResponse)
	err := grpc.Invoke(ctx, "/apipb.RegistryService/Search", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Server API for RegistryService service

type RegistryServiceServer interface {
	// Publish tries to create a new GameRelease by given manifest
	Publish(context.Context, *GameManifest) (*PublishResponse, error)
	// ChangeReleaseState changes state of a release, If user is admin than s/he can change
	// from WAITING to REJECTED or VALIDATED, developers can change to any except VALIDATED
	ChangeReleaseState(context.Context, *ValidateRequest) (*Response, error)
	// GetLatestVersions retusn latest versions of given game ids
	GetLatestVersions(context.Context, *GetLatestVersionsRequest) (*GameVersionsResponse, error)
	// GetLatestVersionsStream returns versions of given game ids by steam
	GetLatestVersionsStream(*GetLatestVersionsRequest, RegistryService_GetLatestVersionsStreamServer) error
	// Search does search
	Search(context.Context, *SearchRequest) (*SearchResponse, error)
}

func RegisterRegistryServiceServer(s *grpc.Server, srv RegistryServiceServer) {
	s.RegisterService(&_RegistryService_serviceDesc, srv)
}

func _RegistryService_Publish_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error) (interface{}, error) {
	in := new(GameManifest)
	if err := dec(in); err != nil {
		return nil, err
	}
	out, err := srv.(RegistryServiceServer).Publish(ctx, in)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func _RegistryService_ChangeReleaseState_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error) (interface{}, error) {
	in := new(ValidateRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	out, err := srv.(RegistryServiceServer).ChangeReleaseState(ctx, in)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func _RegistryService_GetLatestVersions_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error) (interface{}, error) {
	in := new(GetLatestVersionsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	out, err := srv.(RegistryServiceServer).GetLatestVersions(ctx, in)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func _RegistryService_GetLatestVersionsStream_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(GetLatestVersionsRequest)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(RegistryServiceServer).GetLatestVersionsStream(m, &registryServiceGetLatestVersionsStreamServer{stream})
}

type RegistryService_GetLatestVersionsStreamServer interface {
	Send(*GameAndVersion) error
	grpc.ServerStream
}

type registryServiceGetLatestVersionsStreamServer struct {
	grpc.ServerStream
}

func (x *registryServiceGetLatestVersionsStreamServer) Send(m *GameAndVersion) error {
	return x.ServerStream.SendMsg(m)
}

func _RegistryService_Search_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error) (interface{}, error) {
	in := new(SearchRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	out, err := srv.(RegistryServiceServer).Search(ctx, in)
	if err != nil {
		return nil, err
	}
	return out, nil
}

var _RegistryService_serviceDesc = grpc.ServiceDesc{
	ServiceName: "apipb.RegistryService",
	HandlerType: (*RegistryServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Publish",
			Handler:    _RegistryService_Publish_Handler,
		},
		{
			MethodName: "ChangeReleaseState",
			Handler:    _RegistryService_ChangeReleaseState_Handler,
		},
		{
			MethodName: "GetLatestVersions",
			Handler:    _RegistryService_GetLatestVersions_Handler,
		},
		{
			MethodName: "Search",
			Handler:    _RegistryService_Search_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "GetLatestVersionsStream",
			Handler:       _RegistryService_GetLatestVersionsStream_Handler,
			ServerStreams: true,
		},
	},
}
