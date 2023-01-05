// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.2.0
// - protoc             v3.21.12
// source: protobuf/payshield.proto

package protobuf

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

// HSMClient is the client API for HSM service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type HSMClient interface {
	// Sends a greeting
	VerifyPin(ctx context.Context, in *PinVer, opts ...grpc.CallOption) (*PinVer, error)
	Version(ctx context.Context, in *Diagnostics, opts ...grpc.CallOption) (*DiagnosticsRes, error)
	Migrate(ctx context.Context, in *MigrateReq, opts ...grpc.CallOption) (*MigrateRes, error)
	MigratePrivate(ctx context.Context, in *TranslatePrivate, opts ...grpc.CallOption) (*TranslatePrivateResp, error)
	Generatekey(ctx context.Context, in *GenerateKey, opts ...grpc.CallOption) (*GenerateKeyResp, error)
	ExportKey(ctx context.Context, in *ExportKeyReq, opts ...grpc.CallOption) (*ExportKeyResp, error)
	GenerateKeyPair(ctx context.Context, in *GeneratePair, opts ...grpc.CallOption) (*GeneratePairResp, error)
	ImportKeyRSA(ctx context.Context, in *ImportKeyOrDataUnderRSAPubKey, opts ...grpc.CallOption) (*ImportKeyOrDataUnderRSAPubKeyResp, error)
}

type hSMClient struct {
	cc grpc.ClientConnInterface
}

func NewHSMClient(cc grpc.ClientConnInterface) HSMClient {
	return &hSMClient{cc}
}

func (c *hSMClient) VerifyPin(ctx context.Context, in *PinVer, opts ...grpc.CallOption) (*PinVer, error) {
	out := new(PinVer)
	err := c.cc.Invoke(ctx, "/protobuf.HSM/VerifyPin", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *hSMClient) Version(ctx context.Context, in *Diagnostics, opts ...grpc.CallOption) (*DiagnosticsRes, error) {
	out := new(DiagnosticsRes)
	err := c.cc.Invoke(ctx, "/protobuf.HSM/Version", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *hSMClient) Migrate(ctx context.Context, in *MigrateReq, opts ...grpc.CallOption) (*MigrateRes, error) {
	out := new(MigrateRes)
	err := c.cc.Invoke(ctx, "/protobuf.HSM/Migrate", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *hSMClient) MigratePrivate(ctx context.Context, in *TranslatePrivate, opts ...grpc.CallOption) (*TranslatePrivateResp, error) {
	out := new(TranslatePrivateResp)
	err := c.cc.Invoke(ctx, "/protobuf.HSM/MigratePrivate", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *hSMClient) Generatekey(ctx context.Context, in *GenerateKey, opts ...grpc.CallOption) (*GenerateKeyResp, error) {
	out := new(GenerateKeyResp)
	err := c.cc.Invoke(ctx, "/protobuf.HSM/Generatekey", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *hSMClient) ExportKey(ctx context.Context, in *ExportKeyReq, opts ...grpc.CallOption) (*ExportKeyResp, error) {
	out := new(ExportKeyResp)
	err := c.cc.Invoke(ctx, "/protobuf.HSM/ExportKey", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *hSMClient) GenerateKeyPair(ctx context.Context, in *GeneratePair, opts ...grpc.CallOption) (*GeneratePairResp, error) {
	out := new(GeneratePairResp)
	err := c.cc.Invoke(ctx, "/protobuf.HSM/GenerateKeyPair", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *hSMClient) ImportKeyRSA(ctx context.Context, in *ImportKeyOrDataUnderRSAPubKey, opts ...grpc.CallOption) (*ImportKeyOrDataUnderRSAPubKeyResp, error) {
	out := new(ImportKeyOrDataUnderRSAPubKeyResp)
	err := c.cc.Invoke(ctx, "/protobuf.HSM/ImportKeyRSA", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// HSMServer is the server API for HSM service.
// All implementations must embed UnimplementedHSMServer
// for forward compatibility
type HSMServer interface {
	// Sends a greeting
	VerifyPin(context.Context, *PinVer) (*PinVer, error)
	Version(context.Context, *Diagnostics) (*DiagnosticsRes, error)
	Migrate(context.Context, *MigrateReq) (*MigrateRes, error)
	MigratePrivate(context.Context, *TranslatePrivate) (*TranslatePrivateResp, error)
	Generatekey(context.Context, *GenerateKey) (*GenerateKeyResp, error)
	ExportKey(context.Context, *ExportKeyReq) (*ExportKeyResp, error)
	GenerateKeyPair(context.Context, *GeneratePair) (*GeneratePairResp, error)
	ImportKeyRSA(context.Context, *ImportKeyOrDataUnderRSAPubKey) (*ImportKeyOrDataUnderRSAPubKeyResp, error)
	mustEmbedUnimplementedHSMServer()
}

// UnimplementedHSMServer must be embedded to have forward compatible implementations.
type UnimplementedHSMServer struct {
}

func (UnimplementedHSMServer) VerifyPin(context.Context, *PinVer) (*PinVer, error) {
	return nil, status.Errorf(codes.Unimplemented, "method VerifyPin not implemented")
}
func (UnimplementedHSMServer) Version(context.Context, *Diagnostics) (*DiagnosticsRes, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Version not implemented")
}
func (UnimplementedHSMServer) Migrate(context.Context, *MigrateReq) (*MigrateRes, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Migrate not implemented")
}
func (UnimplementedHSMServer) MigratePrivate(context.Context, *TranslatePrivate) (*TranslatePrivateResp, error) {
	return nil, status.Errorf(codes.Unimplemented, "method MigratePrivate not implemented")
}
func (UnimplementedHSMServer) Generatekey(context.Context, *GenerateKey) (*GenerateKeyResp, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Generatekey not implemented")
}
func (UnimplementedHSMServer) ExportKey(context.Context, *ExportKeyReq) (*ExportKeyResp, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ExportKey not implemented")
}
func (UnimplementedHSMServer) GenerateKeyPair(context.Context, *GeneratePair) (*GeneratePairResp, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GenerateKeyPair not implemented")
}
func (UnimplementedHSMServer) ImportKeyRSA(context.Context, *ImportKeyOrDataUnderRSAPubKey) (*ImportKeyOrDataUnderRSAPubKeyResp, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ImportKeyRSA not implemented")
}
func (UnimplementedHSMServer) mustEmbedUnimplementedHSMServer() {}

// UnsafeHSMServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to HSMServer will
// result in compilation errors.
type UnsafeHSMServer interface {
	mustEmbedUnimplementedHSMServer()
}

func RegisterHSMServer(s grpc.ServiceRegistrar, srv HSMServer) {
	s.RegisterService(&HSM_ServiceDesc, srv)
}

func _HSM_VerifyPin_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(PinVer)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(HSMServer).VerifyPin(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/protobuf.HSM/VerifyPin",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(HSMServer).VerifyPin(ctx, req.(*PinVer))
	}
	return interceptor(ctx, in, info, handler)
}

func _HSM_Version_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Diagnostics)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(HSMServer).Version(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/protobuf.HSM/Version",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(HSMServer).Version(ctx, req.(*Diagnostics))
	}
	return interceptor(ctx, in, info, handler)
}

func _HSM_Migrate_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(MigrateReq)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(HSMServer).Migrate(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/protobuf.HSM/Migrate",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(HSMServer).Migrate(ctx, req.(*MigrateReq))
	}
	return interceptor(ctx, in, info, handler)
}

func _HSM_MigratePrivate_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(TranslatePrivate)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(HSMServer).MigratePrivate(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/protobuf.HSM/MigratePrivate",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(HSMServer).MigratePrivate(ctx, req.(*TranslatePrivate))
	}
	return interceptor(ctx, in, info, handler)
}

func _HSM_Generatekey_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GenerateKey)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(HSMServer).Generatekey(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/protobuf.HSM/Generatekey",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(HSMServer).Generatekey(ctx, req.(*GenerateKey))
	}
	return interceptor(ctx, in, info, handler)
}

func _HSM_ExportKey_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ExportKeyReq)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(HSMServer).ExportKey(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/protobuf.HSM/ExportKey",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(HSMServer).ExportKey(ctx, req.(*ExportKeyReq))
	}
	return interceptor(ctx, in, info, handler)
}

func _HSM_GenerateKeyPair_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GeneratePair)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(HSMServer).GenerateKeyPair(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/protobuf.HSM/GenerateKeyPair",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(HSMServer).GenerateKeyPair(ctx, req.(*GeneratePair))
	}
	return interceptor(ctx, in, info, handler)
}

func _HSM_ImportKeyRSA_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ImportKeyOrDataUnderRSAPubKey)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(HSMServer).ImportKeyRSA(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/protobuf.HSM/ImportKeyRSA",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(HSMServer).ImportKeyRSA(ctx, req.(*ImportKeyOrDataUnderRSAPubKey))
	}
	return interceptor(ctx, in, info, handler)
}

// HSM_ServiceDesc is the grpc.ServiceDesc for HSM service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var HSM_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "protobuf.HSM",
	HandlerType: (*HSMServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "VerifyPin",
			Handler:    _HSM_VerifyPin_Handler,
		},
		{
			MethodName: "Version",
			Handler:    _HSM_Version_Handler,
		},
		{
			MethodName: "Migrate",
			Handler:    _HSM_Migrate_Handler,
		},
		{
			MethodName: "MigratePrivate",
			Handler:    _HSM_MigratePrivate_Handler,
		},
		{
			MethodName: "Generatekey",
			Handler:    _HSM_Generatekey_Handler,
		},
		{
			MethodName: "ExportKey",
			Handler:    _HSM_ExportKey_Handler,
		},
		{
			MethodName: "GenerateKeyPair",
			Handler:    _HSM_GenerateKeyPair_Handler,
		},
		{
			MethodName: "ImportKeyRSA",
			Handler:    _HSM_ImportKeyRSA_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "protobuf/payshield.proto",
}