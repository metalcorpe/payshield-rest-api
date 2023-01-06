package rpc

import (
	"context"

	"github.com/metalcorpe/payshield-rest-gopher/controllers"
	"github.com/metalcorpe/payshield-rest-gopher/interfaces"
	"github.com/metalcorpe/payshield-rest-gopher/models"
	pb "github.com/metalcorpe/payshield-rest-gopher/protobuf"
	"github.com/mitchellh/mapstructure"
)

type HsmRpcController struct {
	interfaces.IHsmService
	pb.UnimplementedHSMServer
}

func (controller *HsmRpcController) VerifyPin(ctx context.Context, in *pb.PinVer) (*pb.PinVer, error) {
	//	var p models.PinVer
	//	nil := controller.NewVerifyPinResponse(p)
	return &pb.PinVer{}, nil
}
func (controller *HsmRpcController) Version(ctx context.Context, in *pb.Diagnostics) (*pb.DiagnosticsRes, error) {
	//	var p models.Diagnostics
	//	resp, nil := controller.NewVersionResponse(p)
	return &pb.DiagnosticsRes{}, nil
}
func (controller *HsmRpcController) Migrate(ctx context.Context, in *pb.MigrateReq) (*pb.MigrateRes, error) {
	//	var p models.Migrate
	//	resp, nil := controller.NewMigrateResponse(p)
	return &pb.MigrateRes{}, nil
}
func (controller *HsmRpcController) MigratePrivate(ctx context.Context, in *pb.TranslatePrivate) (*pb.TranslatePrivateResp, error) {
	//	var p models.TranslatePrivate
	//	resp, nil := controller.NewMigratePrivateResponse(p)
	return &pb.TranslatePrivateResp{}, nil
}
func (controller *HsmRpcController) Generatekey(ctx context.Context, in *pb.GenerateKey) (*pb.GenerateKeyResp, error) {
	var p models.GenerateKey
	err := mapstructure.Decode(in, &p)
	if err != nil {
		panic(err)
	}
	resp, err := controller.NewGenerateKeyResponse(p)
	if err != nil {
		return &pb.GenerateKeyResp{}, controllers.ErrRenderGrpc(err)
	}
	var p2 pb.GenerateKeyResp
	err = mapstructure.Decode(resp, &p2)
	if err != nil {
		panic(err)
	}
	return &p2, err
}
func (controller *HsmRpcController) ExportKey(ctx context.Context, in *pb.ExportKeyReq) (*pb.ExportKeyResp, error) {
	//	var p models.ExportKey
	//	resp, nil := controller.NewExportKeyResponse(p)
	return &pb.ExportKeyResp{}, nil
}
func (controller *HsmRpcController) GenerateKeyPair(ctx context.Context, in *pb.GeneratePair) (*pb.GeneratePairResp, error) {
	//	var p models.GeneratePair
	//	resp, nil := controller.NewGenerateKeyPairResponse(p)
	return &pb.GeneratePairResp{}, nil
}
func (controller *HsmRpcController) ImportKeyRSA(ctx context.Context, in *pb.ImportKeyOrDataUnderRSAPubKey) (*pb.ImportKeyOrDataUnderRSAPubKeyResp, error) {
	//	var p models.ImportKeyOrDataUnderRSAPubKey
	//	resp, nil := controller.ImportKeyRSAResponse(p)
	return &pb.ImportKeyOrDataUnderRSAPubKeyResp{}, nil
}
