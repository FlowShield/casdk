package main

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"flag"
	"fmt"
	"github.com/cloudslit/casdk/caclient"
	"github.com/cloudslit/cfssl/hook"
	"os"

	"github.com/cloudslit/casdk/keygen"
	"github.com/cloudslit/casdk/pkg/logger"
	"github.com/cloudslit/casdk/pkg/spiffe"
	"go.uber.org/zap/zapcore"
)

var (
	caAddr   = flag.String("ca", "https://127.0.0.1:8081", "CA Server")
	ocspAddr = flag.String("ocsp", "http://127.0.0.1:8082", "Ocsp Server")
	authKey  = flag.String("auth-key", "0739a645a7d6601d9d45f6b237c4edeadad904f2fce53625dfdd541ec4fc8134", "Auth Key")
	//authKey  = flag.String("auth-key", "f02904181c52a887263723e8deddcad6fc402e2dbcf7440e2936908fbc004f12", "Auth Key")
)

func init() {
	_ = logger.GlobalConfig(logger.Conf{
		Debug: true,
		Level: zapcore.DebugLevel,
	})
}

func main() {
	flag.Parse()
	err := NewIDGRegistry()
	if err != nil {
		fmt.Fprint(os.Stderr, err)
		os.Exit(1)
	}
}

// NewIDGRegistry 注册中心测试示例
func NewIDGRegistry() error {
	cai := caclient.NewCAI(
		caclient.WithCAServer(caclient.RoleDefault, *caAddr),
		caclient.WithAuthKey(*authKey),
	)
	cm, err := cai.NewCertManager()
	if err != nil {
		logger.Errorf("cert manager 创建错误: %s", err)
		return err
	}
	caPEMBytes, err := cm.CACertsPEM()
	if err != nil {
		logger.Errorf("mgr.CACertsPEM() err : %v", err)
		return err
	}
	logger.Info("根证书:\n", string(caPEMBytes))

	_, keyPEM, _ := keygen.GenKey(keygen.EcdsaSigAlg)
	logger.Info("生成私钥:\n", string(keyPEM))

	csrBytes, err := keygen.GenCustomExtendCSR(keyPEM, &spiffe.IDGIdentity{
		SiteID:    "test_site",
		ClusterID: "test_cluster",
		UniqueID:  "idg_registy_0001",
	}, &keygen.CertOptions{
		CN: "test",
	}, []pkix.Extension{
		{
			Id:       asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6, 7, 8, 1},
			Critical: true,
			Value:    []byte("fake data"),
		},
		{
			Id:       asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6, 7, 8, 2},
			Critical: true,
			Value:    []byte("fake data"),
		},
	})
	if err != nil {
		return err
	}
	//logger.Infof("生成自定义 CSR: \n%s", string(csrBytes))

	// 申请证书
	certBytes, err := cm.SignPEM(csrBytes, map[string]interface{}{
		hook.MetadataUniqueID: "test_111",
	})
	if err != nil {
		logger.Errorf("申请证书失败: %s", err)
		return err
	}

	logger.Infof("从 CA 申请证书: \n%s", string(certBytes))

	// 验证证书
	if err := cm.VerifyCertDefaultIssuer(certBytes); err != nil {
		logger.Errorf("验证证书失败: %s", err)
		return err
	}
	logger.Infof("验证证书成功, 证书有效")

	//// 吊销证书
	//if err := cm.RevokeIDGRegistryCert(certBytes); err != nil {
	//	logger.Errorf("吊销证书失败: %s", err)
	//	return err
	//}
	//logger.Infof("吊销证书成功")

	return nil
}
