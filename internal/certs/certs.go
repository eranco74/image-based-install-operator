package certs

import (
	"crypto/x509/pkix"
	"fmt"
	"github.com/openshift/library-go/pkg/crypto"
	"github.com/pkg/errors"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"path/filepath"
	"time"
)

type CertManager struct {
	CertificatesDir string
	userCert        []byte
	userKey         []byte
	caBundle        []byte
}
type CertInfo struct {
	keyPath         string
	certificatePath string
	commonName      string
}

func (r *CertManager) GenerateAllCertificates() error {
	err := r.generateSignerCerts()
	if err != nil {
		return err
	}
	adminCA := CertInfo{
		commonName:      "admin-kubeconfig-signer",
		certificatePath: filepath.Join(r.CertificatesDir, "admin-kubeconfig-client-ca.crt"),
		keyPath:         filepath.Join(r.CertificatesDir, "admin-kubeconfig-client-ca.key"),
	}
	ca, err := generateAndWriteCA(adminCA)
	if err != nil {
		return err
	}

	r.userCert, r.userKey, err = generateAdminUserCertificate(ca)
	if err != nil {
		return err
	}
	return nil
}

// Create signer keys and certificates and return a CA bundle from all CA certificates
func (r *CertManager) generateSignerCerts() error {
	var certAuthData []byte
	for _, ci := range []CertInfo{
		{
			keyPath:    filepath.Join(r.CertificatesDir, "loadbalancer-serving-signer.key"),
			commonName: "kube-apiserver-lb-signer",
		},
		{
			keyPath:    filepath.Join(r.CertificatesDir, "localhost-serving-signer.key"),
			commonName: "kube-apiserver-localhost-signer",
		},
		{
			keyPath:    filepath.Join(r.CertificatesDir, "service-network-serving-signer.key"),
			commonName: "kube-apiserver-service-network-signer",
		},
		{
			keyPath:    filepath.Join(r.CertificatesDir, "ingresskey-ingress-operator.key"),
			commonName: fmt.Sprintf("%s@%d", "ingress-operator", time.Now().Unix()),
		},
	} {
		ca, err := generateAndWriteCA(ci)
		if err != nil {
			return err
		}
		certBytes, err := crypto.EncodeCertificates(ca.Config.Certs...)
		if err != nil {
			return err
		}
		// Append the PEM-encoded certificate to the bundle
		certAuthData = append(certAuthData, certBytes...)
	}
	return nil
}

func (r *CertManager) GenerateKubeConfig(url string) ([]byte, error) {
	kubeCfg := clientcmdapi.Config{
		Kind:       "Config",
		APIVersion: "v1",
	}
	kubeCfg.Clusters = map[string]*clientcmdapi.Cluster{
		"cluster": {
			Server:                   fmt.Sprintf("https://api.%s:6443", url),
			CertificateAuthorityData: r.caBundle,
		},
	}
	kubeCfg.AuthInfos = map[string]*clientcmdapi.AuthInfo{
		"admin": {
			ClientCertificateData: r.userCert,
			ClientKeyData:         r.userKey,
		},
	}
	kubeCfg.Contexts = map[string]*clientcmdapi.Context{
		"admin": {
			Cluster:   "cluster",
			AuthInfo:  "admin",
			Namespace: "default",
		},
	}
	kubeCfg.CurrentContext = "admin"
	return clientcmd.Write(kubeCfg)
}

func generateSelfSignedCACertificate(commonName string) (*crypto.CA, error) {
	subject := pkix.Name{CommonName: commonName, OrganizationalUnit: []string{"openshift"}}
	newCAConfig, err := crypto.MakeSelfSignedCAConfigForSubject(
		subject,
		crypto.DefaultCACertificateLifetimeInDays,
	)
	if err != nil {
		return nil, errors.Wrap(err, "error generating self signed CA")
	}
	return &crypto.CA{
		SerialGenerator: &crypto.RandomSerialGenerator{},
		Config:          newCAConfig,
	}, nil
}

func generateAndWriteCA(certInfo CertInfo) (*crypto.CA, error) {
	ca, err := generateSelfSignedCACertificate(certInfo.commonName)
	if err != nil {
		return nil, err
	}
	if certInfo.certificatePath == "" {
		certInfo.certificatePath = "/dev/null"
	}
	ca.Config.WriteCertConfigFile(certInfo.certificatePath, certInfo.keyPath)
	return ca, nil
}

func generateAdminUserCertificate(ca *crypto.CA) ([]byte, []byte, error) {
	user := user.DefaultInfo{Name: "system:admin"}
	lifetime := time.Duration(crypto.DefaultCertificateLifetimeInDays) * 24 * time.Hour

	cfg, err := ca.MakeClientCertificateForDuration(&user, lifetime)
	if err != nil {
		return nil, nil, errors.Wrap(err, "error making client certificate")
	}
	crt, key, err := cfg.GetPEMBytes()
	if err != nil {
		return nil, nil, errors.Wrap(err, "error getting PEM bytes for system:admin client certificate")
	}

	return crt, key, nil
}
