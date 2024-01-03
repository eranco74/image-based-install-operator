package certs

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"k8s.io/client-go/tools/clientcmd"
	"os"
	"path/filepath"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("CertManager", func() {
	var (
		dir string
		cm  CertManager
	)
	BeforeEach(func() {
		var err error
		dir, err = os.MkdirTemp("", "certs")
		Expect(err).NotTo(HaveOccurred())
		cm = CertManager{CertificatesDir: dir}
	})

	AfterEach(func() {
		Expect(os.RemoveAll(dir)).To(Succeed())
	})

	It("generateCA success", func() {
		certPath := filepath.Join(dir, "admin-kubeconfig-client-ca.crt")
		keyPath := filepath.Join(dir, "admin-kubeconfig-client-ca.key")
		adminCA := CertInfo{
			commonName:      "admin-kubeconfig-signer",
			certificatePath: certPath,
			keyPath:         keyPath,
		}
		_, err := generateAndWriteCA(adminCA)
		Expect(err).NotTo(HaveOccurred())
		_, err = os.Stat(certPath)
		Expect(err).NotTo(HaveOccurred())
		_, err = os.Stat(keyPath)
		Expect(err).NotTo(HaveOccurred())
	})

	It("generateSignerCerts success", func() {
		err := cm.generateSignerCerts()
		Expect(err).NotTo(HaveOccurred())
		// verify all signer keys exists
		signerKeyFileNames := []string{
			"loadbalancer-serving-signer.key",
			"localhost-serving-signer.key",
			"service-network-serving-signer.key",
			"ingresskey-ingress-operator.key",
		}
		for _, fileName := range signerKeyFileNames {
			// verify all signer keys exists
			_, err = os.Stat(filepath.Join(dir, fileName))
			Expect(err).NotTo(HaveOccurred())
		}
	})

	It("generateAdminUserCertificate success", func() {
		certPath := filepath.Join(dir, "admin-kubeconfig-client-ca.crt")
		keyPath := filepath.Join(dir, "admin-kubeconfig-client-ca.key")
		adminCA := CertInfo{
			commonName:      "admin-kubeconfig-signer",
			certificatePath: certPath,
			keyPath:         keyPath,
		}
		ca, err := generateAndWriteCA(adminCA)
		caCert := loadCACertFromFile(certPath)

		userCert, _, err := generateAdminUserCertificate(ca)
		Expect(err).NotTo(HaveOccurred())

		// Verify that the client cert was signed by the given
		block, _ := pem.Decode(userCert)
		cert, err := x509.ParseCertificate(block.Bytes)
		Expect(err).NotTo(HaveOccurred())
		cert.CheckSignatureFrom(caCert)
	})

	It("GenerateKubeConfig", func() {
		apiUrl := "apiurl.com"
		cm.userCert = []byte("userCert")
		cm.userKey = []byte("userKey")
		kubeconifg, err := cm.GenerateKubeConfig(apiUrl)
		Expect(err).NotTo(HaveOccurred())
		// Load the kubeconfig file
		conifg, err := clientcmd.Load(kubeconifg)
		Expect(err).NotTo(HaveOccurred())
		Expect(conifg.Clusters["cluster"].Server).To(Equal(fmt.Sprintf("https://api.%s:6443", apiUrl)))
		Expect(string(conifg.AuthInfos["admin"].ClientKeyData)).To(Equal("userKey"))
		Expect(string(conifg.AuthInfos["admin"].ClientCertificateData)).To(Equal("userCert"))
		Expect(conifg.CurrentContext).To(Equal("admin"))
	})
})

func loadCACertFromFile(caCertPath string) *x509.Certificate {
	// Load CA certificate from a file
	caCertPEM, err := os.ReadFile(caCertPath)
	Expect(err).NotTo(HaveOccurred())
	// Decode PEM-encoded CA certificate
	block, _ := pem.Decode(caCertPEM)
	Expect(block).NotTo(Equal(nil))
	// Parse the CA certificate
	caCert, err := x509.ParseCertificate(block.Bytes)
	Expect(err).NotTo(HaveOccurred())
	return caCert
}

func TestCertManager(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Certs Suite")
}
