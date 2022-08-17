// Based on Code from https://medium.com/@elfakharany/automate-kubernetes-user-creation-using-the-native-go-client-e2d20dcdc9de
// Updated to take account of change API versions

package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v2"
	certificates "k8s.io/api/certificates/v1"
	v1core "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// Cluster holds the cluster data
type Cluster struct {
	CertificateAuthorityData string `yaml:"certificate-authority-data"`
	Server                   string `yaml:"server"`
}

//Clusters hold an array of the clusters that would exist in the config file
type Clusters []struct {
	Cluster Cluster `yaml:"cluster"`
	Name    string  `yaml:"name"`
}

//Context holds the cluster context
type Context struct {
	Cluster string `yaml:"cluster"`
	User    string `yaml:"user"`
}

//Contexts holds an array of the contexts
type Contexts []struct {
	Context Context `yaml:"context"`
	Name    string  `yaml:"name"`
}

//Users holds an array of the users that would exist in the config file
type Users []struct {
	User User   `yaml:"user"`
	Name string `yaml:"name"`
}

//User holds the user authentication data
type User struct {
	ClientCertificateData string `yaml:"client-certificate-data"`
	ClientKeyData         string `yaml:"client-key-data"`
}

//KubeConfig holds the necessary data for creating a new KubeConfig file
type KubeConfig struct {
	APIVersion     string   `yaml:"apiVersion"`
	Clusters       Clusters `yaml:"clusters"`
	Contexts       Contexts `yaml:"contexts"`
	CurrentContext string   `yaml:"current-context"`
	Kind           string   `yaml:"kind"`
	Preferences    struct{} `yaml:"preferences"`
	Users          Users    `yaml:"users"`
}

func connectToCluster(kubeconfig string) *kubernetes.Clientset {
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		log.Fatal(err)
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatal(err)
	}
	return clientset
}

func main() {
	commonName := flag.String("username", "", "Username to generate certificate for")
	org := flag.String("group", "", "Group to assign to certificate")
	homedir, _ := os.UserHomeDir()
	defaultkubeconfig := homedir + "/.kube/config"
	kubeconfig := flag.String("kubeconfig", defaultkubeconfig, "Kubeconfig file")
	outputFile := flag.String("output-file", "", "File to output Kubeconfig to")
	expirationSeconds := flag.Int("expiration-seconds", 0, "Seconds till the certificate expires")
	flag.Parse()
	if *commonName == "" {
		fmt.Println("ERROR - Username is required")
		fmt.Println("")
		flag.Usage()
		os.Exit(1)
	}

	if *outputFile == "" {
		*outputFile = *commonName + ".config"
	}

	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		log.Fatal(fmt.Printf("Error %s", err))
	}
	keyDer := x509.MarshalPKCS1PrivateKey(key)

	subject := pkix.Name{
		CommonName:   *commonName,
		Organization: []string{*org},
	}
	asn1, err := asn1.Marshal(subject.ToRDNSequence())
	if err != nil {
		log.Fatal(fmt.Printf("Error %s", err))
	}
	csrReq := x509.CertificateRequest{
		RawSubject:         asn1,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
	bytes, err := x509.CreateCertificateRequest(rand.Reader, &csrReq, key)
	if err != nil {
		log.Fatal(fmt.Printf("Error %s", err))
	}

	clientset := connectToCluster(*kubeconfig)
	csr := &certificates.CertificateSigningRequest{
		ObjectMeta: v1.ObjectMeta{
			Name: "tempcsr",
		},
		Spec: certificates.CertificateSigningRequestSpec{
			Groups: []string{
				"system:authenticated",
			},
			SignerName: "kubernetes.io/kube-apiserver-client",
			Usages: []certificates.KeyUsage{
				"client auth",
			},
			Request: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: bytes}),
		},
	}
	var expire int32 = int32(*expirationSeconds)
	if expire != 0 {
		csr.Spec.ExpirationSeconds = &expire
	}
	_, err = clientset.CertificatesV1().CertificateSigningRequests().Create(context.TODO(), csr, v1.CreateOptions{})
	if err != nil {
		log.Fatal(fmt.Printf("Error %s", err))
	}
	csr.Status.Conditions = append(csr.Status.Conditions, certificates.CertificateSigningRequestCondition{
		Type:           certificates.CertificateApproved,
		Status:         v1core.ConditionTrue,
		Reason:         "User activation",
		Message:        "This CSR was approved",
		LastUpdateTime: v1.Now(),
	})
	csr, err = clientset.CertificatesV1().CertificateSigningRequests().UpdateApproval(context.Background(), "tempcsr", csr, v1.UpdateOptions{})
	if err != nil {
		log.Fatal(fmt.Printf("Error %s", err))
	}
	// Give the API server a couple of seconds to issue the cert.
	time.Sleep(2 * time.Second)
	csr, _ = clientset.CertificatesV1().CertificateSigningRequests().Get(context.TODO(), csr.GetName(), v1.GetOptions{})
	pb, _ := pem.Decode(csr.Status.Certificate)
	if pb == nil {
		_ = clientset.CertificatesV1().CertificateSigningRequests().Delete(context.TODO(), csr.GetName(), v1.DeleteOptions{})
		log.Fatal(err)
	}
	issued_cert, err := x509.ParseCertificate(pb.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	issued_group := "none"
	if issued_cert.Subject.Organization[0] != "" {
		issued_group = issued_cert.Subject.Organization[0]
	}
	fmt.Printf("Certificate Successfully issued to username %s in group %s , signed by %s, valid until %s\n", issued_cert.Subject.CommonName, issued_group, issued_cert.Issuer.CommonName, issued_cert.NotAfter.String())

	config, _ := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		&clientcmd.ClientConfigLoadingRules{ExplicitPath: *kubeconfig},
		&clientcmd.ConfigOverrides{
			CurrentContext: "",
		}).RawConfig()
	cluster := config.Contexts[config.CurrentContext].Cluster

	kc := &KubeConfig{
		APIVersion: "v1",
		Clusters: Clusters{
			0: {
				Cluster{
					base64.StdEncoding.EncodeToString([]byte(config.Clusters[cluster].CertificateAuthorityData)),
					config.Clusters[cluster].Server,
				},
				cluster,
			},
		},
		Contexts: Contexts{
			0: {
				Context{
					Cluster: cluster,
					User:    *commonName,
				},
				cluster,
			},
		},
		CurrentContext: cluster,
		Kind:           "Config",
		Users: Users{
			0: {
				User{
					ClientCertificateData: base64.StdEncoding.EncodeToString(csr.Status.Certificate),
					ClientKeyData:         base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyDer})),
				},
				*commonName,
			},
		},
	}

	dir, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}
	_, err = os.Create(filepath.Join(dir, *outputFile))
	if err != nil {
		log.Fatal(err)
	}
	file, err := os.OpenFile(*outputFile, os.O_APPEND|os.O_WRONLY, os.ModeAppend)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	e := yaml.NewEncoder(file)
	err = e.Encode(kc)
	if err != nil {
		log.Fatal(err)
	}
	clientset.CertificatesV1().CertificateSigningRequests().Delete(context.TODO(), csr.GetName(), v1.DeleteOptions{})

}
