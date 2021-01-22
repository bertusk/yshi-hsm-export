// Yubico YubiKey OTP FIDO CCID

package main

import (
	"crypto"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/go-piv/piv-go/piv"

	"yshi/oid/oid_cloud"
)

const enciphermentKeySlotId uint32 = 0x82
const signingKeySlotId uint32 = 0x83
const generateEnciphermentKey = true
const generateSigningKey = true

func main() {
	var signingCertificate *x509.Certificate
	var signingPublicKey crypto.PublicKey
	var targetPublicKey crypto.PublicKey
	var pinChars []byte

	commonName := os.Args[3]
	var signerSecurity asn1.ObjectIdentifier
	switch os.Args[4] {
	case "hsm":
		signerSecurity = oid_cloud.SignerSecurityHSM
	case "software":
		signerSecurity = oid_cloud.SignerSecuritySoftware
	default:
		log.Fatalf("Argument #4 must be hsm or software")
	}
	{
		pemData, err := ioutil.ReadFile(os.Args[1])
		if err != nil {
			log.Fatalf("failed loading file: %v", err)
		}

		for {
			b, rest := pem.Decode(pemData)
			if b == nil {
				break
			}
			switch b.Type {
			case "PIV PIN":
				pinChars = b.Bytes
				break
			case "PUBLIC KEY":
				pub, err := x509.ParsePKIXPublicKey(b.Bytes)
				if err != nil {
					log.Fatalf("failed loading file: %v", err)
				}
				signingPublicKey = pub
				break
			case "CERTIFICATE":
				cert, err := x509.ParseCertificate(b.Bytes)
				if err != nil {
					log.Fatalf("failed loading file: %v", err)
				}
				signingCertificate = cert
				break
			default:
				log.Fatalf("unknown block: %v", b.Type)
			}
			pemData = rest
		}
	}
	{
		pemData, err := ioutil.ReadFile(os.Args[2])
		if err != nil {
			log.Fatalf("failed loading file: %v", err)
		}
		for {
			b, rest := pem.Decode(pemData)
			if b == nil {
				break
			}
			switch b.Type {
			case "PUBLIC KEY":
				pub, err := x509.ParsePKIXPublicKey(b.Bytes)
				if err != nil {
					log.Fatalf("failed loading file: %v", err)
				}
				targetPublicKey = pub
				break
			}
			pemData = rest
		}
	}

	cards, err := piv.Cards()
	if err != nil {
		log.Fatalf("Failed to fetch cards")
	}
	// Find a YubiKey and open the reader.
	var yk *piv.YubiKey
	for _, card := range cards {
		if strings.Contains(strings.ToLower(card), "yubikey") {
			yk2, err := piv.Open(card)
			if err != nil {
				log.Fatalf("failed to open card: %v", err)
			} else {
				yk = yk2
				break
			}

		}
	}
	if yk == nil {
		log.Fatalf("no HSM found")
	}

	slot, ok := piv.RetiredKeyManagementSlot(signingKeySlotId)
	if !ok {
		log.Fatalf("Invalid slot")
	}
	signer, err := yk.PrivateKey(slot, signingPublicKey, piv.KeyAuth {
		PIN: string(pinChars),
		PINPolicy: piv.PINPolicyAlways,
	})
	if err != nil {
		log.Fatalf("Failed to obtain private key handle: %v", err)
	}

	var cert x509.Certificate
	switch pub := targetPublicKey.(type) {
	case *rsa.PublicKey:
		cert.PublicKey = pub
		cert.PublicKeyAlgorithm = x509.RSA
	case *dsa.PublicKey:
		cert.PublicKey = pub
		cert.PublicKeyAlgorithm = x509.DSA
	case *ecdsa.PublicKey:
		cert.PublicKey = pub
		cert.PublicKeyAlgorithm = x509.ECDSA
	case ed25519.PublicKey:
		cert.PublicKey = pub
		cert.PublicKeyAlgorithm = x509.Ed25519
	default:
		log.Fatalf("Invalid public key type")
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("failed to generate serial number")
	}
	cert.SerialNumber = serialNumber
	now := time.Now()
	cert.NotBefore = now
	cert.NotAfter = now.Add(200 * 24 * time.Hour)
	cert.BasicConstraintsValid = true
	cert.IsCA = true

	cert.KeyUsage = x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature
	cert.KeyUsage |= x509.KeyUsageCertSign

	cert.ExtKeyUsage = []x509.ExtKeyUsage{
		x509.ExtKeyUsageServerAuth,
		x509.ExtKeyUsageClientAuth,
	}
	cert.Subject = pkix.Name{
		CommonName: commonName,
		SerialNumber: cert.SerialNumber.String(),
	}

	extData, err := asn1.Marshal(signerSecurity)
	if err != nil {
		log.Fatalf("failed to marshal signer security value")
	}
	cert.ExtraExtensions = append(cert.ExtraExtensions, pkix.Extension {
		Id: oid_cloud.SignerSecurity,
		Critical: false,
		Value: extData,
	})

	if signingCertificate == nil {
		signingCertificate = &cert
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &cert,
		signingCertificate, cert.PublicKey, signer)
	if err != nil {
		log.Fatalf("Failed to generate certificate %v", err)
	}
	pem.Encode(os.Stdout, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})
}