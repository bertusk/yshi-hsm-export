// Yubico YubiKey OTP FIDO CCID

package main

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"strings"
	"io/ioutil"

	"github.com/go-piv/piv-go/piv"
)

const enciphermentKeySlotId uint32 = 0x82
const signingKeySlotId uint32 = 0x83
const generateEnciphermentKey = true
const generateSigningKey = true

var pivPinAllowedChars []byte = []byte{
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
	'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',

	'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o',
	'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',

	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
}

func main() {
	var managementKey [24]byte
	var fromScratch = true
	var pinChars []byte

	if len(os.Args) > 1 {
		fromScratch = false

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
			case "PIV MANAGEMENT KEY":
				if copy(managementKey[:], b.Bytes) != 24 {
					log.Fatalf("short copy")
				}
				break
			case "PIV PIN":
				pinChars = b.Bytes
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

	if fromScratch {
		rand.Read(managementKey[:])

		fmt.Printf("### Secrets\n")
		pem.Encode(os.Stdout, &pem.Block{
			Type:  "PIV MANAGEMENT KEY",
			Bytes: managementKey[:],
		})
		fmt.Printf("\n")

		for i := 0; i < 8; i += 1 {
			idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(pivPinAllowedChars))))
			if err != nil {
				log.Fatalf("failed to generate pin: %v", err)
			}
			pinChars = append(pinChars, pivPinAllowedChars[idx.Int64()])
		}
		var newPIN = string(pinChars)


		fmt.Printf("\n### Export\n")

		pem.Encode(os.Stdout, &pem.Block{
			Type:  "PIV PIN",
			Bytes: pinChars,
		})

		yk.SetManagementKey(piv.DefaultManagementKey, managementKey)
		yk.SetPIN(piv.DefaultPIN, newPIN)

		slot, ok := piv.RetiredKeyManagementSlot(signingKeySlotId)
		if !ok {
			log.Fatalf("Invalid slot")
		}
		pub, err := yk.GenerateKey(managementKey, slot, piv.Key{
			Algorithm:   piv.AlgorithmEC256,
			PINPolicy:   piv.PINPolicyAlways,
			TouchPolicy: piv.TouchPolicyNever,
		})
		if err != nil {
			log.Fatalf("error generating key: %v", err)
		}

		der, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			log.Fatalf("error marshaling key: %v", err)
		}
		pem.Encode(os.Stdout, &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: der,
		})
	}
}
