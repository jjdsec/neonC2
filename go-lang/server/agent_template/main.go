// This is a template file. The placeholders will be replaced by the server during compilation.
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"
)

// The server's URL and public key are "baked in" by the builder.
const serverURL = "{{SERVER_URL}}"
const serverPublicKeyPEM = `{{SERVER_PUBLIC_KEY}}`

// AgentInfo holds the agent's state, loaded from files.
type AgentInfo struct {
	UUID       uuid.UUID       `json:"uuid"`
	PrivateKey *rsa.PrivateKey `json:"-"`
}

func beaconLoop() {
	for {
		// In a real scenario, you would add random "jitter" to this sleep time
		// to avoid all agents checking in at the exact same time.
		time.Sleep(10 * time.Second)
		log.Printf("Beaconing to server...")

		// The agent identifies itself to the server using its UUID.
		beaconURL := fmt.Sprintf("%s/beacon?uuid=%s", serverURL, agentInfo.UUID)
		resp, err := http.Get(beaconURL)
		if err != nil {
			log.Printf("Error beaconing: %v", err)
			continue
		}
		defer resp.Body.Close()

		// For now, we just log the server's response.
		// In the next step, this is where we would decode and execute tasks.
		if resp.StatusCode == http.StatusNoContent {
			log.Println("No new tasks.")
		} else {
			log.Println("Received a response from server (task processing to be added).")
		}
	}
}

type RegisterRequest struct {
	Hostname  string `json:"hostname"`
	PublicKey string `json:"public_key"`
}

type RegisterResponse struct {
	UUID uuid.UUID `json:"uuid"`
}

const (
	keyFile = "agent_private.pem"
	idFile  = "agent_id.json"
)

var agentInfo AgentInfo

func main() {
	privateKey, err := loadOrGenerateAgentKey(keyFile)
	if err != nil {
		log.Fatalf("Error with agent key: %v", err)
	}
	agentInfo.PrivateKey = privateKey

	if _, err := os.Stat(idFile); os.IsNotExist(err) {
		log.Println("No agent ID file found. Registering with server...")
		if err := registerAgent(); err != nil {
			log.Fatalf("Could not register agent: %v", err)
		}
		idData, _ := json.MarshalIndent(agentInfo, "", "  ")
		if err := os.WriteFile(idFile, idData, 0600); err != nil {
			log.Fatalf("Could not save agent ID file: %v", err)
		}
		log.Printf("Agent registered and ID saved. UUID: %s", agentInfo.UUID)
	} else {
		log.Println("Agent ID file found. Loading existing identity.")
		idData, err := os.ReadFile(idFile)
		if err != nil {
			log.Fatalf("Could not read agent ID file: %v", err)
		}
		if err := json.Unmarshal(idData, &agentInfo); err != nil {
			log.Fatalf("Could not parse agent ID file: %v", err)
		}
		log.Printf("Agent identity loaded. UUID: %s", agentInfo.UUID)
	}

	log.Println("Agent running.")

	beaconLoop()
	log.Println("Agent exiting.")
}

func loadOrGenerateAgentKey(file string) (*rsa.PrivateKey, error) {
	if _, err := os.Stat(file); os.IsNotExist(err) {
		log.Printf("Generating new private key and saving to %s", file)
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		keyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes})
		if err := os.WriteFile(file, keyPEM, 0600); err != nil {
			return nil, err
		}
		return privateKey, nil
	} else {
		log.Printf("Loading existing private key from %s", file)
		keyPEM, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		block, _ := pem.Decode(keyPEM)
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	}
}

func registerAgent() error {
	hostname, err := os.Hostname()
	if err != nil {
		return err
	}
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&agentInfo.PrivateKey.PublicKey)
	if err != nil {
		return err
	}
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubKeyBytes})
	reqData := RegisterRequest{
		Hostname:  hostname,
		PublicKey: string(pubKeyPEM),
	}
	jsonData, _ := json.Marshal(reqData)
	resp, err := http.Post(serverURL+"/register", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("registration failed with status: %s", resp.Status)
	}
	var regResp RegisterResponse
	if err := json.NewDecoder(resp.Body).Decode(&regResp); err != nil {
		return fmt.Errorf("could not decode registration response: %v", err)
	}
	agentInfo.UUID = regResp.UUID
	return nil
}
