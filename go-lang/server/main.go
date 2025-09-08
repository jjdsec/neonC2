package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"embed"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath" // Make sure this is imported
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
)

//go:embed agent_template/main.go
var agentTemplate embed.FS

var (
	db        *sql.DB
	serverKey *rsa.PrivateKey
)

type Config struct {
	URL  string `json:"url"`
	Port string `json:"port"`
}

type RegisterRequest struct {
	Hostname  string `json:"hostname"`
	PublicKey string `json:"public_key"`
}

type RegisterResponse struct {
	UUID uuid.UUID `json:"uuid"`
}

// CORRECTED: This function now creates a full Go module for the agent build.
func buildAgents(config Config) error {
	log.Println("Starting agent build process...")
	buildDir := "./build"
	if err := os.MkdirAll(buildDir, 0755); err != nil {
		return err
	}

	templateBytes, err := agentTemplate.ReadFile("agent_template/main.go")
	if err != nil {
		return err
	}
	templateCode := string(templateBytes)

	pubKeyPEM, err := os.ReadFile("server_public.pem")
	if err != nil {
		return fmt.Errorf("could not read server public key to embed: %w", err)
	}

	finalCode := strings.ReplaceAll(templateCode, "{{SERVER_URL}}", config.URL)
	finalCode = strings.ReplaceAll(finalCode, "{{SERVER_PUBLIC_KEY}}", string(pubKeyPEM))

	tmpBuildDir, err := os.MkdirTemp("", "agent-build-*")
	if err != nil {
		return fmt.Errorf("could not create temp build dir: %w", err)
	}
	defer os.RemoveAll(tmpBuildDir)

	tmpGoFile := filepath.Join(tmpBuildDir, "agent.go")
	if err := os.WriteFile(tmpGoFile, []byte(finalCode), 0644); err != nil {
		return err
	}

	// NEW: Create a go.mod file for the agent.
	tmpGoModFile := filepath.Join(tmpBuildDir, "go.mod")
	// Using Go 1.22, you can adjust this if needed.
	if err := os.WriteFile(tmpGoModFile, []byte("module tempagent\n\ngo 1.22"), 0644); err != nil {
		return err
	}

	// NEW: Run 'go mod tidy' to fetch dependencies.
	log.Println("Running 'go mod tidy' for agent dependencies...")
	cmdTidy := exec.Command("go", "mod", "tidy")
	cmdTidy.Dir = tmpBuildDir // Run from the temp directory
	if output, err := cmdTidy.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to run go mod tidy: %s\n%w", string(output), err)
	}
	log.Println("'go mod tidy' completed.")

	targets := map[string]string{
		"windows/amd64": "agent.exe",
		"linux/amd64":   "agent",
		"darwin/amd64":  "agent_mac",
	}

	for target, outputName := range targets {
		parts := strings.Split(target, "/")
		goos, goarch := parts[0], parts[1]

		absOutputPath, err := filepath.Abs(filepath.Join(buildDir, outputName))
		if err != nil {
			return fmt.Errorf("could not get absolute path for output: %w", err)
		}

		log.Printf("Building agent for %s...", target)

		cmdBuild := exec.Command("go", "build", "-ldflags", "-s -w", "-o", absOutputPath, ".")
		cmdBuild.Dir = tmpBuildDir
		cmdBuild.Env = append(os.Environ(), "GOOS="+goos, "GOARCH="+goarch, "CGO_ENABLED=0") // CGO_ENABLED=0 helps with cross-compilation

		if output, err := cmdBuild.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to build for %s: %s\n%w", target, string(output), err)
		}
	}

	log.Println("Agent builds completed successfully.")
	return nil
}

// --- The rest of the file is unchanged ---

func main() {
	config, err := loadOrGenerateConfig()
	if err != nil {
		log.Fatalf("Error with server config: %v", err)
	}

	if err := loadOrGenerateServerKeys(); err != nil {
		log.Fatalf("Error with server keys: %v", err)
	}

	if err := buildAgents(config); err != nil {
		log.Fatalf("Error building agents: %v", err)
	}

	db, err = sql.Open("sqlite3", "./agents.db")
	if err != nil {
		log.Fatalf("Error opening database: %v", err)
	}
	defer db.Close()

	if err := initDB(); err != nil {
		log.Fatalf("Error initializing database: %v", err)
	}

	r := chi.NewRouter()
	r.Post("/register", registerAgentHandler)

	fs := http.FileServer(http.Dir("./build"))
	r.Handle("/agents/*", http.StripPrefix("/agents/", fs))

	serverAddr := ":" + config.Port
	log.Printf("Server starting on %s...", serverAddr)
	if err := http.ListenAndServe(serverAddr, r); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}

func loadOrGenerateConfig() (Config, error) {
	var config Config
	configFile := "server.conf"

	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		log.Println("Config file not found. Generating new config...")
		resp, err := http.Get("https://ipinfo.io/ip")
		if err != nil {
			return config, fmt.Errorf("could not fetch public IP: %w", err)
		}
		defer resp.Body.Close()
		ip, err := io.ReadAll(resp.Body)
		if err != nil {
			return config, err
		}

		config.Port = "8443"
		config.URL = fmt.Sprintf("http://%s:%s", strings.TrimSpace(string(ip)), config.Port)

		configData, _ := json.MarshalIndent(config, "", "  ")
		if err := os.WriteFile(configFile, configData, 0644); err != nil {
			return config, err
		}
		log.Printf("New config saved. Server URL set to: %s", config.URL)
	} else {
		log.Println("Loading existing config file...")
		configData, err := os.ReadFile(configFile)
		if err != nil {
			return config, err
		}
		if err := json.Unmarshal(configData, &config); err != nil {
			return config, err
		}
	}
	return config, nil
}

func loadOrGenerateServerKeys() error {
	privateKeyFile := "server_private.pem"
	if _, err := os.Stat(privateKeyFile); os.IsNotExist(err) {
		log.Println("Generating new server key pair...")
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return err
		}
		serverKey = privateKey
		privKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
		privKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privKeyBytes})
		if err := os.WriteFile(privateKeyFile, privKeyPEM, 0600); err != nil {
			return err
		}
		pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
		if err != nil {
			return err
		}
		pubKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubKeyBytes})
		if err := os.WriteFile("server_public.pem", pubKeyPEM, 0644); err != nil {
			return err
		}
		log.Println("New server key pair saved.")
	} else {
		log.Println("Loading existing server private key...")
		privKeyPEM, err := os.ReadFile(privateKeyFile)
		if err != nil {
			return err
		}
		block, _ := pem.Decode(privKeyPEM)
		privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return err
		}
		serverKey = privateKey
	}
	return nil
}

func initDB() error {
	sqlStmt := `
    CREATE TABLE IF NOT EXISTS agents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        uuid TEXT NOT NULL UNIQUE,
        hostname TEXT NOT NULL,
        public_key TEXT NOT NULL,
        last_seen DATETIME,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );`
	_, err := db.Exec(sqlStmt)
	return err
}

func registerAgentHandler(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	newUUID := uuid.New()
	stmt, err := db.Prepare("INSERT INTO agents (uuid, hostname, public_key, last_seen) VALUES (?, ?, ?, ?)")
	if err != nil {
		log.Printf("Error preparing statement: %v", err)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
	defer stmt.Close()
	_, err = stmt.Exec(newUUID.String(), req.Hostname, req.PublicKey, time.Now())
	if err != nil {
		log.Printf("Error executing statement: %v", err)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
	log.Printf("Registered new agent from hostname '%s' with UUID: %s", req.Hostname, newUUID)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(RegisterResponse{UUID: newUUID})
}
