package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"image/color"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/data/binding"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

// --- Configuration ---
type Config struct {
	ServerURL     string `json:"server_url"`
	APIKey        string `json:"api_key"`
	CertFile      string `json:"cert_file"`       // Path to server's cert.pem
	SkipTLSVerify bool   `json:"skip_tls_verify"` // Should be true for self-signed certs
}

var config Config
var hackFont fyne.Resource // Global variable to hold our custom font

// --- Cyberpunk Theme ---
type CyberpunkTheme struct{}

var _ fyne.Theme = (*CyberpunkTheme)(nil)

func (c *CyberpunkTheme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	switch name {
	case theme.ColorNameBackground:
		return color.NRGBA{R: 0x10, G: 0x10, B: 0x1a, A: 0xff}
	case theme.ColorNameButton, theme.ColorNamePrimary:
		return color.NRGBA{R: 0x00, G: 0x8f, B: 0xff, A: 0xff} // Bright Blue
	case theme.ColorNameFocus:
		return color.NRGBA{R: 0xf0, G: 0x00, B: 0xf0, A: 0xff} // Magenta
	case theme.ColorNameInputBackground, theme.ColorNameMenuBackground, theme.ColorNameSelection:
		return color.NRGBA{R: 0x20, G: 0x20, B: 0x2a, A: 0xff}
	case theme.ColorNamePlaceHolder, theme.ColorNameDisabled:
		return color.NRGBA{R: 0x77, G: 0x77, B: 0x80, A: 0xff}
	default:
		return color.NRGBA{R: 0x00, G: 0xef, B: 0xd1, A: 0xff} // Cyan text
	}
}

func (c *CyberpunkTheme) Font(style fyne.TextStyle) fyne.Resource {
	// Return the globally loaded custom font.
	return hackFont
}
func (c *CyberpunkTheme) Icon(name fyne.ThemeIconName) fyne.Resource {
	return theme.DefaultTheme().Icon(name)
}
func (c *CyberpunkTheme) Size(name fyne.ThemeSizeName) float32 {
	return theme.DefaultTheme().Size(name)
}

// --- API Client ---
type APIClient struct {
	client *http.Client
	config *Config
}
type Agent struct {
	UUID     string    `json:"uuid"`
	Hostname string    `json:"hostname"`
	LastSeen time.Time `json:"last_seen"`
}
type TaskResponse struct {
	TaskID string `json:"task_id"`
}
type ResultResponse struct {
	Status string `json:"status"` // "pending", "dispatched", "complete", "error"
	Result string `json:"result"`
}

// --- Main Application ---
type AppState struct {
	fyneApp   fyne.App
	apiClient *APIClient

	// Data bindings for UI
	agentData     binding.UntypedList
	openTabs      map[string]*container.TabItem
	tabsContainer *container.AppTabs
	tabsMutex     sync.Mutex
}

func main() {
	// 1. Load configuration
	loadOrGenerateConfig()

	// 2. Load the custom font into our global variable
	var err error
	hackFont, err = fyne.LoadResourceFromPath("fonts/Hack-Regular.ttf")
	if err != nil {
		log.Fatalf("Failed to load font: %v. Make sure Hack-Regular.ttf is in the fonts directory.", err)
	}

	// 3. Set up the Fyne app and a single, complete theme
	myApp := app.New()
	myApp.Settings().SetTheme(&CyberpunkTheme{})

	// 4. Create the main window
	myWindow := myApp.NewWindow("C2 Commander")

	// 5. Initialize application state
	appState := &AppState{
		fyneApp:   myApp,
		apiClient: newAPIClient(&config),
		agentData: binding.NewUntypedList(),
		openTabs:  make(map[string]*container.TabItem),
	}

	// 6. Build the UI
	ui := appState.buildUI()
	myWindow.SetContent(ui)

	// 7. Start background tasks
	go appState.startAgentRefreshLoop()

	// 8. Run the application
	myWindow.Resize(fyne.NewSize(1200, 700))
	myWindow.ShowAndRun()
}

func (a *AppState) buildUI() fyne.CanvasObject {
	// Left side: Agent List
	agentList := widget.NewListWithData(a.agentData,
		func() fyne.CanvasObject {
			return container.NewVBox(
				widget.NewLabel("Hostname"),
				widget.NewLabel("Last Seen"),
			)
		},
		func(i binding.DataItem, o fyne.CanvasObject) {
			item, _ := i.(binding.Untyped).Get()
			agent := item.(Agent)
			box := o.(*fyne.Container)
			hostnameLabel := box.Objects[0].(*widget.Label)
			lastSeenLabel := box.Objects[1].(*widget.Label)

			hostnameLabel.SetText(agent.Hostname)
			lastSeenLabel.SetText(fmt.Sprintf("Seen: %s", agent.LastSeen.Format("15:04:05 MST")))
		},
	)

	agentList.OnSelected = func(id widget.ListItemID) {
		item, _ := a.agentData.GetValue(id)
		agent := item.(Agent)
		a.openAgentTab(agent)
		agentList.UnselectAll()
	}

	// Right side: Tabs for each agent
	a.tabsContainer = container.NewAppTabs()
	a.tabsContainer.SetTabLocation(container.TabLocationTop)
	a.tabsContainer.Append(container.NewTabItem("Welcome", widget.NewLabel("Select an agent from the list to begin.")))

	// Final Layout
	split := container.NewHSplit(agentList, a.tabsContainer)
	split.Offset = 0.25
	return split
}

func (a *AppState) openAgentTab(agent Agent) {
	a.tabsMutex.Lock()
	defer a.tabsMutex.Unlock()

	// If tab already exists, just select it
	if tab, exists := a.openTabs[agent.UUID]; exists {
		a.tabsContainer.Select(tab)
		return
	}

	// Create new tab content
	output := widget.NewMultiLineEntry()
	output.TextStyle.Monospace = true
	output.Wrapping = fyne.TextWrapWord
	output.SetText(fmt.Sprintf("--- Terminal for %s (%s) ---\n", agent.Hostname, agent.UUID))

	input := widget.NewEntry()
	input.SetPlaceHolder("Enter command and press Enter...")
	input.OnSubmitted = func(cmd string) {
		if cmd == "" {
			return
		}
		output.SetText(output.Text + "\n> " + cmd + "\n")
		input.SetText("")
		go a.executeTask(agent.UUID, cmd, output)
	}

	content := container.NewBorder(nil, input, nil, nil, output)
	newTab := container.NewTabItemWithIcon(agent.Hostname, theme.ComputerIcon(), content)
	a.tabsContainer.Append(newTab)
	a.tabsContainer.Select(newTab)
	a.openTabs[agent.UUID] = newTab
}

func (a *AppState) executeTask(uuid, command string, output *widget.Entry) {
	// 1. Issue the task
	taskID, err := a.apiClient.issueTask(uuid, command)
	if err != nil {
		output.SetText(output.Text + fmt.Sprintf("Error issuing task: %v\n", err))
		return
	}
	output.SetText(output.Text + fmt.Sprintf("[Task ID: %s] Task dispatched. Waiting for result...\n", taskID))

	// 2. Poll for the result
	for {
		time.Sleep(2 * time.Second)
		res, err := a.apiClient.getResult(taskID)
		if err != nil {
			output.SetText(output.Text + fmt.Sprintf("[Task ID: %s] Error polling for result: %v\n", taskID, err))
			// Stop polling on error
			return
		}

		if res.Status == "complete" || res.Status == "error" {
			output.SetText(output.Text + res.Result)
			return // Stop polling
		}
		// If status is "pending" or "dispatched", just continue polling
	}
}

func (a *AppState) startAgentRefreshLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	// Initial refresh
	a.refreshAgentList()

	for range ticker.C {
		a.refreshAgentList()
	}
}

func (a *AppState) refreshAgentList() {
	log.Println("Refreshing agent list...")
	agents, err := a.apiClient.listAgents()
	if err != nil {
		log.Printf("Failed to refresh agents: %v", err)
		return
	}
	items := make([]interface{}, len(agents))
	for i, agent := range agents {
		items[i] = agent
	}
	a.agentData.Set(items)
	log.Printf("Found %d agents.", len(agents))
}

// --- Helper Functions ---
func loadOrGenerateConfig() {
	configFile := "commander.json"
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		log.Println("Config file not found. Creating default commander.json...")
		defaultConfig := Config{
			ServerURL:     "https://localhost:8443",
			APIKey:        "---REPLACE-WITH-SERVER-API-KEY---",
			CertFile:      "cert.pem", // Assumes cert is in the same folder
			SkipTLSVerify: true,       // Necessary for self-signed certs
		}
		configData, _ := json.MarshalIndent(defaultConfig, "", "  ")
		_ = os.WriteFile(configFile, configData, 0644)
	}

	configData, err := os.ReadFile(configFile)
	if err != nil {
		log.Fatalf("Could not read config file: %v", err)
	}
	if err := json.Unmarshal(configData, &config); err != nil {
		log.Fatalf("Could not parse config file: %v", err)
	}
}

func newAPIClient(cfg *Config) *APIClient {
	// Setup HTTPS client to trust our self-signed server certificate
	caCert, err := os.ReadFile(cfg.CertFile)
	if err != nil {
		log.Printf("WARNING: Could not read cert file '%s'. Using system certs only. %v", cfg.CertFile, err)
	}
	caCertPool := x509.NewCertPool()
	if caCert != nil {
		caCertPool.AppendCertsFromPEM(caCert)
	}

	tlsConfig := &tls.Config{
		RootCAs:            caCertPool,
		InsecureSkipVerify: cfg.SkipTLSVerify, // Set to true for self-signed certs
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig}

	return &APIClient{
		client: &http.Client{Transport: transport, Timeout: 30 * time.Second},
		config: cfg,
	}
}

func (c *APIClient) newRequest(method, urlPath string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(method, c.config.ServerURL+urlPath, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", c.config.APIKey)
	return req, nil
}

// --- API Client Method Implementations ---
func (c *APIClient) listAgents() ([]Agent, error) {
	req, err := c.newRequest("GET", "/agents", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned error: %s", resp.Status)
	}

	var agents []Agent
	if err := json.NewDecoder(resp.Body).Decode(&agents); err != nil {
		return nil, err
	}
	return agents, nil
}

func (c *APIClient) issueTask(uuid, command string) (string, error) {
	taskData := map[string]string{
		"uuid":    uuid,
		"command": command,
	}
	jsonData, _ := json.Marshal(taskData)

	req, err := c.newRequest("POST", "/task", bytes.NewBuffer(jsonData))
	if err != nil {
		return "", err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("server error: %s - %s", resp.Status, string(body))
	}

	var taskResp TaskResponse
	if err := json.NewDecoder(resp.Body).Decode(&taskResp); err != nil {
		return "", err
	}

	return taskResp.TaskID, nil
}

func (c *APIClient) getResult(taskID string) (*ResultResponse, error) {
	req, err := c.newRequest("GET", "/results/"+taskID, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned error: %s", resp.Status)
	}

	var res ResultResponse
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, err
	}
	return &res, nil
}
