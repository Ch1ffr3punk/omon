package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ANSI Color Codes for terminal highlighting
const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[93m"
	ColorCyan   = "\033[36m"
	ColorGray   = "\033[90m"
	ColorBlue   = "\033[34m"
)

// Config structure for omon.json
type OmonConfig struct {
	CookiePaths []string `json:"cookie_paths"`
	Ports       []string `json:"ports"`
}

// StreamInfo tracks metadata and traffic for a single Tor stream
type StreamInfo struct {
	ID            string    `json:"id"`
	Target        string    `json:"target"`
	BytesSent     int64     `json:"bytes_sent"`
	BytesReceived int64     `json:"bytes_received"`
	StartTime     time.Time `json:"start_time"`
	EndTime       time.Time `json:"end_time,omitempty"`
	Closed        bool      `json:"closed"`
}

// TorMonitor handles the connection to Tor Control Port and stats aggregation
type TorMonitor struct {
	address       string
	conn          net.Conn
	reader        *bufio.Reader
	streams       map[string]*StreamInfo
	mu            sync.Mutex
	logger        *log.Logger
	stats         map[string]int64
	report        map[string]int64
	activeStreams int
	totalStreams  int
}

// NewTorMonitor initializes the monitor struct
func NewTorMonitor(addr string, trafficLog *os.File) *TorMonitor {
	return &TorMonitor{
		address: addr,
		streams: make(map[string]*StreamInfo),
		logger:  log.New(trafficLog, "", log.LstdFlags),
		stats:   make(map[string]int64),
		report:  make(map[string]int64),
	}
}

// createDefaultConfig creates a default omon.json file if it doesn't exist
func createDefaultConfig() error {
	configFile := "omon.json"

	if _, err := os.Stat(configFile); err == nil {
		return nil // File already exists
	}

	defaultConfig := OmonConfig{
		CookiePaths: []string{
			`C:\Program Files (x86)\OmniMix\tor\data\control_auth_cookie`,
			`/home/your_name/.tor/control_auth_cookie`,
			`/var/lib/tor/control_auth_cookie`,
		},
		Ports: []string{"9051"}, // Only system Tor port; exclude 9151 (Tor Browser)
	}

	configData, err := json.MarshalIndent(defaultConfig, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to create config JSON: %v", err)
	}

	if err := os.WriteFile(configFile, configData, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %v", err)
	}

	fmt.Printf("%sCreated default configuration file: %s%s\n", ColorGreen, configFile, ColorReset)
	fmt.Printf("Please edit this file with your correct paths and ports.\n")

	return nil
}

// loadConfig loads the configuration from omon.json
func loadConfig() (*OmonConfig, error) {
	configFile := "omon.json"

	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		return nil, fmt.Errorf("config file '%s' not found", configFile)
	}

	configData, err := os.ReadFile(configFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read config: %v", err)
	}

	var config OmonConfig
	if err := json.Unmarshal(configData, &config); err != nil {
		fmt.Printf("%sInvalid JSON in config file:%s\n", ColorRed, ColorReset)
		if len(configData) > 500 {
			fmt.Printf("Content (first 500 chars):\n%s\n", string(configData[:500]))
		} else {
			fmt.Printf("Content:\n%s\n", string(configData))
		}
		return nil, fmt.Errorf("failed to parse config: %v", err)
	}

	if config.CookiePaths == nil || len(config.CookiePaths) == 0 {
		return nil, fmt.Errorf("'cookie_paths' array is empty or missing in config")
	}

	// Ensure we don't use 9151 by accident
	filteredPorts := []string{}
	for _, p := range config.Ports {
		if p != "9151" {
			filteredPorts = append(filteredPorts, p)
		}
	}
	if len(filteredPorts) == 0 {
		filteredPorts = []string{"9051"}
		fmt.Printf("%sNo valid ports found; using default port 9051%s\n", ColorYellow, ColorReset)
	}
	config.Ports = filteredPorts

	return &config, nil
}

// findCookieFile searches for cookie file using user-defined paths from omon.json
func findCookieFile() (string, error) {
	config, err := loadConfig()
	if err != nil {
		return "", fmt.Errorf("config error: %v", err)
	}

	fmt.Printf("%sSearching for cookie file in configured paths...%s\n", ColorCyan, ColorReset)

	for i, path := range config.CookiePaths {
		expandedPath := os.ExpandEnv(path)

		if _, err := os.Stat(expandedPath); err == nil {
			fmt.Printf("%s✓ Found cookie file at path #%d: %s%s\n", ColorGreen, i+1, expandedPath, ColorReset)
			return expandedPath, nil
		}

		if !filepath.IsAbs(expandedPath) {
			absPath, err := filepath.Abs(expandedPath)
			if err == nil {
				if _, err := os.Stat(absPath); err == nil {
					fmt.Printf("%s✓ Found cookie file at relative path #%d: %s%s\n", ColorGreen, i+1, absPath, ColorReset)
					return absPath, nil
				}
			}
		}

		fmt.Printf("%s✗ Path #%d not found: %s%s\n", ColorGray, i+1, expandedPath, ColorReset)
	}

	return "", fmt.Errorf("cookie file not found in any configured path. Check your omon.json file")
}

// tryConnect attempts to connect to Tor on a specific address
func tryConnect(address string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", address, 3*time.Second)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// connectToTor attempts to connect to Tor on multiple ports (excluding 9151)
func connectToTor() (net.Conn, string, error) {
	config, err := loadConfig()
	if err != nil {
		return nil, "", fmt.Errorf("config error: %v", err)
	}

	fmt.Printf("%sTrying to connect to Tor control port...%s\n", ColorCyan, ColorReset)

	for _, port := range config.Ports {
		address := fmt.Sprintf("127.0.0.1:%s", port)
		fmt.Printf("  Trying port %s... ", port)

		conn, err := tryConnect(address)
		if err == nil {
			fmt.Printf("%s✓ Connected%s\n", ColorGreen, ColorReset)
			return conn, address, nil
		}

		fmt.Printf("%s✗ Failed%s\n", ColorRed, ColorReset)

		address = fmt.Sprintf("localhost:%s", port)
		conn, err = tryConnect(address)
		if err == nil {
			fmt.Printf("  localhost:%s %s✓ Connected%s\n", port, ColorGreen, ColorReset)
			return conn, address, nil
		}
	}

	return nil, "", fmt.Errorf("could not connect to Tor on any configured port: %v", config.Ports)
}

// Start connects to Tor, authenticates, and begins event monitoring
func (m *TorMonitor) Start() error {
	var err error

	m.conn, m.address, err = connectToTor()
	if err != nil {
		return fmt.Errorf("failed to connect to Tor control port: %v", err)
	}

	m.reader = bufio.NewReader(m.conn)

	path, err := findCookieFile()
	if err != nil {
		return fmt.Errorf("authentication error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read cookie file: %v", err)
	}

	authCmd := fmt.Sprintf("AUTHENTICATE %s\r\n", hex.EncodeToString(data))
	fmt.Fprintf(m.conn, authCmd)

	response, err := m.reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read authentication response: %v", err)
	}

	if !strings.Contains(response, "250 OK") {
		return fmt.Errorf("authentication failed: %s", strings.TrimSpace(response))
	}

	fmt.Printf("%s✓ Successfully authenticated with Tor on %s%s\n", ColorGreen, m.address, ColorReset)

	fmt.Fprintf(m.conn, "SETEVENTS STREAM STREAM_BW\r\n")
	m.reader.ReadString('\n')

	fmt.Printf("%s✓ Onion Monitor Started.%s\n", ColorCyan, ColorReset)
	fmt.Printf("%sLogging all events to file...%s\n", ColorCyan, ColorReset)

	go m.eventLoop()
	go m.periodicStats()

	return nil
}

// eventLoop reads the raw stream from Tor Control Port
func (m *TorMonitor) eventLoop() {
	for {
		line, err := m.reader.ReadString('\n')
		if err != nil {
			fmt.Printf("%sError reading from Tor control port: %v%s\n", ColorRed, err, ColorReset)
			return
		}
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "650 STREAM ") && !strings.Contains(line, "STREAM_BW") {
			m.handleStreamEvent(line)
		} else if strings.HasPrefix(line, "650 STREAM_BW") {
			m.handleStreamBWEvent(line)
		}
	}
}

// handleStreamEvent processes status changes (NEW, SUCCEEDED, CLOSED, etc.)
func (m *TorMonitor) handleStreamEvent(line string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	parts := strings.Fields(line)
	if len(parts) < 4 {
		return
	}

	id, status := parts[2], parts[3]

	if _, exists := m.streams[id]; !exists {
		m.streams[id] = &StreamInfo{
			ID:        id,
			StartTime: time.Now(),
		}
		m.stats["streams_total"]++
		m.report["streams_total"]++
		m.activeStreams++
		m.totalStreams++
	}

	s := m.streams[id]

	for i := 4; i < len(parts); i++ {
		p := parts[i]
		if !strings.Contains(p, "=") && p != "-" {
			s.Target = p
		}
	}

	color := ColorGray
	switch status {
	case "SUCCEEDED":
		color = ColorGreen
	case "FAILED":
		color = ColorRed
	case "NEW":
		color = ColorCyan
	case "SENTCONNECT":
		color = ColorBlue
	}

	// Console output WITHOUT any process/PID info
	fmt.Printf("[%s] Stream %s %s%s%s | Target: %s\n",
		time.Now().Format("15:04:05"), id, color, status, ColorReset, s.Target)

	// Log to file (same simplified format)
	m.logger.Printf("Stream %s %s | Target: %s", id, status, s.Target)

	if status == "CLOSED" || status == "FAILED" {
		if !s.Closed {
			s.Closed = true
			s.EndTime = time.Now()
			m.activeStreams--

			reason := "NONE"
			for _, p := range parts {
				if strings.HasPrefix(p, "REASON=") {
					reason = strings.TrimPrefix(p, "REASON=")
				}
			}

			m.finalizeStream(s, reason)
			delete(m.streams, id)
		}
	}
}

// handleStreamBWEvent accumulates byte counts
func (m *TorMonitor) handleStreamBWEvent(line string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	parts := strings.Fields(line)
	if len(parts) < 5 {
		return
	}

	id := parts[2]
	sent, _ := strconv.ParseInt(parts[3], 10, 64)
	rcvd, _ := strconv.ParseInt(parts[4], 10, 64)

	if s, exists := m.streams[id]; exists {
		s.BytesSent += sent
		s.BytesReceived += rcvd

		m.stats["total_sent"] += sent
		m.stats["total_received"] += rcvd

		m.report["total_sent"] += sent
		m.report["total_received"] += rcvd
	}
}

// finalizeStream logs final stream results and global totals
func (m *TorMonitor) finalizeStream(s *StreamInfo, reason string) {
	duration := time.Since(s.StartTime).Round(time.Millisecond)

	displayReason := reason
	if reason == "DONE" {
		displayReason = "END"
	}

	summary := fmt.Sprintf("Stream %s FINISHED: S:%d R:%d bytes | %v | To: %s (%s)",
		s.ID, s.BytesSent, s.BytesReceived, duration, s.Target, displayReason)

	accMsg := fmt.Sprintf("Total now: S:%d R:%d bytes | All Streams: %d | Active: %d",
		m.stats["total_sent"], m.stats["total_received"], m.totalStreams, m.activeStreams)

	fmt.Printf("[%s] %s%s%s\n", time.Now().Format("15:04:05"), ColorYellow, summary, ColorReset)
	fmt.Printf("[%s] %s%s%s\n", time.Now().Format("15:04:05"), ColorCyan, accMsg, ColorReset)

	m.logger.Println(summary)
	m.logger.Println(accMsg)
}

// periodicStats prints a summary every 10 minutes and resets report counters
func (m *TorMonitor) periodicStats() {
	ticker := time.NewTicker(10 * time.Minute)

	for {
		select {
		case <-ticker.C:
			m.mu.Lock()

			sentMB := float64(m.report["total_sent"]) / 1048576.0
			receivedMB := float64(m.report["total_received"]) / 1048576.0

			report := fmt.Sprintf("--- 10 min Report | Sent: %.2f MB (%d bytes) | Received: %.2f MB (%d bytes) | Total Streams: %d | Active Streams: %d ---",
				sentMB, m.report["total_sent"], receivedMB, m.report["total_received"],
				m.report["streams_total"], m.activeStreams)

			fmt.Printf("\n%s%s%s\n\n", ColorGreen, report, ColorReset)
			m.logger.Println(report)

			m.report["total_sent"] = 0
			m.report["total_received"] = 0
			m.report["streams_total"] = 0

			m.mu.Unlock()
		}
	}
}

func main() {
	fmt.Printf("Onion Monitor v0.1.0\n\n")

	if err := createDefaultConfig(); err != nil {
		fmt.Printf("%sNote: %v%s\n", ColorYellow, err, ColorReset)
	}

	if _, err := os.Stat("omon.json"); os.IsNotExist(err) {
		fmt.Printf("%sERROR: omon.json configuration file not found!%s\n\n", ColorRed, ColorReset)

		fmt.Printf("Create a file named 'omon.json' with this content:\n\n")
		fmt.Printf(`{
  "cookie_paths": [
    "C:\\Program Files (x86)\\OmniMix\\tor\\data\\control_auth_cookie",
    "/home/your_name/.tor/control_auth_cookie",
    "/var/lib/tor/control_auth_cookie"
  ],
  "ports": [
    "9051"
  ]
}`)
		fmt.Printf("\n\nOr use Notepad and save as 'omon.json' (not 'omon.json.txt'!)\n")
		os.Exit(1)
	}

	if err := os.MkdirAll("logs", 0755); err != nil {
		fmt.Printf("%sFailed to create logs directory: %v%s\n", ColorRed, err, ColorReset)
		os.Exit(1)
	}

	logFileName := fmt.Sprintf("logs/traffic_%s.log", time.Now().Format("2006-01-02"))
	logF, err := os.OpenFile(logFileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("%sFailed to open log file: %v%s\n", ColorRed, err, ColorReset)
		os.Exit(1)
	}
	defer logF.Close()

	monitor := NewTorMonitor("", logF)
	if err := monitor.Start(); err != nil {
		fmt.Printf("\n%sStartup Error: %v%s\n", ColorRed, err, ColorReset)
		fmt.Printf("\n%sTroubleshooting tips:%s\n", ColorYellow, ColorReset)
		fmt.Printf("1. Make sure Tor is running with ControlPort enabled\n")
		fmt.Printf("2. Check cookie file paths in omon.json\n")
		fmt.Printf("3. Verify file permissions on cookie file\n")
		fmt.Printf("4. Ensure port 9051 is accessible (Tor Browser's 9151 is intentionally excluded)\n")
		fmt.Printf("5. Check if Tor is configured to listen on localhost\n")
		os.Exit(1)
	}

	fmt.Printf("\n%sMonitoring active. Press Ctrl+C to exit.%s\n", ColorGreen, ColorReset)
	fmt.Printf("%sConnected to: %s%s\n", ColorGray, monitor.address, ColorReset)
	fmt.Printf("%sLog file: %s%s\n", ColorGray, logFileName, ColorReset)
	fmt.Printf("%sProcess detection: Disabled (as requested)%s\n", ColorGray, ColorReset)

	// Keep main goroutine alive
	select {}
}
