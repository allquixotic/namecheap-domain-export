package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/namecheap/go-namecheap-sdk/v2/namecheap"
	"golang.org/x/term"
)

type Config struct {
	Domain        string
	OutputFile    string
	APIEndpoint   string
	APIUser       string
	APIKey        string
	ClientIP      string
	UseSandbox    bool
}

type DNSRecord struct {
	Name     string
	Type     string
	Address  string
	MXPref   string
	TTL      string
}

func main() {
	var config Config
	
	flag.StringVar(&config.OutputFile, "output", "", "Output file path (default: <domain>.zone)")
	flag.StringVar(&config.APIEndpoint, "endpoint", "", "Custom API endpoint URL (e.g., http://localhost:8080)")
	flag.BoolVar(&config.UseSandbox, "sandbox", getEnv("NAMECHEAP_SANDBOX", "false") == "true", "Use Namecheap sandbox")
	
	// Get sensitive data from environment variables only
	config.APIUser = getEnv("NAMECHEAP_API_USER", "")
	config.APIKey = getEnv("NAMECHEAP_API_KEY", "")
	config.ClientIP = getEnv("NAMECHEAP_CLIENT_IP", "")
	
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS] <domain>\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Export DNS records from Namecheap to BIND format\n\n")
		fmt.Fprintf(os.Stderr, "Arguments:\n")
		fmt.Fprintf(os.Stderr, "  domain    Domain name to export (e.g., example.com)\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nEnvironment Variables:\n")
		fmt.Fprintf(os.Stderr, "  NAMECHEAP_API_USER     API username (for direct API)\n")
		fmt.Fprintf(os.Stderr, "  NAMECHEAP_API_KEY      API key or filter token\n")
		fmt.Fprintf(os.Stderr, "  NAMECHEAP_CLIENT_IP    Client IP address (for direct API)\n")
		fmt.Fprintf(os.Stderr, "  NAMECHEAP_SANDBOX      Use sandbox (true/false)\n")
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  # Direct Namecheap API:\n")
		fmt.Fprintf(os.Stderr, "  %s example.com\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -output example.zone example.com\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\n  # Via namecheap-api-filter:\n")
		fmt.Fprintf(os.Stderr, "  %s -endpoint http://localhost:8080 example.com\n", os.Args[0])
	}
	
	flag.Parse()
	
	// Check if we should run setup
	if len(os.Args) > 1 && os.Args[1] == "setup" {
		if err := runInteractiveSetup(); err != nil {
			log.Fatalf("Setup failed: %v", err)
		}
		return
	}
	
	// Check if .env exists and no domain provided
	if flag.NArg() == 0 {
		if _, err := os.Stat(".env"); os.IsNotExist(err) {
			fmt.Println("No .env file found. Would you like to run the setup wizard?")
			fmt.Print("Run setup? (Y/n): ")
			reader := bufio.NewReader(os.Stdin)
			response, _ := reader.ReadString('\n')
			response = strings.TrimSpace(strings.ToLower(response))
			
			if response == "" || response == "y" || response == "yes" {
				if err := runInteractiveSetup(); err != nil {
					log.Fatalf("Setup failed: %v", err)
				}
				return
			}
		}
		flag.Usage()
		os.Exit(1)
	}
	
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(1)
	}
	
	config.Domain = flag.Arg(0)
	
	if config.OutputFile == "" {
		config.OutputFile = config.Domain + ".zone"
	}
	
	if config.APIKey == "" {
		log.Fatal("API key is required (use -key flag or NAMECHEAP_API_KEY environment variable)")
	}
	
	// When using direct Namecheap API (no custom endpoint), user and IP are required
	if config.APIEndpoint == "" {
		if config.APIUser == "" {
			log.Fatal("API username is required (use -user flag or NAMECHEAP_API_USER environment variable)")
		}
		if config.ClientIP == "" {
			log.Fatal("Client IP is required (use -ip flag or NAMECHEAP_CLIENT_IP environment variable)")
		}
	}
	
	fmt.Printf("Exporting DNS records for domain: %s\n", config.Domain)
	
	records, err := fetchRecordsFromAPI(config)
	
	if err != nil {
		log.Fatalf("Failed to fetch DNS records: %v", err)
	}
	
	err = exportToBIND(config.Domain, records, config.OutputFile)
	if err != nil {
		log.Fatalf("Failed to export BIND file: %v", err)
	}
	
	fmt.Printf("Successfully exported %d DNS records to %s\n", len(records), config.OutputFile)
}

func fetchRecordsFromAPI(config Config) ([]DNSRecord, error) {
	// When using custom endpoint, user and IP can be dummy values
	apiUser := config.APIUser
	clientIP := config.ClientIP
	if config.APIEndpoint != "" && apiUser == "" {
		apiUser = "dummy"
	}
	if config.APIEndpoint != "" && clientIP == "" {
		clientIP = "127.0.0.1"
	}
	
	client := namecheap.NewClient(&namecheap.ClientOptions{
		UserName:   apiUser,
		ApiUser:    apiUser,
		ApiKey:     config.APIKey,
		ClientIp:   clientIP,
		UseSandbox: config.UseSandbox,
	})
	
	// Set custom endpoint if provided
	if config.APIEndpoint != "" {
		client.BaseURL = config.APIEndpoint
		if !strings.HasSuffix(client.BaseURL, "/") {
			client.BaseURL += "/"
		}
	}
	
	sld, tld, err := splitDomain(config.Domain)
	if err != nil {
		return nil, fmt.Errorf("invalid domain format: %v", err)
	}
	
	domain := sld + "." + tld
	response, err := client.DomainsDNS.GetHosts(domain)
	if err != nil {
		return nil, fmt.Errorf("failed to get DNS hosts: %v", err)
	}
	
	var records []DNSRecord
	if response.DomainDNSGetHostsResult != nil && response.DomainDNSGetHostsResult.Hosts != nil {
		for _, host := range *response.DomainDNSGetHostsResult.Hosts {
			record := DNSRecord{
				Name:    safeString(host.Name),
				Type:    safeString(host.Type),
				Address: safeString(host.Address),
				MXPref:  safeInt(host.MXPref),
				TTL:     safeInt(host.TTL),
			}
			records = append(records, record)
		}
	}
	
	return records, nil
}


func exportToBIND(domain string, records []DNSRecord, outputFile string) error {
	file, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create output file: %v", err)
	}
	defer file.Close()
	
	serial := time.Now().Format("2006010215")
	
	fmt.Fprintf(file, "$ORIGIN %s.\n", domain)
	fmt.Fprintf(file, "$TTL 3600\n\n")
	
	fmt.Fprintf(file, "; SOA Record\n")
	fmt.Fprintf(file, "@\t3600\tIN\tSOA\tns1.%s. admin.%s. (\n", domain, domain)
	fmt.Fprintf(file, "\t\t\t%s\t; serial\n", serial)
	fmt.Fprintf(file, "\t\t\t3600\t\t; refresh\n")
	fmt.Fprintf(file, "\t\t\t900\t\t; retry\n")
	fmt.Fprintf(file, "\t\t\t604800\t\t; expire\n")
	fmt.Fprintf(file, "\t\t\t86400\t\t; minimum TTL\n")
	fmt.Fprintf(file, "\t\t\t)\n\n")
	
	aRecords := []DNSRecord{}
	aaaaRecords := []DNSRecord{}
	cnameRecords := []DNSRecord{}
	mxRecords := []DNSRecord{}
	txtRecords := []DNSRecord{}
	otherRecords := []DNSRecord{}
	
	for _, record := range records {
		switch strings.ToUpper(record.Type) {
		case "A":
			aRecords = append(aRecords, record)
		case "AAAA":
			aaaaRecords = append(aaaaRecords, record)
		case "CNAME":
			cnameRecords = append(cnameRecords, record)
		case "MX", "MXE":
			mxRecords = append(mxRecords, record)
		case "TXT":
			txtRecords = append(txtRecords, record)
		default:
			otherRecords = append(otherRecords, record)
		}
	}
	
	if len(aRecords) > 0 {
		fmt.Fprintf(file, "; A Records (IPv4)\n")
		for _, record := range aRecords {
			name := formatHostname(record.Name)
			ttl := formatTTL(record.TTL)
			fmt.Fprintf(file, "%s\t%s\tIN\tA\t%s\n", name, ttl, record.Address)
		}
		fmt.Fprintf(file, "\n")
	}
	
	if len(aaaaRecords) > 0 {
		fmt.Fprintf(file, "; AAAA Records (IPv6)\n")
		for _, record := range aaaaRecords {
			name := formatHostname(record.Name)
			ttl := formatTTL(record.TTL)
			fmt.Fprintf(file, "%s\t%s\tIN\tAAAA\t%s\n", name, ttl, record.Address)
		}
		fmt.Fprintf(file, "\n")
	}
	
	if len(cnameRecords) > 0 {
		fmt.Fprintf(file, "; CNAME Records\n")
		for _, record := range cnameRecords {
			name := formatHostname(record.Name)
			ttl := formatTTL(record.TTL)
			target := record.Address
			if !strings.HasSuffix(target, ".") {
				target += "."
			}
			fmt.Fprintf(file, "%s\t%s\tIN\tCNAME\t%s\n", name, ttl, target)
		}
		fmt.Fprintf(file, "\n")
	}
	
	if len(mxRecords) > 0 {
		fmt.Fprintf(file, "; MX Records\n")
		for _, record := range mxRecords {
			name := formatHostname(record.Name)
			ttl := formatTTL(record.TTL)
			priority := record.MXPref
			if priority == "" {
				priority = "10"
			}
			target := record.Address
			if !strings.HasSuffix(target, ".") {
				target += "."
			}
			fmt.Fprintf(file, "%s\t%s\tIN\tMX\t%s %s\n", name, ttl, priority, target)
		}
		fmt.Fprintf(file, "\n")
	}
	
	if len(txtRecords) > 0 {
		fmt.Fprintf(file, "; TXT Records\n")
		for _, record := range txtRecords {
			name := formatHostname(record.Name)
			ttl := formatTTL(record.TTL)
			value := record.Address
			if !strings.HasPrefix(value, "\"") {
				value = "\"" + value + "\""
			}
			fmt.Fprintf(file, "%s\t%s\tIN\tTXT\t%s\n", name, ttl, value)
		}
		fmt.Fprintf(file, "\n")
	}
	
	if len(otherRecords) > 0 {
		fmt.Fprintf(file, "; Other Records\n")
		for _, record := range otherRecords {
			name := formatHostname(record.Name)
			ttl := formatTTL(record.TTL)
			fmt.Fprintf(file, "%s\t%s\tIN\t%s\t%s\n", name, ttl, record.Type, record.Address)
		}
	}
	
	return nil
}

func formatHostname(name string) string {
	if name == "" || name == "@" {
		return "@"
	}
	return name
}

func formatTTL(ttl string) string {
	if ttl == "" {
		return "3600"
	}
	
	if _, err := strconv.Atoi(ttl); err != nil {
		return "3600"
	}
	return ttl
}

func splitDomain(domain string) (string, string, error) {
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return "", "", fmt.Errorf("domain must have at least two parts")
	}
	
	tld := parts[len(parts)-1]
	sld := strings.Join(parts[:len(parts)-1], ".")
	
	return sld, tld, nil
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func safeString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func safeInt(i *int) string {
	if i == nil {
		return ""
	}
	return strconv.Itoa(*i)
}

// Setup functions
func runInteractiveSetup() error {
	fmt.Println("\n======================================")
	fmt.Println("namecheap-domain-export Setup Wizard")
	fmt.Println("======================================\n")
	
	// Check dotenvx
	if err := checkDotenvx(); err != nil {
		return err
	}
	
	// Check if .env already exists
	if _, err := os.Stat(".env"); err == nil {
		fmt.Println("⚠️  .env file already exists!")
		if !confirm("Do you want to overwrite it?") {
			fmt.Println("Setup cancelled")
			return nil
		}
		// Backup existing file
		backupFile(".env")
	}
	
	// Ask which mode
	fmt.Println("\n🔧 How will you use namecheap-domain-export?")
	fmt.Println("1) Direct connection to Namecheap API")
	fmt.Println("2) Via namecheap-api-filter proxy")
	fmt.Println()
	reader := bufio.NewReader(os.Stdin)
	mode := readLine(reader, "Select option (1 or 2): ")
	
	var envContent string
	
	switch mode {
	case "1":
		fmt.Println("\n📡 Setting up for direct Namecheap API access...\n")
		
		apiUser := readLine(reader, "Enter your Namecheap username: ")
		
		fmt.Println("\n💡 You can find your API key at: https://ap.www.namecheap.com/settings/tools/apiaccess/")
		apiKey := readPassword("Enter your Namecheap API key: ")
		
		fmt.Printf("\n🌐 Your current IP address is: %s\n", getCurrentIP())
		clientIP := readLine(reader, "Enter your whitelisted IP address: ")
		
		sandbox := "false"
		fmt.Println()
		if confirm("Use Namecheap sandbox?") {
			sandbox = "true"
		}
		
		envContent = fmt.Sprintf(`# namecheap-domain-export environment variables

# For direct Namecheap API usage:
NAMECHEAP_API_USER=%s
NAMECHEAP_API_KEY=%s
NAMECHEAP_CLIENT_IP=%s

# Optional: Use Namecheap sandbox API (default: false)
NAMECHEAP_SANDBOX=%s
`, apiUser, apiKey, clientIP, sandbox)
		
	case "2":
		fmt.Println("\n🔌 Setting up for namecheap-api-filter proxy access...\n")
		
		authToken := readLine(reader, "Enter your namecheap-api-filter AUTH_TOKEN: ")
		
		sandbox := "false"
		fmt.Println()
		if confirm("Use sandbox mode?") {
			sandbox = "true"
		}
		
		envContent = fmt.Sprintf(`# namecheap-domain-export environment variables

# For namecheap-api-filter usage:
# Only NAMECHEAP_API_KEY is required (use the filter's AUTH_TOKEN value)
NAMECHEAP_API_KEY=%s

# Optional: Use Namecheap sandbox API (default: false)
NAMECHEAP_SANDBOX=%s
`, authToken, sandbox)
		
	default:
		return fmt.Errorf("invalid option selected")
	}
	
	// Write .env file
	if err := os.WriteFile(".env", []byte(envContent), 0600); err != nil {
		return fmt.Errorf("failed to write .env: %v", err)
	}
	
	fmt.Println("\n✅ .env file created successfully!")
	
	// Encrypt with dotenvx
	fmt.Println("\n🔒 Encrypting .env file with dotenvx...")
	if err := runDotenvxEncrypt(); err != nil {
		return fmt.Errorf("encryption failed: %v", err)
	}
	
	fmt.Println("✅ Encryption successful!")
	fmt.Println("\n⚠️  IMPORTANT: Your .env.keys file contains the decryption key")
	fmt.Println("⚠️  Keep it safe and NEVER commit it to version control!")
	
	// Update .gitignore
	updateGitignore()
	
	// Show next steps
	fmt.Println("\n======================================")
	fmt.Println("Setup Complete! Next steps:")
	fmt.Println("======================================\n")
	fmt.Println("1. Export a domain:")
	
	if mode == "1" {
		fmt.Println("   dotenvx run -- go run main.go example.com")
		fmt.Println("   or")
		fmt.Println("   go build && dotenvx run -- ./namecheap-domain-export example.com\n")
		fmt.Println("2. Export to custom file:")
		fmt.Println("   dotenvx run -- ./namecheap-domain-export -output backup.zone example.com")
	} else {
		fmt.Println("   dotenvx run -- go run main.go -endpoint http://localhost:8080 example.com")
		fmt.Println("   or")
		fmt.Println("   go build && dotenvx run -- ./namecheap-domain-export -endpoint http://localhost:8080 example.com\n")
		fmt.Println("2. Export to custom file:")
		fmt.Println("   dotenvx run -- ./namecheap-domain-export -endpoint http://localhost:8080 -output backup.zone example.com")
	}
	
	fmt.Println()
	return nil
}

func checkDotenvx() error {
	if _, err := exec.LookPath("dotenvx"); err != nil {
		fmt.Println("❌ dotenvx is not installed!")
		fmt.Println("\nPlease install dotenvx first:")
		fmt.Println("  curl -sfS https://dotenvx.sh | sh")
		fmt.Println("  or")
		fmt.Println("  brew install dotenvx/brew/dotenvx")
		return fmt.Errorf("dotenvx not found")
	}
	fmt.Println("✅ dotenvx is installed")
	return nil
}

func generateToken() string {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback to timestamp-based token
		return fmt.Sprintf("token-%d", time.Now().Unix())
	}
	return hex.EncodeToString(bytes)
}

func getCurrentIP() string {
	resp, err := http.Get("https://api.ipify.org")
	if err != nil {
		return "unable to detect"
	}
	defer resp.Body.Close()
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "unable to detect"
	}
	
	return string(body)
}

func readLine(reader *bufio.Reader, prompt string) string {
	fmt.Print(prompt)
	input, _ := reader.ReadString('\n')
	return strings.TrimSpace(input)
}

func readPassword(prompt string) string {
	fmt.Print(prompt)
	password, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		// Fallback to regular input
		reader := bufio.NewReader(os.Stdin)
		input, _ := reader.ReadString('\n')
		return strings.TrimSpace(input)
	}
	return string(password)
}

func confirm(prompt string) bool {
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("%s (y/N): ", prompt)
	response, _ := reader.ReadString('\n')
	response = strings.TrimSpace(strings.ToLower(response))
	return response == "y" || response == "yes"
}

func backupFile(filename string) {
	timestamp := time.Now().Format("20060102_150405")
	backupName := fmt.Sprintf("%s.backup.%s", filename, timestamp)
	
	input, err := os.ReadFile(filename)
	if err != nil {
		return
	}
	
	if err := os.WriteFile(backupName, input, 0600); err != nil {
		return
	}
	
	fmt.Printf("📁 Existing %s backed up to %s\n", filename, backupName)
}

func runDotenvxEncrypt() error {
	cmd := exec.Command("dotenvx", "encrypt")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func updateGitignore() {
	// Check if .env.keys is already in .gitignore
	content, err := os.ReadFile(".gitignore")
	if err == nil && strings.Contains(string(content), ".env.keys") {
		return
	}
	
	// Add to .gitignore
	file, err := os.OpenFile(".gitignore", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer file.Close()
	
	file.WriteString("\n# Dotenvx\n.env.keys\n*.env.keys\n")
	fmt.Println("📝 Added .env.keys to .gitignore")
}