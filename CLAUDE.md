# Namecheap API Automation Project

## Overview
This project consists of two separate Go modules that automate Namecheap API operations using the Go Namecheap SDK v2.

## Requirements
- Go 1.24.x or later
- Go Namecheap SDK v2: `github.com/namecheap/go-namecheap-sdk/v2`

## Project 1: namecheap-api-filter

### Purpose
A web server that acts as a security proxy for the Namecheap API, allowing controlled access with token-based authentication for DNS management operations.

### Architecture
- **Input**: Static authentication token (not the real Namecheap API key)
- **Network**: Listens on specific IP (designed for Tailscale network with ACLs)
- **Authorization**: Uses real Namecheap API token internally
- **Security**: Only allows pre-approved DNS API operations, denies all others
- **Domain Filtering**: Optional domain allowlist for additional security

### Allowed API Operations
- **Read Operations** (always allowed):
  - `namecheap.domains.dns.getList` - Get DNS servers for domain
  - `namecheap.domains.dns.getHosts` - Get DNS host records
  - `namecheap.domains.dns.getEmailForwarding` - Get email forwarding settings
  - `namecheap.domains.ns.getInfo` - Get nameserver information
- **Write Operations**:
  - `namecheap.domains.dns.setHosts` - Set DNS host records (always allowed, but subject to domain filtering and deletion control)

### Environment Variables
- `AUTH_TOKEN` (required): Static token for client authentication
- `NAMECHEAP_API_USER` (required): Namecheap API username
- `NAMECHEAP_API_KEY` (required): Namecheap API key
- `NAMECHEAP_CLIENT_IP` (required): Whitelisted IP address for Namecheap API
- `ALLOWED_DOMAINS` (optional): Comma-separated list of allowed domains/subdomains. If blank, all domains are allowed
- `ALLOW_DELETE` (optional): Set to "true" to enable delete operations via setHosts. Default: "false"
- `LISTEN_ADDR` (optional): Server listen address. Default: ":8080"
- `NAMECHEAP_SANDBOX` (optional): Set to "true" to use Namecheap sandbox API. Default: "false"

### Domain Filtering
- Supports exact domain matches and subdomain wildcards
- Example: If `ALLOWED_DOMAINS="example.com,test.org"`, allows:
  - `example.com`, `subdomain.example.com`
  - `test.org`, `api.test.org`
- Empty `ALLOWED_DOMAINS` allows all domains

### Important DNS Behavior
- **setHosts Operation**: When updating DNS records, ALL existing host records not included in the API call will be deleted
- **POST Method Recommended**: For domains with more than 10 hostnames, use HTTP POST method
- **Complete Record Set**: Always include existing records when adding new ones to prevent accidental deletion

### API Compatibility
- Must maintain identical API interface to Namecheap's actual API
- Ensures client compatibility without exposing real API credentials
- Response formats must match Namecheap API specifications
- Error responses follow Namecheap XML format

## Project 2: namecheap-domain-export

### Purpose
A CLI tool that exports DNS records from Namecheap to standard BIND format files.

### Functionality
- Queries specific domain (e.g., example.com) via Namecheap API
- Retrieves all DNS entries for the domain
- Exports to standard BIND format flat file

### Compatibility
- Must work with both real Namecheap API and namecheap-api-filter
- Configurable API endpoint
- Supports both authentication methods

### Configuration
- API endpoint URL (real Namecheap API or namecheap-api-filter)
- Authentication credentials
- Target domain name
- Output file path

## Implementation Notes

### Module Structure
- Each project is a separate Go module
- Separate GitHub repositories for each tool
- Independent versioning and deployment

### Dependencies
- Go Namecheap SDK v2 for API operations
- Standard library for HTTP server (namecheap-api-filter)
- CLI framework (consider cobra/cli for namecheap-domain-export)

### Security Considerations
- namecheap-api-filter: Token validation, operation allowlisting, secure credential storage
- namecheap-domain-export: Secure credential handling, endpoint validation

### Error Handling
- Comprehensive error responses matching Namecheap API patterns
- Logging for debugging and audit trails
- Graceful handling of network and API failures