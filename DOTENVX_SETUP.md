# Dotenvx Setup for namecheap-domain-export

This guide explains how to securely manage credentials for namecheap-domain-export using dotenvx encryption.

## Prerequisites

Install dotenvx:
```bash
# Using curl
curl -sfS https://dotenvx.sh | sh

# Or using npm
npm install -g @dotenvx/dotenvx

# Or using Homebrew
brew install dotenvx/brew/dotenvx
```

## Quick Start

1. **Copy the example environment file**:
   ```bash
   cp .env.example .env
   ```

2. **Edit `.env` based on your usage**:
   ```bash
   nano .env  # or use your preferred editor
   ```

3. **Encrypt the `.env` file**:
   ```bash
   dotenvx encrypt
   ```
   
   This creates:
   - An encrypted `.env` file (safe to commit)
   - A `.env.keys` file containing your private key (NEVER commit this!)

4. **Add to `.gitignore`**:
   ```bash
   echo ".env.keys" >> .gitignore
   echo "*.env.keys" >> .gitignore
   ```

5. **Run the exporter**:
   ```bash
   # Export a domain
   dotenvx run -- go run main.go example.com
   
   # Or with the built binary
   dotenvx run -- ./namecheap-domain-export example.com
   ```

## Configuration Scenarios

### Scenario 1: Direct Namecheap API

When connecting directly to Namecheap's API, you need:

```env
# Required for direct API access
NAMECHEAP_API_USER=your-namecheap-username
NAMECHEAP_API_KEY=your-namecheap-api-key
NAMECHEAP_CLIENT_IP=your-whitelisted-ip

# Optional
NAMECHEAP_SANDBOX=false
```

Usage:
```bash
dotenvx run -- ./namecheap-domain-export example.com
dotenvx run -- ./namecheap-domain-export -output myzone.txt example.com
```

### Scenario 2: Via namecheap-api-filter

When using namecheap-api-filter as a proxy, you only need:

```env
# The AUTH_TOKEN from your namecheap-api-filter
NAMECHEAP_API_KEY=your-filter-auth-token

# Optional
NAMECHEAP_SANDBOX=false
```

Usage:
```bash
dotenvx run -- ./namecheap-domain-export -endpoint http://localhost:8080 example.com
dotenvx run -- ./namecheap-domain-export -endpoint https://filter.example.com example.com
```

## Environment Variables

- **`NAMECHEAP_API_USER`**: Your Namecheap username (only for direct API)
- **`NAMECHEAP_API_KEY`**: 
  - For direct API: Your Namecheap API key
  - For filter proxy: The AUTH_TOKEN configured in namecheap-api-filter
- **`NAMECHEAP_CLIENT_IP`**: Your whitelisted IP address (only for direct API)
- **`NAMECHEAP_SANDBOX`**: Set to `true` to use sandbox API. Default: `false`

## Production Usage

1. **Extract your private key**:
   ```bash
   cat .env.keys
   # Copy the DOTENV_PRIVATE_KEY value
   ```

2. **Set the private key** where you'll run the tool:
   ```bash
   export DOTENV_PRIVATE_KEY="your-private-key-here"
   ```

3. **Run the exporter**:
   ```bash
   # Direct API
   dotenvx run -- ./namecheap-domain-export example.com
   
   # Via filter
   dotenvx run -- ./namecheap-domain-export -endpoint https://api-filter.example.com example.com
   ```

## Multiple Configurations

You can maintain different encrypted configurations:

```bash
# For direct API access
cp .env.example .env.direct
# Edit with Namecheap credentials
dotenvx encrypt -f .env.direct

# For filter access
echo "NAMECHEAP_API_KEY=filter-token-here" > .env.filter
dotenvx encrypt -f .env.filter

# Use specific configuration
dotenvx run -f .env.direct -- ./namecheap-domain-export example.com
dotenvx run -f .env.filter -- ./namecheap-domain-export -endpoint http://localhost:8080 example.com
```

## Examples

### Export to default filename (domain.zone):
```bash
dotenvx run -- ./namecheap-domain-export example.com
```

### Export to custom filename:
```bash
dotenvx run -- ./namecheap-domain-export -output /path/to/backup.zone example.com
```

### Export via filter with custom output:
```bash
dotenvx run -- ./namecheap-domain-export -endpoint http://localhost:8080 -output example-backup.zone example.com
```

### Use sandbox environment:
```bash
dotenvx run -- ./namecheap-domain-export -sandbox example.com
```

## Security Notes

- Never pass API keys via command line arguments
- Keep `.env.keys` files secure and backed up
- Use different credentials for different environments
- When using the filter, you don't need to expose your real Namecheap credentials