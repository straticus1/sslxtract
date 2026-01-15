# sslxtract

A blazing fast SSL/TLS certificate extraction utility for any TCP endpoint.

## Features

- **Multi-protocol support**: Direct TLS, SMTP STARTTLS, IMAP, POP3, FTP, XMPP, PostgreSQL
- **Certificate chain extraction**: Get leaf, intermediate, and root certificates
- **Validation**: Verify certificate chains against system trust store
- **Expiration tracking**: Check certificate expiry with days remaining
- **Multiple output formats**: PEM, DER, JSON
- **Batch processing**: Extract from multiple hosts in parallel
- **REST API server**: Remote certificate extraction via HTTPS API

## Installation

```bash
git clone https://github.com/yourusername/sslxtract.git
cd sslxtract
chmod +x sslxtract.py ssl_extract_server.py
```

Requirements: Python 3.7+, OpenSSL (for certificate parsing)

## CLI Usage

### Basic extraction

```bash
# Direct TLS (HTTPS)
./sslxtract.py example.com:443

# SMTP with STARTTLS
./sslxtract.py smtp://smtp.gmail.com:587

# Scan mode - just show info, no output
./sslxtract.py google.com:443 --scan
```

### Certificate validation

```bash
# Validate certificate chain
./sslxtract.py example.com:443 --validate

# Check expiration date
./sslxtract.py example.com:443 --expire-date

# Check entire chain expiration
./sslxtract.py example.com:443 --expire-chain
```

### Saving certificates

```bash
# Save to file
./sslxtract.py example.com:443 --save cert.pem

# Save full chain
./sslxtract.py example.com:443 --chain --save chain.pem

# Save as DER format
./sslxtract.py example.com:443 --der --save cert.der
```

### Piping to OpenSSL

```bash
# Pipe to openssl
./sslxtract.py example.com:443 | openssl x509 -text

# Built-in openssl pipe
./sslxtract.py example.com:443 --openssl x509 -text -noout
```

### Batch operations

```bash
# Multiple targets
./sslxtract.py host1:443 host2:443 host3:443 --scan

# From file
./sslxtract.py -f hosts.txt --scan

# JSON output
./sslxtract.py host1:443 host2:443 --json

# Save all to directory
./sslxtract.py host1:443 host2:443 --save ./certs/
```

### Display options

```bash
# Verbose output (full openssl x509 -text)
./sslxtract.py example.com:443 --scan -v

# Show only leaf certificate
./sslxtract.py example.com:443 --show-leaf

# Show only intermediate certificates
./sslxtract.py example.com:443 --show-intermediate
```

## API Server

### Starting the server

```bash
# Generate self-signed certificate
./ssl_extract_server.py --generate-cert

# Start with generated cert
./ssl_extract_server.py --cert server.crt --key server.key

# Start without SSL (development only)
./ssl_extract_server.py --no-ssl

# Use config file
./ssl_extract_server.py -c config.json
```

### Configuration

Create `config.json` from the example:

```bash
./ssl_extract_server.py --init-config config.json
```

Example configuration:

```json
{
  "host": "0.0.0.0",
  "port": 8443,
  "ssl_cert": "server.crt",
  "ssl_key": "server.key",
  "storage_dir": "./certs",
  "timeout": 10.0,
  "blocked_hosts": ["localhost", "127.0.0.1"],
  "require_auth": true,
  "api_keys": ["your-api-key"],
  "max_concurrent": 10
}
```

### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| GET | `/extract?target=host:port` | Extract certificate |
| POST | `/extract` | Extract with JSON body |
| POST | `/extract/batch` | Batch extraction |
| GET | `/certs` | List stored certificates |
| GET | `/certs/<id>` | Get certificate info |
| GET | `/certs/<id>/pem` | Download PEM file |
| DELETE | `/certs/<id>` | Delete stored certificate |

### API Examples

```bash
# Extract certificate
curl -k "https://localhost:8443/extract?target=google.com:443"

# Extract and save
curl -k -X POST "https://localhost:8443/extract" \
  -H "Content-Type: application/json" \
  -d '{"target": "google.com:443", "save": true}'

# Batch extraction
curl -k -X POST "https://localhost:8443/extract/batch" \
  -H "Content-Type: application/json" \
  -d '{"targets": ["google.com:443", "github.com:443"], "save": true}'

# List stored certificates
curl -k "https://localhost:8443/certs"

# Download certificate
curl -k "https://localhost:8443/certs/<id>/pem" -o cert.pem
```

## Supported Protocols

| Protocol | Port | Method |
|----------|------|--------|
| HTTPS | 443 | Direct TLS |
| SMTPS | 465 | Direct TLS |
| SMTP | 25, 587 | STARTTLS |
| IMAPS | 993 | Direct TLS |
| IMAP | 143 | STARTTLS |
| POP3S | 995 | Direct TLS |
| POP3 | 110 | STARTTLS |
| FTPS | 990 | Direct TLS |
| FTP | 21 | AUTH TLS |
| LDAPS | 636 | Direct TLS |
| XMPP | 5222 | STARTTLS |
| PostgreSQL | 5432 | SSL Request |

## License

MIT License
