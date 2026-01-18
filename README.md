# CrawlX - Advanced URL Discovery Tool

```
   ▄████▄   ██▀███   ▄▄▄       █     █░ ██▓    ▒██   ██▒
  ▒██▀ ▀█  ▓██ ▒ ██▒▒████▄    ▓█░ █ ░█░▓██▒    ▒▒ █ █ ▒░
  ▒▓█    ▄ ▓██ ░▄█ ▒▒██  ▀█▄  ▒█░ █ ░█ ▒██░    ░░  █   ░
  ▒▓▓▄ ▄██▒▒██▀▀█▄  ░██▄▄▄▄██ ░█░ █ ░█ ▒██░     ░ █ █ ▒ 
  ▒ ▓███▀ ░░██▓ ▒██▒ ▓█   ▓██▒░░██▒██▓ ░██████▒▒██▒ ▒██▒
  ░ ░▒ ▒  ░░ ▒▓ ░▒▓░ ▒▒   ▓▒█░░ ▓░▒ ▒  ░ ▒░▓  ░▒▒ ░ ░▓ ░
    ░  ▒     ░▒ ░ ▒░  ▒   ▒▒ ░  ▒ ░ ░  ░ ░ ▒  ░░░   ░▒ ░
  ░          ░░   ░   ░   ▒     ░   ░    ░ ░    ░    ░  
  ░ ░         ░           ░  ░    ░        ░  ░ ░    ░  
  ░  
              v2.1.0 | Author: Muhammed Farhan
```

CrawlX is a comprehensive URL discovery tool designed for security researchers and penetration testers. It combines multiple subdomain enumeration techniques with intelligent URL discovery and high-performance asynchronous crawling.

## ✨ What's New in v2.1.0

- 📜 **JavaScript Endpoint Extraction** - Parse JS files for hidden API endpoints
- 🔒 **Proxy Support** - HTTP, SOCKS4, and SOCKS5 proxies
- ⏱️ **Rate Limiting** - Avoid WAF detection and rate limits
- 🎭 **Random User-Agents** - Evade fingerprinting
- 📝 **Custom Wordlists** - Use your own path lists
- 🔄 **Recursive Crawling** - Configurable crawl depth
- 📊 **Enhanced Output** - Status-based and parameter-based URL organization
- 📋 **CSV Export** - Easy data analysis
- 🔓 **SSL Toggle** - Handle self-signed certificates

## 🚀 Features

### Core Features
- **Multi-Source Subdomain Enumeration**: Combines crt.sh and subfinder
- **Intelligent URL Discovery**: 100+ common paths built-in
- **Asynchronous Crawling**: High-performance with configurable concurrency
- **Rich Terminal UI**: Beautiful progress tracking with real-time stats

### Advanced Features
- **JavaScript Parsing**: Extract hidden endpoints from JS files
- **Proxy Support**: HTTP, SOCKS4, SOCKS5 proxies for anonymity
- **Rate Limiting**: Control requests per second to avoid detection
- **User-Agent Rotation**: 8 modern browser user-agents
- **Custom Wordlists**: Load your own path wordlists
- **Recursive Crawling**: Discover URLs from page content
- **SSL Verification Toggle**: Handle self-signed certificates

### Output Organization
- **Status Code Files**: URLs organized by HTTP status (200, 301, 403, 404, etc.)
- **Parameter URLs**: Separate files for URLs with query parameters
- **JavaScript Endpoints**: Hidden endpoints extracted from JS files (`js_endpoints.txt`)
- **Multiple Formats**: TXT, JSON, and CSV exports
- **Unique Parameters**: List of all discovered parameter names

## 📦 Installation

### Quick Install

```bash
# Clone the repository
git clone https://github.com/7H3CYF4RX/crawlx.git
cd crawlx

# Install dependencies
pip install -r requirements.txt

# Optional: Install SOCKS proxy support
pip install aiohttp-socks

# Make executable
chmod +x crawlx.py

# Run
python crawlx.py -d example.com
```

### Dependencies

```txt
aiohttp>=3.8.0
requests>=2.28.0
rich>=12.0.0
aiohttp-socks>=0.7.0  # Optional, for SOCKS proxies
```

### Optional: Install Subfinder

For enhanced subdomain enumeration:

```bash
# Using Go
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Or download from releases
# https://github.com/projectdiscovery/subfinder/releases
```

## 📖 Usage

### Basic Usage

```bash
python crawlx.py -d example.com
```

### Advanced Usage

```bash
# Custom output directory and threads
python crawlx.py -d example.com -o my_results -t 100

# With HTTP proxy
python crawlx.py -d example.com --proxy http://127.0.0.1:8080

# With SOCKS5 proxy (e.g., Tor)
python crawlx.py -d example.com --proxy socks5://127.0.0.1:9050

# Rate limiting (10 requests/second)
python crawlx.py -d example.com --rate-limit 10

# Custom wordlist with random user-agents
python crawlx.py -d example.com -w /path/to/wordlist.txt --random-ua

# Deep recursive crawl with SSL disabled
python crawlx.py -d example.com --depth 3 --no-verify-ssl

# Extract endpoints from JavaScript files
python crawlx.py -d example.com --parse-js

# Full featured scan with JS parsing
python crawlx.py -d example.com \
    -o results \
    -t 100 \
    --timeout 15 \
    --rate-limit 20 \
    --depth 2 \
    --random-ua \
    --parse-js \
    --no-verify-ssl
```

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-d, --domain` | Target domain to scan | Required |
| `-o, --output` | Output directory | `crawlx_results` |
| `-t, --threads` | Concurrent threads | `50` |
| `--timeout` | Request timeout (seconds) | `10` |
| `--rate-limit` | Max requests/second (0=unlimited) | `0` |
| `--proxy` | Proxy URL (http/socks4/socks5) | None |
| `-w, --wordlist` | Custom wordlist file | Built-in |
| `--depth` | Recursive crawl depth | `1` |
| `--user-agent` | Custom User-Agent string | Random |
| `--random-ua` | Rotate User-Agents per request | Off |
| `--no-verify-ssl` | Disable SSL verification | Verify |
| `--parse-js` | Extract endpoints from JavaScript files | Off |

## 📂 Output Structure

CrawlX organizes results in a comprehensive directory structure:

```
crawlx_results/
├── subdomains/
│   └── all_subdomains.txt          # All discovered subdomains
│
├── urls/
│   ├── all_urls.txt                # All discovered URLs
│   ├── live_urls.txt               # Only responsive URLs
│   │
│   ├── by_status/                  # URLs organized by status code
│   │   ├── STATUS_INDEX.txt        # Index of all status files
│   │   ├── status_200.txt          # 200 OK responses
│   │   ├── status_301.txt          # 301 Redirects
│   │   ├── status_302.txt          # 302 Redirects
│   │   ├── status_403.txt          # 403 Forbidden
│   │   ├── status_404.txt          # 404 Not Found
│   │   └── status_[code].txt       # Other status codes
│   │
│   ├── parameters/                 # URLs with query parameters
│   │   ├── all_param_urls.txt      # All URLs with parameters
│   │   ├── params_status_200.txt   # Param URLs with 200 status
│   │   ├── params_status_[code].txt
│   │   └── unique_parameters.txt   # List of unique parameter names
│   │
│   └── javascript/                 # JavaScript endpoint extraction
│       ├── js_endpoints.txt        # All extracted endpoints
│       └── parsed_js_files.txt     # List of parsed JS files
│
└── reports/
    ├── detailed_results.json       # Full JSON report with metadata
    ├── results.csv                 # CSV export for analysis
    └── scan_statistics.json        # Scan statistics and timing
```

### Output File Details

#### Status Code Files (`urls/by_status/`)
Each status code gets its own file:
- `status_200.txt` - Successful responses (interesting endpoints)
- `status_301.txt` / `status_302.txt` - Redirects
- `status_403.txt` - Forbidden (access control issues)
- `status_404.txt` - Not found
- `status_500.txt` - Server errors
- `status_0.txt` - Connection failures/timeouts

#### Parameter URLs (`urls/parameters/`)
URLs with query parameters are saved separately for further testing:
- `all_param_urls.txt` - All URLs containing `?param=value`
- `params_status_200.txt` - Live endpoints with parameters (best for injection testing)
- `unique_parameters.txt` - All unique parameter names discovered

#### JavaScript Endpoints (`urls/javascript/`)
Hidden endpoints extracted from JavaScript files:
- `js_endpoints.txt` - All API endpoints and URLs found in JS files
- `parsed_js_files.txt` - List of JavaScript files that were parsed

### JavaScript Endpoint Extraction

The `--parse-js` flag enables extraction of hidden endpoints from JavaScript files. It detects:

| Pattern Type | Examples |
|--------------|----------|
| **API Paths** | `/api/v1/users`, `/rest/data`, `/graphql` |
| **Fetch Calls** | `fetch('/api/endpoint')` |
| **Axios Calls** | `axios.get('/data')`, `axios.post('/submit')` |
| **jQuery AJAX** | `$.ajax({url: '/api'})`, `$.get('/endpoint')` |
| **XMLHttpRequest** | `xhr.open('GET', '/api/data')` |
| **Object Properties** | `endpoint: '/api/v1'`, `baseURL: '/rest/'` |
| **Route Definitions** | `path: '/dashboard'`, `route: '/admin'` |
| **Full URLs** | `https://api.example.com/v1/users` |

Example output in `js_endpoints.txt`:
```
# JavaScript Endpoints Extracted from 15 JS files
# Total endpoints found: 47
# ==================================================

https://example.com/api/v1/auth/login
https://example.com/api/v1/users
https://example.com/api/v1/users/profile
https://example.com/api/v2/data
https://example.com/graphql
https://example.com/internal/admin
...
```

### JSON Report Format

```json
{
  "url": "https://example.com/api?id=1",
  "status_code": 200,
  "response_time": 0.245,
  "content_length": 1234,
  "content_type": "application/json",
  "title": "API Response",
  "redirect_url": "",
  "has_params": true,
  "params": {"id": ["1"]}
}
```

## 🔧 Configuration Tips

### Thread Configuration

| Threads | Use Case |
|---------|----------|
| 10-25 | Rate-limited or sensitive targets |
| 50 | Balanced (default) |
| 100-150 | Fast networks, resilient targets |
| 200+ | High-bandwidth, distributed targets |

### Rate Limiting

```bash
# Stealth mode - 1 request every 2 seconds
python crawlx.py -d example.com --rate-limit 0.5

# Normal - 10 requests per second
python crawlx.py -d example.com --rate-limit 10

# Aggressive - 50 requests per second
python crawlx.py -d example.com --rate-limit 50

# Unlimited (default)
python crawlx.py -d example.com --rate-limit 0
```

### Proxy Examples

```bash
# HTTP proxy (Burp Suite)
python crawlx.py -d example.com --proxy http://127.0.0.1:8080

# SOCKS5 (Tor)
python crawlx.py -d example.com --proxy socks5://127.0.0.1:9050

# Authenticated proxy
python crawlx.py -d example.com --proxy http://user:pass@proxy.com:8080
```

## 🛡️ Built-in Wordlist

CrawlX includes 100+ common paths covering:

- **Admin Interfaces**: `/admin`, `/administrator`, `/panel`, `/dashboard`
- **Authentication**: `/login`, `/logout`, `/register`, `/signin`
- **API Endpoints**: `/api/v1`, `/api/v2`, `/graphql`, `/rest`
- **Documentation**: `/docs`, `/swagger`, `/api-docs`, `/openapi`
- **Configuration**: `/robots.txt`, `/sitemap.xml`, `/.env`, `/.git/`
- **Backup/Dev**: `/backup`, `/test`, `/dev`, `/staging`
- **Database**: `/phpmyadmin`, `/adminer`, `/mysql`
- **CMS**: `/wp-admin`, `/wp-login.php`, `/joomla/`, `/drupal/`

### Custom Wordlist

Create a text file with one path per line:

```txt
# my_wordlist.txt
/admin
/api/v1/users
/api/v1/config
/internal
/debug
/actuator/health
```

```bash
python crawlx.py -d example.com -w my_wordlist.txt
```

## 🔒 Security Considerations

- **Authorization**: Always obtain proper authorization before scanning
- **Rate Limiting**: Use `--rate-limit` to avoid overwhelming targets
- **Proxy**: Use proxies for anonymity when appropriate
- **Legal**: Ensure compliance with applicable laws and regulations

## 🐛 Troubleshooting

### Common Issues

**SSL Certificate Errors:**
```bash
python crawlx.py -d example.com --no-verify-ssl
```

**SOCKS Proxy Not Working:**
```bash
pip install aiohttp-socks
```

**Rate Limited / Blocked:**
```bash
python crawlx.py -d example.com --rate-limit 5 --random-ua
```

**Memory Issues:**
```bash
python crawlx.py -d example.com -t 25 --depth 1
```

**Subfinder Not Found:**
```bash
# Warning only - CrawlX will still work with crt.sh
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

## 📝 Changelog

### v2.1.0
- Added JavaScript endpoint extraction (`--parse-js`)
- Extracts hidden API endpoints from JS files
- Supports fetch, axios, jQuery AJAX, XMLHttpRequest patterns
- New output directory: `urls/javascript/`
- Saves endpoints to `js_endpoints.txt`
- Tracks parsed JS files in `parsed_js_files.txt`

### v2.0.0
- Added proxy support (HTTP, SOCKS4, SOCKS5)
- Added rate limiting
- Added User-Agent rotation
- Added custom wordlist support
- Added recursive crawling with depth control
- Added SSL verification toggle
- Enhanced output: status-based and parameter-based organization
- Added CSV export format
- Added unique parameters extraction
- Improved error handling
- Updated terminal UI with better statistics

### v1.0.0
- Initial release
- Subdomain enumeration (crt.sh, subfinder)
- URL discovery and async crawling
- Basic status code organization
- JSON export

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## 📄 License

This tool is provided for educational and authorized security testing purposes only. Users are responsible for compliance with applicable laws.

## 👤 Author

**Muhammed Farhan**  
Security Research Team

---

*CrawlX v2.1.0 - Advanced URL Discovery Tool for Security Researchers*
