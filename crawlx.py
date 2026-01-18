#!/usr/bin/env python3
"""
CrawlX - Advanced URL Discovery Tool for Security Researchers
Author: Muhammed Farhan
Version: 2.1.0

Features:
- Multi-source subdomain enumeration (crt.sh, subfinder)
- Intelligent URL discovery with custom wordlists
- High-performance async crawling with rate limiting
- Proxy support (HTTP/SOCKS4/SOCKS5)
- Organized output by status codes and parameter URLs
- JavaScript endpoint extraction from JS files
- CSV and JSON export formats
- Recursive crawling with configurable depth
"""

import asyncio
import aiohttp
import requests
import json
import csv
import re
import os
import sys
import argparse
import subprocess
import time
import random
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from pathlib import Path
from typing import Set, List, Dict, Optional, Tuple
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from rich.console import Console
from rich.progress import Progress, TaskID, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn, MofNCompleteColumn
from rich.panel import Panel
from rich.table import Table
from rich.live import Live
from rich.layout import Layout
from rich.text import Text
from rich import box
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

# Optional: SOCKS proxy support
try:
    from aiohttp_socks import ProxyConnector
    SOCKS_AVAILABLE = True
except ImportError:
    SOCKS_AVAILABLE = False

# User-Agent rotation list
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
]

# Default wordlist for URL discovery
DEFAULT_PATHS = [
    # Root and common pages
    '/', '/index', '/index.php', '/index.html', '/home', '/main',
    
    # Admin interfaces
    '/admin', '/admin/', '/admin/login', '/admin/dashboard', '/admin/index.php',
    '/administrator', '/administrator/', '/adminpanel', '/cpanel', '/controlpanel',
    '/panel', '/panel/', '/manage', '/management', '/backend', '/backoffice',
    '/wp-admin', '/wp-admin/', '/wp-login.php', '/wp-config.php',
    
    # Authentication
    '/login', '/login/', '/signin', '/sign-in', '/auth', '/authenticate',
    '/logout', '/signout', '/sign-out', '/register', '/signup', '/sign-up',
    '/forgot-password', '/reset-password', '/password-reset', '/account',
    '/profile', '/user', '/users', '/member', '/members',
    
    # API endpoints
    '/api', '/api/', '/api/v1', '/api/v2', '/api/v3', '/api/v1/', '/api/v2/', '/api/v3/',
    '/rest', '/rest/', '/graphql', '/graphql/', '/gql',
    '/api/users', '/api/user', '/api/auth', '/api/login', '/api/config',
    '/api/admin', '/api/data', '/api/info', '/api/status', '/api/health',
    '/api/docs', '/api/swagger', '/api/openapi', '/api/schema',
    
    # Documentation
    '/docs', '/docs/', '/documentation', '/doc', '/swagger', '/swagger/',
    '/swagger-ui', '/swagger-ui.html', '/swagger.json', '/swagger.yaml',
    '/openapi', '/openapi.json', '/openapi.yaml', '/redoc', '/api-docs',
    '/help', '/faq', '/support', '/wiki',
    
    # Configuration and sensitive files
    '/robots.txt', '/sitemap.xml', '/sitemap_index.xml', '/sitemaps.xml',
    '/crossdomain.xml', '/clientaccesspolicy.xml',
    '/.well-known/security.txt', '/security.txt', '/.well-known/',
    '/.git/', '/.git/config', '/.git/HEAD', '/.gitignore',
    '/.svn/', '/.svn/entries', '/.hg/', '/.env', '/.env.local', '/.env.prod',
    '/config', '/config/', '/config.php', '/config.json', '/config.yaml', '/config.yml',
    '/configuration', '/settings', '/settings.php', '/settings.json',
    '/web.config', '/applicationhost.config', '/phpinfo.php',
    
    # Backup and development
    '/backup', '/backup/', '/backups', '/bak', '/old', '/old/', '/new',
    '/test', '/test/', '/testing', '/dev', '/dev/', '/development',
    '/staging', '/stage', '/demo', '/demo/', '/debug', '/debug/',
    '/temp', '/tmp', '/cache', '/log', '/logs', '/error', '/errors',
    
    # Database interfaces
    '/phpmyadmin', '/phpmyadmin/', '/pma', '/mysql', '/mysqladmin',
    '/adminer', '/adminer.php', '/dbadmin', '/database',
    '/pgadmin', '/postgres', '/mongodb', '/redis',
    
    # CMS specific
    '/wp-content/', '/wp-includes/', '/wp-json/', '/wp-json/wp/v2/',
    '/joomla/', '/drupal/', '/magento/', '/shopify/',
    '/static/', '/assets/', '/media/', '/uploads/', '/files/',
    '/images/', '/img/', '/css/', '/js/', '/scripts/',
    
    # Server status
    '/status', '/server-status', '/server-info', '/nginx-status',
    '/health', '/healthcheck', '/health-check', '/ping', '/version',
    '/info', '/phpinfo', '/info.php', '/metrics', '/stats',
    
    # Common applications
    '/jenkins/', '/jenkins', '/gitlab/', '/gitlab', '/jira/', '/jira',
    '/confluence/', '/bitbucket/', '/sonarqube/', '/grafana/', '/kibana/',
    '/console', '/console/', '/shell', '/terminal', '/webshell',
    
    # Hidden/sensitive paths
    '/.htaccess', '/.htpasswd', '/server.key', '/server.crt',
    '/id_rsa', '/id_rsa.pub', '/authorized_keys',
    '/etc/passwd', '/etc/shadow', '/proc/self/environ',
    
    # File extensions to check
    '/index.asp', '/index.aspx', '/index.jsp', '/default.asp', '/default.aspx',
    '/main.php', '/home.php', '/start.php', '/portal.php',
]

# Common parameters for fuzzing
COMMON_PARAMS = [
    'id', 'page', 'user', 'name', 'file', 'path', 'url', 'redirect',
    'next', 'return', 'callback', 'data', 'query', 'search', 'q',
    'action', 'cmd', 'command', 'exec', 'run', 'do', 'func', 'function',
    'cat', 'category', 'type', 'sort', 'order', 'dir', 'view', 'show',
    'token', 'key', 'api_key', 'apikey', 'secret', 'password', 'pass',
    'username', 'email', 'login', 'admin', 'debug', 'test', 'dev',
]

# JavaScript endpoint extraction patterns
JS_ENDPOINT_PATTERNS = [
    # API paths in strings
    r'["\'](/api/[a-zA-Z0-9_/\-\.]+)["\']',
    r'["\'](/v[0-9]+/[a-zA-Z0-9_/\-\.]+)["\']',
    r'["\'](/rest/[a-zA-Z0-9_/\-\.]+)["\']',
    r'["\'](/graphql[a-zA-Z0-9_/\-\.]*)["\']',
    
    # Full URLs in strings
    r'["\']((https?:)?//[a-zA-Z0-9\-\.]+/[a-zA-Z0-9_/\-\.\?=&]+)["\']',
    
    # Fetch/axios/ajax patterns
    r'fetch\s*\(\s*["\']([^"\')]+)["\']',
    r'axios\.[a-z]+\s*\(\s*["\']([^"\')]+)["\']',
    r'\$\.ajax\s*\(\s*{[^}]*url\s*:\s*["\']([^"\')]+)["\']',
    r'\$\.(get|post|put|delete)\s*\(\s*["\']([^"\')]+)["\']',
    r'XMLHttpRequest[^;]*open\s*\([^,]*,\s*["\']([^"\')]+)["\']',
    
    # Common path patterns
    r'["\'](/[a-zA-Z0-9_\-]+/[a-zA-Z0-9_\-]+(?:/[a-zA-Z0-9_\-\.]+)*)["\']',
    
    # Endpoints in object properties
    r'endpoint\s*:\s*["\']([^"\')]+)["\']',
    r'url\s*:\s*["\']([^"\')]+)["\']',
    r'path\s*:\s*["\']([^"\')]+)["\']',
    r'api\s*:\s*["\']([^"\')]+)["\']',
    r'baseURL\s*:\s*["\']([^"\')]+)["\']',
    r'baseUrl\s*:\s*["\']([^"\')]+)["\']',
    
    # Route definitions (React Router, Vue Router, etc.)
    r'path\s*:\s*["\'](/[^"\')]+)["\']',
    r'route\s*:\s*["\'](/[^"\')]+)["\']',
    
    # Webpack/module patterns
    r'__webpack_require__[^"]*["\']([^"\')]+\.js)["\']',
]

# File extensions to skip when extracting endpoints
SKIP_EXTENSIONS = {
    '.css', '.scss', '.sass', '.less',
    '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.webp',
    '.woff', '.woff2', '.ttf', '.eot', '.otf',
    '.mp3', '.mp4', '.wav', '.avi', '.mov',
    '.pdf', '.doc', '.docx', '.xls', '.xlsx',
    '.zip', '.tar', '.gz', '.rar',
}

@dataclass
class URLResult:
    url: str
    status_code: int
    response_time: float
    content_length: int
    content_type: str
    title: str = ""
    redirect_url: str = ""
    has_params: bool = False
    params: Dict = None
    
    def __post_init__(self):
        if self.params is None:
            self.params = {}

class CrawlX:
    def __init__(
        self,
        domain: str,
        output_dir: str = "crawlx_results",
        threads: int = 50,
        timeout: int = 10,
        proxy: str = None,
        rate_limit: float = 0,
        wordlist: str = None,
        depth: int = 1,
        user_agent: str = None,
        verify_ssl: bool = True,
        random_ua: bool = False,
        parse_js: bool = False
    ):
        self.domain = domain.strip().lower()
        self.output_dir = Path(output_dir)
        self.threads = threads
        self.timeout = timeout
        self.proxy = proxy
        self.rate_limit = rate_limit  # Requests per second (0 = unlimited)
        self.wordlist = wordlist
        self.depth = depth
        self.user_agent = user_agent or random.choice(USER_AGENTS)
        self.verify_ssl = verify_ssl
        self.random_ua = random_ua
        self.parse_js = parse_js
        
        self.console = Console()
        self.subdomains: Set[str] = set()
        self.urls: Set[str] = set()
        self.crawled_urls: Set[str] = set()
        self.results: List[URLResult] = []
        self.param_urls: Set[str] = set()
        self.js_endpoints: Set[str] = set()  # Endpoints extracted from JS files
        self.js_files_parsed: Set[str] = set()  # Track parsed JS files
        self.session = None
        
        self.stats = {
            'subdomains_found': 0,
            'urls_discovered': 0,
            'urls_crawled': 0,
            'active_urls': 0,
            'param_urls': 0,
            'js_endpoints': 0,
            'js_files_parsed': 0,
            'status_codes': {},
            'start_time': None,
            'end_time': None
        }
        
        # Rate limiting
        self.last_request_time = 0
        self.request_lock = asyncio.Lock()
        
        # Create output directory structure
        self._create_output_dirs()
    
    def _create_output_dirs(self):
        """Create organized output directory structure"""
        dirs = [
            self.output_dir,
            self.output_dir / "subdomains",
            self.output_dir / "urls",
            self.output_dir / "urls" / "by_status",
            self.output_dir / "urls" / "parameters",
            self.output_dir / "urls" / "javascript",
            self.output_dir / "reports"
        ]
        for d in dirs:
            d.mkdir(parents=True, exist_ok=True)
    
    def _get_user_agent(self) -> str:
        """Get user agent (random if enabled)"""
        if self.random_ua:
            return random.choice(USER_AGENTS)
        return self.user_agent
    
    def print_banner(self):
        """Display the CrawlX banner"""
        banner = """
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
              [bold white]v2.1.0[/bold white] | Author: [bold cyan]Muhammed Farhan[/bold cyan]
        """
        self.console.print(banner, style="bold cyan")
    
    def check_dependencies(self):
        """Check if required tools are installed"""
        tools = ['subfinder']
        missing_tools = []
        
        for tool in tools:
            try:
                subprocess.run([tool, '-version'], capture_output=True, check=True, timeout=10)
            except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
                missing_tools.append(tool)
        
        if missing_tools:
            self.console.print(f"[yellow]⚠ Optional tools not found: {', '.join(missing_tools)}[/yellow]")
            self.console.print("[yellow]  Subfinder provides better subdomain discovery.[/yellow]")
            self.console.print("[yellow]  Install: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest[/yellow]\n")
    
    def load_wordlist(self) -> List[str]:
        """Load custom wordlist or use default paths"""
        if self.wordlist and Path(self.wordlist).exists():
            try:
                with open(self.wordlist, 'r') as f:
                    custom_paths = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                self.console.print(f"[green]✓ Loaded {len(custom_paths)} paths from wordlist[/green]")
                return custom_paths
            except Exception as e:
                self.console.print(f"[yellow]⚠ Failed to load wordlist: {e}. Using defaults.[/yellow]")
        return DEFAULT_PATHS
    
    def enumerate_subdomains_crt(self) -> Set[str]:
        """Enumerate subdomains using crt.sh"""
        subdomains = set()
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            headers = {'User-Agent': self._get_user_agent()}
            response = requests.get(url, timeout=30, headers=headers, verify=self.verify_ssl)
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name = entry.get('name_value', '')
                    if name:
                        for subdomain in name.split('\n'):
                            subdomain = subdomain.strip().lower()
                            if subdomain and not subdomain.startswith('*'):
                                # Validate subdomain belongs to target
                                if subdomain.endswith(self.domain):
                                    subdomains.add(subdomain)
        except Exception as e:
            self.console.print(f"[yellow]⚠ crt.sh enumeration failed: {e}[/yellow]")
        
        return subdomains
    
    def enumerate_subdomains_subfinder(self) -> Set[str]:
        """Enumerate subdomains using subfinder"""
        subdomains = set()
        try:
            cmd = ['subfinder', '-d', self.domain, '-silent', '-all']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        subdomains.add(line.strip().lower())
        except FileNotFoundError:
            pass  # Subfinder not installed
        except Exception as e:
            self.console.print(f"[yellow]⚠ Subfinder enumeration failed: {e}[/yellow]")
        
        return subdomains
    
    def discover_urls_from_domain(self, domain: str, paths: List[str]) -> Set[str]:
        """Discover URLs from a domain using wordlist"""
        urls = set()
        
        # Add protocol variants
        for protocol in ['https', 'http']:
            base_url = f"{protocol}://{domain}"
            urls.add(base_url)
            for path in paths:
                # Ensure path starts with /
                if not path.startswith('/'):
                    path = '/' + path
                urls.add(urljoin(base_url, path))
        
        return urls
    
    def extract_urls_from_response(self, content: str, base_url: str, current_depth: int) -> Set[str]:
        """Extract URLs from HTML content with depth control"""
        if current_depth >= self.depth:
            return set()
        
        urls = set()
        parsed_base = urlparse(base_url)
        
        # Patterns to extract URLs
        patterns = [
            r'href=["\']([^"\']+)["\']',
            r'src=["\']([^"\']+)["\']',
            r'action=["\']([^"\']+)["\']',
            r'data-url=["\']([^"\']+)["\']',
            r'data-href=["\']([^"\']+)["\']',
            r'content=["\']([^"\']*https?://[^"\']+)["\']',
        ]
        
        for pattern in patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                url = match.group(1)
                
                # Skip data/javascript URLs
                if url.startswith(('data:', 'javascript:', 'mailto:', 'tel:', '#')):
                    continue
                
                # Convert to absolute URL
                if url.startswith(('http://', 'https://')):
                    parsed_url = urlparse(url)
                    # Only include URLs from same domain
                    if parsed_url.netloc.endswith(self.domain):
                        urls.add(url)
                elif url.startswith('//'):
                    urls.add(f"{parsed_base.scheme}:{url}")
                elif url.startswith('/'):
                    urls.add(urljoin(base_url, url))
                else:
                    urls.add(urljoin(base_url, url))
        
        return urls
    
    def extract_params_from_url(self, url: str) -> Dict:
        """Extract query parameters from URL"""
        parsed = urlparse(url)
        return parse_qs(parsed.query)
    
    def has_parameters(self, url: str) -> bool:
        """Check if URL has query parameters"""
        parsed = urlparse(url)
        return bool(parsed.query)
    
    def is_js_file(self, url: str, content_type: str = "") -> bool:
        """Check if URL is a JavaScript file"""
        parsed = urlparse(url)
        path = parsed.path.lower()
        
        # Check extension
        if path.endswith('.js') or path.endswith('.mjs'):
            return True
        
        # Check content type
        if 'javascript' in content_type.lower() or 'ecmascript' in content_type.lower():
            return True
        
        return False
    
    def extract_js_endpoints(self, content: str, source_url: str) -> Set[str]:
        """Extract API endpoints and URLs from JavaScript content"""
        endpoints = set()
        parsed_source = urlparse(source_url)
        base_url = f"{parsed_source.scheme}://{parsed_source.netloc}"
        
        for pattern in JS_ENDPOINT_PATTERNS:
            try:
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in matches:
                    # Handle tuple results from patterns with groups
                    if isinstance(match, tuple):
                        endpoint = match[-1] if match[-1] else match[0]
                    else:
                        endpoint = match
                    
                    if not endpoint:
                        continue
                    
                    # Clean up the endpoint
                    endpoint = endpoint.strip()
                    
                    # Skip empty or invalid endpoints
                    if len(endpoint) < 2:
                        continue
                    
                    # Skip data URLs and javascript: URLs
                    if endpoint.startswith(('data:', 'javascript:', 'mailto:', 'tel:')):
                        continue
                    
                    # Skip file extensions we don't want
                    path_lower = endpoint.lower()
                    if any(path_lower.endswith(ext) for ext in SKIP_EXTENSIONS):
                        continue
                    
                    # Skip common false positives
                    if endpoint in ['/', '//', '#', '.', '..', 'undefined', 'null', 'true', 'false']:
                        continue
                    
                    # Skip if it looks like a version number or random string
                    if re.match(r'^[0-9\.]+$', endpoint):
                        continue
                    
                    # Convert relative URLs to absolute
                    if endpoint.startswith('//'):
                        endpoint = f"{parsed_source.scheme}:{endpoint}"
                    elif endpoint.startswith('/'):
                        endpoint = urljoin(base_url, endpoint)
                    elif not endpoint.startswith(('http://', 'https://')):
                        # Relative path
                        endpoint = urljoin(source_url, endpoint)
                    
                    # Only include endpoints from same domain or relative paths
                    if endpoint.startswith(('http://', 'https://')):
                        endpoint_parsed = urlparse(endpoint)
                        if not endpoint_parsed.netloc.endswith(self.domain):
                            continue
                    
                    endpoints.add(endpoint)
                    
            except Exception:
                continue
        
        return endpoints
    
    async def rate_limit_wait(self):
        """Apply rate limiting if configured"""
        if self.rate_limit > 0:
            async with self.request_lock:
                current_time = time.time()
                min_interval = 1.0 / self.rate_limit
                elapsed = current_time - self.last_request_time
                if elapsed < min_interval:
                    await asyncio.sleep(min_interval - elapsed)
                self.last_request_time = time.time()
    
    async def check_url_async(
        self,
        session: aiohttp.ClientSession,
        url: str,
        current_depth: int = 0
    ) -> Optional[URLResult]:
        """Asynchronously check URL status with enhanced features"""
        try:
            # Apply rate limiting
            await self.rate_limit_wait()
            
            headers = {'User-Agent': self._get_user_agent()}
            start_time = time.time()
            
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                headers=headers,
                allow_redirects=True,
                ssl=self.verify_ssl if self.verify_ssl else False
            ) as response:
                content = await response.text()
                response_time = time.time() - start_time
                
                # Extract title
                title = ""
                title_match = re.search(r'<title[^>]*>([^<]+)</title>', content, re.IGNORECASE)
                if title_match:
                    title = title_match.group(1).strip()[:100]  # Limit title length
                
                # Check for redirect
                redirect_url = ""
                if response.history:
                    redirect_url = str(response.url)
                
                # Check for parameters
                has_params = self.has_parameters(url)
                params = self.extract_params_from_url(url) if has_params else {}
                
                # Track parameter URLs
                if has_params:
                    self.param_urls.add(url)
                
                # Extract more URLs for recursive crawling
                if current_depth < self.depth and response.status == 200:
                    new_urls = self.extract_urls_from_response(content, url, current_depth)
                    for new_url in new_urls:
                        if new_url not in self.crawled_urls:
                            self.urls.add(new_url)
                
                # Extract endpoints from JavaScript files
                if self.parse_js and response.status == 200:
                    content_type = response.headers.get('content-type', '')
                    if self.is_js_file(url, content_type) and url not in self.js_files_parsed:
                        self.js_files_parsed.add(url)
                        js_endpoints = self.extract_js_endpoints(content, url)
                        self.js_endpoints.update(js_endpoints)
                        self.stats['js_files_parsed'] = len(self.js_files_parsed)
                        self.stats['js_endpoints'] = len(self.js_endpoints)
                
                return URLResult(
                    url=url,
                    status_code=response.status,
                    response_time=round(response_time, 3),
                    content_length=len(content),
                    content_type=response.headers.get('content-type', ''),
                    title=title,
                    redirect_url=redirect_url,
                    has_params=has_params,
                    params=params
                )
        except asyncio.TimeoutError:
            return URLResult(
                url=url, status_code=0, response_time=0,
                content_length=0, content_type='', title='Timeout'
            )
        except aiohttp.ClientSSLError:
            return URLResult(
                url=url, status_code=0, response_time=0,
                content_length=0, content_type='', title='SSL Error'
            )
        except Exception as e:
            return URLResult(
                url=url, status_code=0, response_time=0,
                content_length=0, content_type='', title=str(e)[:50]
            )
    
    def _get_connector(self):
        """Get appropriate connector based on proxy settings"""
        if self.proxy:
            if self.proxy.startswith(('socks4://', 'socks5://')):
                if not SOCKS_AVAILABLE:
                    self.console.print("[yellow]⚠ SOCKS proxy requires aiohttp-socks. Install: pip install aiohttp-socks[/yellow]")
                    return aiohttp.TCPConnector(limit=self.threads, limit_per_host=10, ssl=self.verify_ssl)
                return ProxyConnector.from_url(self.proxy, limit=self.threads, limit_per_host=10)
            else:
                # HTTP proxy handled differently
                return aiohttp.TCPConnector(limit=self.threads, limit_per_host=10, ssl=self.verify_ssl)
        return aiohttp.TCPConnector(limit=self.threads, limit_per_host=10, ssl=self.verify_ssl)
    
    async def crawl_urls_async(self, urls: Set[str], progress: Progress, task_id: TaskID, depth: int = 0):
        """Asynchronously crawl URLs with enhanced features"""
        connector = self._get_connector()
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        
        # Set up proxy for HTTP proxies
        proxy_url = self.proxy if self.proxy and self.proxy.startswith('http') else None
        
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={'User-Agent': self._get_user_agent()}
        ) as session:
            
            semaphore = asyncio.Semaphore(self.threads)
            
            async def crawl_with_semaphore(url):
                if url in self.crawled_urls:
                    return None
                self.crawled_urls.add(url)
                
                async with semaphore:
                    result = await self.check_url_async(session, url, depth)
                    if result:
                        self.results.append(result)
                        self.stats['urls_crawled'] += 1
                        if result.status_code > 0:
                            self.stats['active_urls'] += 1
                            self.stats['status_codes'][result.status_code] = \
                                self.stats['status_codes'].get(result.status_code, 0) + 1
                        if result.has_params:
                            self.stats['param_urls'] += 1
                    progress.update(task_id, advance=1)
                    return result
            
            # Create tasks for all URLs
            tasks = [crawl_with_semaphore(url) for url in urls if url not in self.crawled_urls]
            await asyncio.gather(*tasks, return_exceptions=True)
    
    def save_results(self):
        """Save results to organized files"""
        # Save subdomains
        subdomain_file = self.output_dir / "subdomains" / "all_subdomains.txt"
        with open(subdomain_file, 'w') as f:
            for subdomain in sorted(self.subdomains):
                f.write(f"{subdomain}\n")
        
        # Save all URLs
        all_urls_file = self.output_dir / "urls" / "all_urls.txt"
        with open(all_urls_file, 'w') as f:
            for result in sorted(self.results, key=lambda x: x.url):
                f.write(f"{result.url}\n")
        
        # Save live/active URLs only
        live_urls_file = self.output_dir / "urls" / "live_urls.txt"
        with open(live_urls_file, 'w') as f:
            for result in sorted(self.results, key=lambda x: x.url):
                if result.status_code > 0:
                    f.write(f"{result.url}\n")
        
        # Group results by status code and save separately
        status_groups: Dict[int, List[URLResult]] = {}
        for result in self.results:
            status = result.status_code
            if status not in status_groups:
                status_groups[status] = []
            status_groups[status].append(result)
        
        # Save URLs by status code in separate files
        status_dir = self.output_dir / "urls" / "by_status"
        for status_code, results in sorted(status_groups.items()):
            filename = f"status_{status_code}.txt"
            with open(status_dir / filename, 'w') as f:
                for result in sorted(results, key=lambda x: x.url):
                    f.write(f"{result.url}\n")
        
        # Create status code index file
        status_index = self.output_dir / "urls" / "by_status" / "STATUS_INDEX.txt"
        with open(status_index, 'w') as f:
            f.write("=" * 50 + "\n")
            f.write("STATUS CODE INDEX\n")
            f.write("=" * 50 + "\n\n")
            status_descriptions = {
                0: "Connection Failed/Timeout",
                200: "OK - Success",
                201: "Created",
                204: "No Content",
                301: "Moved Permanently",
                302: "Found (Redirect)",
                304: "Not Modified",
                400: "Bad Request",
                401: "Unauthorized",
                403: "Forbidden",
                404: "Not Found",
                405: "Method Not Allowed",
                429: "Too Many Requests",
                500: "Internal Server Error",
                502: "Bad Gateway",
                503: "Service Unavailable",
            }
            for status_code in sorted(status_groups.keys()):
                count = len(status_groups[status_code])
                desc = status_descriptions.get(status_code, "Unknown")
                f.write(f"[{status_code}] {desc}: {count} URLs\n")
                f.write(f"    → status_{status_code}.txt\n\n")
        
        # Save parameter URLs separately
        params_dir = self.output_dir / "urls" / "parameters"
        
        # All parameter URLs
        param_urls_file = params_dir / "all_param_urls.txt"
        param_results = [r for r in self.results if r.has_params]
        with open(param_urls_file, 'w') as f:
            for result in sorted(param_results, key=lambda x: x.url):
                f.write(f"{result.url}\n")
        
        # Parameter URLs grouped by status code
        for status_code in sorted(status_groups.keys()):
            param_status_results = [r for r in status_groups[status_code] if r.has_params]
            if param_status_results:
                filename = f"params_status_{status_code}.txt"
                with open(params_dir / filename, 'w') as f:
                    for result in sorted(param_status_results, key=lambda x: x.url):
                        f.write(f"{result.url}\n")
        
        # Save unique parameters found
        all_params = set()
        for result in param_results:
            all_params.update(result.params.keys())
        
        unique_params_file = params_dir / "unique_parameters.txt"
        with open(unique_params_file, 'w') as f:
            f.write("# Unique parameters discovered\n")
            f.write("# " + "=" * 40 + "\n\n")
            for param in sorted(all_params):
                f.write(f"{param}\n")
        
        # Save JavaScript endpoints
        js_dir = self.output_dir / "urls" / "javascript"
        js_endpoints_file = js_dir / "js_endpoints.txt"
        with open(js_endpoints_file, 'w') as f:
            f.write(f"# JavaScript Endpoints Extracted from {len(self.js_files_parsed)} JS files\n")
            f.write(f"# Total endpoints found: {len(self.js_endpoints)}\n")
            f.write("# " + "=" * 50 + "\n\n")
            for endpoint in sorted(self.js_endpoints):
                f.write(f"{endpoint}\n")
        
        # Save list of parsed JS files
        js_files_list = js_dir / "parsed_js_files.txt"
        with open(js_files_list, 'w') as f:
            f.write(f"# JavaScript files parsed: {len(self.js_files_parsed)}\n")
            f.write("# " + "=" * 50 + "\n\n")
            for js_file in sorted(self.js_files_parsed):
                f.write(f"{js_file}\n")
        
        # Save detailed results as JSON
        detailed_results = []
        for result in self.results:
            detailed_results.append({
                'url': result.url,
                'status_code': result.status_code,
                'response_time': result.response_time,
                'content_length': result.content_length,
                'content_type': result.content_type,
                'title': result.title,
                'redirect_url': result.redirect_url,
                'has_params': result.has_params,
                'params': result.params
            })
        
        json_file = self.output_dir / "reports" / "detailed_results.json"
        with open(json_file, 'w') as f:
            json.dump(detailed_results, f, indent=2)
        
        # Save as CSV
        csv_file = self.output_dir / "reports" / "results.csv"
        with open(csv_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['URL', 'Status Code', 'Response Time', 'Content Length', 
                           'Content Type', 'Title', 'Has Parameters', 'Redirect URL'])
            for result in sorted(self.results, key=lambda x: x.url):
                writer.writerow([
                    result.url,
                    result.status_code,
                    result.response_time,
                    result.content_length,
                    result.content_type,
                    result.title,
                    result.has_params,
                    result.redirect_url
                ])
        
        # Save scan statistics
        self.stats['end_time'] = time.strftime('%Y-%m-%d %H:%M:%S')
        stats_file = self.output_dir / "reports" / "scan_statistics.json"
        with open(stats_file, 'w') as f:
            json.dump(self.stats, f, indent=2)
    
    def display_summary(self):
        """Display final summary with enhanced statistics"""
        # Main summary table
        table = Table(show_header=True, header_style="bold magenta", box=box.ROUNDED)
        table.add_column("Metric", style="cyan", width=25)
        table.add_column("Value", style="green", width=20)
        
        table.add_row("Target Domain", self.domain)
        table.add_row("Subdomains Found", str(self.stats['subdomains_found']))
        table.add_row("URLs Discovered", str(self.stats['urls_discovered']))
        table.add_row("URLs Crawled", str(self.stats['urls_crawled']))
        table.add_row("Active URLs", str(self.stats['active_urls']))
        table.add_row("Parameter URLs", str(self.stats['param_urls']))
        if self.parse_js:
            table.add_row("JS Files Parsed", str(self.stats['js_files_parsed']))
            table.add_row("JS Endpoints", str(self.stats['js_endpoints']))
        
        self.console.print("\n")
        self.console.print(Panel(table, title="[bold]📊 CrawlX Summary Report[/bold]", border_style="green"))
        
        # Status code breakdown
        if self.stats['status_codes']:
            status_table = Table(show_header=True, header_style="bold yellow", box=box.ROUNDED)
            status_table.add_column("Status", style="cyan", width=10)
            status_table.add_column("Count", style="green", width=10)
            status_table.add_column("Description", style="white", width=25)
            status_table.add_column("File", style="dim", width=20)
            
            status_descriptions = {
                0: ("Connection Failed", "🔴"),
                200: ("OK", "🟢"),
                201: ("Created", "🟢"),
                301: ("Moved Permanently", "🟡"),
                302: ("Found", "🟡"),
                304: ("Not Modified", "🟡"),
                400: ("Bad Request", "🔴"),
                401: ("Unauthorized", "🟠"),
                403: ("Forbidden", "🟠"),
                404: ("Not Found", "⚪"),
                405: ("Method Not Allowed", "🟠"),
                429: ("Rate Limited", "🟠"),
                500: ("Server Error", "🔴"),
                502: ("Bad Gateway", "🔴"),
                503: ("Unavailable", "🔴"),
            }
            
            for status_code in sorted(self.stats['status_codes'].keys()):
                count = self.stats['status_codes'][status_code]
                desc, emoji = status_descriptions.get(status_code, ("Unknown", "⚪"))
                status_table.add_row(
                    f"{emoji} {status_code}",
                    str(count),
                    desc,
                    f"status_{status_code}.txt"
                )
            
            self.console.print(Panel(status_table, title="[bold]📈 Status Code Breakdown[/bold]", border_style="yellow"))
        
        # Output files summary
        files_table = Table(show_header=True, header_style="bold blue", box=box.ROUNDED)
        files_table.add_column("Category", style="cyan")
        files_table.add_column("Path", style="green")
        
        files_table.add_row("📁 All URLs", "urls/all_urls.txt")
        files_table.add_row("✅ Live URLs", "urls/live_urls.txt")
        files_table.add_row("📊 By Status", "urls/by_status/")
        files_table.add_row("🔗 Param URLs", "urls/parameters/all_param_urls.txt")
        if self.parse_js:
            files_table.add_row("📜 JS Endpoints", "urls/javascript/js_endpoints.txt")
        files_table.add_row("📋 CSV Report", "reports/results.csv")
        files_table.add_row("📄 JSON Report", "reports/detailed_results.json")
        
        self.console.print(Panel(files_table, title="[bold]📂 Output Files[/bold]", border_style="blue"))
        
        self.console.print(f"\n[bold green]✓ Results saved to: {self.output_dir}[/bold green]\n")
    
    async def run(self):
        """Main execution method"""
        self.stats['start_time'] = time.strftime('%Y-%m-%d %H:%M:%S')
        
        self.print_banner()
        
        # Display configuration
        config_table = Table(show_header=False, box=box.SIMPLE)
        config_table.add_column("Setting", style="bold cyan")
        config_table.add_column("Value", style="green")
        
        config_table.add_row("Target", self.domain)
        config_table.add_row("Output", str(self.output_dir))
        config_table.add_row("Threads", str(self.threads))
        config_table.add_row("Timeout", f"{self.timeout}s")
        config_table.add_row("Rate Limit", f"{self.rate_limit}/s" if self.rate_limit > 0 else "Unlimited")
        config_table.add_row("Proxy", self.proxy or "None")
        config_table.add_row("Crawl Depth", str(self.depth))
        config_table.add_row("SSL Verify", "Yes" if self.verify_ssl else "No")
        config_table.add_row("Random UA", "Yes" if self.random_ua else "No")
        config_table.add_row("Parse JS", "Yes" if self.parse_js else "No")
        
        self.console.print(Panel(config_table, title="[bold]⚙️ Configuration[/bold]", border_style="cyan"))
        self.console.print()
        
        # Check dependencies (non-blocking)
        self.check_dependencies()
        
        # Load wordlist
        paths = self.load_wordlist()
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=self.console,
            transient=False
        ) as progress:
            
            # Subdomain enumeration
            subdomain_task = progress.add_task("[cyan]🔍 Enumerating subdomains...", total=2)
            
            # crt.sh
            progress.update(subdomain_task, description="[cyan]📜 Fetching from crt.sh...")
            crt_subdomains = self.enumerate_subdomains_crt()
            progress.update(subdomain_task, advance=1)
            
            # subfinder
            progress.update(subdomain_task, description="[cyan]🔎 Running subfinder...")
            subfinder_subdomains = self.enumerate_subdomains_subfinder()
            progress.update(subdomain_task, advance=1)
            
            # Combine results
            self.subdomains = crt_subdomains.union(subfinder_subdomains)
            self.subdomains.add(self.domain)  # Add main domain
            self.stats['subdomains_found'] = len(self.subdomains)
            
            progress.update(subdomain_task, description=f"[green]✓ Found {len(self.subdomains)} subdomains")
            
            # URL discovery
            url_discovery_task = progress.add_task(
                "[yellow]🌐 Discovering URLs...",
                total=len(self.subdomains)
            )
            
            for subdomain in self.subdomains:
                discovered_urls = self.discover_urls_from_domain(subdomain, paths)
                self.urls.update(discovered_urls)
                progress.update(url_discovery_task, advance=1)
            
            self.stats['urls_discovered'] = len(self.urls)
            progress.update(url_discovery_task, description=f"[green]✓ Discovered {len(self.urls)} URLs")
            
            # URL crawling
            crawl_task = progress.add_task("[magenta]🕷️ Crawling URLs...", total=len(self.urls))
            await self.crawl_urls_async(self.urls, progress, crawl_task)
            
            progress.update(crawl_task, description=f"[green]✓ Crawled {len(self.crawled_urls)} URLs")
        
        # Save results and display summary
        self.save_results()
        self.display_summary()


def main():
    parser = argparse.ArgumentParser(
        description="CrawlX v2.1 - Advanced URL Discovery Tool for Security Researchers",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scan
  python crawlx.py -d example.com
  
  # Scan with custom settings
  python crawlx.py -d example.com -o results -t 100 --timeout 15
  
  # Scan with proxy and rate limiting
  python crawlx.py -d example.com --proxy http://127.0.0.1:8080 --rate-limit 10
  
  # Scan with SOCKS proxy
  python crawlx.py -d example.com --proxy socks5://127.0.0.1:9050
  
  # Use custom wordlist with random user-agents
  python crawlx.py -d example.com -w /path/to/wordlist.txt --random-ua
  
  # Deep recursive crawl with JS parsing
  python crawlx.py -d example.com --depth 3 --parse-js
  
  # Extract endpoints from JavaScript files
  python crawlx.py -d example.com --parse-js --no-verify-ssl
        """
    )
    
    # Required arguments
    parser.add_argument('-d', '--domain', required=True,
                        help='Target domain to scan (e.g., example.com)')
    
    # Output options
    parser.add_argument('-o', '--output', default='crawlx_results',
                        help='Output directory (default: crawlx_results)')
    
    # Performance options
    parser.add_argument('-t', '--threads', type=int, default=50,
                        help='Number of concurrent threads (default: 50)')
    parser.add_argument('--timeout', type=int, default=10,
                        help='Request timeout in seconds (default: 10)')
    parser.add_argument('--rate-limit', type=float, default=0,
                        help='Max requests per second, 0 = unlimited (default: 0)')
    
    # Proxy options
    parser.add_argument('--proxy', type=str, default=None,
                        help='Proxy URL (http://host:port or socks5://host:port)')
    
    # Crawling options
    parser.add_argument('-w', '--wordlist', type=str, default=None,
                        help='Custom wordlist file for URL discovery')
    parser.add_argument('--depth', type=int, default=1,
                        help='Recursive crawl depth (default: 1)')
    
    # User-Agent options
    parser.add_argument('--user-agent', type=str, default=None,
                        help='Custom User-Agent string')
    parser.add_argument('--random-ua', action='store_true',
                        help='Use random User-Agent for each request')
    
    # SSL options
    parser.add_argument('--no-verify-ssl', action='store_true',
                        help='Disable SSL certificate verification')
    
    # JavaScript parsing
    parser.add_argument('--parse-js', action='store_true',
                        help='Extract endpoints from JavaScript files')
    
    args = parser.parse_args()
    
    # Validate domain
    domain = args.domain.strip()
    if domain.startswith(('http://', 'https://')):
        # Extract domain from URL
        from urllib.parse import urlparse
        parsed = urlparse(domain)
        domain = parsed.netloc
        if not domain:
            print("Error: Invalid domain provided")
            sys.exit(1)
    
    # Create and run CrawlX
    crawler = CrawlX(
        domain=domain,
        output_dir=args.output,
        threads=args.threads,
        timeout=args.timeout,
        proxy=args.proxy,
        rate_limit=args.rate_limit,
        wordlist=args.wordlist,
        depth=args.depth,
        user_agent=args.user_agent,
        verify_ssl=not args.no_verify_ssl,
        random_ua=args.random_ua,
        parse_js=args.parse_js
    )
    
    try:
        asyncio.run(crawler.run())
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user. Saving partial results...")
        crawler.save_results()
        crawler.display_summary()
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
