"""
Enhanced web scraper for Chinese Security Websites (Security & Reliability Improved)
==================================================================================

This script is specifically designed for scraping Chinese cybersecurity websites
with security and reliability improvements:

* **Chinese language support** - Optimized for Chinese websites with proper headers
* **Chinese proxy filtering** - Specifically uses Chinese proxies when available
* **Manual dependency management** - Users must install dependencies manually
* **Input validation** - All external data is validated before use
* **Proper error handling** - Specific exception handling with recovery strategies
* **Windows console compatibility** - All logging avoids Unicode issues

Target Websites
--------------
This scraper is designed to work with Chinese cybersecurity portals including:
- CNVD (China National Vulnerability Database)
- CNNVD (China National Cyber Vulnerability Database) 
- NVDB/SECRSS security advisories
- HKCERT Hong Kong security bulletins
- Chinese security research websites (360, FreeBuf, AnquanKe, etc.)

Installation Requirements
------------------------
Before running this script, install the required dependencies:

    pip install requests beautifulsoup4 playwright
    playwright install --with-deps

Usage
-----
Run the script with Python 3. The script will validate all inputs and
provide detailed error messages if issues occur.
"""

import os
import logging
import time
import random
import re
from urllib.parse import urlparse, urlunparse
from typing import List, Optional, Tuple, Dict, Any
from dataclasses import dataclass
from enum import Enum

# Check for required dependencies
MISSING_DEPS = []
try:
    import json
except ImportError:
    MISSING_DEPS.append("json (built-in)")

try:
    import requests
except ImportError:
    MISSING_DEPS.append("requests")

try:
    from bs4 import BeautifulSoup
except ImportError:
    MISSING_DEPS.append("beautifulsoup4")

try:
    from playwright.sync_api import sync_playwright
    from playwright._impl._errors import TimeoutError as PlaywrightTimeoutError
    from playwright._impl._errors import Error as PlaywrightError
except ImportError:
    MISSING_DEPS.append("playwright")

if MISSING_DEPS:
    print("ERROR: Missing required dependencies:")
    for dep in MISSING_DEPS:
        print(f"  - {dep}")
    print("\nPlease install them with:")
    print("  pip install requests beautifulsoup4 playwright")
    print("  playwright install --with-deps")
    exit(1)


# -----------------------------------------------------------------------------
# Data validation and error handling

class ValidationError(Exception):
    """Raised when input validation fails."""
    pass


class ProxyError(Exception):
    """Raised when proxy operations fail."""
    pass


class ScrapingError(Exception):
    """Raised when scraping operations fail."""
    pass


@dataclass
class ProxyInfo:
    """Validated proxy information."""
    url: str
    ip: str
    port: int
    type: str
    response_time: float
    
    def __post_init__(self):
        """Validate proxy data after initialization."""
        if not self._is_valid_ip(self.ip):
            raise ValidationError(f"Invalid IP address: {self.ip}")
        if not (1 <= self.port <= 65535):
            raise ValidationError(f"Invalid port: {self.port}")
        if self.type not in ['http', 'https', 'socks4', 'socks5']:
            raise ValidationError(f"Invalid proxy type: {self.type}")
        if self.response_time < 0:
            raise ValidationError(f"Invalid response time: {self.response_time}")
    
    @staticmethod
    def _is_valid_ip(ip: str) -> bool:
        """Validate IP address format."""
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except ValueError:
            return False


class URLValidator:
    """Validates and sanitizes URLs."""
    
    ALLOWED_SCHEMES = {'http', 'https'}
    
    @classmethod
    def validate_url(cls, url: str) -> str:
        """Validate and normalize a URL."""
        if not isinstance(url, str) or not url.strip():
            raise ValidationError("URL cannot be empty")
        
        try:
            parsed = urlparse(url)
        except Exception as e:
            raise ValidationError(f"Invalid URL format: {e}")
        
        if parsed.scheme not in cls.ALLOWED_SCHEMES:
            raise ValidationError(f"Unsupported URL scheme: {parsed.scheme}")
        
        if not parsed.netloc:
            raise ValidationError("URL missing domain")
        
        # Basic domain validation - no restrictive whitelist
        # This allows access to any legitimate Chinese security websites
        domain = parsed.netloc.lower()
        if '..' in domain or domain.startswith('.') or domain.endswith('.'):
            raise ValidationError("Invalid domain format")
        
        # Rebuild URL to ensure it's properly formatted
        return urlunparse(parsed)
    
    @classmethod
    def validate_proxy_url(cls, proxy_url: str) -> str:
        """Validate a proxy URL."""
        if not isinstance(proxy_url, str) or not proxy_url.strip():
            raise ValidationError("Proxy URL cannot be empty")
        
        # Check for supported proxy formats
        if proxy_url.startswith(('http://', 'https://', 'socks4://', 'socks5://')):
            try:
                parsed = urlparse(proxy_url)
                if not parsed.hostname or not parsed.port:
                    raise ValidationError("Proxy URL missing hostname or port")
                return proxy_url
            except Exception as e:
                raise ValidationError(f"Invalid proxy URL format: {e}")
        else:
            raise ValidationError("Proxy URL must start with http://, https://, socks4://, or socks5://")


class JSONValidator:
    """Validates JSON data from external sources."""
    
    @staticmethod
    def validate_proxy_json(data: Any) -> Dict[str, Any]:
        """Validate proxy JSON data structure."""
        if not isinstance(data, dict):
            raise ValidationError("Proxy data must be a JSON object")
        
        if 'proxies' not in data:
            raise ValidationError("Proxy data missing 'proxies' field")
        
        proxies = data['proxies']
        if not isinstance(proxies, list):
            raise ValidationError("'proxies' field must be a list")
        
        if len(proxies) > 10000:  # Reasonable limit
            raise ValidationError("Too many proxies in response (possible attack)")
        
        return data
    
    @staticmethod
    def validate_proxy_item(item: Any) -> Optional[ProxyInfo]:
        """Validate and convert a single proxy item."""
        if not isinstance(item, dict):
            return None
        
        try:
            # Extract required fields
            ip = item.get('ip', '')
            port = item.get('port')
            proxy_type = str(item.get('type', '')).lower()
            country = str(item.get('country', '')).lower()
            response_time = float(item.get('response_time_ms', 9999))
            
            # Filter for Chinese proxies only
            if country != 'china':
                return None
            
            # Skip very slow proxies
            if response_time > 600:
                return None
            
            # Convert port to int
            if isinstance(port, str):
                port = int(port)
            elif not isinstance(port, int):
                return None
            
            # Build proxy URL
            if proxy_type == 'https':
                proxy_url = f"http://{ip}:{port}"
                proxy_type = 'http'
            elif proxy_type in ['socks4', 'socks5']:
                proxy_url = f"{proxy_type}://{ip}:{port}"
            else:
                return None
            
            return ProxyInfo(
                url=proxy_url,
                ip=ip,
                port=port,
                type=proxy_type,
                response_time=response_time
            )
            
        except (ValueError, TypeError, ValidationError):
            return None


# -----------------------------------------------------------------------------
# Configuration

# URL to the proxy list (JSON) - validated source
PROXY_JSON_URL = "https://raw.githubusercontent.com/arandomguyhere/Proxy-Hound/refs/heads/main/docs/proxy_hound_results.json"

# List of pages to scrape - will be validated
URLS: List[str] = [
    # Official vulnerability and threat advisories
    "https://www.secrss.com/articles/82907",
    "https://www.secrss.com/articles/82954",
    "https://www.cnvd.org.cn/flaw/show/CNVD-2025-21033",
    "https://www.cnvd.org.cn/flaw/show/CNVD-2025-21108",
    "https://www.cnvd.org.cn/flaw/show/CNVD-2025-21109",
    "https://www.hkcert.org/tc/security-bulletin/cisco-ios-xr-multiple-vulnerabilities_20250911",
    "https://www.hkcert.org/tc/security-bulletin/gitlab-multiple-vulnerabilities_20250911",
    # Additional recommended sources
    "https://cert.360.cn/daily",
    "https://sec.today/pulses",
    "https://i.hacking8.com",
    "https://sec-wiki.com/index.php",
    "https://govuln.com/news",
    "https://www.freebuf.com",
    "https://www.anquanke.com",
    "https://ti.dbappsecurity.com.cn/info",
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
]


# -----------------------------------------------------------------------------
# Proxy handling with proper error handling

def get_chinese_proxies(json_url: str, max_count: int = 10) -> List[ProxyInfo]:
    """Retrieve and validate Chinese proxy servers from a JSON endpoint."""
    proxies: List[ProxyInfo] = []
    
    try:
        logging.info("Fetching proxy list...")
        
        # Validate the proxy URL
        validated_url = URLValidator.validate_proxy_url(json_url)
        
        # Make request with proper error handling
        try:
            response = requests.get(validated_url, timeout=30)
            response.raise_for_status()
        except requests.RequestException as e:
            raise ProxyError(f"Failed to fetch proxy list: {e}")
        
        # Parse and validate JSON
        try:
            data = response.json()
        except json.JSONDecodeError as e:
            raise ProxyError(f"Invalid JSON in proxy response: {e}")
        
        # Validate JSON structure
        validated_data = JSONValidator.validate_proxy_json(data)
        
        # Process proxy items with validation
        valid_proxies = []
        for item in validated_data['proxies']:
            proxy_info = JSONValidator.validate_proxy_item(item)
            if proxy_info:
                valid_proxies.append(proxy_info)
        
        # Sort by response time and return top entries
        valid_proxies.sort(key=lambda x: x.response_time)
        proxies = valid_proxies[:max_count]
        
        logging.info(f"Found {len(proxies)} valid Chinese proxies")
        for i, proxy in enumerate(proxies[:5]):
            logging.info(f"  {i+1}. {proxy.url} ({proxy.response_time}ms)")
        
    except (ValidationError, ProxyError) as e:
        logging.error(f"Proxy validation error: {e}")
    except Exception as e:
        logging.error(f"Unexpected error fetching proxies: {e}")
    
    return proxies


def test_proxy(proxy_info: ProxyInfo) -> bool:
    """Test whether a proxy works with proper error handling."""
    proxy_url = proxy_info.url
    
    # For HTTP proxies, do an initial request check
    if proxy_info.type == 'http':
        try:
            proxies = {"http": proxy_url, "https": proxy_url}
            resp = requests.get("http://httpbin.org/ip", proxies=proxies, timeout=8)
            if resp.status_code != 200:
                return False
        except requests.RequestException:
            return False
    
    # Test with Playwright
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True, proxy={"server": proxy_url})
            context = browser.new_context(
                user_agent=random.choice(USER_AGENTS),
                ignore_https_errors=True
            )
            page = context.new_page()
            page.goto("https://httpbin.org/ip", timeout=10000)
            content = page.content()
            page.close()
            browser.close()
            return len(content) > 100
    except (PlaywrightTimeoutError, PlaywrightError):
        return False
    except Exception:
        return False


def choose_proxy(proxy_list: List[ProxyInfo]) -> Optional[ProxyInfo]:
    """Select the first working proxy from a list."""
    if not proxy_list:
        return None
    
    for idx, proxy in enumerate(proxy_list, start=1):
        logging.info(f"Testing proxy {idx}/{len(proxy_list)}: {proxy.url}")
        try:
            if test_proxy(proxy):
                logging.info("  [PASS] Proxy works, selecting this proxy")
                return proxy
            else:
                logging.info("  [FAIL] Proxy did not work")
        except Exception as e:
            logging.info(f"  [ERROR] Proxy test failed: {e}")
    
    logging.warning("No working proxies found")
    return None


# -----------------------------------------------------------------------------
# Scraping utilities with proper error handling

def slugify(url: str) -> str:
    """Convert a URL into a filesystem-safe base name."""
    parsed = urlparse(url)
    path = parsed.netloc + parsed.path
    safe = ''.join(c if c.isalnum() else '_' for c in path)
    return safe[:200]


def extract_text(html: str) -> str:
    """Extract visible text from HTML content."""
    if not isinstance(html, str):
        raise ValidationError("HTML content must be a string")
    
    try:
        soup = BeautifulSoup(html, "html.parser")
        for tag in soup(["script", "style"]):
            tag.decompose()
        text = soup.get_text(separator="\n")
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        return "\n".join(lines)
    except Exception as e:
        raise ScrapingError(f"Failed to extract text: {e}")


def save_results(url: str, title: str, text: str, screenshot_data: bytes, 
                base_dir: str, proxy_used: Optional[str]) -> None:
    """Write scraped content and screenshot to disk with error handling."""
    try:
        filename_base = slugify(url)
        
        # Validate inputs
        if not isinstance(text, str):
            raise ValidationError("Text content must be a string")
        if not isinstance(screenshot_data, bytes):
            raise ValidationError("Screenshot data must be bytes")
        
        # Write text file
        txt_path = os.path.join(base_dir, f"{filename_base}.txt")
        with open(txt_path, "w", encoding="utf-8") as f:
            f.write(f"URL: {url}\n")
            f.write(f"Title: {title}\n")
            f.write(f"Proxy: {proxy_used or 'direct'}\n")
            f.write(f"Content length: {len(text)} characters\n")
            f.write(f"Scraped at: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("-" * 50 + "\n\n")
            f.write(text)
        
        # Write screenshot
        screenshot_dir = os.path.join(base_dir, "screenshots")
        os.makedirs(screenshot_dir, exist_ok=True)
        img_path = os.path.join(screenshot_dir, f"{filename_base}.png")
        with open(img_path, "wb") as f:
            f.write(screenshot_data)
            
    except (OSError, IOError) as e:
        raise ScrapingError(f"Failed to save results: {e}")


def scrape_page(url: str, page, base_dir: str, proxy_used: Optional[str]) -> bool:
    """Fetch a single page with comprehensive error handling."""
    try:
        logging.info(f"Navigating to {url}")
        
        # Random delay
        time.sleep(random.uniform(2, 5))
        
        # Try different loading strategies
        page_loaded = False
        strategies = [
            ("networkidle", 60000),
            ("domcontentloaded", 45000),
            ("load", 30000)
        ]
        
        for strategy, timeout in strategies:
            try:
                page.goto(url, wait_until=strategy, timeout=timeout)
                page_loaded = True
                break
            except PlaywrightTimeoutError:
                logging.warning(f"Timeout with {strategy} strategy, trying next...")
                continue
            except PlaywrightError as e:
                logging.warning(f"Playwright error with {strategy}: {e}")
                continue
        
        if not page_loaded:
            raise ScrapingError("All page loading strategies failed")
        
        # Additional wait for dynamic content
        time.sleep(3)
        
        # Capture title with error handling
        try:
            title = page.title() or "Untitled"
        except PlaywrightError:
            title = "Title extraction failed"
        
        # Capture screenshot with error handling
        try:
            screenshot_data = page.screenshot(full_page=True)
        except PlaywrightError as e:
            raise ScrapingError(f"Screenshot capture failed: {e}")
        
        # Extract HTML content
        try:
            html_content = page.content()
        except PlaywrightError as e:
            raise ScrapingError(f"Content extraction failed: {e}")
        
        # Extract and validate text
        text_content = extract_text(html_content)
        if len(text_content.strip()) < 50:
            raise ScrapingError("Extracted very little content - page may be blocked or empty")
        
        # Save results
        save_results(url, title, text_content, screenshot_data, base_dir, proxy_used)
        
        # Safe logging (ASCII only for Windows compatibility)
        safe_title = title.encode('ascii', 'replace').decode('ascii')
        logging.info(f"[SUCCESS] Saved {slugify(url)}")
        logging.info(f"  Title: {safe_title[:50]}{'...' if len(safe_title) > 50 else ''}")
        logging.info(f"  Content length: {len(text_content)} characters")
        
        return True
        
    except (ScrapingError, ValidationError) as e:
        logging.error(f"[FAILED] {url} - {e}")
        return False
    except PlaywrightError as e:
        logging.error(f"[FAILED] {url} - Playwright error: {e}")
        return False
    except Exception as e:
        logging.error(f"[FAILED] {url} - Unexpected error: {e}")
        return False


# -----------------------------------------------------------------------------
# Main execution

def validate_urls(urls: List[str]) -> List[str]:
    """Validate all URLs before processing."""
    validated_urls = []
    for url in urls:
        try:
            validated_url = URLValidator.validate_url(url)
            validated_urls.append(validated_url)
        except ValidationError as e:
            logging.warning(f"Skipping invalid URL '{url}': {e}")
    return validated_urls


def main() -> None:
    """Main execution with comprehensive error handling."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s: %(message)s"
    )
    
    try:
        logging.info("Starting enhanced web scraper")
        
        # Validate URLs
        validated_urls = validate_urls(URLS)
        if not validated_urls:
            logging.error("No valid URLs to process")
            return
        
        logging.info(f"Processing {len(validated_urls)} valid URLs")
        
        # Prepare output directories
        base_dir = "downloaded_articles"
        try:
            os.makedirs(base_dir, exist_ok=True)
            os.makedirs(os.path.join(base_dir, "screenshots"), exist_ok=True)
        except OSError as e:
            logging.error(f"Failed to create output directories: {e}")
            return
        
        # Retrieve and test proxies
        try:
            proxies = get_chinese_proxies(PROXY_JSON_URL, max_count=10)
            working_proxy = choose_proxy(proxies)
        except Exception as e:
            logging.error(f"Proxy setup failed: {e}")
            working_proxy = None
        
        if working_proxy:
            logging.info(f"Using proxy: {working_proxy.url}")
            proxy_url = working_proxy.url
        else:
            logging.info("No working proxy selected; using direct connection")
            proxy_url = None
        
        # Start Playwright session
        try:
            with sync_playwright() as playwright:
                launch_args = {
                    "headless": True,
                    "args": [
                        "--no-sandbox",
                        "--disable-blink-features=AutomationControlled",
                        "--disable-dev-shm-usage",
                    ],
                }
                
                if proxy_url:
                    launch_args["proxy"] = {"server": proxy_url}
                
                browser = playwright.chromium.launch(**launch_args)
                context = browser.new_context(
                    user_agent=random.choice(USER_AGENTS),
                    viewport={"width": 1366, "height": 768},
                    ignore_https_errors=True,
                    extra_http_headers={
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
                        "Accept-Encoding": "gzip, deflate, br",
                        "Connection": "keep-alive",
                        "Upgrade-Insecure-Requests": "1",
                    },
                )
                
                successes = 0
                for idx, url in enumerate(validated_urls, start=1):
                    page = context.new_page()
                    logging.info(f"\nProcessing {idx}/{len(validated_urls)}: {url}")
                    
                    try:
                        if scrape_page(url, page, base_dir, proxy_url):
                            successes += 1
                    finally:
                        page.close()
                    
                    # Polite delay between requests
                    if idx < len(validated_urls):
                        delay = random.uniform(3, 7)
                        logging.info(f"Waiting {delay:.1f} seconds before next URL...")
                        time.sleep(delay)
                
                browser.close()
                
        except PlaywrightError as e:
            logging.error(f"Playwright setup failed: {e}")
            return
        
        # Summary
        logging.info("\n" + "=" * 50)
        logging.info("SCRAPING COMPLETED")
        logging.info("=" * 50)
        logging.info(f"Successfully downloaded: {successes}/{len(validated_urls)} URLs")
        
        if successes == len(validated_urls):
            logging.info("Perfect success! All URLs downloaded successfully")
        elif successes > 0:
            logging.info(f"Partial success: {len(validated_urls) - successes} URLs failed")
            logging.info("Check the logs for more details")
        else:
            logging.error("No URLs were successfully downloaded")
            logging.error("Check network connectivity and proxy settings")
            
    except KeyboardInterrupt:
        logging.info("Scraping interrupted by user")
    except Exception as e:
        logging.error(f"Unexpected error in main execution: {e}")
        raise


if __name__ == "__main__":
    main()
