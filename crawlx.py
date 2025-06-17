#!/usr/bin/env python3
"""
CrawlX - Advanced URL Discovery Tool for Security Researchers
Author: Security Research Team
Version: 1.0.0
"""

import asyncio
import aiohttp
import requests
import json
import re
import os
import sys
import argparse
import subprocess
import time
from urllib.parse import urljoin, urlparse, parse_qs
from pathlib import Path
from typing import Set, List, Dict, Optional
from dataclasses import dataclass
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

@dataclass
class URLResult:
    url: str
    status_code: int
    response_time: float
    content_length: int
    content_type: str
    title: str = ""
    
class CrawlX:
    def __init__(self, domain: str, output_dir: str = "crawlx_results", threads: int = 50, timeout: int = 10):
        self.domain = domain.strip().lower()
        self.output_dir = Path(output_dir)
        self.threads = threads
        self.timeout = timeout
        self.console = Console()
        self.subdomains: Set[str] = set()
        self.urls: Set[str] = set()
        self.results: List[URLResult] = []
        self.session = None
        self.stats = {
            'subdomains_found': 0,
            'urls_discovered': 0,
            'urls_crawled': 0,
            'active_urls': 0,
            'status_codes': {}
        }
        
        # Create output directory structure
        self.output_dir.mkdir(exist_ok=True)
        (self.output_dir / "subdomains").mkdir(exist_ok=True)
        (self.output_dir / "urls").mkdir(exist_ok=True)
        (self.output_dir / "status_codes").mkdir(exist_ok=True)
        
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
                  Author: Muhammed Farhan
        """
        self.console.print(banner, style="bold cyan")
        
    def check_dependencies(self):
        """Check if required tools are installed"""
        tools = ['subfinder']
        missing_tools = []
        
        for tool in tools:
            try:
                subprocess.run([tool, '-version'], capture_output=True, check=True)
            except (subprocess.CalledProcessError, FileNotFoundError):
                missing_tools.append(tool)
        
        if missing_tools:
            self.console.print(f"[red]Missing required tools: {', '.join(missing_tools)}[/red]")
            self.console.print("[yellow]Please install subfinder: https://github.com/projectdiscovery/subfinder[/yellow]")
            sys.exit(1)
    
    def enumerate_subdomains_crt(self) -> Set[str]:
        """Enumerate subdomains using crt.sh"""
        subdomains = set()
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            response = requests.get(url, timeout=30)
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name = entry.get('name_value', '')
                    if name:
                        for subdomain in name.split('\n'):
                            subdomain = subdomain.strip().lower()
                            if subdomain and not subdomain.startswith('*'):
                                subdomains.add(subdomain)
        except Exception as e:
            self.console.print(f"[yellow]crt.sh enumeration failed: {e}[/yellow]")
        
        return subdomains
    
    def enumerate_subdomains_subfinder(self) -> Set[str]:
        """Enumerate subdomains using subfinder"""
        subdomains = set()
        try:
            cmd = ['subfinder', '-d', self.domain, '-silent']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        subdomains.add(line.strip().lower())
        except Exception as e:
            self.console.print(f"[yellow]Subfinder enumeration failed: {e}[/yellow]")
        
        return subdomains
    
    def discover_urls_from_domain(self, domain: str) -> Set[str]:
        """Discover URLs from a domain using various techniques"""
        urls = set()
        
        # Common paths and files
        common_paths = [
            '/', '/admin', '/login', '/dashboard', '/api', '/v1', '/v2',
            '/robots.txt', '/sitemap.xml', '/crossdomain.xml', '/clientaccesspolicy.xml',
            '/.well-known/security.txt', '/security.txt', '/.git/config',
            '/wp-admin', '/wp-login.php', '/wp-config.php', '/phpmyadmin',
            '/admin.php', '/admin/login', '/administrator', '/panel',
            '/api/v1', '/api/v2', '/graphql', '/swagger', '/docs',
            '/test', '/dev', '/staging', '/backup', '/old', '/new',
            '/config', '/configuration', '/settings', '/setup'
        ]
        
        # Add protocol variants
        for protocol in ['http', 'https']:
            base_url = f"{protocol}://{domain}"
            urls.add(base_url)
            for path in common_paths:
                urls.add(urljoin(base_url, path))
        
        return urls
    
    def extract_urls_from_response(self, content: str, base_url: str) -> Set[str]:
        """Extract URLs from HTML content"""
        urls = set()
        
        # Extract from href attributes
        href_pattern = r'href=["\']([^"\']+)["\']'
        for match in re.finditer(href_pattern, content, re.IGNORECASE):
            url = match.group(1)
            if url.startswith(('http://', 'https://')):
                urls.add(url)
            elif url.startswith('/'):
                urls.add(urljoin(base_url, url))
        
        # Extract from src attributes
        src_pattern = r'src=["\']([^"\']+)["\']'
        for match in re.finditer(src_pattern, content, re.IGNORECASE):
            url = match.group(1)
            if url.startswith(('http://', 'https://')):
                urls.add(url)
            elif url.startswith('/'):
                urls.add(urljoin(base_url, url))
        
        # Extract from action attributes
        action_pattern = r'action=["\']([^"\']+)["\']'
        for match in re.finditer(action_pattern, content, re.IGNORECASE):
            url = match.group(1)
            if url.startswith(('http://', 'https://')):
                urls.add(url)
            elif url.startswith('/'):
                urls.add(urljoin(base_url, url))
        
        return urls
    
    async def check_url_async(self, session: aiohttp.ClientSession, url: str) -> Optional[URLResult]:
        """Asynchronously check URL status"""
        try:
            start_time = time.time()
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=self.timeout)) as response:
                content = await response.text()
                response_time = time.time() - start_time
                
                # Extract title
                title = ""
                title_match = re.search(r'<title[^>]*>([^<]+)</title>', content, re.IGNORECASE)
                if title_match:
                    title = title_match.group(1).strip()
                
                return URLResult(
                    url=url,
                    status_code=response.status,
                    response_time=response_time,
                    content_length=len(content),
                    content_type=response.headers.get('content-type', ''),
                    title=title
                )
        except Exception:
            return URLResult(
                url=url,
                status_code=0,
                response_time=0,
                content_length=0,
                content_type='',
                title=''
            )
    
    async def crawl_urls_async(self, urls: Set[str], progress: Progress, task_id: TaskID):
        """Asynchronously crawl URLs"""
        connector = aiohttp.TCPConnector(limit=self.threads, limit_per_host=10)
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={'User-Agent': 'CrawlX/1.0.0 Security Scanner'}
        ) as session:
            
            semaphore = asyncio.Semaphore(self.threads)
            
            async def crawl_with_semaphore(url):
                async with semaphore:
                    result = await self.check_url_async(session, url)
                    if result:
                        self.results.append(result)
                        self.stats['urls_crawled'] += 1
                        if result.status_code > 0:
                            self.stats['active_urls'] += 1
                            self.stats['status_codes'][result.status_code] = self.stats['status_codes'].get(result.status_code, 0) + 1
                    progress.update(task_id, advance=1)
                    return result
            
            tasks = [crawl_with_semaphore(url) for url in urls]
            await asyncio.gather(*tasks, return_exceptions=True)
    
    def save_results(self):
        """Save results to files organized by status codes"""
        # Save subdomains
        with open(self.output_dir / "subdomains" / "all_subdomains.txt", 'w') as f:
            for subdomain in sorted(self.subdomains):
                f.write(f"{subdomain}\n")
        
        # Save all URLs
        with open(self.output_dir / "urls" / "all_urls.txt", 'w') as f:
            for result in sorted(self.results, key=lambda x: x.url):
                f.write(f"{result.url}\n")
        
        # Group results by status code
        status_groups = {}
        for result in self.results:
            status = result.status_code
            if status not in status_groups:
                status_groups[status] = []
            status_groups[status].append(result)
        
        # Save URLs by status code
        for status_code, results in status_groups.items():
            filename = f"status_{status_code}.txt"
            with open(self.output_dir / "status_codes" / filename, 'w') as f:
                for result in sorted(results, key=lambda x: x.url):
                    f.write(f"{result.url}\n")
        
        # Save detailed results as JSON
        detailed_results = []
        for result in self.results:
            detailed_results.append({
                'url': result.url,
                'status_code': result.status_code,
                'response_time': result.response_time,
                'content_length': result.content_length,
                'content_type': result.content_type,
                'title': result.title
            })
        
        with open(self.output_dir / "detailed_results.json", 'w') as f:
            json.dump(detailed_results, f, indent=2)
    
    def display_summary(self):
        """Display final summary"""
        table = Table(show_header=True, header_style="bold magenta", box=box.ROUNDED)
        table.add_column("Metric", style="cyan")
        table.add_column("Count", style="green")
        
        table.add_row("Target Domain", self.domain)
        table.add_row("Subdomains Found", str(self.stats['subdomains_found']))
        table.add_row("URLs Discovered", str(self.stats['urls_discovered']))
        table.add_row("URLs Crawled", str(self.stats['urls_crawled']))
        table.add_row("Active URLs", str(self.stats['active_urls']))
        
        self.console.print("\n")
        self.console.print(Panel(table, title="[bold]CrawlX Summary Report[/bold]", border_style="green"))
        
        # Status code breakdown
        if self.stats['status_codes']:
            status_table = Table(show_header=True, header_style="bold yellow", box=box.ROUNDED)
            status_table.add_column("Status Code", style="cyan")
            status_table.add_column("Count", style="green")
            status_table.add_column("Description", style="white")
            
            status_descriptions = {
                200: "OK", 301: "Moved Permanently", 302: "Found", 
                403: "Forbidden", 404: "Not Found", 500: "Internal Server Error",
                0: "Connection Failed"
            }
            
            for status_code in sorted(self.stats['status_codes'].keys()):
                count = self.stats['status_codes'][status_code]
                desc = status_descriptions.get(status_code, "Unknown")
                status_table.add_row(str(status_code), str(count), desc)
            
            self.console.print(Panel(status_table, title="[bold]Status Code Breakdown[/bold]", border_style="yellow"))
        
        self.console.print(f"\n[green]Results saved to: {self.output_dir}[/green]")
    
    async def run(self):
        """Main execution method"""
        self.print_banner()
        self.console.print(f"[bold green]Target Domain:[/bold green] {self.domain}")
        self.console.print(f"[bold green]Output Directory:[/bold green] {self.output_dir}")
        self.console.print(f"[bold green]Threads:[/bold green] {self.threads}")
        self.console.print(f"[bold green]Timeout:[/bold green] {self.timeout}s\n")
        
        # Check dependencies
        self.check_dependencies()
        
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
            subdomain_task = progress.add_task("[cyan]Enumerating subdomains...", total=2)
            
            # crt.sh
            progress.update(subdomain_task, description="[cyan]Fetching from crt.sh...")
            crt_subdomains = self.enumerate_subdomains_crt()
            progress.update(subdomain_task, advance=1)
            
            # subfinder
            progress.update(subdomain_task, description="[cyan]Running subfinder...")
            subfinder_subdomains = self.enumerate_subdomains_subfinder()
            progress.update(subdomain_task, advance=1)
            
            # Combine results
            self.subdomains = crt_subdomains.union(subfinder_subdomains)
            self.subdomains.add(self.domain)  # Add main domain
            self.stats['subdomains_found'] = len(self.subdomains)
            
            progress.update(subdomain_task, description=f"[green]Found {len(self.subdomains)} subdomains")
            
            # URL discovery
            url_discovery_task = progress.add_task("[yellow]Discovering URLs...", total=len(self.subdomains))
            
            for subdomain in self.subdomains:
                discovered_urls = self.discover_urls_from_domain(subdomain)
                self.urls.update(discovered_urls)
                progress.update(url_discovery_task, advance=1)
            
            self.stats['urls_discovered'] = len(self.urls)
            progress.update(url_discovery_task, description=f"[green]Discovered {len(self.urls)} URLs")
            
            # URL crawling
            crawl_task = progress.add_task("[magenta]Crawling URLs...", total=len(self.urls))
            await self.crawl_urls_async(self.urls, progress, crawl_task)
            
            progress.update(crawl_task, description=f"[green]Crawled {len(self.urls)} URLs")
        
        # Save results and display summary
        self.save_results()
        self.display_summary()

def main():
    parser = argparse.ArgumentParser(
        description="CrawlX - Advanced URL Discovery Tool for Security Researchers",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python crawlx.py -d example.com
  python crawlx.py -d example.com -o my_results -t 100 --timeout 15
        """
    )
    
    parser.add_argument('-d', '--domain', required=True, help='Target domain to scan')
    parser.add_argument('-o', '--output', default='crawlx_results', help='Output directory (default: crawlx_results)')
    parser.add_argument('-t', '--threads', type=int, default=50, help='Number of threads (default: 50)')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    
    args = parser.parse_args()
    
    # Validate domain
    if not args.domain or args.domain.startswith(('http://', 'https://')):
        print("Error: Please provide a valid domain name without protocol (e.g., example.com)")
        sys.exit(1)
    
    # Create and run CrawlX
    crawler = CrawlX(
        domain=args.domain,
        output_dir=args.output,
        threads=args.threads,
        timeout=args.timeout
    )
    
    try:
        asyncio.run(crawler.run())
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
