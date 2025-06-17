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
                  Author: Muhammed Farhan
```

CrawlX is a comprehensive URL discovery tool designed for security researchers and penetration testers. It combines multiple subdomain enumeration techniques with intelligent URL discovery and high-performance asynchronous crawling to provide extensive reconnaissance capabilities.

## Features

- **Multi-Source Subdomain Enumeration**: Combines crt.sh and subfinder for comprehensive subdomain discovery
- **Intelligent URL Discovery**: Generates URLs using common paths, files, and directories
- **Asynchronous Crawling**: High-performance async HTTP requests with configurable concurrency
- **Rich Output**: Beautiful terminal interface with real-time progress tracking
- **Organized Results**: Results categorized by HTTP status codes and saved in multiple formats
- **Content Analysis**: Extracts page titles and response metadata
- **Detailed Reporting**: JSON output with comprehensive scan statistics

## Installation

### Quick Installation from GitHub

```bash
# Clone the repository
git clone https://github.com/VIRTUAL-VIRUZ/crawlx.git
cd crawlx

# Install Python dependencies
pip install -r requirements.txt

# Make executable (Linux/macOS)
chmod +x crawlx.py

# Run CrawlX
python crawlx.py -d example.com
```

### Manual Installation

#### Prerequisites

1. **Python 3.7+** is required
2. **Subfinder** must be installed for subdomain enumeration

#### Install Subfinder

**Linux/macOS:**
```bash
# Using go install
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Or download from releases
wget https://github.com/projectdiscovery/subfinder/releases/download/v2.6.3/subfinder_2.6.3_linux_amd64.zip
unzip subfinder_2.6.3_linux_amd64.zip
sudo mv subfinder /usr/local/bin/
```

**Windows:**
```powershell
# Download from releases page
# https://github.com/projectdiscovery/subfinder/releases
```

#### Install Python Dependencies

Create a `requirements.txt` file:
```txt
aiohttp>=3.8.0
requests>=2.28.0
rich>=12.0.0
```

Then install:
```bash
pip install -r requirements.txt
```

Or install individually:
```bash
pip install aiohttp requests rich
```

## Quick Start

After installation, you can immediately start using CrawlX:

```bash
# Basic scan
python crawlx.py -d target.com

# Scan with custom settings
python crawlx.py -d target.com -o my_results -t 100 --timeout 15
```

## Usage

### Basic Usage

```bash
python crawlx.py -d example.com
```

### Advanced Usage

```bash
# Custom output directory
python crawlx.py -d example.com -o my_scan_results

# Increase threads for faster scanning
python crawlx.py -d example.com -t 100

# Adjust timeout for slow targets
python crawlx.py -d example.com --timeout 20

# Complete example with all options
python crawlx.py -d example.com -o custom_output -t 75 --timeout 15
```

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-d, --domain` | Target domain to scan (required) | - |
| `-o, --output` | Output directory for results | `crawlx_results` |
| `-t, --threads` | Number of concurrent threads | `50` |
| `--timeout` | HTTP request timeout in seconds | `10` |

## Output Structure

CrawlX organizes results in a structured directory format:

```
crawlx_results/
├── subdomains/
│   └── all_subdomains.txt          # All discovered subdomains
├── urls/
│   └── all_urls.txt                # All discovered URLs
├── status_codes/
│   ├── status_200.txt              # URLs returning 200 OK
│   ├── status_404.txt              # URLs returning 404 Not Found
│   ├── status_403.txt              # URLs returning 403 Forbidden
│   └── status_[code].txt           # URLs by status code
└── detailed_results.json           # Complete scan results with metadata
```

### Detailed Results Format

The `detailed_results.json` file contains comprehensive information:

```json
[
  {
    "url": "https://example.com/admin",
    "status_code": 200,
    "response_time": 0.245,
    "content_length": 1234,
    "content_type": "text/html; charset=utf-8",
    "title": "Admin Panel"
  }
]
```

## Scanning Process

CrawlX follows a systematic approach:

1. **Subdomain Enumeration**
   - Queries crt.sh certificate transparency logs
   - Runs subfinder for additional subdomain discovery
   - Combines and deduplicates results

2. **URL Discovery**
   - Generates URLs using common paths and files
   - Includes both HTTP and HTTPS variants
   - Covers admin panels, APIs, configuration files, and more

3. **Asynchronous Crawling**
   - Makes concurrent HTTP requests
   - Extracts response metadata and page titles
   - Categorizes results by HTTP status codes

4. **Result Organization**
   - Saves results in multiple formats
   - Provides detailed statistics and summaries
   - Organizes outputs for easy analysis

## Common Paths Discovered

CrawlX automatically discovers common paths including:

- **Admin Interfaces**: `/admin`, `/administrator`, `/panel`, `/dashboard`
- **Authentication**: `/login`, `/wp-admin`, `/phpmyadmin`
- **API Endpoints**: `/api`, `/api/v1`, `/api/v2`, `/graphql`
- **Configuration Files**: `/robots.txt`, `/sitemap.xml`, `/.git/config`
- **Documentation**: `/docs`, `/swagger`, `/api-docs`
- **Development**: `/test`, `/dev`, `/staging`, `/backup`

## Performance Tuning

### Thread Configuration

- **Default (50 threads)**: Balanced performance for most targets
- **High-performance (100+ threads)**: For targets that can handle high load
- **Conservative (10-25 threads)**: For rate-limited or sensitive targets

### Timeout Settings

- **Fast networks**: 5-10 seconds
- **Standard networks**: 10-15 seconds
- **Slow/unstable networks**: 20+ seconds

## Security Considerations

CrawlX is designed for authorized security testing only:

- Always obtain proper authorization before scanning
- Respect robots.txt and rate limits
- Use appropriate thread counts to avoid overwhelming targets
- Consider legal and ethical implications

## Troubleshooting

### Common Issues

**Subfinder not found:**
```bash
# Verify subfinder installation
subfinder -version

# Check PATH
echo $PATH
```

**Permission denied:**
```bash
# Ensure proper permissions
chmod +x crawlx.py
```

**High memory usage:**
```bash
# Reduce threads for memory-constrained systems
python crawlx.py -d example.com -t 25
```

### Error Handling

CrawlX includes comprehensive error handling:
- Network timeouts are gracefully handled
- Failed requests are logged but don't stop the scan
- Dependencies are verified before execution
- Results are saved even if the scan is interrupted

## Contributing

Contributions are welcome! Here's how to get started:

### Development Setup

```bash
# Fork the repository on GitHub
# Clone your fork
git clone https://github.com/yourusername/crawlx.git
cd crawlx

# Create a new branch
git checkout -b feature/your-feature-name

# Install development dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt  # If available

# Make your changes
# Test your changes
python crawlx.py -d test.com

# Commit and push
git add .
git commit -m "Add your feature description"
git push origin feature/your-feature-name

# Create a Pull Request on GitHub
```

### What to Contribute

Please consider:

1. **Code quality and documentation**
2. **Error handling and edge cases**
3. **Performance optimizations**
4. **Additional enumeration sources**
5. **Output format improvements**
6. **Bug fixes and security improvements**

### Reporting Issues

Please report bugs and feature requests through [GitHub Issues](https://github.com/VIRTUAL-VIRUZ/crawlx/issues).

Include:
- Operating system and Python version
- Complete error messages
- Steps to reproduce the issue
- Expected vs actual behavior

## License

This tool is provided for educational and authorized security testing purposes only. Users are responsible for compliance with applicable laws and regulations.

## Author

**Muhammed Farhan**  
Security Research Team

---

*CrawlX v1.0.0 - Advanced URL Discovery Tool for Security Researchers*
