# Centralized Log Aggregator with Smart Filtering

A powerful, feature-rich daemon that collects logs from multiple sources (syslog, application logs, kernel messages), applies intelligent filtering based on severity/patterns, and stores them efficiently with rotation and compression. Includes a comprehensive CLI for searching, analyzing, and real-time monitoring.

## Features

### Core Features
- **Multi-source Monitoring**: Collect logs from multiple files using efficient inotify-based file watching
- **Regex-based Filtering**: Include or exclude logs using powerful regex patterns with case-sensitive/insensitive options
- **Severity-based Filtering**: Filter by log severity levels (DEBUG, INFO, WARNING, ERROR, CRITICAL)
- **Automatic Log Rotation**: Configurable file size limits with up to N backup files
- **Compression**: GZIP compression for rotated files to save disk space
- **Multiple Output Formats**: Plain text, JSON, CSV, and Syslog (RFC 5424) formats

### Advanced Features
- **Rate Limiting**: Protect against log flooding with configurable rate limits and burst allowance
- **Statistics Tracking**: Real-time statistics including line counts, bytes processed, severity distribution
- **Callback System**: Register callbacks for log entries, errors, and rotation events
- **Global Tags**: Add custom metadata tags to all log entries
- **Thread-safe Design**: Full thread safety for concurrent access
- **Daemon Mode**: Run as a background service with proper signal handling and PID file management

### CLI Features
- **Search**: Regex search with context, count mode, invert match, and colorized output
- **Tail**: Real-time log monitoring with severity filtering
- **Stats**: Comprehensive log statistics with hourly distribution charts
- **Filter**: Transform and filter logs to different formats
- **Merge**: Combine multiple log files with timestamp-based sorting
- **Watch**: Monitor entire directories for log changes
- **Export**: Export logs to JSON/CSV with time range filtering
- **Rotate**: Manual log rotation with compression

## Building

### Prerequisites
- CMake 3.20+
- C++17 compiler (GCC 8+, Clang 7+)
- Linux system with inotify support
- zlib (for compression support)

### Build Steps
```bash
mkdir build
cd build
cmake ..
make -j$(nproc)
```

### Build Options
```bash
cmake -DBUILD_TESTING=ON ..          # Enable tests (default: ON)
cmake -DENABLE_COVERAGE=ON ..        # Enable code coverage
cmake -DENABLE_CLANG_TIDY=ON ..      # Enable clang-tidy
cmake -DBUILD_SHARED_LIBS=ON ..      # Build shared library
```

### Running Tests
```bash
cd build
ctest --output-on-failure
# Or run directly:
./tests/log_aggregator_tests
```

### Installation
```bash
sudo make install
```

## Usage

### Running the Daemon

#### Basic Usage
```bash
# Run with default settings (monitors /var/log/syslog and /var/log/kern.log)
sudo ./log_aggregator_app

# Run in foreground (no daemon)
./log_aggregator_app --no-daemon -v
```

#### Advanced Configuration
```bash
sudo ./log_aggregator_app \
  -s /var/log/syslog,/var/log/auth.log,/var/log/kern.log \
  -o /var/log/aggregated.log \
  --format json \
  -m 50 \
  -b 10 \
  -z gzip \
  -f "ERROR|CRITICAL|FATAL" \
  -x "healthcheck|heartbeat" \
  --min-severity WARNING \
  -r --max-lines 5000 --burst 500 \
  -t environment=production,service=myapp \
  --stats-file /var/log/aggregator_stats.json \
  -d
```

### Daemon Command Line Options

#### Source Configuration
| Option | Description | Default |
|--------|-------------|---------|
| `-s, --sources` | Comma-separated list of log files to monitor | `/var/log/syslog,/var/log/kern.log` |

#### Output Configuration
| Option | Description | Default |
|--------|-------------|---------|
| `-o, --output` | Output file for aggregated logs | `/var/log/aggregated.log` |
| `--format` | Output format: `plain`, `json`, `csv`, `syslog` | `plain` |
| `-m, --max-size` | Maximum file size in MB before rotation | `100` |
| `-b, --max-backups` | Number of backup files to keep | `5` |
| `-z, --compression` | Compression type: `none`, `gzip`, `zstd` | `none` |
| `--buffer-size` | Buffer size for file operations (bytes) | `8192` |

#### Filter Configuration
| Option | Description | Default |
|--------|-------------|---------|
| `-f, --filters` | Regex patterns to include logs | `ERROR\|WARNING` |
| `-x, --exclude` | Regex patterns to exclude logs | - |
| `--min-severity` | Minimum severity level | `DEBUG` |

#### Rate Limiting
| Option | Description | Default |
|--------|-------------|---------|
| `-r, --rate-limit` | Enable rate limiting | `false` |
| `--max-lines` | Max lines per second | `1000` |
| `--burst` | Burst allowance | `100` |

#### Daemon Options
| Option | Description | Default |
|--------|-------------|---------|
| `-d, --daemon` | Run as daemon | `true` |
| `--no-daemon` | Run in foreground | - |
| `--pid-file` | PID file path | `/var/run/log_aggregator.pid` |
| `-v, --verbose` | Verbose output | `false` |

#### Metadata Options
| Option | Description | Default |
|--------|-------------|---------|
| `--hostname` | Override hostname | System hostname |
| `-t, --tags` | Global tags (key=value format) | - |
| `--stats-file` | Export statistics on shutdown | - |
| `--stats-interval` | Print stats interval (seconds) | `0` (disabled) |

### CLI Tool Commands

#### Search Logs
```bash
# Basic search
./log_aggregator_cli search /var/log/aggregated.log "ERROR"

# Case-insensitive search
./log_aggregator_cli search /var/log/aggregated.log "error" -i

# Show context around matches
./log_aggregator_cli search /var/log/aggregated.log "ERROR" -C --context-lines 3

# Count matches only
./log_aggregator_cli search /var/log/aggregated.log "ERROR" -c

# Invert match (show non-matching lines)
./log_aggregator_cli search /var/log/aggregated.log "DEBUG" -v

# Output as JSON
./log_aggregator_cli search /var/log/aggregated.log "ERROR" -f json

# Filter by severity
./log_aggregator_cli search /var/log/aggregated.log ".*" -s ERROR

# Limit results
./log_aggregator_cli search /var/log/aggregated.log "ERROR" -m 100
```

#### Tail Logs
```bash
# Basic tail (last 10 lines + follow)
./log_aggregator_cli tail /var/log/aggregated.log

# Show last 50 lines
./log_aggregator_cli tail /var/log/aggregated.log -n 50

# Don't follow (just show last lines)
./log_aggregator_cli tail /var/log/aggregated.log --no-follow

# Filter while tailing
./log_aggregator_cli tail /var/log/aggregated.log -p "ERROR|CRITICAL"

# Filter by severity
./log_aggregator_cli tail /var/log/aggregated.log -s WARNING

# Disable colors
./log_aggregator_cli tail /var/log/aggregated.log --no-color
```

#### Show Statistics
```bash
# Basic statistics
./log_aggregator_cli stats /var/log/aggregated.log

# Detailed statistics with hourly distribution
./log_aggregator_cli stats /var/log/aggregated.log -d

# Output as JSON
./log_aggregator_cli stats /var/log/aggregated.log -j
```

#### Filter and Transform Logs
```bash
# Filter to new file
./log_aggregator_cli filter /var/log/aggregated.log -o filtered.log -p "ERROR"

# Filter by severity
./log_aggregator_cli filter /var/log/aggregated.log -s ERROR -o errors.log

# Convert to JSON
./log_aggregator_cli filter /var/log/aggregated.log -f json -o logs.json

# Exclude patterns
./log_aggregator_cli filter /var/log/aggregated.log -v -p "healthcheck"
```

#### Merge Log Files
```bash
# Merge multiple files (sorted by timestamp)
./log_aggregator_cli merge /var/log/app1.log /var/log/app2.log -o merged.log

# Merge without sorting
./log_aggregator_cli merge /var/log/*.log -o merged.log --no-sort
```

#### Parse and Format Logs
```bash
# Parse and display formatted
./log_aggregator_cli parse /var/log/aggregated.log

# Output as JSON array
./log_aggregator_cli parse /var/log/aggregated.log -f json

# Output as CSV
./log_aggregator_cli parse /var/log/aggregated.log -f csv

# Limit entries
./log_aggregator_cli parse /var/log/aggregated.log -l 100
```

#### Watch Directory
```bash
# Watch all .log files in directory
./log_aggregator_cli watch /var/log/

# Watch with filter
./log_aggregator_cli watch /var/log/ -p "ERROR|WARNING"

# Watch with severity filter
./log_aggregator_cli watch /var/log/ -s ERROR
```

#### Rotate Logs
```bash
# Manual rotation
./log_aggregator_cli rotate /var/log/aggregated.log

# Keep 10 backups
./log_aggregator_cli rotate /var/log/aggregated.log -k 10

# Compress rotated files
./log_aggregator_cli rotate /var/log/aggregated.log -z
```

#### Export Logs
```bash
# Export to JSON
./log_aggregator_cli export /var/log/aggregated.log -f json -o export.json

# Export to CSV
./log_aggregator_cli export /var/log/aggregated.log -f csv -o export.csv

# Export with time range
./log_aggregator_cli export /var/log/aggregated.log -f json \
  --start "2025-12-01" --end "2025-12-04" -o export.json

# Limit entries
./log_aggregator_cli export /var/log/aggregated.log -f json -l 1000
```

## Library API Usage

### Basic Usage
```cpp
#include "log_aggregator/log_aggregator.h"

using namespace log_aggregator;

int main() {
    LogAggregator aggregator;
    
    // Add sources
    aggregator.addSource("/var/log/syslog");
    aggregator.addSource("/var/log/auth.log");
    
    // Configure output
    aggregator.setOutputFile("/var/log/aggregated.log");
    aggregator.setOutputFormat(OutputFormat::JSON);
    aggregator.setMaxFileSize(100);  // 100 MB
    
    // Add filters
    aggregator.addFilter("ERROR|WARNING");
    aggregator.setMinSeverity(Severity::INFO);
    
    // Start monitoring
    aggregator.start();
    
    // ... wait for shutdown signal ...
    
    aggregator.stop();
    return 0;
}
```

### Advanced Usage with Callbacks
```cpp
#include "log_aggregator/log_aggregator.h"

using namespace log_aggregator;

int main() {
    LogAggregator aggregator;
    
    // Configure rate limiting
    RateLimitConfig rl_config;
    rl_config.max_lines_per_second = 1000;
    rl_config.burst_size = 100;
    aggregator.setRateLimit(rl_config);
    aggregator.setRateLimitEnabled(true);
    
    // Add global metadata
    aggregator.addGlobalTag("environment", "production");
    aggregator.addGlobalTag("service", "myapp");
    
    // Register callbacks
    aggregator.onLogEntry([](const LogEntry& entry) {
        if (entry.severity >= Severity::ERROR) {
            // Send alert
            std::cout << "ALERT: " << entry.message << std::endl;
        }
    });
    
    aggregator.onError([](const std::string& source, const std::string& error) {
        std::cerr << "Error monitoring " << source << ": " << error << std::endl;
    });
    
    aggregator.onRotation([](const std::string& old_file, const std::string& new_file) {
        std::cout << "Rotated " << old_file << " to " << new_file << std::endl;
    });
    
    // Configure and start
    aggregator.addSource("/var/log/myapp.log");
    aggregator.setOutputFile("/var/log/aggregated.log");
    aggregator.setCompressionType(CompressionType::GZIP);
    
    aggregator.start();
    
    // Periodically check statistics
    while (running) {
        auto stats = aggregator.getStatistics();
        std::cout << "Processed: " << stats.total_lines << " lines" << std::endl;
        sleep(60);
    }
    
    aggregator.stop();
    aggregator.exportStatistics("/var/log/final_stats.json");
    return 0;
}
```

### Static Methods for Log Analysis
```cpp
#include "log_aggregator/log_aggregator.h"

using namespace log_aggregator;

// Parse entire log file
auto entries = LogAggregator::parseLogFile("/var/log/test.log");
for (const auto& entry : entries) {
    std::cout << entry.timestamp << " [" << severityToString(entry.severity) 
              << "] " << entry.message << std::endl;
}

// Search for specific patterns
auto errors = LogAggregator::searchLogFile("/var/log/test.log", "ERROR|CRITICAL", true);
std::cout << "Found " << errors.size() << " error entries" << std::endl;
```

## Output Formats

### Plain Text
```
2025-12-04 10:30:45 [ERROR] myhost myapp: Connection failed
```

### JSON
```json
{
  "timestamp": "2025-12-04 10:30:45",
  "severity": "ERROR",
  "source": "/var/log/myapp.log",
  "hostname": "myhost",
  "process": "myapp",
  "line_number": 1234,
  "message": "Connection failed",
  "tags": {"environment": "production"}
}
```

### CSV
```csv
"2025-12-04 10:30:45","ERROR","/var/log/myapp.log","myhost","myapp","Connection failed"
```

### Syslog (RFC 5424)
```
<131>1 2025-12-04 10:30:45 myhost myapp - - - Connection failed
```

## Configuration Examples

### High-Volume Production Setup
```bash
./log_aggregator_app \
  -s /var/log/nginx/access.log,/var/log/nginx/error.log,/var/log/app/*.log \
  -o /var/log/aggregated.log \
  --format json \
  -m 500 \
  -b 30 \
  -z gzip \
  -f "ERROR|CRITICAL|5[0-9]{2}|4[0-9]{2}" \
  -x "healthcheck|/ping|/status" \
  --min-severity WARNING \
  -r --max-lines 10000 --burst 1000 \
  -t env=prod,cluster=us-east-1 \
  --stats-interval 300 \
  -d
```

### Development/Debug Setup
```bash
./log_aggregator_app \
  -s /var/log/myapp.log \
  -o /tmp/dev-logs.log \
  --format plain \
  --min-severity DEBUG \
  --no-daemon \
  -v \
  --stats-interval 60
```

## Systemd Service

Create `/etc/systemd/system/log-aggregator.service`:
```ini
[Unit]
Description=Centralized Log Aggregator
After=network.target

[Service]
Type=forking
PIDFile=/var/run/log_aggregator.pid
ExecStart=/usr/local/bin/log_aggregator_app -d
ExecReload=/bin/kill -HUP $MAINPID
ExecStop=/bin/kill -TERM $MAINPID
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl enable log-aggregator
sudo systemctl start log-aggregator
```

## License
MIT License

## Author
Sandesh Ghimire | sandesh@soccentric
(C) Soccentric LLC. All rights reserved.
