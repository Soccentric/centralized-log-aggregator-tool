# Centralized Log Aggregator with Smart Filtering

A lightweight daemon that collects logs from multiple sources (syslog, application logs, kernel messages), applies intelligent filtering based on severity/patterns, and stores them efficiently with rotation. Includes a CLI for searching and real-time tailing.

## Features

- Collects logs from multiple sources using inotify with efficient file position tracking
- Applies regex-based filtering with case-sensitive and case-insensitive options
- Efficient storage with automatic rotation (up to 5 backup files)
- Daemon mode for background operation with proper signal handling
- CLI tool for searching (with line numbers) and real-time tailing with truncation detection

## Building

### Prerequisites
- CMake 3.20+
- C++17 compiler
- Linux system with inotify support

### Build Steps
```bash
mkdir build
cd build
cmake ..
make
```

### Installation
```bash
make install
```

## Usage

### Running the Daemon
```bash
# Run with default settings
sudo ./log_aggregator_app

# Run with custom configuration
sudo ./log_aggregator_app -s /var/log/syslog,/var/log/kern.log,/var/log/auth.log -o /var/log/aggregated.log -m 50 -f "ERROR|CRITICAL" -d

# Run in foreground (no daemon)
./log_aggregator_app --no-daemon
```

### CLI Commands
```bash
# Search logs
./log_aggregator_cli search /var/log/aggregated.log "ERROR"

# Case-insensitive search
./log_aggregator_cli search /var/log/aggregated.log "error" --ignore-case

# Tail logs in real-time (show last 10 lines then follow)
./log_aggregator_cli tail /var/log/aggregated.log

# Tail with custom number of initial lines
./log_aggregator_cli tail /var/log/aggregated.log --lines 20

# Show help
./log_aggregator_cli --help
```

### Command Line Options

#### Daemon Options
- `-s, --sources`: Comma-separated list of log source files to monitor (default: /var/log/syslog,/var/log/kern.log)
- `-o, --output`: Output file for aggregated logs (default: /var/log/aggregated.log)
- `-m, --max-size`: Maximum file size in MB before rotation (default: 100)
- `-f, --filters`: Comma-separated regex patterns to filter logs (default: ERROR|WARNING)
- `-d, --daemon`: Run as daemon (default: true)

#### CLI Options
- `search <file> <pattern>`: Search logs for regex pattern, displays line numbers
  - `-i, --ignore-case`: Case insensitive search
- `tail <file>`: Tail logs in real-time with truncation detection
  - `-n, --lines`: Number of lines to show initially (default: 10)

## Configuration
The daemon monitors `/var/log/syslog` and `/var/log/kern.log` by default, filters for ERROR and WARNING messages, and outputs to `/var/log/aggregated.log` with 100MB rotation.

## License
MIT License
