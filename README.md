# Centralized Log Aggregator with Smart Filtering

A lightweight daemon that collects logs from multiple sources (syslog, application logs, kernel messages), applies intelligent filtering based on severity/patterns, and stores them efficiently with rotation. Includes a CLI for searching and real-time tailing.

## Features

- Collects logs from multiple sources using inotify
- Applies regex-based filtering
- Efficient storage with automatic rotation
- Daemon mode for background operation
- CLI tool for searching and tailing logs

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
sudo ./log_aggregator_app
```

### CLI Commands
```bash
# Search logs
./log_aggregator_cli search /var/log/aggregated.log "ERROR"

# Tail logs in real-time
./log_aggregator_cli tail /var/log/aggregated.log
```

## Configuration
The daemon monitors `/var/log/syslog` and `/var/log/kern.log` by default, filters for ERROR and WARNING messages, and outputs to `/var/log/aggregated.log` with 100MB rotation.

## License
MIT License
