/**
 * @file main.cpp
 * @brief Main application entry point for log_aggregator daemon.
 * @author Sandesh Ghimire | sandesh@soccentric
 * @copyright (C) Soccentric LLC. All rights reserved.
 *
 * This file contains the main() function that serves as the entry point
 * for the log_aggregator daemon application. It provides comprehensive
 * configuration options for log collection, filtering, and output.
 *
 * @version 2.0
 * @date 2025-12-04
 *
 * @details
 * The application creates an instance of LogAggregator and runs it as a daemon
 * to collect and filter logs from multiple sources with support for:
 * - Multiple output formats (Plain, JSON, CSV, Syslog)
 * - Severity-based filtering
 * - Rate limiting
 * - Automatic compression
 * - Statistics tracking
 */

#include <sys/stat.h>
#include <unistd.h>

#include <CLI/CLI.hpp>
#include <csignal>
#include <fstream>
#include <iostream>

#include "log_aggregator/log_aggregator.h"

using namespace log_aggregator;

/**
 * @brief Global aggregator instance for signal handler access.
 */
LogAggregator aggregator;
volatile sig_atomic_t stop_flag = 0;

/**
 * @brief Signal handler for graceful shutdown.
 * @param signum The signal number received.
 */
void signal_handler(int signum) {
  std::cerr << "\nReceived signal " << signum << ", shutting down..." << std::endl;
  stop_flag = 1;
  aggregator.stop();
}

/**
 * @brief Parse output format string to enum.
 * @param format The format string.
 * @return The corresponding OutputFormat enum value.
 */
OutputFormat parseOutputFormat(const std::string& format) {
  if (format == "json") return OutputFormat::JSON;
  if (format == "csv") return OutputFormat::CSV;
  if (format == "syslog") return OutputFormat::SYSLOG;
  return OutputFormat::PLAIN;
}

/**
 * @brief Parse compression type string to enum.
 * @param type The compression type string.
 * @return The corresponding CompressionType enum value.
 */
CompressionType parseCompressionType(const std::string& type) {
  if (type == "gzip" || type == "gz") return CompressionType::GZIP;
  if (type == "zstd") return CompressionType::ZSTD;
  return CompressionType::NONE;
}

/**
 * @brief Main entry point of the application.
 *
 * Parses command-line arguments using CLI11, configures the LogAggregator,
 * and runs it as a daemon to collect and filter logs from multiple sources.
 *
 * @param argc Number of command-line arguments.
 * @param argv Array of command-line argument strings.
 *
 * @return 0 on successful execution, non-zero on error.
 */
int main(int argc, char* argv[]) {
  CLI::App app{"Centralized Log Aggregator Daemon v2.0"};

  // Source configuration
  std::vector<std::string> sources = {"/var/log/syslog", "/var/log/kern.log"};
  app.add_option("-s,--sources", sources, "Log source files to monitor")
      ->delimiter(',')
      ->expected(1, -1);

  // Output configuration
  std::string output_file = "/var/log/aggregated.log";
  app.add_option("-o,--output", output_file, "Output file for aggregated logs");

  std::string output_format = "plain";
  app.add_option("--format", output_format, "Output format: plain, json, csv, syslog");

  size_t max_size = 100;
  app.add_option("-m,--max-size", max_size, "Maximum file size in MB before rotation");

  size_t max_backups = 5;
  app.add_option("-b,--max-backups", max_backups, "Number of backup files to keep");

  std::string compression = "none";
  app.add_option("-z,--compression", compression, "Compression: none, gzip, zstd");

  // Filter configuration
  std::vector<std::string> filters = {"ERROR|WARNING"};
  app.add_option("-f,--filters", filters, "Regex patterns to filter logs")
      ->delimiter(',')
      ->expected(1, -1);

  std::vector<std::string> exclusions;
  app.add_option("-x,--exclude", exclusions, "Regex patterns to exclude")
      ->delimiter(',');

  std::string min_severity = "DEBUG";
  app.add_option("--min-severity", min_severity, 
                 "Minimum severity: DEBUG, INFO, WARNING, ERROR, CRITICAL");

  // Rate limiting
  bool rate_limit_enabled = false;
  app.add_flag("-r,--rate-limit", rate_limit_enabled, "Enable rate limiting");

  uint64_t max_lines_per_sec = 1000;
  app.add_option("--max-lines", max_lines_per_sec, "Max lines per second (rate limiting)");

  uint64_t burst_size = 100;
  app.add_option("--burst", burst_size, "Burst allowance for rate limiting");

  // Daemon configuration
  bool daemon_mode = true;
  app.add_flag("-d,--daemon,!--no-daemon", daemon_mode, "Run as daemon (default: true)");

  std::string pid_file = "/var/run/log_aggregator.pid";
  app.add_option("--pid-file", pid_file, "PID file path");

  // Metadata configuration
  std::string hostname;
  app.add_option("--hostname", hostname, "Override hostname in log entries");

  std::vector<std::string> tags;
  app.add_option("-t,--tags", tags, "Global tags in key=value format")
      ->delimiter(',');

  // Statistics
  std::string stats_file;
  app.add_option("--stats-file", stats_file, "File to export statistics on shutdown");

  int stats_interval = 0;
  app.add_option("--stats-interval", stats_interval, 
                 "Interval in seconds to print statistics (0 = disabled)");

  // Buffer configuration
  size_t buffer_size = 8192;
  app.add_option("--buffer-size", buffer_size, "Buffer size for file operations");

  // Advanced options
  bool normalize_timestamps = true;
  app.add_flag("--normalize-timestamps,!--no-normalize-timestamps", normalize_timestamps,
               "Normalize timestamps in output");

  bool verbose = false;
  app.add_flag("-v,--verbose", verbose, "Enable verbose output");

  CLI11_PARSE(app, argc, argv);

  // Validate configuration
  if (sources.empty()) {
    std::cerr << "Error: At least one source file must be specified" << std::endl;
    return 1;
  }

  // Set up signal handlers
  signal(SIGTERM, signal_handler);
  signal(SIGINT, signal_handler);
  signal(SIGHUP, signal_handler);

  // Daemonize if requested
  if (daemon_mode) {
    pid_t pid = fork();
    if (pid < 0) {
      std::cerr << "Fork failed: " << strerror(errno) << std::endl;
      return 1;
    }
    if (pid > 0) {
      // Parent: write PID file and exit
      std::ofstream pf(pid_file);
      if (pf.is_open()) {
        pf << pid << std::endl;
      }
      return 0;
    }

    // Child becomes session leader
    if (setsid() < 0) {
      std::cerr << "setsid failed: " << strerror(errno) << std::endl;
      return 1;
    }

    // Close standard file descriptors
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    // Set working directory
    chdir("/");

    // Set file mode mask
    umask(0);
  }

  // Configure aggregator
  for (const auto& source : sources) {
    if (!aggregator.addSource(source)) {
      if (!daemon_mode) {
        std::cerr << "Warning: Failed to add source: " << source << std::endl;
      }
    }
  }

  aggregator.setOutputFile(output_file);
  aggregator.setOutputFormat(parseOutputFormat(output_format));
  aggregator.setMaxFileSize(max_size);
  aggregator.setMaxBackupFiles(max_backups);
  aggregator.setCompressionType(parseCompressionType(compression));
  aggregator.setTimestampNormalization(normalize_timestamps);
  aggregator.setBufferSize(buffer_size);

  // Configure filters
  for (const auto& filter : filters) {
    if (!aggregator.addFilter(filter)) {
      if (!daemon_mode) {
        std::cerr << "Warning: Invalid filter pattern: " << filter << std::endl;
      }
    }
  }

  for (const auto& exclusion : exclusions) {
    if (!aggregator.addExclusionPattern(exclusion)) {
      if (!daemon_mode) {
        std::cerr << "Warning: Invalid exclusion pattern: " << exclusion << std::endl;
      }
    }
  }

  auto sev = severityFromString(min_severity);
  if (sev) {
    aggregator.setMinSeverity(*sev);
  }

  // Configure rate limiting
  if (rate_limit_enabled) {
    RateLimitConfig rl_config;
    rl_config.max_lines_per_second = max_lines_per_sec;
    rl_config.burst_size = burst_size;
    aggregator.setRateLimit(rl_config);
    aggregator.setRateLimitEnabled(true);
  }

  // Configure metadata
  if (!hostname.empty()) {
    aggregator.setHostname(hostname);
  }

  for (const auto& tag : tags) {
    size_t eq_pos = tag.find('=');
    if (eq_pos != std::string::npos) {
      std::string key = tag.substr(0, eq_pos);
      std::string value = tag.substr(eq_pos + 1);
      aggregator.addGlobalTag(key, value);
    }
  }

  // Register callbacks for verbose mode or statistics
  if (verbose && !daemon_mode) {
    aggregator.onLogEntry([](const LogEntry& entry) {
      std::cout << "[" << severityToString(entry.severity) << "] " 
                << entry.source << ": " << entry.message << std::endl;
    });

    aggregator.onError([](const std::string& source, const std::string& error) {
      std::cerr << "Error [" << source << "]: " << error << std::endl;
    });

    aggregator.onRotation([](const std::string& old_file, const std::string& new_file) {
      std::cout << "Rotated: " << old_file << " -> " << new_file << std::endl;
    });
  }

  // Start aggregating
  try {
    aggregator.start();
    
    if (!daemon_mode) {
      std::cout << "Log aggregator started. Press Ctrl+C to stop." << std::endl;
      std::cout << "Monitoring " << sources.size() << " sources" << std::endl;
      std::cout << "Output: " << output_file << " (" << output_format << ")" << std::endl;
    }
  } catch (const std::exception& e) {
    if (!daemon_mode) {
      std::cerr << "Failed to start aggregator: " << e.what() << std::endl;
    }
    return 1;
  }

  // Main loop
  auto last_stats_time = std::chrono::steady_clock::now();
  
  while (!stop_flag) {
    sleep(1);
    
    // Print statistics periodically if requested
    if (stats_interval > 0 && !daemon_mode) {
      auto now = std::chrono::steady_clock::now();
      auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_stats_time);
      
      if (elapsed.count() >= stats_interval) {
        auto stats = aggregator.getStatistics();
        std::cout << "\n=== Statistics ===" << std::endl;
        std::cout << "Total lines: " << stats.total_lines << std::endl;
        std::cout << "Filtered lines: " << stats.filtered_lines << std::endl;
        std::cout << "Dropped lines: " << stats.dropped_lines << std::endl;
        std::cout << "Bytes processed: " << stats.bytes_processed << std::endl;
        std::cout << "Bytes written: " << stats.bytes_written << std::endl;
        last_stats_time = now;
      }
    }
  }

  // Cleanup
  aggregator.stop();
  aggregator.flush();

  // Export statistics on shutdown
  if (!stats_file.empty()) {
    aggregator.exportStatistics(stats_file);
  }

  // Remove PID file
  if (daemon_mode) {
    unlink(pid_file.c_str());
  }

  if (!daemon_mode) {
    auto stats = aggregator.getStatistics();
    std::cout << "\n=== Final Statistics ===" << std::endl;
    std::cout << "Total lines processed: " << stats.total_lines << std::endl;
    std::cout << "Lines written: " << stats.filtered_lines << std::endl;
    std::cout << "Lines dropped (rate limit): " << stats.dropped_lines << std::endl;
  }

  return 0;
}