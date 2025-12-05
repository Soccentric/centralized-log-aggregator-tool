/**
 * @file log_aggregator.h
 * @brief Main header file for the log_aggregator library.
 * @author Sandesh Ghimire | sandesh@soccentric
 * @copyright (C) Soccentric LLC. All rights reserved.
 *
 * This header file provides the public interface for the log_aggregator library.
 * It contains the main class declaration and related type definitions.
 *
 * @version 2.0
 * @date 2025-12-04
 *
 * @details
 * The library implements a centralized log aggregator with smart filtering,
 * statistics tracking, JSON export, compression, rate limiting, and callbacks.
 *
 * @note This library requires C++17 or later.
 */

#ifndef LOG_AGGREGATOR_H
#define LOG_AGGREGATOR_H

#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <regex>
#include <string>
#include <vector>

/**
 * @namespace log_aggregator
 * @brief Main namespace for log_aggregator library.
 */
namespace log_aggregator {

/**
 * @enum Severity
 * @brief Log severity levels.
 */
enum class Severity { DEBUG = 0, INFO = 1, WARNING = 2, ERROR = 3, CRITICAL = 4 };

/**
 * @brief Convert severity to string representation.
 * @param severity The severity level.
 * @return String representation of the severity.
 */
inline std::string severityToString(Severity severity) {
  switch (severity) {
    case Severity::DEBUG: return "DEBUG";
    case Severity::INFO: return "INFO";
    case Severity::WARNING: return "WARNING";
    case Severity::ERROR: return "ERROR";
    case Severity::CRITICAL: return "CRITICAL";
    default: return "UNKNOWN";
  }
}

/**
 * @brief Parse severity from string.
 * @param str The string representation.
 * @return The severity level, or nullopt if invalid.
 */
inline std::optional<Severity> severityFromString(const std::string& str) {
  if (str == "DEBUG" || str == "debug") return Severity::DEBUG;
  if (str == "INFO" || str == "info") return Severity::INFO;
  if (str == "WARNING" || str == "warning" || str == "WARN" || str == "warn") return Severity::WARNING;
  if (str == "ERROR" || str == "error" || str == "ERR" || str == "err") return Severity::ERROR;
  if (str == "CRITICAL" || str == "critical" || str == "CRIT" || str == "crit" || str == "FATAL" || str == "fatal")
    return Severity::CRITICAL;
  return std::nullopt;
}

/**
 * @struct LogEntry
 * @brief Represents a parsed log entry with full metadata.
 */
struct LogEntry {
  std::string                                          timestamp;   ///< Timestamp string
  std::chrono::system_clock::time_point                time_point;  ///< Parsed time point
  Severity                                             severity;    ///< Log severity level
  std::string                                          source;      ///< Source file path
  std::string                                          hostname;    ///< Hostname if available
  std::string                                          process;     ///< Process name/PID
  std::string                                          message;     ///< Log message content
  std::map<std::string, std::string>                   tags;        ///< Custom tags/metadata
  uint64_t                                             line_number; ///< Line number in source

  /**
   * @brief Convert log entry to JSON string.
   * @return JSON representation of the log entry.
   */
  std::string toJson() const;

  /**
   * @brief Parse a log line into a LogEntry.
   * @param line The raw log line.
   * @param source The source file path.
   * @return Parsed LogEntry.
   */
  static LogEntry parse(const std::string& line, const std::string& source);
};

/**
 * @struct LogStatistics
 * @brief Statistics about collected logs.
 */
struct LogStatistics {
  uint64_t                    total_lines;           ///< Total lines processed
  uint64_t                    filtered_lines;        ///< Lines that matched filters
  uint64_t                    dropped_lines;         ///< Lines dropped (rate limiting)
  uint64_t                    bytes_processed;       ///< Total bytes processed
  uint64_t                    bytes_written;         ///< Bytes written to output
  std::map<Severity, uint64_t> severity_counts;      ///< Count by severity
  std::map<std::string, uint64_t> source_counts;     ///< Count by source file
  std::chrono::system_clock::time_point start_time; ///< When aggregation started
  std::chrono::system_clock::time_point last_update; ///< Last update time

  /**
   * @brief Convert statistics to JSON string.
   * @return JSON representation of statistics.
   */
  std::string toJson() const;

  /**
   * @brief Reset all statistics.
   */
  void reset();
};

/**
 * @enum OutputFormat
 * @brief Output format options.
 */
enum class OutputFormat { PLAIN, JSON, CSV, SYSLOG };

/**
 * @enum CompressionType
 * @brief Compression options for rotated files.
 */
enum class CompressionType { NONE, GZIP, ZSTD };

/**
 * @struct RateLimitConfig
 * @brief Rate limiting configuration.
 */
struct RateLimitConfig {
  uint64_t                  max_lines_per_second;  ///< Max lines per second (0 = unlimited)
  uint64_t                  max_bytes_per_second;  ///< Max bytes per second (0 = unlimited)
  uint64_t                  burst_size;            ///< Burst allowance
  std::chrono::milliseconds window;                ///< Time window for rate calculation

  RateLimitConfig()
      : max_lines_per_second(0), max_bytes_per_second(0), burst_size(100),
        window(std::chrono::milliseconds(1000)) {}
};

/**
 * @typedef LogCallback
 * @brief Callback type for log events.
 */
using LogCallback = std::function<void(const LogEntry&)>;

/**
 * @typedef ErrorCallback
 * @brief Callback type for error events.
 */
using ErrorCallback = std::function<void(const std::string& source, const std::string& error)>;

/**
 * @typedef RotationCallback
 * @brief Callback type for rotation events.
 */
using RotationCallback = std::function<void(const std::string& old_file, const std::string& new_file)>;

/**
 * @class LogAggregator
 * @brief Primary class implementing the core functionality of log_aggregator.
 *
 * This class provides a comprehensive log aggregation solution with:
 * - Multi-source monitoring using inotify
 * - Regex-based and severity-based filtering
 * - Multiple output formats (Plain, JSON, CSV, Syslog)
 * - Log rotation with optional compression
 * - Rate limiting to prevent log flooding
 * - Statistics and analytics
 * - Callback hooks for custom processing
 */
class LogAggregator {
public:
  /**
   * @brief Constructs a new LogAggregator object.
   */
  LogAggregator();

  /**
   * @brief Destroys the LogAggregator object.
   */
  ~LogAggregator();

  // Disable copy
  LogAggregator(const LogAggregator&) = delete;
  LogAggregator& operator=(const LogAggregator&) = delete;

  // Enable move
  LogAggregator(LogAggregator&&) noexcept;
  LogAggregator& operator=(LogAggregator&&) noexcept;

  // ==================== Core Operations ====================

  /**
   * @brief Starts the log aggregation daemon.
   * @throws std::runtime_error if inotify initialization fails.
   */
  void start();

  /**
   * @brief Stops the log aggregation.
   */
  void stop();

  /**
   * @brief Checks if the aggregator is currently running.
   * @return true if running, false otherwise.
   */
  bool isRunning() const;

  /**
   * @brief Blocks until the aggregator stops or timeout.
   * @param timeout Maximum wait time (0 = infinite).
   * @return true if stopped normally, false if timed out.
   */
  bool waitForStop(std::chrono::milliseconds timeout = std::chrono::milliseconds(0));

  // ==================== Source Management ====================

  /**
   * @brief Adds a log source file to monitor.
   * @param path Path to the log file.
   * @return true if source was added successfully.
   */
  bool addSource(const std::string& path);

  /**
   * @brief Removes a log source from monitoring.
   * @param path Path to the log file.
   * @return true if source was removed successfully.
   */
  bool removeSource(const std::string& path);

  /**
   * @brief Gets the list of monitored sources.
   * @return Vector of source file paths.
   */
  std::vector<std::string> getSources() const;

  /**
   * @brief Clears all sources.
   */
  void clearSources();

  // ==================== Filter Management ====================

  /**
   * @brief Adds a regex filter pattern.
   * @param pattern Regex pattern to filter logs.
   * @param case_insensitive Whether to match case-insensitively.
   * @return true if filter was added successfully.
   */
  bool addFilter(const std::string& pattern, bool case_insensitive = false);

  /**
   * @brief Removes a filter pattern.
   * @param pattern The pattern to remove.
   * @return true if filter was removed.
   */
  bool removeFilter(const std::string& pattern);

  /**
   * @brief Clears all filters.
   */
  void clearFilters();

  /**
   * @brief Sets the minimum severity level to capture.
   * @param min_severity Minimum severity (logs below this are ignored).
   */
  void setMinSeverity(Severity min_severity);

  /**
   * @brief Gets the minimum severity level.
   * @return Current minimum severity.
   */
  Severity getMinSeverity() const;

  /**
   * @brief Adds a severity level to filter for.
   * @param severity The severity to include.
   */
  void addSeverityFilter(Severity severity);

  /**
   * @brief Sets exclusion patterns (logs matching these are dropped).
   * @param pattern Regex pattern to exclude.
   * @return true if pattern was added.
   */
  bool addExclusionPattern(const std::string& pattern);

  /**
   * @brief Checks if a log line matches any of the filters.
   * @param line The log line to check.
   * @return true if the line matches any filter, false otherwise.
   */
  bool matchesFilter(const std::string& line) const;

  // ==================== Output Configuration ====================

  /**
   * @brief Sets the output file for aggregated logs.
   * @param path Output file path.
   */
  void setOutputFile(const std::string& path);

  /**
   * @brief Gets the current output file path.
   * @return Current output file path.
   */
  std::string getOutputFile() const;

  /**
   * @brief Sets the output format.
   * @param format Output format to use.
   */
  void setOutputFormat(OutputFormat format);

  /**
   * @brief Gets the current output format.
   * @return Current output format.
   */
  OutputFormat getOutputFormat() const;

  /**
   * @brief Sets the maximum file size before rotation (in MB).
   * @param size Size in MB.
   */
  void setMaxFileSize(size_t size);

  /**
   * @brief Gets the maximum file size.
   * @return Maximum size in MB.
   */
  size_t getMaxFileSize() const;

  /**
   * @brief Sets the maximum number of backup files.
   * @param count Number of backup files to keep.
   */
  void setMaxBackupFiles(size_t count);

  /**
   * @brief Gets the maximum number of backup files.
   * @return Number of backup files.
   */
  size_t getMaxBackupFiles() const;

  /**
   * @brief Sets compression for rotated files.
   * @param type Compression type.
   */
  void setCompressionType(CompressionType type);

  /**
   * @brief Gets the compression type.
   * @return Current compression type.
   */
  CompressionType getCompressionType() const;

  // ==================== Rate Limiting ====================

  /**
   * @brief Sets the rate limiting configuration.
   * @param config Rate limit configuration.
   */
  void setRateLimit(const RateLimitConfig& config);

  /**
   * @brief Gets the current rate limit configuration.
   * @return Current rate limit config.
   */
  RateLimitConfig getRateLimit() const;

  /**
   * @brief Enables or disables rate limiting.
   * @param enabled Whether to enable rate limiting.
   */
  void setRateLimitEnabled(bool enabled);

  /**
   * @brief Checks if rate limiting is enabled.
   * @return true if rate limiting is enabled.
   */
  bool isRateLimitEnabled() const;

  // ==================== Statistics ====================

  /**
   * @brief Gets the current statistics.
   * @return Current log statistics.
   */
  LogStatistics getStatistics() const;

  /**
   * @brief Resets all statistics.
   */
  void resetStatistics();

  /**
   * @brief Exports statistics to a file.
   * @param path File path for statistics.
   * @return true if export was successful.
   */
  bool exportStatistics(const std::string& path) const;

  // ==================== Callbacks ====================

  /**
   * @brief Registers a callback for log events.
   * @param callback Function to call for each log entry.
   * @return Callback ID for removal.
   */
  size_t onLogEntry(LogCallback callback);

  /**
   * @brief Registers a callback for error events.
   * @param callback Function to call on errors.
   * @return Callback ID for removal.
   */
  size_t onError(ErrorCallback callback);

  /**
   * @brief Registers a callback for rotation events.
   * @param callback Function to call on file rotation.
   * @return Callback ID for removal.
   */
  size_t onRotation(RotationCallback callback);

  /**
   * @brief Removes a callback by ID.
   * @param id The callback ID to remove.
   */
  void removeCallback(size_t id);

  // ==================== Advanced Features ====================

  /**
   * @brief Manually triggers log rotation.
   */
  void forceRotation();

  /**
   * @brief Flushes all pending writes to disk.
   */
  void flush();

  /**
   * @brief Adds a custom tag to all log entries.
   * @param key Tag key.
   * @param value Tag value.
   */
  void addGlobalTag(const std::string& key, const std::string& value);

  /**
   * @brief Removes a global tag.
   * @param key Tag key to remove.
   */
  void removeGlobalTag(const std::string& key);

  /**
   * @brief Sets the hostname to use in log entries.
   * @param hostname Hostname string.
   */
  void setHostname(const std::string& hostname);

  /**
   * @brief Enables or disables timestamp normalization.
   * @param enabled Whether to normalize timestamps.
   */
  void setTimestampNormalization(bool enabled);

  /**
   * @brief Sets the buffer size for file operations.
   * @param size Buffer size in bytes.
   */
  void setBufferSize(size_t size);

  /**
   * @brief Gets the buffer size.
   * @return Current buffer size.
   */
  size_t getBufferSize() const;

  /**
   * @brief Parse a log file and return entries without aggregating.
   * @param path Path to log file.
   * @param limit Maximum entries to return (0 = all).
   * @return Vector of parsed log entries.
   */
  static std::vector<LogEntry> parseLogFile(const std::string& path, size_t limit = 0);

  /**
   * @brief Search a log file for matching entries.
   * @param path Path to log file.
   * @param pattern Regex pattern to match.
   * @param case_insensitive Case insensitive matching.
   * @return Vector of matching log entries.
   */
  static std::vector<LogEntry> searchLogFile(const std::string& path, const std::string& pattern,
                                              bool case_insensitive = false);

private:
  /**
   * @class Impl
   * @brief Private implementation class (PIMPL pattern).
   */
  class Impl;

  /**
   * @brief Pointer to the private implementation.
   */
  std::unique_ptr<Impl> pimpl_;
};

}  // namespace log_aggregator

#endif  // LOG_AGGREGATOR_H