/**
 * @file log_aggregator.h
 * @brief Main header file for the log_aggregator library.
 * @author Sandesh Ghimire | sandesh@soccentric
 * @copyright (C) Soccentric LLC. All rights reserved.
 *
 * This header file provides the public interface for the log_aggregator library.
 * It contains the main class declaration and related type definitions.
 *
 * @version 1.0
 * @date 2025-12-04
 *
 * @details
 * The library implements a centralized log aggregator with smart filtering.
 *
 * @note This library requires C++17 or later.
 */

#ifndef LOG_AGGREGATOR_H
#define LOG_AGGREGATOR_H

#include <memory>
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
enum class Severity { DEBUG, INFO, WARNING, ERROR, CRITICAL };

/**
 * @struct LogEntry
 * @brief Represents a log entry.
 */
struct LogEntry {
  std::string timestamp;
  Severity    severity;
  std::string source;
  std::string message;
};

/**
 * @class LogAggregator
 * @brief Primary class implementing the core functionality of log_aggregator.
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

  /**
   * @brief Starts the log aggregation daemon.
   */
  void start();

  /**
   * @brief Stops the log aggregation.
   */
  void stop();

  /**
   * @brief Adds a log source file to monitor.
   * @param path Path to the log file.
   */
  void addSource(const std::string& path);

  /**
   * @brief Adds a filter pattern.
   * @param pattern Regex pattern to filter logs.
   */
  void addFilter(const std::string& pattern);

  /**
   * @brief Sets the output file for aggregated logs.
   * @param path Output file path.
   */
  void setOutputFile(const std::string& path);

  /**
   * @brief Sets the maximum file size before rotation (in MB).
   * @param size Size in MB.
   */
  void setMaxFileSize(size_t size);

  /**
   * @brief Checks if a log line matches any of the filters.
   * @param line The log line to check.
   * @return true if the line matches any filter, false otherwise.
   */
  bool matchesFilter(const std::string& line);

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