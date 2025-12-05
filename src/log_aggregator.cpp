/**
 * @file log_aggregator.cpp
 * @brief Implementation file for the log_aggregator library.
 * @author Sandesh Ghimire | sandesh@soccentric
 * @copyright (C) Soccentric LLC. All rights reserved.
 *
 * This file contains the complete implementation of the LogAggregator class
 * with all advanced features including statistics, compression, rate limiting,
 * and multiple output formats.
 */

#include "log_aggregator/log_aggregator.h"

#include <sys/inotify.h>
#include <sys/stat.h>
#include <unistd.h>
#include <zlib.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <ctime>
#include <deque>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <sstream>
#include <thread>
#include <unordered_map>
#include <unordered_set>

namespace fs = std::filesystem;

namespace log_aggregator {

// ==================== LogEntry Implementation ====================

std::string LogEntry::toJson() const {
  std::ostringstream oss;
  oss << "{";
  oss << "\"timestamp\":\"" << timestamp << "\",";
  oss << "\"severity\":\"" << severityToString(severity) << "\",";
  oss << "\"source\":\"" << source << "\",";
  oss << "\"hostname\":\"" << hostname << "\",";
  oss << "\"process\":\"" << process << "\",";
  oss << "\"line_number\":" << line_number << ",";
  
  // Escape message for JSON
  std::string escaped_msg;
  for (char c : message) {
    switch (c) {
      case '"': escaped_msg += "\\\""; break;
      case '\\': escaped_msg += "\\\\"; break;
      case '\n': escaped_msg += "\\n"; break;
      case '\r': escaped_msg += "\\r"; break;
      case '\t': escaped_msg += "\\t"; break;
      default: escaped_msg += c;
    }
  }
  oss << "\"message\":\"" << escaped_msg << "\"";
  
  if (!tags.empty()) {
    oss << ",\"tags\":{";
    bool first = true;
    for (const auto& [key, value] : tags) {
      if (!first) oss << ",";
      oss << "\"" << key << "\":\"" << value << "\"";
      first = false;
    }
    oss << "}";
  }
  oss << "}";
  return oss.str();
}

LogEntry LogEntry::parse(const std::string& line, const std::string& source) {
  LogEntry entry;
  entry.source = source;
  entry.time_point = std::chrono::system_clock::now();
  entry.severity = Severity::INFO;  // Default
  entry.line_number = 0;
  
  // Try to parse syslog format: "Mon DD HH:MM:SS hostname process[pid]: message"
  static const std::regex syslog_regex(
      R"(^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)$)");
  
  // Try to parse ISO timestamp format: "YYYY-MM-DD HH:MM:SS"
  static const std::regex iso_regex(
      R"(^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+\[?(\w+)\]?\s*(.*)$)");
  
  std::smatch match;
  if (std::regex_match(line, match, syslog_regex)) {
    entry.timestamp = match[1].str();
    entry.hostname = match[2].str();
    entry.process = match[3].str();
    entry.message = match[5].str();
  } else if (std::regex_match(line, match, iso_regex)) {
    entry.timestamp = match[1].str();
    std::string level_str = match[2].str();
    auto sev = severityFromString(level_str);
    if (sev) entry.severity = *sev;
    entry.message = match[3].str();
  } else {
    // Fallback: use whole line as message
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    std::tm tm = *std::localtime(&time_t);
    char time_str[20];
    std::strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", &tm);
    entry.timestamp = time_str;
    entry.message = line;
  }
  
  // Detect severity from message content
  std::string upper_line = line;
  std::transform(upper_line.begin(), upper_line.end(), upper_line.begin(), ::toupper);
  
  if (upper_line.find("CRITICAL") != std::string::npos || 
      upper_line.find("FATAL") != std::string::npos ||
      upper_line.find("EMERG") != std::string::npos) {
    entry.severity = Severity::CRITICAL;
  } else if (upper_line.find("ERROR") != std::string::npos || 
             upper_line.find("ERR") != std::string::npos) {
    entry.severity = Severity::ERROR;
  } else if (upper_line.find("WARNING") != std::string::npos || 
             upper_line.find("WARN") != std::string::npos) {
    entry.severity = Severity::WARNING;
  } else if (upper_line.find("DEBUG") != std::string::npos) {
    entry.severity = Severity::DEBUG;
  }
  
  return entry;
}

// ==================== LogStatistics Implementation ====================

std::string LogStatistics::toJson() const {
  std::ostringstream oss;
  oss << "{";
  oss << "\"total_lines\":" << total_lines << ",";
  oss << "\"filtered_lines\":" << filtered_lines << ",";
  oss << "\"dropped_lines\":" << dropped_lines << ",";
  oss << "\"bytes_processed\":" << bytes_processed << ",";
  oss << "\"bytes_written\":" << bytes_written << ",";
  
  auto start_time_t = std::chrono::system_clock::to_time_t(start_time);
  auto last_time_t = std::chrono::system_clock::to_time_t(last_update);
  
  oss << "\"start_time\":\"" << std::ctime(&start_time_t) << "\",";
  oss << "\"last_update\":\"" << std::ctime(&last_time_t) << "\",";
  
  oss << "\"severity_counts\":{";
  bool first = true;
  for (const auto& [sev, count] : severity_counts) {
    if (!first) oss << ",";
    oss << "\"" << severityToString(sev) << "\":" << count;
    first = false;
  }
  oss << "},";
  
  oss << "\"source_counts\":{";
  first = true;
  for (const auto& [src, count] : source_counts) {
    if (!first) oss << ",";
    oss << "\"" << src << "\":" << count;
    first = false;
  }
  oss << "}";
  oss << "}";
  return oss.str();
}

void LogStatistics::reset() {
  total_lines = 0;
  filtered_lines = 0;
  dropped_lines = 0;
  bytes_processed = 0;
  bytes_written = 0;
  severity_counts.clear();
  source_counts.clear();
  start_time = std::chrono::system_clock::now();
  last_update = start_time;
}

// ==================== Rate Limiter ====================

class RateLimiter {
public:
  RateLimiter() : enabled_(false), tokens_(0), last_update_(std::chrono::steady_clock::now()) {}
  
  void setConfig(const RateLimitConfig& config) {
    std::lock_guard<std::mutex> lock(mutex_);
    config_ = config;
    tokens_ = config.burst_size;
  }
  
  RateLimitConfig getConfig() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return config_;
  }
  
  void setEnabled(bool enabled) {
    enabled_ = enabled;
  }
  
  bool isEnabled() const {
    return enabled_;
  }
  
  bool tryAcquire(size_t bytes = 1) {
    if (!enabled_ || config_.max_lines_per_second == 0) {
      return true;
    }
    
    std::lock_guard<std::mutex> lock(mutex_);
    refillTokens();
    
    if (tokens_ >= 1) {
      tokens_ -= 1;
      return true;
    }
    return false;
  }
  
private:
  void refillTokens() {
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_update_);
    
    if (elapsed.count() > 0) {
      double tokens_to_add = (elapsed.count() / 1000.0) * config_.max_lines_per_second;
      tokens_ = std::min(static_cast<double>(config_.burst_size), tokens_ + tokens_to_add);
      last_update_ = now;
    }
  }
  
  mutable std::mutex mutex_;
  RateLimitConfig config_;
  std::atomic<bool> enabled_;
  double tokens_;
  std::chrono::steady_clock::time_point last_update_;
};

// ==================== LogAggregator::Impl ====================

class LogAggregator::Impl {
public:
  Impl()
      : running_(false),
        max_file_size_(100 * 1024 * 1024),  // 100MB default
        max_backup_files_(5),
        output_format_(OutputFormat::PLAIN),
        compression_type_(CompressionType::NONE),
        min_severity_(Severity::DEBUG),
        timestamp_normalization_(true),
        buffer_size_(8192),
        next_callback_id_(1) {
    statistics_.reset();
    
    // Get system hostname
    char hostname_buf[256];
    if (gethostname(hostname_buf, sizeof(hostname_buf)) == 0) {
      hostname_ = hostname_buf;
    } else {
      hostname_ = "localhost";
    }
  }

  ~Impl() {
    stop();
  }

  void start() {
    if (running_) return;
    running_ = true;
    statistics_.start_time = std::chrono::system_clock::now();

    // Initialize inotify
    inotify_fd_ = inotify_init1(IN_NONBLOCK);
    if (inotify_fd_ < 0) {
      throw std::runtime_error("Failed to initialize inotify: " + std::string(strerror(errno)));
    }

    // Add watches for sources
    for (const auto& source : sources_) {
      addWatch(source);
    }

    // Start monitoring thread
    monitor_thread_ = std::thread(&Impl::monitor, this);
  }

  void stop() {
    if (!running_) return;
    running_ = false;
    stop_cv_.notify_all();
    
    if (monitor_thread_.joinable()) {
      monitor_thread_.join();
    }
    
    // Remove all watches
    for (const auto& [wd, _] : watches_) {
      inotify_rm_watch(inotify_fd_, wd);
    }
    watches_.clear();
    
    if (inotify_fd_ >= 0) {
      close(inotify_fd_);
      inotify_fd_ = -1;
    }
    
    flush();
  }

  bool isRunning() const {
    return running_;
  }

  bool waitForStop(std::chrono::milliseconds timeout) {
    std::unique_lock<std::mutex> lock(stop_mutex_);
    if (timeout.count() == 0) {
      stop_cv_.wait(lock, [this] { return !running_.load(); });
      return true;
    }
    return stop_cv_.wait_for(lock, timeout, [this] { return !running_.load(); });
  }

  bool addSource(const std::string& path) {
    std::lock_guard<std::mutex> lock(sources_mutex_);
    if (std::find(sources_.begin(), sources_.end(), path) != sources_.end()) {
      return false;  // Already exists
    }
    sources_.push_back(path);
    file_positions_[path] = 0;
    
    if (running_) {
      addWatch(path);
    }
    return true;
  }

  bool removeSource(const std::string& path) {
    std::lock_guard<std::mutex> lock(sources_mutex_);
    auto it = std::find(sources_.begin(), sources_.end(), path);
    if (it == sources_.end()) return false;
    
    sources_.erase(it);
    file_positions_.erase(path);
    
    // Remove watch if running
    for (auto wit = watches_.begin(); wit != watches_.end(); ++wit) {
      if (wit->second == path) {
        if (running_) {
          inotify_rm_watch(inotify_fd_, wit->first);
        }
        watches_.erase(wit);
        break;
      }
    }
    return true;
  }

  std::vector<std::string> getSources() const {
    std::lock_guard<std::mutex> lock(sources_mutex_);
    return sources_;
  }

  void clearSources() {
    std::lock_guard<std::mutex> lock(sources_mutex_);
    if (running_) {
      for (const auto& [wd, _] : watches_) {
        inotify_rm_watch(inotify_fd_, wd);
      }
    }
    watches_.clear();
    sources_.clear();
    file_positions_.clear();
  }

  bool addFilter(const std::string& pattern, bool case_insensitive) {
    std::lock_guard<std::mutex> lock(filters_mutex_);
    try {
      auto flags = case_insensitive ? std::regex_constants::icase : std::regex_constants::ECMAScript;
      filters_.emplace_back(pattern, flags);
      filter_patterns_.push_back(pattern);
      return true;
    } catch (const std::regex_error& e) {
      invokeErrorCallbacks("filter", "Invalid regex: " + std::string(e.what()));
      return false;
    }
  }

  bool removeFilter(const std::string& pattern) {
    std::lock_guard<std::mutex> lock(filters_mutex_);
    auto it = std::find(filter_patterns_.begin(), filter_patterns_.end(), pattern);
    if (it == filter_patterns_.end()) return false;
    
    size_t index = std::distance(filter_patterns_.begin(), it);
    filter_patterns_.erase(it);
    filters_.erase(filters_.begin() + index);
    return true;
  }

  void clearFilters() {
    std::lock_guard<std::mutex> lock(filters_mutex_);
    filters_.clear();
    filter_patterns_.clear();
  }

  void setMinSeverity(Severity min_severity) {
    min_severity_ = min_severity;
  }

  Severity getMinSeverity() const {
    return min_severity_;
  }

  void addSeverityFilter(Severity severity) {
    std::lock_guard<std::mutex> lock(filters_mutex_);
    severity_filters_.insert(severity);
  }

  bool addExclusionPattern(const std::string& pattern) {
    std::lock_guard<std::mutex> lock(filters_mutex_);
    try {
      exclusion_patterns_.emplace_back(pattern);
      return true;
    } catch (const std::regex_error& e) {
      invokeErrorCallbacks("filter", "Invalid exclusion regex: " + std::string(e.what()));
      return false;
    }
  }

  bool matchesFilter(const std::string& line) const {
    std::lock_guard<std::mutex> lock(filters_mutex_);
    
    // Check exclusion patterns first
    for (const auto& regex : exclusion_patterns_) {
      if (std::regex_search(line, regex)) {
        return false;
      }
    }
    
    // If no filters, match everything
    if (filters_.empty() && severity_filters_.empty()) {
      return true;
    }
    
    // Check regex filters
    for (const auto& regex : filters_) {
      if (std::regex_search(line, regex)) {
        return true;
      }
    }
    
    // Check severity filters
    if (!severity_filters_.empty()) {
      auto entry = LogEntry::parse(line, "");
      if (entry.severity < min_severity_) {
        return false;
      }
      if (severity_filters_.find(entry.severity) != severity_filters_.end()) {
        return true;
      }
    }
    
    return filters_.empty();  // If only severity filters, and none matched
  }

  void setOutputFile(const std::string& path) {
    output_file_ = path;
  }

  std::string getOutputFile() const {
    return output_file_;
  }

  void setOutputFormat(OutputFormat format) {
    output_format_ = format;
  }

  OutputFormat getOutputFormat() const {
    return output_format_;
  }

  void setMaxFileSize(size_t size) {
    max_file_size_ = size * 1024 * 1024;
  }

  size_t getMaxFileSize() const {
    return max_file_size_ / (1024 * 1024);
  }

  void setMaxBackupFiles(size_t count) {
    max_backup_files_ = count;
  }

  size_t getMaxBackupFiles() const {
    return max_backup_files_;
  }

  void setCompressionType(CompressionType type) {
    compression_type_ = type;
  }

  CompressionType getCompressionType() const {
    return compression_type_;
  }

  void setRateLimit(const RateLimitConfig& config) {
    rate_limiter_.setConfig(config);
  }

  RateLimitConfig getRateLimit() const {
    return rate_limiter_.getConfig();
  }

  void setRateLimitEnabled(bool enabled) {
    rate_limiter_.setEnabled(enabled);
  }

  bool isRateLimitEnabled() const {
    return rate_limiter_.isEnabled();
  }

  LogStatistics getStatistics() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return statistics_;
  }

  void resetStatistics() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    statistics_.reset();
  }

  bool exportStatistics(const std::string& path) const {
    std::ofstream out(path);
    if (!out.is_open()) return false;
    
    std::lock_guard<std::mutex> lock(stats_mutex_);
    out << statistics_.toJson();
    return true;
  }

  size_t onLogEntry(LogCallback callback) {
    std::lock_guard<std::mutex> lock(callbacks_mutex_);
    size_t id = next_callback_id_++;
    log_callbacks_[id] = std::move(callback);
    return id;
  }

  size_t onError(ErrorCallback callback) {
    std::lock_guard<std::mutex> lock(callbacks_mutex_);
    size_t id = next_callback_id_++;
    error_callbacks_[id] = std::move(callback);
    return id;
  }

  size_t onRotation(RotationCallback callback) {
    std::lock_guard<std::mutex> lock(callbacks_mutex_);
    size_t id = next_callback_id_++;
    rotation_callbacks_[id] = std::move(callback);
    return id;
  }

  void removeCallback(size_t id) {
    std::lock_guard<std::mutex> lock(callbacks_mutex_);
    log_callbacks_.erase(id);
    error_callbacks_.erase(id);
    rotation_callbacks_.erase(id);
  }

  void forceRotation() {
    std::lock_guard<std::mutex> lock(output_mutex_);
    if (!output_file_.empty() && fs::exists(output_file_)) {
      rotateFile();
    }
  }

  void flush() {
    std::lock_guard<std::mutex> lock(output_mutex_);
    if (output_stream_.is_open()) {
      output_stream_.flush();
    }
  }

  void addGlobalTag(const std::string& key, const std::string& value) {
    std::lock_guard<std::mutex> lock(tags_mutex_);
    global_tags_[key] = value;
  }

  void removeGlobalTag(const std::string& key) {
    std::lock_guard<std::mutex> lock(tags_mutex_);
    global_tags_.erase(key);
  }

  void setHostname(const std::string& hostname) {
    hostname_ = hostname;
  }

  void setTimestampNormalization(bool enabled) {
    timestamp_normalization_ = enabled;
  }

  void setBufferSize(size_t size) {
    buffer_size_ = size;
  }

  size_t getBufferSize() const {
    return buffer_size_;
  }

  static std::vector<LogEntry> parseLogFile(const std::string& path, size_t limit) {
    std::vector<LogEntry> entries;
    std::ifstream file(path);
    if (!file.is_open()) return entries;
    
    std::string line;
    uint64_t line_num = 0;
    while (std::getline(file, line)) {
      ++line_num;
      auto entry = LogEntry::parse(line, path);
      entry.line_number = line_num;
      entries.push_back(std::move(entry));
      
      if (limit > 0 && entries.size() >= limit) break;
    }
    return entries;
  }

  static std::vector<LogEntry> searchLogFile(const std::string& path, const std::string& pattern,
                                              bool case_insensitive) {
    std::vector<LogEntry> matches;
    std::ifstream file(path);
    if (!file.is_open()) return matches;
    
    auto flags = case_insensitive ? std::regex_constants::icase : std::regex_constants::ECMAScript;
    std::regex regex(pattern, flags);
    
    std::string line;
    uint64_t line_num = 0;
    while (std::getline(file, line)) {
      ++line_num;
      if (std::regex_search(line, regex)) {
        auto entry = LogEntry::parse(line, path);
        entry.line_number = line_num;
        matches.push_back(std::move(entry));
      }
    }
    return matches;
  }

private:
  void addWatch(const std::string& path) {
    if (!fs::exists(path)) {
      std::cerr << "Source file does not exist: " << path << std::endl;
      return;
    }
    
    int wd = inotify_add_watch(inotify_fd_, path.c_str(), 
                               IN_MODIFY | IN_DELETE_SELF | IN_MOVE_SELF | IN_ATTRIB);
    if (wd < 0) {
      invokeErrorCallbacks(path, "Failed to add watch: " + std::string(strerror(errno)));
    } else {
      watches_[wd] = path;
      
      // Initialize file position to end of file to avoid processing old content
      std::ifstream file(path, std::ios::ate);
      if (file.is_open()) {
        file_positions_[path] = file.tellg();
      }
    }
  }

  void monitor() {
    const size_t BUF_LEN = 4096;
    char buffer[BUF_LEN];
    
    while (running_) {
      fd_set fds;
      FD_ZERO(&fds);
      FD_SET(inotify_fd_, &fds);
      
      struct timeval tv;
      tv.tv_sec = 0;
      tv.tv_usec = 100000;  // 100ms timeout
      
      int ret = select(inotify_fd_ + 1, &fds, nullptr, nullptr, &tv);
      if (ret < 0) {
        if (errno != EINTR) {
          invokeErrorCallbacks("inotify", "Select error: " + std::string(strerror(errno)));
        }
        continue;
      }
      
      if (ret == 0) continue;  // Timeout
      
      int length = read(inotify_fd_, buffer, BUF_LEN);
      if (length < 0) {
        if (errno != EAGAIN && errno != EINTR) {
          invokeErrorCallbacks("inotify", "Read error: " + std::string(strerror(errno)));
        }
        continue;
      }

      int i = 0;
      while (i < length) {
        struct inotify_event* event = reinterpret_cast<struct inotify_event*>(&buffer[i]);
        
        auto it = watches_.find(event->wd);
        if (it != watches_.end()) {
          if (event->mask & IN_MODIFY) {
            processFile(it->second);
          } else if (event->mask & (IN_DELETE_SELF | IN_MOVE_SELF)) {
            // File was deleted or moved, reset position and try to re-watch
            file_positions_[it->second] = 0;
            inotify_rm_watch(inotify_fd_, event->wd);
            watches_.erase(it);
            
            // Try to re-add watch after a short delay
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            addWatch(it->second);
          } else if (event->mask & IN_ATTRIB) {
            // File attributes changed (truncation)
            std::ifstream file(it->second, std::ios::ate);
            if (file.is_open()) {
              auto current_size = file.tellg();
              if (current_size < file_positions_[it->second]) {
                // File was truncated
                file_positions_[it->second] = 0;
              }
            }
          }
        }
        i += sizeof(struct inotify_event) + event->len;
      }
    }
  }

  void processFile(const std::string& path) {
    std::ifstream file(path, std::ios::in);
    if (!file.is_open()) {
      invokeErrorCallbacks(path, "Cannot open file");
      return;
    }

    file.seekg(file_positions_[path]);
    std::string line;
    uint64_t lines_in_batch = 0;
    
    while (std::getline(file, line)) {
      ++lines_in_batch;
      
      {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        statistics_.total_lines++;
        statistics_.bytes_processed += line.size();
        statistics_.source_counts[path]++;
        statistics_.last_update = std::chrono::system_clock::now();
      }
      
      // Check rate limit
      if (!rate_limiter_.tryAcquire(line.size())) {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        statistics_.dropped_lines++;
        continue;
      }
      
      // Check filters
      if (!matchesFilter(line)) continue;
      
      // Parse and process entry
      auto entry = LogEntry::parse(line, path);
      
      // Check severity filter
      if (entry.severity < min_severity_) continue;
      
      // Add global tags
      {
        std::lock_guard<std::mutex> lock(tags_mutex_);
        for (const auto& [key, value] : global_tags_) {
          entry.tags[key] = value;
        }
      }
      entry.hostname = hostname_;
      
      // Update statistics
      {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        statistics_.filtered_lines++;
        statistics_.severity_counts[entry.severity]++;
      }
      
      // Write to output
      writeToOutput(entry);
      
      // Invoke callbacks
      invokeLogCallbacks(entry);
    }
    
    file_positions_[path] = file.tellg();
  }

  void writeToOutput(const LogEntry& entry) {
    if (output_file_.empty()) return;
    
    std::lock_guard<std::mutex> lock(output_mutex_);
    
    // Check file size and rotate if needed
    if (fs::exists(output_file_) && fs::file_size(output_file_) > max_file_size_) {
      rotateFile();
    }
    
    // Open file if not already open
    if (!output_stream_.is_open()) {
      output_stream_.open(output_file_, std::ios::app);
      if (!output_stream_.is_open()) {
        invokeErrorCallbacks(output_file_, "Cannot open output file");
        return;
      }
    }
    
    std::string output_line;
    switch (output_format_) {
      case OutputFormat::JSON:
        output_line = entry.toJson();
        break;
      case OutputFormat::CSV:
        output_line = formatCsv(entry);
        break;
      case OutputFormat::SYSLOG:
        output_line = formatSyslog(entry);
        break;
      case OutputFormat::PLAIN:
      default:
        output_line = formatPlain(entry);
        break;
    }
    
    output_stream_ << output_line << std::endl;
    
    {
      std::lock_guard<std::mutex> stats_lock(stats_mutex_);
      statistics_.bytes_written += output_line.size() + 1;
    }
  }

  std::string formatPlain(const LogEntry& entry) const {
    std::ostringstream oss;
    if (timestamp_normalization_ && entry.timestamp.empty()) {
      auto now = std::chrono::system_clock::now();
      auto time_t = std::chrono::system_clock::to_time_t(now);
      std::tm tm = *std::localtime(&time_t);
      char time_str[20];
      std::strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", &tm);
      oss << time_str;
    } else {
      oss << entry.timestamp;
    }
    oss << " [" << severityToString(entry.severity) << "] ";
    if (!entry.hostname.empty()) {
      oss << entry.hostname << " ";
    }
    if (!entry.process.empty()) {
      oss << entry.process << ": ";
    }
    oss << entry.message;
    return oss.str();
  }

  std::string formatCsv(const LogEntry& entry) const {
    std::ostringstream oss;
    auto escape_csv = [](const std::string& s) {
      std::string result;
      result.reserve(s.size() + 2);
      result += '"';
      for (char c : s) {
        if (c == '"') result += "\"\"";
        else result += c;
      }
      result += '"';
      return result;
    };
    
    oss << escape_csv(entry.timestamp) << ","
        << escape_csv(severityToString(entry.severity)) << ","
        << escape_csv(entry.source) << ","
        << escape_csv(entry.hostname) << ","
        << escape_csv(entry.process) << ","
        << escape_csv(entry.message);
    return oss.str();
  }

  std::string formatSyslog(const LogEntry& entry) const {
    // RFC 5424 format
    std::ostringstream oss;
    int priority = 16 * 8 + static_cast<int>(entry.severity);  // local0 facility
    oss << "<" << priority << ">1 " << entry.timestamp << " " 
        << (entry.hostname.empty() ? "-" : entry.hostname) << " "
        << (entry.process.empty() ? "-" : entry.process) << " - - - "
        << entry.message;
    return oss.str();
  }

  void rotateFile() {
    output_stream_.close();
    
    std::string old_file = output_file_;
    
    // Rotate existing backups
    for (int i = static_cast<int>(max_backup_files_) - 1; i >= 1; --i) {
      std::string current = output_file_ + "." + std::to_string(i);
      std::string next = output_file_ + "." + std::to_string(i + 1);
      
      // Add compression extension if applicable
      if (compression_type_ == CompressionType::GZIP) {
        current += ".gz";
        next += ".gz";
      }
      
      if (fs::exists(current)) {
        if (fs::exists(next)) {
          fs::remove(next);
        }
        fs::rename(current, next);
      }
    }
    
    std::string first_backup = output_file_ + ".1";
    if (compression_type_ == CompressionType::GZIP) {
      first_backup += ".gz";
      compressFile(output_file_, first_backup);
      fs::remove(output_file_);
    } else {
      if (fs::exists(first_backup)) {
        fs::remove(first_backup);
      }
      fs::rename(output_file_, first_backup);
    }
    
    // Invoke rotation callbacks
    invokeRotationCallbacks(old_file, first_backup);
    
    // Reopen output file
    output_stream_.open(output_file_, std::ios::app);
  }

  void compressFile(const std::string& input, const std::string& output) {
    std::ifstream in(input, std::ios::binary);
    if (!in.is_open()) return;
    
    gzFile gz = gzopen(output.c_str(), "wb9");
    if (!gz) return;
    
    char buffer[8192];
    while (in.read(buffer, sizeof(buffer)) || in.gcount() > 0) {
      gzwrite(gz, buffer, static_cast<unsigned>(in.gcount()));
    }
    
    gzclose(gz);
  }

  void invokeLogCallbacks(const LogEntry& entry) {
    std::lock_guard<std::mutex> lock(callbacks_mutex_);
    for (const auto& [_, callback] : log_callbacks_) {
      try {
        callback(entry);
      } catch (...) {
        // Ignore callback exceptions
      }
    }
  }

  void invokeErrorCallbacks(const std::string& source, const std::string& error) {
    std::lock_guard<std::mutex> lock(callbacks_mutex_);
    for (const auto& [_, callback] : error_callbacks_) {
      try {
        callback(source, error);
      } catch (...) {
        // Ignore callback exceptions
      }
    }
  }

  void invokeRotationCallbacks(const std::string& old_file, const std::string& new_file) {
    std::lock_guard<std::mutex> lock(callbacks_mutex_);
    for (const auto& [_, callback] : rotation_callbacks_) {
      try {
        callback(old_file, new_file);
      } catch (...) {
        // Ignore callback exceptions
      }
    }
  }

  // Sources
  std::vector<std::string> sources_;
  mutable std::mutex sources_mutex_;
  
  // Filters
  std::vector<std::regex> filters_;
  std::vector<std::string> filter_patterns_;
  std::vector<std::regex> exclusion_patterns_;
  std::unordered_set<Severity> severity_filters_;
  mutable std::mutex filters_mutex_;
  std::atomic<Severity> min_severity_;
  
  // Output
  std::string output_file_;
  std::ofstream output_stream_;
  std::mutex output_mutex_;
  size_t max_file_size_;
  size_t max_backup_files_;
  OutputFormat output_format_;
  CompressionType compression_type_;
  bool timestamp_normalization_;
  size_t buffer_size_;
  
  // Inotify
  std::atomic<bool> running_;
  int inotify_fd_ = -1;
  std::unordered_map<int, std::string> watches_;
  std::unordered_map<std::string, std::streampos> file_positions_;
  std::thread monitor_thread_;
  
  // Stop synchronization
  std::mutex stop_mutex_;
  std::condition_variable stop_cv_;
  
  // Rate limiting
  RateLimiter rate_limiter_;
  
  // Statistics
  LogStatistics statistics_;
  mutable std::mutex stats_mutex_;
  
  // Callbacks
  std::map<size_t, LogCallback> log_callbacks_;
  std::map<size_t, ErrorCallback> error_callbacks_;
  std::map<size_t, RotationCallback> rotation_callbacks_;
  std::mutex callbacks_mutex_;
  size_t next_callback_id_;
  
  // Tags and metadata
  std::map<std::string, std::string> global_tags_;
  std::mutex tags_mutex_;
  std::string hostname_;
};

// ==================== LogAggregator Public Interface ====================

LogAggregator::LogAggregator() : pimpl_(std::make_unique<Impl>()) {}

LogAggregator::~LogAggregator() = default;

LogAggregator::LogAggregator(LogAggregator&&) noexcept = default;
LogAggregator& LogAggregator::operator=(LogAggregator&&) noexcept = default;

void LogAggregator::start() { pimpl_->start(); }
void LogAggregator::stop() { pimpl_->stop(); }
bool LogAggregator::isRunning() const { return pimpl_->isRunning(); }
bool LogAggregator::waitForStop(std::chrono::milliseconds timeout) { return pimpl_->waitForStop(timeout); }

bool LogAggregator::addSource(const std::string& path) { return pimpl_->addSource(path); }
bool LogAggregator::removeSource(const std::string& path) { return pimpl_->removeSource(path); }
std::vector<std::string> LogAggregator::getSources() const { return pimpl_->getSources(); }
void LogAggregator::clearSources() { pimpl_->clearSources(); }

bool LogAggregator::addFilter(const std::string& pattern, bool case_insensitive) {
  return pimpl_->addFilter(pattern, case_insensitive);
}
bool LogAggregator::removeFilter(const std::string& pattern) { return pimpl_->removeFilter(pattern); }
void LogAggregator::clearFilters() { pimpl_->clearFilters(); }
void LogAggregator::setMinSeverity(Severity min_severity) { pimpl_->setMinSeverity(min_severity); }
Severity LogAggregator::getMinSeverity() const { return pimpl_->getMinSeverity(); }
void LogAggregator::addSeverityFilter(Severity severity) { pimpl_->addSeverityFilter(severity); }
bool LogAggregator::addExclusionPattern(const std::string& pattern) {
  return pimpl_->addExclusionPattern(pattern);
}
bool LogAggregator::matchesFilter(const std::string& line) const { return pimpl_->matchesFilter(line); }

void LogAggregator::setOutputFile(const std::string& path) { pimpl_->setOutputFile(path); }
std::string LogAggregator::getOutputFile() const { return pimpl_->getOutputFile(); }
void LogAggregator::setOutputFormat(OutputFormat format) { pimpl_->setOutputFormat(format); }
OutputFormat LogAggregator::getOutputFormat() const { return pimpl_->getOutputFormat(); }
void LogAggregator::setMaxFileSize(size_t size) { pimpl_->setMaxFileSize(size); }
size_t LogAggregator::getMaxFileSize() const { return pimpl_->getMaxFileSize(); }
void LogAggregator::setMaxBackupFiles(size_t count) { pimpl_->setMaxBackupFiles(count); }
size_t LogAggregator::getMaxBackupFiles() const { return pimpl_->getMaxBackupFiles(); }
void LogAggregator::setCompressionType(CompressionType type) { pimpl_->setCompressionType(type); }
CompressionType LogAggregator::getCompressionType() const { return pimpl_->getCompressionType(); }

void LogAggregator::setRateLimit(const RateLimitConfig& config) { pimpl_->setRateLimit(config); }
RateLimitConfig LogAggregator::getRateLimit() const { return pimpl_->getRateLimit(); }
void LogAggregator::setRateLimitEnabled(bool enabled) { pimpl_->setRateLimitEnabled(enabled); }
bool LogAggregator::isRateLimitEnabled() const { return pimpl_->isRateLimitEnabled(); }

LogStatistics LogAggregator::getStatistics() const { return pimpl_->getStatistics(); }
void LogAggregator::resetStatistics() { pimpl_->resetStatistics(); }
bool LogAggregator::exportStatistics(const std::string& path) const {
  return pimpl_->exportStatistics(path);
}

size_t LogAggregator::onLogEntry(LogCallback callback) { return pimpl_->onLogEntry(std::move(callback)); }
size_t LogAggregator::onError(ErrorCallback callback) { return pimpl_->onError(std::move(callback)); }
size_t LogAggregator::onRotation(RotationCallback callback) { return pimpl_->onRotation(std::move(callback)); }
void LogAggregator::removeCallback(size_t id) { pimpl_->removeCallback(id); }

void LogAggregator::forceRotation() { pimpl_->forceRotation(); }
void LogAggregator::flush() { pimpl_->flush(); }
void LogAggregator::addGlobalTag(const std::string& key, const std::string& value) {
  pimpl_->addGlobalTag(key, value);
}
void LogAggregator::removeGlobalTag(const std::string& key) { pimpl_->removeGlobalTag(key); }
void LogAggregator::setHostname(const std::string& hostname) { pimpl_->setHostname(hostname); }
void LogAggregator::setTimestampNormalization(bool enabled) { pimpl_->setTimestampNormalization(enabled); }
void LogAggregator::setBufferSize(size_t size) { pimpl_->setBufferSize(size); }
size_t LogAggregator::getBufferSize() const { return pimpl_->getBufferSize(); }

std::vector<LogEntry> LogAggregator::parseLogFile(const std::string& path, size_t limit) {
  return Impl::parseLogFile(path, limit);
}

std::vector<LogEntry> LogAggregator::searchLogFile(const std::string& path, const std::string& pattern,
                                                    bool case_insensitive) {
  return Impl::searchLogFile(path, pattern, case_insensitive);
}

}  // namespace log_aggregator