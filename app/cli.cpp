/**
 * @file cli.cpp
 * @brief Enhanced CLI tool for the log_aggregator library.
 * @author Sandesh Ghimire | sandesh@soccentric
 * @copyright (C) Soccentric LLC. All rights reserved.
 *
 * This file provides a comprehensive CLI interface for searching, analyzing,
 * and monitoring log files with support for multiple output formats, filtering,
 * and real-time monitoring capabilities.
 */

#include <CLI/CLI.hpp>
#include <algorithm>
#include <chrono>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <regex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "log_aggregator/log_aggregator.h"

namespace fs = std::filesystem;
using namespace log_aggregator;

// ==================== Output Formatting ====================

namespace colors {
const std::string RESET = "\033[0m";
const std::string RED = "\033[31m";
const std::string GREEN = "\033[32m";
const std::string YELLOW = "\033[33m";
const std::string BLUE = "\033[34m";
const std::string MAGENTA = "\033[35m";
const std::string CYAN = "\033[36m";
const std::string WHITE = "\033[37m";
const std::string BOLD = "\033[1m";
const std::string DIM = "\033[2m";

std::string severityColor(Severity sev) {
  switch (sev) {
    case Severity::DEBUG: return DIM;
    case Severity::INFO: return GREEN;
    case Severity::WARNING: return YELLOW;
    case Severity::ERROR: return RED;
    case Severity::CRITICAL: return BOLD + RED;
    default: return RESET;
  }
}
}  // namespace colors

// ==================== Search Command ====================

void searchLogs(const std::string& file, const std::string& pattern, bool case_insensitive,
                bool show_context, int context_lines, bool count_only, bool invert_match,
                const std::string& output_format, bool colorize, int max_results,
                const std::string& severity_filter) {
  std::ifstream in(file);
  if (!in.is_open()) {
    std::cerr << "Cannot open file: " << file << std::endl;
    return;
  }

  std::regex regex_pattern(
      pattern, case_insensitive ? std::regex_constants::icase : std::regex_constants::ECMAScript);

  std::optional<Severity> min_severity;
  if (!severity_filter.empty()) {
    min_severity = severityFromString(severity_filter);
    if (!min_severity) {
      std::cerr << "Invalid severity level: " << severity_filter << std::endl;
      return;
    }
  }

  std::vector<std::pair<size_t, std::string>> all_lines;
  std::string line;
  size_t line_number = 0;
  
  while (std::getline(in, line)) {
    ++line_number;
    all_lines.emplace_back(line_number, line);
  }

  std::vector<size_t> matches;
  for (size_t i = 0; i < all_lines.size(); ++i) {
    const auto& [num, content] = all_lines[i];
    bool match = std::regex_search(content, regex_pattern);
    if (invert_match) match = !match;
    
    if (match) {
      // Check severity filter
      if (min_severity) {
        auto entry = LogEntry::parse(content, file);
        if (entry.severity < *min_severity) continue;
      }
      matches.push_back(i);
      if (max_results > 0 && static_cast<int>(matches.size()) >= max_results) break;
    }
  }

  if (count_only) {
    std::cout << matches.size() << std::endl;
    return;
  }

  // Output results
  std::set<size_t> printed_lines;
  
  for (size_t match_idx : matches) {
    size_t start = (show_context && match_idx >= static_cast<size_t>(context_lines))
                       ? match_idx - context_lines : 0;
    size_t end = (show_context && match_idx + context_lines < all_lines.size())
                     ? match_idx + context_lines : match_idx;

    for (size_t i = start; i <= end && i < all_lines.size(); ++i) {
      if (printed_lines.count(i)) continue;
      printed_lines.insert(i);

      const auto& [num, content] = all_lines[i];
      bool is_match = (i == match_idx);

      if (output_format == "json") {
        auto entry = LogEntry::parse(content, file);
        entry.line_number = num;
        std::cout << entry.toJson() << std::endl;
      } else if (output_format == "csv") {
        std::cout << num << ",\"" << content << "\"," << (is_match ? "1" : "0") << std::endl;
      } else {
        // Plain format
        if (colorize && is_match) {
          std::cout << colors::CYAN << num << colors::RESET << ": ";
          // Highlight matching part
          std::string highlighted = content;
          std::smatch match;
          if (std::regex_search(content, match, regex_pattern)) {
            size_t pos = match.position();
            size_t len = match.length();
            highlighted = content.substr(0, pos) + colors::BOLD + colors::YELLOW +
                          content.substr(pos, len) + colors::RESET + content.substr(pos + len);
          }
          std::cout << highlighted << std::endl;
        } else {
          std::cout << num << ": " << content << std::endl;
        }
      }
    }

    if (show_context && !printed_lines.empty()) {
      std::cout << "--" << std::endl;
    }
  }
}

// ==================== Tail Command ====================

void tailLogs(const std::string& file, int lines, bool follow, bool colorize,
              const std::string& filter_pattern, const std::string& severity_filter) {
  std::ifstream in(file);
  if (!in.is_open()) {
    std::cerr << "Cannot open file: " << file << std::endl;
    return;
  }

  std::optional<std::regex> filter_regex;
  if (!filter_pattern.empty()) {
    filter_regex = std::regex(filter_pattern, std::regex_constants::icase);
  }

  std::optional<Severity> min_severity;
  if (!severity_filter.empty()) {
    min_severity = severityFromString(severity_filter);
  }

  // Read last N lines
  std::vector<std::string> buffer;
  std::string line;
  while (std::getline(in, line)) {
    if (filter_regex && !std::regex_search(line, *filter_regex)) continue;
    if (min_severity) {
      auto entry = LogEntry::parse(line, file);
      if (entry.severity < *min_severity) continue;
    }
    buffer.push_back(line);
    if (buffer.size() > static_cast<size_t>(lines)) {
      buffer.erase(buffer.begin());
    }
  }

  // Print initial lines
  for (const auto& l : buffer) {
    if (colorize) {
      auto entry = LogEntry::parse(l, file);
      std::cout << colors::severityColor(entry.severity) << l << colors::RESET << std::endl;
    } else {
      std::cout << l << std::endl;
    }
  }

  if (!follow) return;

  // Continue monitoring for new lines
  in.clear();
  in.seekg(0, std::ios::end);
  std::streampos last_pos = in.tellg();

  while (true) {
    in.seekg(last_pos);
    while (std::getline(in, line)) {
      if (filter_regex && !std::regex_search(line, *filter_regex)) {
        last_pos = in.tellg();
        continue;
      }
      if (min_severity) {
        auto entry = LogEntry::parse(line, file);
        if (entry.severity < *min_severity) {
          last_pos = in.tellg();
          continue;
        }
      }
      if (colorize) {
        auto entry = LogEntry::parse(line, file);
        std::cout << colors::severityColor(entry.severity) << line << colors::RESET << std::endl;
      } else {
        std::cout << line << std::endl;
      }
      last_pos = in.tellg();
    }
    in.clear();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Check for file truncation
    in.seekg(0, std::ios::end);
    std::streampos current_size = in.tellg();
    if (current_size < last_pos) {
      last_pos = 0;
      in.seekg(0);
      std::cout << colors::YELLOW << "=== File truncated, restarting ===" << colors::RESET << std::endl;
    }
  }
}

// ==================== Stats Command ====================

void showStats(const std::string& file, bool json_output, bool detailed) {
  std::ifstream in(file);
  if (!in.is_open()) {
    std::cerr << "Cannot open file: " << file << std::endl;
    return;
  }

  struct Stats {
    uint64_t total_lines = 0;
    uint64_t total_bytes = 0;
    std::map<Severity, uint64_t> severity_counts;
    std::map<std::string, uint64_t> hourly_distribution;
    std::map<std::string, uint64_t> source_counts;
    std::string first_timestamp;
    std::string last_timestamp;
    uint64_t avg_line_length = 0;
    uint64_t max_line_length = 0;
    uint64_t min_line_length = UINT64_MAX;
  } stats;

  std::string line;
  while (std::getline(in, line)) {
    stats.total_lines++;
    stats.total_bytes += line.size();
    stats.max_line_length = std::max(stats.max_line_length, static_cast<uint64_t>(line.size()));
    stats.min_line_length = std::min(stats.min_line_length, static_cast<uint64_t>(line.size()));

    auto entry = LogEntry::parse(line, file);
    stats.severity_counts[entry.severity]++;

    if (!entry.timestamp.empty()) {
      if (stats.first_timestamp.empty()) stats.first_timestamp = entry.timestamp;
      stats.last_timestamp = entry.timestamp;

      // Extract hour for distribution
      std::regex hour_regex(R"((\d{2}):\d{2}:\d{2})");
      std::smatch match;
      if (std::regex_search(entry.timestamp, match, hour_regex)) {
        stats.hourly_distribution[match[1].str()]++;
      }
    }

    if (!entry.hostname.empty()) {
      stats.source_counts[entry.hostname]++;
    }
  }

  if (stats.total_lines > 0) {
    stats.avg_line_length = stats.total_bytes / stats.total_lines;
  }
  if (stats.min_line_length == UINT64_MAX) stats.min_line_length = 0;

  if (json_output) {
    std::cout << "{" << std::endl;
    std::cout << "  \"file\": \"" << file << "\"," << std::endl;
    std::cout << "  \"total_lines\": " << stats.total_lines << "," << std::endl;
    std::cout << "  \"total_bytes\": " << stats.total_bytes << "," << std::endl;
    std::cout << "  \"avg_line_length\": " << stats.avg_line_length << "," << std::endl;
    std::cout << "  \"min_line_length\": " << stats.min_line_length << "," << std::endl;
    std::cout << "  \"max_line_length\": " << stats.max_line_length << "," << std::endl;
    std::cout << "  \"first_timestamp\": \"" << stats.first_timestamp << "\"," << std::endl;
    std::cout << "  \"last_timestamp\": \"" << stats.last_timestamp << "\"," << std::endl;
    std::cout << "  \"severity_counts\": {";
    bool first = true;
    for (const auto& [sev, count] : stats.severity_counts) {
      if (!first) std::cout << ",";
      std::cout << "\"" << severityToString(sev) << "\": " << count;
      first = false;
    }
    std::cout << "}";
    if (detailed) {
      std::cout << "," << std::endl << "  \"hourly_distribution\": {";
      first = true;
      for (const auto& [hour, count] : stats.hourly_distribution) {
        if (!first) std::cout << ",";
        std::cout << "\"" << hour << "\": " << count;
        first = false;
      }
      std::cout << "}";
    }
    std::cout << std::endl << "}" << std::endl;
  } else {
    std::cout << colors::BOLD << "=== Log Statistics ===" << colors::RESET << std::endl;
    std::cout << "File: " << file << std::endl;
    std::cout << "Total lines: " << stats.total_lines << std::endl;
    std::cout << "Total size: " << (stats.total_bytes / 1024.0) << " KB" << std::endl;
    std::cout << "Line length (min/avg/max): " << stats.min_line_length << "/" 
              << stats.avg_line_length << "/" << stats.max_line_length << std::endl;
    std::cout << "Time range: " << stats.first_timestamp << " to " << stats.last_timestamp << std::endl;
    
    std::cout << std::endl << colors::BOLD << "Severity Distribution:" << colors::RESET << std::endl;
    for (const auto& [sev, count] : stats.severity_counts) {
      double pct = (stats.total_lines > 0) ? (count * 100.0 / stats.total_lines) : 0;
      std::cout << "  " << colors::severityColor(sev) << std::setw(10) << severityToString(sev)
                << colors::RESET << ": " << std::setw(8) << count 
                << " (" << std::fixed << std::setprecision(1) << pct << "%)" << std::endl;
    }

    if (detailed && !stats.hourly_distribution.empty()) {
      std::cout << std::endl << colors::BOLD << "Hourly Distribution:" << colors::RESET << std::endl;
      uint64_t max_count = 0;
      for (const auto& [_, count] : stats.hourly_distribution) {
        max_count = std::max(max_count, count);
      }
      for (int h = 0; h < 24; ++h) {
        std::string hour = (h < 10 ? "0" : "") + std::to_string(h);
        auto it = stats.hourly_distribution.find(hour);
        uint64_t count = (it != stats.hourly_distribution.end()) ? it->second : 0;
        int bar_len = (max_count > 0) ? static_cast<int>(count * 40.0 / max_count) : 0;
        std::cout << "  " << hour << ":00 |" << std::string(bar_len, '#') 
                  << std::string(40 - bar_len, ' ') << "| " << count << std::endl;
      }
    }
  }
}

// ==================== Filter Command ====================

void filterLogs(const std::string& input_file, const std::string& output_file,
                const std::string& pattern, const std::string& severity_filter,
                bool case_insensitive, bool invert_match, const std::string& output_format) {
  std::ifstream in(input_file);
  if (!in.is_open()) {
    std::cerr << "Cannot open input file: " << input_file << std::endl;
    return;
  }

  std::ofstream out;
  std::ostream* output = &std::cout;
  if (!output_file.empty()) {
    out.open(output_file);
    if (!out.is_open()) {
      std::cerr << "Cannot open output file: " << output_file << std::endl;
      return;
    }
    output = &out;
  }

  std::optional<std::regex> filter_regex;
  if (!pattern.empty()) {
    auto flags = case_insensitive ? std::regex_constants::icase : std::regex_constants::ECMAScript;
    filter_regex = std::regex(pattern, flags);
  }

  std::optional<Severity> min_severity;
  if (!severity_filter.empty()) {
    min_severity = severityFromString(severity_filter);
  }

  std::string line;
  uint64_t line_num = 0;
  uint64_t matched = 0;

  while (std::getline(in, line)) {
    ++line_num;
    bool match = true;

    if (filter_regex) {
      match = std::regex_search(line, *filter_regex);
      if (invert_match) match = !match;
    }

    if (match && min_severity) {
      auto entry = LogEntry::parse(line, input_file);
      match = (entry.severity >= *min_severity);
    }

    if (match) {
      ++matched;
      if (output_format == "json") {
        auto entry = LogEntry::parse(line, input_file);
        entry.line_number = line_num;
        *output << entry.toJson() << std::endl;
      } else {
        *output << line << std::endl;
      }
    }
  }

  std::cerr << "Processed " << line_num << " lines, matched " << matched << std::endl;
}

// ==================== Merge Command ====================

void mergeLogs(const std::vector<std::string>& input_files, const std::string& output_file,
               bool sort_by_time) {
  struct TimedLine {
    std::string timestamp;
    std::string content;
    std::string source;

    bool operator<(const TimedLine& other) const {
      return timestamp < other.timestamp;
    }
  };

  std::vector<TimedLine> all_lines;

  for (const auto& file : input_files) {
    std::ifstream in(file);
    if (!in.is_open()) {
      std::cerr << "Cannot open file: " << file << std::endl;
      continue;
    }

    std::string line;
    while (std::getline(in, line)) {
      auto entry = LogEntry::parse(line, file);
      all_lines.push_back({entry.timestamp, line, file});
    }
  }

  if (sort_by_time) {
    std::sort(all_lines.begin(), all_lines.end());
  }

  std::ofstream out;
  std::ostream* output = &std::cout;
  if (!output_file.empty()) {
    out.open(output_file);
    if (!out.is_open()) {
      std::cerr << "Cannot open output file: " << output_file << std::endl;
      return;
    }
    output = &out;
  }

  for (const auto& tl : all_lines) {
    *output << tl.content << std::endl;
  }

  std::cerr << "Merged " << all_lines.size() << " lines from " << input_files.size() << " files" << std::endl;
}

// ==================== Parse Command ====================

void parseLogs(const std::string& file, int limit, const std::string& output_format, bool colorize) {
  auto entries = LogAggregator::parseLogFile(file, limit);

  if (output_format == "json") {
    std::cout << "[" << std::endl;
    for (size_t i = 0; i < entries.size(); ++i) {
      std::cout << "  " << entries[i].toJson();
      if (i < entries.size() - 1) std::cout << ",";
      std::cout << std::endl;
    }
    std::cout << "]" << std::endl;
  } else if (output_format == "csv") {
    std::cout << "timestamp,severity,source,hostname,process,message" << std::endl;
    for (const auto& entry : entries) {
      std::cout << "\"" << entry.timestamp << "\","
                << "\"" << severityToString(entry.severity) << "\","
                << "\"" << entry.source << "\","
                << "\"" << entry.hostname << "\","
                << "\"" << entry.process << "\","
                << "\"" << entry.message << "\"" << std::endl;
    }
  } else {
    for (const auto& entry : entries) {
      if (colorize) {
        std::cout << colors::DIM << entry.timestamp << colors::RESET << " "
                  << colors::severityColor(entry.severity) << "[" 
                  << severityToString(entry.severity) << "]" << colors::RESET << " ";
        if (!entry.hostname.empty()) {
          std::cout << colors::CYAN << entry.hostname << colors::RESET << " ";
        }
        if (!entry.process.empty()) {
          std::cout << colors::MAGENTA << entry.process << colors::RESET << ": ";
        }
        std::cout << entry.message << std::endl;
      } else {
        std::cout << entry.timestamp << " [" << severityToString(entry.severity) << "] ";
        if (!entry.hostname.empty()) std::cout << entry.hostname << " ";
        if (!entry.process.empty()) std::cout << entry.process << ": ";
        std::cout << entry.message << std::endl;
      }
    }
  }
}

// ==================== Watch Command ====================

void watchDirectory(const std::string& directory, const std::string& pattern,
                    const std::string& severity_filter, bool colorize) {
  if (!fs::is_directory(directory)) {
    std::cerr << "Not a directory: " << directory << std::endl;
    return;
  }

  std::optional<std::regex> filter_regex;
  if (!pattern.empty()) {
    filter_regex = std::regex(pattern, std::regex_constants::icase);
  }

  std::optional<Severity> min_severity;
  if (!severity_filter.empty()) {
    min_severity = severityFromString(severity_filter);
  }

  std::map<std::string, std::streampos> file_positions;

  // Initialize file positions
  for (const auto& entry : fs::directory_iterator(directory)) {
    if (entry.is_regular_file() && entry.path().extension() == ".log") {
      std::ifstream file(entry.path(), std::ios::ate);
      if (file.is_open()) {
        file_positions[entry.path().string()] = file.tellg();
      }
    }
  }

  std::cout << "Watching " << file_positions.size() << " log files in " << directory << std::endl;
  std::cout << "Press Ctrl+C to stop..." << std::endl << std::endl;

  while (true) {
    for (auto& [file_path, pos] : file_positions) {
      std::ifstream file(file_path);
      if (!file.is_open()) continue;

      file.seekg(pos);
      std::string line;
      while (std::getline(file, line)) {
        if (filter_regex && !std::regex_search(line, *filter_regex)) {
          pos = file.tellg();
          continue;
        }

        auto entry = LogEntry::parse(line, file_path);
        if (min_severity && entry.severity < *min_severity) {
          pos = file.tellg();
          continue;
        }

        std::string filename = fs::path(file_path).filename().string();
        if (colorize) {
          std::cout << colors::BLUE << "[" << filename << "]" << colors::RESET << " "
                    << colors::severityColor(entry.severity) << line << colors::RESET << std::endl;
        } else {
          std::cout << "[" << filename << "] " << line << std::endl;
        }
        pos = file.tellg();
      }

      // Check for file truncation
      file.seekg(0, std::ios::end);
      if (file.tellg() < pos) {
        pos = 0;
      }
    }

    // Check for new files
    for (const auto& entry : fs::directory_iterator(directory)) {
      if (entry.is_regular_file() && entry.path().extension() == ".log") {
        std::string path = entry.path().string();
        if (file_positions.find(path) == file_positions.end()) {
          std::cout << colors::GREEN << "New file detected: " << path << colors::RESET << std::endl;
          file_positions[path] = 0;
        }
      }
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(200));
  }
}

// ==================== Rotate Command ====================

void rotateLog(const std::string& file, int keep_backups, bool compress) {
  if (!fs::exists(file)) {
    std::cerr << "File does not exist: " << file << std::endl;
    return;
  }

  // Rotate existing backups
  for (int i = keep_backups - 1; i >= 1; --i) {
    std::string current = file + "." + std::to_string(i);
    std::string next = file + "." + std::to_string(i + 1);
    if (compress) {
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

  std::string first_backup = file + ".1";
  if (compress) {
    // Simple compression placeholder - in production would use zlib
    std::string gz_file = first_backup + ".gz";
    std::ifstream in(file, std::ios::binary);
    std::ofstream out(gz_file, std::ios::binary);
    // Copy content (would compress in real implementation)
    out << in.rdbuf();
    fs::remove(file);
    std::ofstream(file).close();  // Create empty file
  } else {
    if (fs::exists(first_backup)) {
      fs::remove(first_backup);
    }
    fs::rename(file, first_backup);
    std::ofstream(file).close();  // Create empty file
  }

  std::cout << "Rotated " << file << " (keeping " << keep_backups << " backups)" << std::endl;
}

// ==================== Export Command ====================

void exportLogs(const std::string& file, const std::string& output_file, const std::string& format,
                const std::string& start_time, const std::string& end_time, int limit) {
  auto entries = LogAggregator::parseLogFile(file, 0);

  // Filter by time if specified
  if (!start_time.empty() || !end_time.empty()) {
    entries.erase(
        std::remove_if(entries.begin(), entries.end(),
                       [&](const LogEntry& e) {
                         if (!start_time.empty() && e.timestamp < start_time) return true;
                         if (!end_time.empty() && e.timestamp > end_time) return true;
                         return false;
                       }),
        entries.end());
  }

  if (limit > 0 && entries.size() > static_cast<size_t>(limit)) {
    entries.resize(limit);
  }

  std::ofstream out;
  std::ostream* output = &std::cout;
  if (!output_file.empty()) {
    out.open(output_file);
    if (!out.is_open()) {
      std::cerr << "Cannot open output file: " << output_file << std::endl;
      return;
    }
    output = &out;
  }

  if (format == "json") {
    *output << "[" << std::endl;
    for (size_t i = 0; i < entries.size(); ++i) {
      *output << "  " << entries[i].toJson();
      if (i < entries.size() - 1) *output << ",";
      *output << std::endl;
    }
    *output << "]" << std::endl;
  } else if (format == "csv") {
    *output << "timestamp,severity,source,hostname,process,line_number,message" << std::endl;
    for (const auto& e : entries) {
      *output << "\"" << e.timestamp << "\",\"" << severityToString(e.severity) << "\",\""
              << e.source << "\",\"" << e.hostname << "\",\"" << e.process << "\","
              << e.line_number << ",\"" << e.message << "\"" << std::endl;
    }
  } else {
    for (const auto& e : entries) {
      *output << e.timestamp << " [" << severityToString(e.severity) << "] " << e.message << std::endl;
    }
  }

  std::cerr << "Exported " << entries.size() << " entries" << std::endl;
}

// ==================== Main Function ====================

int main(int argc, char* argv[]) {
  CLI::App app{"Log Aggregator CLI Tool - Enhanced log analysis and monitoring"};
  app.require_subcommand(1);

  std::string file;
  std::string pattern;
  bool case_insensitive = false;
  int lines = 10;
  bool colorize = true;
  std::string output_format = "plain";
  std::string severity_filter;
  std::string output_file;

  // ==================== Search Subcommand ====================
  auto search_cmd = app.add_subcommand("search", "Search logs for patterns");
  search_cmd->add_option("file", file, "Log file to search")->required();
  search_cmd->add_option("pattern", pattern, "Regex pattern to search for")->required();
  search_cmd->add_flag("-i,--ignore-case", case_insensitive, "Case insensitive search");
  
  bool show_context = false;
  int context_lines = 2;
  bool count_only = false;
  bool invert_match = false;
  int max_results = 0;
  
  search_cmd->add_flag("-C,--context", show_context, "Show context around matches");
  search_cmd->add_option("--context-lines", context_lines, "Number of context lines (default: 2)");
  search_cmd->add_flag("-c,--count", count_only, "Only print count of matching lines");
  search_cmd->add_flag("-v,--invert-match", invert_match, "Select non-matching lines");
  search_cmd->add_option("-f,--format", output_format, "Output format: plain, json, csv");
  search_cmd->add_flag("--no-color", [&colorize](int) { colorize = false; }, "Disable colorized output");
  search_cmd->add_option("-m,--max-count", max_results, "Stop after N matches");
  search_cmd->add_option("-s,--severity", severity_filter, "Minimum severity level");

  // ==================== Tail Subcommand ====================
  auto tail_cmd = app.add_subcommand("tail", "Tail logs in real-time");
  tail_cmd->add_option("file", file, "Log file to tail")->required();
  tail_cmd->add_option("-n,--lines", lines, "Number of lines to show initially (default: 10)");
  bool follow = true;
  tail_cmd->add_flag("-f,--follow,!--no-follow", follow, "Follow file for new content (default: true)");
  tail_cmd->add_flag("--no-color", [&colorize](int) { colorize = false; }, "Disable colorized output");
  tail_cmd->add_option("-p,--pattern", pattern, "Filter pattern");
  tail_cmd->add_option("-s,--severity", severity_filter, "Minimum severity level");

  // ==================== Stats Subcommand ====================
  auto stats_cmd = app.add_subcommand("stats", "Show log statistics and analysis");
  stats_cmd->add_option("file", file, "Log file to analyze")->required();
  bool json_stats = false;
  bool detailed_stats = false;
  stats_cmd->add_flag("-j,--json", json_stats, "Output in JSON format");
  stats_cmd->add_flag("-d,--detailed", detailed_stats, "Show detailed statistics");

  // ==================== Filter Subcommand ====================
  auto filter_cmd = app.add_subcommand("filter", "Filter and transform log files");
  filter_cmd->add_option("file", file, "Input log file")->required();
  filter_cmd->add_option("-o,--output", output_file, "Output file (default: stdout)");
  filter_cmd->add_option("-p,--pattern", pattern, "Regex pattern to match");
  filter_cmd->add_option("-s,--severity", severity_filter, "Minimum severity level");
  filter_cmd->add_flag("-i,--ignore-case", case_insensitive, "Case insensitive matching");
  filter_cmd->add_flag("-v,--invert-match", invert_match, "Select non-matching lines");
  filter_cmd->add_option("-f,--format", output_format, "Output format: plain, json");

  // ==================== Merge Subcommand ====================
  auto merge_cmd = app.add_subcommand("merge", "Merge multiple log files");
  std::vector<std::string> input_files;
  merge_cmd->add_option("files", input_files, "Input log files")->required()->expected(2, -1);
  merge_cmd->add_option("-o,--output", output_file, "Output file (default: stdout)");
  bool sort_by_time = true;
  merge_cmd->add_flag("-t,--sort-time,!--no-sort", sort_by_time, "Sort by timestamp (default: true)");

  // ==================== Parse Subcommand ====================
  auto parse_cmd = app.add_subcommand("parse", "Parse and format log entries");
  parse_cmd->add_option("file", file, "Log file to parse")->required();
  int limit = 0;
  parse_cmd->add_option("-l,--limit", limit, "Maximum number of entries");
  parse_cmd->add_option("-f,--format", output_format, "Output format: plain, json, csv");
  parse_cmd->add_flag("--no-color", [&colorize](int) { colorize = false; }, "Disable colorized output");

  // ==================== Watch Subcommand ====================
  auto watch_cmd = app.add_subcommand("watch", "Watch a directory for log changes");
  std::string directory;
  watch_cmd->add_option("directory", directory, "Directory to watch")->required();
  watch_cmd->add_option("-p,--pattern", pattern, "Filter pattern");
  watch_cmd->add_option("-s,--severity", severity_filter, "Minimum severity level");
  watch_cmd->add_flag("--no-color", [&colorize](int) { colorize = false; }, "Disable colorized output");

  // ==================== Rotate Subcommand ====================
  auto rotate_cmd = app.add_subcommand("rotate", "Manually rotate a log file");
  rotate_cmd->add_option("file", file, "Log file to rotate")->required();
  int keep_backups = 5;
  bool compress = false;
  rotate_cmd->add_option("-k,--keep", keep_backups, "Number of backups to keep (default: 5)");
  rotate_cmd->add_flag("-z,--compress", compress, "Compress rotated files");

  // ==================== Export Subcommand ====================
  auto export_cmd = app.add_subcommand("export", "Export logs to different formats");
  export_cmd->add_option("file", file, "Log file to export")->required();
  export_cmd->add_option("-o,--output", output_file, "Output file (default: stdout)");
  export_cmd->add_option("-f,--format", output_format, "Output format: plain, json, csv")->required();
  std::string start_time, end_time;
  export_cmd->add_option("--start", start_time, "Start timestamp filter");
  export_cmd->add_option("--end", end_time, "End timestamp filter");
  export_cmd->add_option("-l,--limit", limit, "Maximum number of entries");

  // ==================== Version Subcommand ====================
  auto version_cmd = app.add_subcommand("version", "Show version information");

  CLI11_PARSE(app, argc, argv);

  if (search_cmd->parsed()) {
    searchLogs(file, pattern, case_insensitive, show_context, context_lines, count_only,
               invert_match, output_format, colorize, max_results, severity_filter);
  } else if (tail_cmd->parsed()) {
    tailLogs(file, lines, follow, colorize, pattern, severity_filter);
  } else if (stats_cmd->parsed()) {
    showStats(file, json_stats, detailed_stats);
  } else if (filter_cmd->parsed()) {
    filterLogs(file, output_file, pattern, severity_filter, case_insensitive, invert_match, output_format);
  } else if (merge_cmd->parsed()) {
    mergeLogs(input_files, output_file, sort_by_time);
  } else if (parse_cmd->parsed()) {
    parseLogs(file, limit, output_format, colorize);
  } else if (watch_cmd->parsed()) {
    watchDirectory(directory, pattern, severity_filter, colorize);
  } else if (rotate_cmd->parsed()) {
    rotateLog(file, keep_backups, compress);
  } else if (export_cmd->parsed()) {
    exportLogs(file, output_file, output_format, start_time, end_time, limit);
  } else if (version_cmd->parsed()) {
    std::cout << "Log Aggregator CLI v2.0.0" << std::endl;
    std::cout << "Copyright (C) Soccentric LLC. All rights reserved." << std::endl;
  } else {
    std::cout << app.help() << std::endl;
  }

  return 0;
}