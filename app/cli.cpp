#include <CLI/CLI.hpp>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <regex>
#include <string>
#include <thread>

#include "log_aggregator/log_aggregator.h"

namespace fs = std::filesystem;

void searchLogs(const std::string& file, const std::string& pattern,
                bool case_insensitive = false) {
  std::ifstream in(file);
  if (!in.is_open()) {
    std::cerr << "Cannot open file: " << file << std::endl;
    return;
  }

  std::string line;
  std::regex  regex_pattern(
      pattern, case_insensitive ? std::regex_constants::icase : std::regex_constants::ECMAScript);
  size_t line_number = 0;
  while (std::getline(in, line)) {
    ++line_number;
    if (std::regex_search(line, regex_pattern)) {
      std::cout << line_number << ": " << line << std::endl;
    }
  }
}

void tailLogs(const std::string& file, int lines = 10) {
  std::ifstream in(file);
  if (!in.is_open()) {
    std::cerr << "Cannot open file: " << file << std::endl;
    return;
  }

  // Read last N lines
  std::vector<std::string> buffer;
  std::string              line;
  while (std::getline(in, line)) {
    buffer.push_back(line);
    if (buffer.size() > static_cast<size_t>(lines)) {
      buffer.erase(buffer.begin());
    }
  }

  // Print the last lines
  for (const auto& l : buffer) {
    std::cout << l << std::endl;
  }

  // Continue monitoring for new lines
  in.clear();  // Clear EOF flag
  in.seekg(0, std::ios::end);
  std::streampos last_pos = in.tellg();

  while (true) {
    in.seekg(last_pos);
    while (std::getline(in, line)) {
      std::cout << line << std::endl;
      last_pos = in.tellg();
    }
    in.clear();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Check if file has been truncated or recreated
    in.seekg(0, std::ios::end);
    std::streampos current_size = in.tellg();
    if (current_size < last_pos) {
      // File was truncated, reset position
      last_pos = 0;
      in.seekg(0);
    }
  }
}

int main(int argc, char* argv[]) {
  CLI::App app{"Log Aggregator CLI Tool"};

  std::string file;
  std::string pattern;
  bool        case_insensitive = false;
  int         tail_lines       = 10;

  // Search subcommand
  auto search_cmd = app.add_subcommand("search", "Search logs for patterns");
  search_cmd->add_option("file", file, "Log file to search")->required();
  search_cmd->add_option("pattern", pattern, "Regex pattern to search for")->required();
  search_cmd->add_flag("-i,--ignore-case", case_insensitive, "Case insensitive search");

  // Tail subcommand
  auto tail_cmd = app.add_subcommand("tail", "Tail logs in real-time");
  tail_cmd->add_option("file", file, "Log file to tail")->required();
  tail_cmd->add_option("-n,--lines", tail_lines, "Number of lines to show initially");

  CLI11_PARSE(app, argc, argv);

  if (search_cmd->parsed()) {
    searchLogs(file, pattern, case_insensitive);
  } else if (tail_cmd->parsed()) {
    tailLogs(file, tail_lines);
  } else {
    std::cout << app.help() << std::endl;
  }

  return 0;
}