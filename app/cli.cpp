#include "log_aggregator/log_aggregator.h"
#include <iostream>
#include <fstream>
#include <string>
#include <regex>
#include <filesystem>
#include <thread>
#include <chrono>

namespace fs = std::filesystem;

void searchLogs(const std::string& file, const std::string& pattern) {
    std::ifstream in(file);
    if (!in.is_open()) {
        std::cerr << "Cannot open file: " << file << std::endl;
        return;
    }

    std::string line;
    std::regex regex_pattern(pattern);
    while (std::getline(in, line)) {
        if (std::regex_search(line, regex_pattern)) {
            std::cout << line << std::endl;
        }
    }
}

void tailLogs(const std::string& file) {
    std::ifstream in(file);
    if (!in.is_open()) {
        std::cerr << "Cannot open file: " << file << std::endl;
        return;
    }

    // Seek to end
    in.seekg(0, std::ios::end);
    std::string line;
    while (true) {
        while (std::getline(in, line)) {
            std::cout << line << std::endl;
        }
        in.clear(); // Clear EOF flag
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cout << "Usage: " << argv[0] << " <command> <file> [pattern]" << std::endl;
        std::cout << "Commands: search, tail" << std::endl;
        return 1;
    }

    std::string command = argv[1];
    std::string file = argv[2];

    if (command == "search") {
        if (argc < 4) {
            std::cerr << "Pattern required for search" << std::endl;
            return 1;
        }
        std::string pattern = argv[3];
        searchLogs(file, pattern);
    } else if (command == "tail") {
        tailLogs(file);
    } else {
        std::cerr << "Unknown command: " << command << std::endl;
        return 1;
    }

    return 0;
}