/**
 * @file log_aggregator.cpp
 * @brief Implementation file for the log_aggregator library.
 * @author Sandesh Ghimire | sandesh@soccentric
 * @copyright (C) Soccentric LLC. All rights reserved.
 * 
 * This file contains the complete implementation of the LogAggregator class.
 */

#include "log_aggregator/log_aggregator.h"
#include <iostream>
#include <fstream>
#include <thread>
#include <atomic>
#include <filesystem>
#include <chrono>
#include <unordered_map>
#include <sys/inotify.h>
#include <unistd.h>

namespace fs = std::filesystem;

namespace log_aggregator {

class LogAggregator::Impl {
public:
    Impl() : running_(false), max_file_size_(100 * 1024 * 1024) {} // 100MB default

    void start() {
        if (running_) return;
        running_ = true;

        // Initialize inotify
        inotify_fd_ = inotify_init();
        if (inotify_fd_ < 0) {
            throw std::runtime_error("Failed to initialize inotify");
        }

        // Add watches for sources
        for (const auto& source : sources_) {
            int wd = inotify_add_watch(inotify_fd_, source.c_str(), IN_MODIFY | IN_DELETE_SELF | IN_MOVE_SELF);
            if (wd < 0) {
                std::cerr << "Failed to watch " << source << std::endl;
            } else {
                watches_[wd] = source;
                file_positions_[source] = 0;
            }
        }

        // Start monitoring thread
        monitor_thread_ = std::thread(&Impl::monitor, this);
    }

    void stop() {
        if (!running_) return;
        running_ = false;
        if (monitor_thread_.joinable()) {
            monitor_thread_.join();
        }
        close(inotify_fd_);
    }

    void addSource(const std::string& path) {
        sources_.push_back(path);
    }

    void addFilter(const std::string& pattern) {
        filters_.emplace_back(pattern);
    }

    void setOutputFile(const std::string& path) {
        output_file_ = path;
    }

    void setMaxFileSize(size_t size) {
        max_file_size_ = size * 1024 * 1024;
    }

private:
    void monitor() {
        const size_t BUF_LEN = 4096;
        char buffer[BUF_LEN];

        while (running_) {
            int length = read(inotify_fd_, buffer, BUF_LEN);
            if (length < 0) {
                if (errno != EINTR) {
                    std::cerr << "Read error" << std::endl;
                }
                continue;
            }

            int i = 0;
            while (i < length) {
                struct inotify_event* event = (struct inotify_event*)&buffer[i];
                auto it = watches_.find(event->wd);
                if (it != watches_.end()) {
                    if (event->mask & IN_MODIFY) {
                        processFile(it->second);
                    } else if (event->mask & (IN_DELETE_SELF | IN_MOVE_SELF)) {
                        // File was deleted or moved, reset position
                        file_positions_[it->second] = 0;
                    }
                }
                i += sizeof(struct inotify_event) + event->len;
            }
        }
    }

    void processFile(const std::string& path) {
        std::ifstream file(path, std::ios::in);
        if (!file.is_open()) return;

        file.seekg(file_positions_[path]);
        std::string line;
        while (std::getline(file, line)) {
            if (shouldFilter(line)) {
                writeToOutput(line);
            }
        }
        file_positions_[path] = file.tellg();
    }

    bool shouldFilter(const std::string& line) {
        if (filters_.empty()) return true;
        for (const auto& regex : filters_) {
            if (std::regex_search(line, regex)) {
                return true;
            }
        }
        return false;
    }

    void writeToOutput(const std::string& line) {
        if (output_file_.empty()) return;

        // Check file size and rotate if needed
        if (fs::exists(output_file_) && fs::file_size(output_file_) > max_file_size_) {
            rotateFile();
        }

        std::ofstream out(output_file_, std::ios::app);
        if (out.is_open()) {
            auto now = std::chrono::system_clock::now();
            auto time_t = std::chrono::system_clock::to_time_t(now);
            out << std::ctime(&time_t) << ": " << line << std::endl;
        }
    }

    void rotateFile() {
        const int max_backups = 5;
        for (int i = max_backups - 1; i >= 1; --i) {
            std::string current = output_file_ + "." + std::to_string(i);
            std::string next = output_file_ + "." + std::to_string(i + 1);
            if (fs::exists(current)) {
                if (fs::exists(next)) {
                    fs::remove(next);
                }
                fs::rename(current, next);
            }
        }
        std::string first_backup = output_file_ + ".1";
        if (fs::exists(first_backup)) {
            fs::remove(first_backup);
        }
        fs::rename(output_file_, first_backup);
    }

    std::vector<std::string> sources_;
    std::vector<std::regex> filters_;
    std::string output_file_;
    size_t max_file_size_;
    std::atomic<bool> running_;
    int inotify_fd_;
    std::unordered_map<int, std::string> watches_;
    std::unordered_map<std::string, std::streampos> file_positions_;
    std::thread monitor_thread_;
};

LogAggregator::LogAggregator() : pimpl_(std::make_unique<Impl>()) {}

LogAggregator::~LogAggregator() = default;

void LogAggregator::start() {
    pimpl_->start();
}

void LogAggregator::stop() {
    pimpl_->stop();
}

void LogAggregator::addSource(const std::string& path) {
    pimpl_->addSource(path);
}

void LogAggregator::addFilter(const std::string& pattern) {
    pimpl_->addFilter(pattern);
}

void LogAggregator::setOutputFile(const std::string& path) {
    pimpl_->setOutputFile(path);
}

void LogAggregator::setMaxFileSize(size_t size) {
    pimpl_->setMaxFileSize(size);
}

} // namespace log_aggregator