/**
 * @file motor_control_pwm_rpi5.cpp
 * @brief Implementation file for the motor_control_pwm_rpi5 library.
 * @author Sandesh Ghimire | sandesh@soccentric
 * @copyright (C) Soccentric LLC. All rights reserved.
 * 
 * This file contains the complete implementation of the motorControlPwmRpi5 class
 * and its private implementation class (PIMPL pattern).
 * 
 * @version 1.0
 * @date 2025-11-26
 * 
 * @details
 * The implementation uses the PIMPL (Pointer to Implementation) idiom to hide
 * implementation details and maintain binary compatibility. All private data
 * members and helper functions are encapsulated in the Impl class.
 */

#include "motor_control_pwm_rpi5/motor_control_pwm_rpi5.h"
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

/**
 * @class motorControlPwmRpi5::Impl
 * @brief Private implementation class for motorControlPwmRpi5.
 * 
 * This class contains the actual data members and private implementation
 * details of the motorControlPwmRpi5 class. It is hidden from the public
 * interface to provide ABI stability and reduce compilation dependencies.
 * 
 * @invariant name_ is never modified after construction.
 */
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
            int wd = inotify_add_watch(inotify_fd_, source.c_str(), IN_MODIFY);
            if (wd < 0) {
                std::cerr << "Failed to watch " << source << std::endl;
            } else {
                watches_[wd] = source;
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
                if (event->mask & IN_MODIFY) {
                    auto it = watches_.find(event->wd);
                    if (it != watches_.end()) {
                        processFile(it->second);
                    }
                }
                i += sizeof(struct inotify_event) + event->len;
            }
        }
    }

    void processFile(const std::string& path) {
        std::ifstream file(path, std::ios::in);
        if (!file.is_open()) return;

        std::string line;
        while (std::getline(file, line)) {
            if (shouldFilter(line)) {
                writeToOutput(line);
            }
        }
        // Note: This simplistic implementation reads the entire file each time.
        // A production version should track file positions.
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
        std::string rotated = output_file_ + ".1";
        if (fs::exists(rotated)) {
            fs::remove(rotated);
        }
        fs::rename(output_file_, rotated);
    }

    std::vector<std::string> sources_;
    std::vector<std::regex> filters_;
    std::string output_file_;
    size_t max_file_size_;
    std::atomic<bool> running_;
    int inotify_fd_;
    std::unordered_map<int, std::string> watches_;
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