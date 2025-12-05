/**
 * @file main.cpp
 * @brief Main application entry point for log_aggregator.
 * @author Sandesh Ghimire | sandesh@soccentric
 * @copyright (C) Soccentric LLC. All rights reserved.
 * 
 * This file contains the main() function that serves as the entry point
 * for the log_aggregator application. It runs the log aggregation daemon.
 * 
 * @version 1.0
 * @date 2025-12-04
 * 
 * @details
 * The application creates an instance of LogAggregator and runs it as a daemon
 * to collect and filter logs from multiple sources.
 */

#include "log_aggregator/log_aggregator.h"
#include <iostream>
#include <csignal>
#include <unistd.h>
#include <sys/stat.h>
#include <CLI/CLI.hpp>

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
 * 
 * @par Example usage:
 * @code
 * ./log_aggregator_app -s /var/log/syslog,/var/log/kern.log -o /var/log/aggregated.log -f "ERROR|WARNING"
 * @endcode
 */
log_aggregator::LogAggregator aggregator;
volatile sig_atomic_t stop_flag = 0;

void signal_handler(int signum) {
    stop_flag = 1;
    aggregator.stop();
}

int main(int argc, char* argv[]) {
    CLI::App app{"Centralized Log Aggregator Daemon"};

    std::vector<std::string> sources = {"/var/log/syslog", "/var/log/kern.log"};
    std::string output_file = "/var/log/aggregated.log";
    size_t max_size = 100;
    std::vector<std::string> filters = {"ERROR|WARNING"};
    bool daemon_mode = true;

    app.add_option("-s,--sources", sources, "Log source files to monitor")
        ->delimiter(',')
        ->expected(1, -1);
    app.add_option("-o,--output", output_file, "Output file for aggregated logs");
    app.add_option("-m,--max-size", max_size, "Maximum file size in MB before rotation");
    app.add_option("-f,--filters", filters, "Regex patterns to filter logs")
        ->delimiter(',')
        ->expected(1, -1);
    app.add_flag("-d,--daemon", daemon_mode, "Run as daemon (default: true)");

    CLI11_PARSE(app, argc, argv);

    if (daemon_mode) {
        // Daemonize
        pid_t pid = fork();
        if (pid < 0) {
            std::cerr << "Fork failed" << std::endl;
            return 1;
        }
        if (pid > 0) {
            return 0; // Parent exits
        }

        // Child becomes session leader
        if (setsid() < 0) {
            return 1;
        }
    }

    // Set up signal handler
    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);

    // Configure aggregator
    for (const auto& source : sources) {
        aggregator.addSource(source);
    }
    aggregator.setOutputFile(output_file);
    aggregator.setMaxFileSize(max_size);
    for (const auto& filter : filters) {
        aggregator.addFilter(filter);
    }

    // Start aggregating
    aggregator.start();

    // Wait for stop signal
    while (!stop_flag) {
        sleep(1);
    }

    return 0;
}