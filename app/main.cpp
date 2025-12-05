/**
 * @file main.cpp
 * @brief Main application entry point for motor_control_pwm_rpi5.
 * @author Sandesh Ghimire | sandesh@soccentric
 * @copyright (C) Soccentric LLC. All rights reserved.
 * 
 * This file contains the main() function that serves as the entry point
 * for the motor_control_pwm_rpi5 application. It demonstrates basic usage
 * of the library API.
 * 
 * @version 1.0
 * @date 2025-11-26
 * 
 * @details
 * The application creates an instance of the main library class and
 * executes its primary functionality. Command-line arguments are currently
 * unused but available for future extensions.
 */

#include "log_aggregator/log_aggregator.h"
#include <iostream>
#include <csignal>
#include <unistd.h>
#include <sys/stat.h>

/**
 * @brief Main entry point of the application.
 * 
 * Creates an instance of motorControlPwmRpi5, demonstrates its usage by
 * calling its public methods, and terminates normally.
 * 
 * @param argc Number of command-line arguments (currently unused).
 * @param argv Array of command-line argument strings (currently unused).
 * 
 * @return 0 on successful execution, non-zero on error.
 * 
 * @note Currently, command-line arguments are not processed. Future versions
 *       may add support for configuration via command-line options.
 * 
 * @par Example usage:
 * @code
 * ./my_cmake_project
 * @endcode
 */
log_aggregator::LogAggregator aggregator;
volatile sig_atomic_t stop_flag = 0;

void signal_handler(int signum) {
    stop_flag = 1;
    aggregator.stop();
}

int main(int argc, char* argv[]) {
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

    // Set up signal handler
    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);

    // Configure aggregator
    aggregator.addSource("/var/log/syslog");
    aggregator.addSource("/var/log/kern.log");
    aggregator.setOutputFile("/var/log/aggregated.log");
    aggregator.setMaxFileSize(100); // 100MB

    // Add filters (example: filter ERROR and WARNING)
    aggregator.addFilter("ERROR|WARNING");

    // Start aggregating
    aggregator.start();

    // Wait for stop signal
    while (!stop_flag) {
        sleep(1);
    }

    return 0;
}