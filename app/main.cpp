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

#include "motor_control_pwm_rpi5/motor_control_pwm_rpi5.h"
#include <iostream>

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
int main(int argc, char* argv[]) {
    // Suppress unused parameter warnings
    (void)argc;
    (void)argv;

    // Create an instance of the main library class
    motor_control_pwm_rpi5::motorControlPwmRpi5 instance("motor_control_pwm_rpi5");
    
    // Demonstrate basic functionality
    std::cout << "Hello from " << instance.get_name() << std::endl;
    instance.run();

    return 0;
}