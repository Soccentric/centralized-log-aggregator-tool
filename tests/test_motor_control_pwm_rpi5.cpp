/**
 * @file test_motor_control_pwm_rpi5.cpp
 * @brief Unit tests for the motor_control_pwm_rpi5 library.
 * @author Sandesh Ghimire | sandesh@soccentric
 * @copyright (C) Soccentric LLC. All rights reserved.
 * 
 * This file contains comprehensive unit tests for all public interfaces
 * of the motor_control_pwm_rpi5 library using the Google Test framework.
 * 
 * @version 1.0
 * @date 2025-11-26
 * 
 * @details
 * The test suite validates the correctness of the motorControlPwmRpi5 class
 * implementation, including constructor behavior, getter methods, and
 * main functionality.
 * 
 * @note Tests are executed using Google Test. Run with: ctest or ./test_motor_control_pwm_rpi5
 */

#include "motor_control_pwm_rpi5/motor_control_pwm_rpi5.h"
#include <gtest/gtest.h>

namespace {

/**
 * @brief Test fixture for motorControlPwmRpi5 class tests.
 * 
 * Provides a common testing environment for all motorControlPwmRpi5 test cases.
 * Currently uses the default test fixture, but can be extended with setup
 * and teardown methods if needed.
 */

/**
 * @test ConstructorAndGetName
 * @brief Verifies that the constructor initializes the object correctly
 *        and get_name() returns the expected value.
 * 
 * @details
 * Creates an instance with a known name and validates that get_name()
 * returns exactly that name. This tests both the constructor and the
 * getter method.
 * 
 * @par Test Steps:
 * 1. Create motorControlPwmRpi5 instance with name "TestName"
 * 2. Call get_name() and verify it returns "TestName"
 * 
 * @pre None
 * @post Instance is created and destroyed successfully
 */
TEST(motorControlPwmRpi5Test, ConstructorAndGetName) {
    motor_control_pwm_rpi5::motorControlPwmRpi5 instance("TestName");
    EXPECT_EQ(instance.get_name(), "TestName");
}

/**
 * @test RunDoesNotThrow
 * @brief Verifies that the run() method executes without throwing exceptions.
 * 
 * @details
 * Creates an instance and calls run() to ensure it completes normally
 * without throwing any exceptions. This tests the basic execution path
 * of the primary functionality.
 * 
 * @par Test Steps:
 * 1. Create motorControlPwmRpi5 instance with name "TestName"
 * 2. Call run() and verify no exceptions are thrown
 * 
 * @pre None
 * @post Instance executes run() successfully
 * 
 * @note This test will produce output to stdout, which is normal behavior.
 */
TEST(motorControlPwmRpi5Test, RunDoesNotThrow) {
    motor_control_pwm_rpi5::motorControlPwmRpi5 instance("TestName");
    EXPECT_NO_THROW(instance.run());
}

} // namespace