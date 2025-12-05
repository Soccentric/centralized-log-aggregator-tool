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

#include "log_aggregator/log_aggregator.h"
#include <gtest/gtest.h>

namespace {

TEST(LogAggregatorTest, ConstructorDoesNotThrow) {
    EXPECT_NO_THROW(log_aggregator::LogAggregator aggregator;);
}

TEST(LogAggregatorTest, AddSource) {
    log_aggregator::LogAggregator aggregator;
    EXPECT_NO_THROW(aggregator.addSource("/var/log/test.log"););
}

TEST(LogAggregatorTest, AddFilter) {
    log_aggregator::LogAggregator aggregator;
    EXPECT_NO_THROW(aggregator.addFilter("ERROR"););
}

TEST(LogAggregatorTest, SetOutputFile) {
    log_aggregator::LogAggregator aggregator;
    EXPECT_NO_THROW(aggregator.setOutputFile("/tmp/test.log"););
}

TEST(LogAggregatorTest, SetMaxFileSize) {
    log_aggregator::LogAggregator aggregator;
    EXPECT_NO_THROW(aggregator.setMaxFileSize(50););
}

} // namespace