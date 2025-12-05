/**
 * @file test_log_aggregator.cpp
 * @brief Unit tests for the log_aggregator library.
 * @author Sandesh Ghimire | sandesh@soccentric
 * @copyright (C) Soccentric LLC. All rights reserved.
 *
 * This file contains comprehensive unit tests for all public interfaces
 * of the log_aggregator library using the Google Test framework.
 *
 * @version 1.0
 * @date 2025-12-04
 *
 * @details
 * The test suite validates the correctness of the LogAggregator class
 * implementation, including constructor behavior, configuration methods.
 *
 * @note Tests are executed using Google Test. Run with: ctest or ./test_log_aggregator
 */

#include <gtest/gtest.h>

#include "log_aggregator/log_aggregator.h"

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

TEST(LogAggregatorTest, MatchesFilterNoFilters) {
  log_aggregator::LogAggregator aggregator;
  EXPECT_TRUE(aggregator.matchesFilter("some log line"));
}

TEST(LogAggregatorTest, MatchesFilterWithFilters) {
  log_aggregator::LogAggregator aggregator;
  aggregator.addFilter("ERROR");
  aggregator.addFilter("WARNING");
  EXPECT_TRUE(aggregator.matchesFilter("This is an ERROR message"));
  EXPECT_TRUE(aggregator.matchesFilter("This is a WARNING message"));
  EXPECT_FALSE(aggregator.matchesFilter("This is an info message"));
}

TEST(LogAggregatorTest, MatchesFilterCaseSensitive) {
  log_aggregator::LogAggregator aggregator;
  aggregator.addFilter("error");
  EXPECT_TRUE(aggregator.matchesFilter("This is an error message"));
  EXPECT_FALSE(aggregator.matchesFilter("This is an ERROR message"));
}

}  // namespace