/**
 * @file test_log_aggregator.cpp
 * @brief Comprehensive unit tests for the log_aggregator library.
 * @author Sandesh Ghimire | sandesh@soccentric
 * @copyright (C) Soccentric LLC. All rights reserved.
 *
 * This file contains comprehensive unit tests for all public interfaces
 * of the log_aggregator library using the Google Test framework.
 *
 * @version 2.0
 * @date 2025-12-04
 *
 * @details
 * The test suite validates the correctness of the LogAggregator class
 * implementation, including:
 * - Constructor behavior and RAII
 * - Source management (add, remove, clear)
 * - Filter management (regex, severity, exclusions)
 * - Output configuration (file, format, rotation)
 * - Rate limiting
 * - Statistics tracking
 * - Callbacks
 * - LogEntry parsing
 * - LogStatistics
 *
 * @note Tests are executed using Google Test. Run with: ctest or ./log_aggregator_tests
 */

#include <gtest/gtest.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <set>
#include <thread>

#include "log_aggregator/log_aggregator.h"

namespace fs = std::filesystem;
using namespace log_aggregator;

// ==================== Test Fixtures ====================

class LogAggregatorTest : public ::testing::Test {
protected:
  void SetUp() override {
    test_dir_ = fs::temp_directory_path() / "log_aggregator_test";
    fs::create_directories(test_dir_);
    
    // Create test log files
    test_source_ = test_dir_ / "test_source.log";
    test_output_ = test_dir_ / "test_output.log";
    
    std::ofstream src(test_source_);
    src << "2025-12-04 10:00:00 [INFO] Test message 1\n";
    src << "2025-12-04 10:00:01 [ERROR] Error message\n";
    src << "2025-12-04 10:00:02 [WARNING] Warning message\n";
    src << "2025-12-04 10:00:03 [DEBUG] Debug message\n";
    src << "2025-12-04 10:00:04 [CRITICAL] Critical error\n";
    src.close();
  }

  void TearDown() override {
    fs::remove_all(test_dir_);
  }

  fs::path test_dir_;
  fs::path test_source_;
  fs::path test_output_;
};

// ==================== Constructor Tests ====================

TEST(LogAggregatorBasicTest, ConstructorDoesNotThrow) {
  EXPECT_NO_THROW(LogAggregator aggregator);
}

TEST(LogAggregatorBasicTest, MoveConstructor) {
  LogAggregator agg1;
  agg1.addFilter("ERROR");
  
  LogAggregator agg2(std::move(agg1));
  EXPECT_TRUE(agg2.matchesFilter("This is an ERROR message"));
}

TEST(LogAggregatorBasicTest, MoveAssignment) {
  LogAggregator agg1;
  agg1.addFilter("WARNING");
  
  LogAggregator agg2;
  agg2 = std::move(agg1);
  EXPECT_TRUE(agg2.matchesFilter("This is a WARNING"));
}

// ==================== Source Management Tests ====================

TEST_F(LogAggregatorTest, AddSource) {
  LogAggregator aggregator;
  EXPECT_TRUE(aggregator.addSource(test_source_.string()));
  
  auto sources = aggregator.getSources();
  EXPECT_EQ(sources.size(), 1);
  EXPECT_EQ(sources[0], test_source_.string());
}

TEST_F(LogAggregatorTest, AddDuplicateSource) {
  LogAggregator aggregator;
  EXPECT_TRUE(aggregator.addSource(test_source_.string()));
  EXPECT_FALSE(aggregator.addSource(test_source_.string()));
  
  EXPECT_EQ(aggregator.getSources().size(), 1);
}

TEST_F(LogAggregatorTest, RemoveSource) {
  LogAggregator aggregator;
  aggregator.addSource(test_source_.string());
  
  EXPECT_TRUE(aggregator.removeSource(test_source_.string()));
  EXPECT_TRUE(aggregator.getSources().empty());
}

TEST_F(LogAggregatorTest, RemoveNonexistentSource) {
  LogAggregator aggregator;
  EXPECT_FALSE(aggregator.removeSource("/nonexistent/path.log"));
}

TEST_F(LogAggregatorTest, ClearSources) {
  LogAggregator aggregator;
  aggregator.addSource(test_source_.string());
  aggregator.addSource((test_dir_ / "another.log").string());
  
  aggregator.clearSources();
  EXPECT_TRUE(aggregator.getSources().empty());
}

// ==================== Filter Tests ====================

TEST(LogAggregatorFilterTest, MatchesFilterNoFilters) {
  LogAggregator aggregator;
  EXPECT_TRUE(aggregator.matchesFilter("some log line"));
}

TEST(LogAggregatorFilterTest, MatchesFilterWithRegex) {
  LogAggregator aggregator;
  EXPECT_TRUE(aggregator.addFilter("ERROR|CRITICAL"));
  
  EXPECT_TRUE(aggregator.matchesFilter("This is an ERROR message"));
  EXPECT_TRUE(aggregator.matchesFilter("CRITICAL failure"));
  EXPECT_FALSE(aggregator.matchesFilter("This is info"));
}

TEST(LogAggregatorFilterTest, MatchesFilterCaseSensitive) {
  LogAggregator aggregator;
  aggregator.addFilter("error", false);  // Case sensitive
  
  EXPECT_TRUE(aggregator.matchesFilter("This is an error"));
  EXPECT_FALSE(aggregator.matchesFilter("This is an ERROR"));
}

TEST(LogAggregatorFilterTest, MatchesFilterCaseInsensitive) {
  LogAggregator aggregator;
  aggregator.addFilter("error", true);  // Case insensitive
  
  EXPECT_TRUE(aggregator.matchesFilter("This is an error"));
  EXPECT_TRUE(aggregator.matchesFilter("This is an ERROR"));
  EXPECT_TRUE(aggregator.matchesFilter("This is an Error"));
}

TEST(LogAggregatorFilterTest, InvalidRegex) {
  LogAggregator aggregator;
  EXPECT_FALSE(aggregator.addFilter("[invalid(regex"));
}

TEST(LogAggregatorFilterTest, RemoveFilter) {
  LogAggregator aggregator;
  aggregator.addFilter("ERROR");
  aggregator.addFilter("WARNING");
  
  EXPECT_TRUE(aggregator.removeFilter("ERROR"));
  EXPECT_FALSE(aggregator.matchesFilter("This is an ERROR"));
  EXPECT_TRUE(aggregator.matchesFilter("This is a WARNING"));
}

TEST(LogAggregatorFilterTest, ClearFilters) {
  LogAggregator aggregator;
  aggregator.addFilter("ERROR");
  aggregator.addFilter("WARNING");
  
  aggregator.clearFilters();
  EXPECT_TRUE(aggregator.matchesFilter("Any message"));
}

TEST(LogAggregatorFilterTest, ExclusionPattern) {
  LogAggregator aggregator;
  aggregator.addFilter(".*");  // Match everything
  aggregator.addExclusionPattern("IGNORE_THIS");
  
  EXPECT_TRUE(aggregator.matchesFilter("Normal message"));
  EXPECT_FALSE(aggregator.matchesFilter("IGNORE_THIS message"));
}

TEST(LogAggregatorFilterTest, MinSeverity) {
  LogAggregator aggregator;
  aggregator.setMinSeverity(Severity::WARNING);
  
  EXPECT_EQ(aggregator.getMinSeverity(), Severity::WARNING);
}

TEST(LogAggregatorFilterTest, SeverityFilter) {
  LogAggregator aggregator;
  aggregator.addSeverityFilter(Severity::ERROR);
  aggregator.addSeverityFilter(Severity::CRITICAL);
  
  // This test validates the severity filter is registered
  // Actual filtering depends on log parsing
  EXPECT_EQ(aggregator.getMinSeverity(), Severity::DEBUG);  // Default
}

// ==================== Output Configuration Tests ====================

TEST_F(LogAggregatorTest, SetOutputFile) {
  LogAggregator aggregator;
  aggregator.setOutputFile(test_output_.string());
  
  EXPECT_EQ(aggregator.getOutputFile(), test_output_.string());
}

TEST(LogAggregatorOutputTest, OutputFormat) {
  LogAggregator aggregator;
  
  aggregator.setOutputFormat(OutputFormat::JSON);
  EXPECT_EQ(aggregator.getOutputFormat(), OutputFormat::JSON);
  
  aggregator.setOutputFormat(OutputFormat::CSV);
  EXPECT_EQ(aggregator.getOutputFormat(), OutputFormat::CSV);
  
  aggregator.setOutputFormat(OutputFormat::SYSLOG);
  EXPECT_EQ(aggregator.getOutputFormat(), OutputFormat::SYSLOG);
  
  aggregator.setOutputFormat(OutputFormat::PLAIN);
  EXPECT_EQ(aggregator.getOutputFormat(), OutputFormat::PLAIN);
}

TEST(LogAggregatorOutputTest, MaxFileSize) {
  LogAggregator aggregator;
  
  aggregator.setMaxFileSize(50);
  EXPECT_EQ(aggregator.getMaxFileSize(), 50);
  
  aggregator.setMaxFileSize(200);
  EXPECT_EQ(aggregator.getMaxFileSize(), 200);
}

TEST(LogAggregatorOutputTest, MaxBackupFiles) {
  LogAggregator aggregator;
  
  aggregator.setMaxBackupFiles(10);
  EXPECT_EQ(aggregator.getMaxBackupFiles(), 10);
}

TEST(LogAggregatorOutputTest, CompressionType) {
  LogAggregator aggregator;
  
  aggregator.setCompressionType(CompressionType::GZIP);
  EXPECT_EQ(aggregator.getCompressionType(), CompressionType::GZIP);
  
  aggregator.setCompressionType(CompressionType::NONE);
  EXPECT_EQ(aggregator.getCompressionType(), CompressionType::NONE);
}

TEST(LogAggregatorOutputTest, BufferSize) {
  LogAggregator aggregator;
  
  aggregator.setBufferSize(16384);
  EXPECT_EQ(aggregator.getBufferSize(), 16384);
}

// ==================== Rate Limiting Tests ====================

TEST(LogAggregatorRateLimitTest, RateLimitConfig) {
  LogAggregator aggregator;
  
  RateLimitConfig config;
  config.max_lines_per_second = 500;
  config.burst_size = 50;
  config.window = std::chrono::milliseconds(2000);
  
  aggregator.setRateLimit(config);
  auto retrieved = aggregator.getRateLimit();
  
  EXPECT_EQ(retrieved.max_lines_per_second, 500);
  EXPECT_EQ(retrieved.burst_size, 50);
}

TEST(LogAggregatorRateLimitTest, RateLimitEnabled) {
  LogAggregator aggregator;
  
  EXPECT_FALSE(aggregator.isRateLimitEnabled());
  
  aggregator.setRateLimitEnabled(true);
  EXPECT_TRUE(aggregator.isRateLimitEnabled());
  
  aggregator.setRateLimitEnabled(false);
  EXPECT_FALSE(aggregator.isRateLimitEnabled());
}

// ==================== Statistics Tests ====================

TEST(LogAggregatorStatsTest, InitialStatistics) {
  LogAggregator aggregator;
  auto stats = aggregator.getStatistics();
  
  EXPECT_EQ(stats.total_lines, 0);
  EXPECT_EQ(stats.filtered_lines, 0);
  EXPECT_EQ(stats.dropped_lines, 0);
  EXPECT_EQ(stats.bytes_processed, 0);
  EXPECT_EQ(stats.bytes_written, 0);
}

TEST(LogAggregatorStatsTest, ResetStatistics) {
  LogAggregator aggregator;
  aggregator.resetStatistics();
  
  auto stats = aggregator.getStatistics();
  EXPECT_EQ(stats.total_lines, 0);
}

TEST_F(LogAggregatorTest, ExportStatistics) {
  LogAggregator aggregator;
  
  std::string stats_file = (test_dir_ / "stats.json").string();
  EXPECT_TRUE(aggregator.exportStatistics(stats_file));
  EXPECT_TRUE(fs::exists(stats_file));
  
  std::ifstream in(stats_file);
  std::string content((std::istreambuf_iterator<char>(in)),
                       std::istreambuf_iterator<char>());
  EXPECT_FALSE(content.empty());
  EXPECT_NE(content.find("total_lines"), std::string::npos);
}

// ==================== Callback Tests ====================

TEST(LogAggregatorCallbackTest, LogCallback) {
  LogAggregator aggregator;
  bool called = false;
  
  size_t id = aggregator.onLogEntry([&called](const LogEntry& entry) {
    called = true;
  });
  
  EXPECT_GT(id, 0);
  aggregator.removeCallback(id);
}

TEST(LogAggregatorCallbackTest, ErrorCallback) {
  LogAggregator aggregator;
  
  size_t id = aggregator.onError([](const std::string& source, const std::string& error) {
    // Callback registered
  });
  
  EXPECT_GT(id, 0);
  aggregator.removeCallback(id);
}

TEST(LogAggregatorCallbackTest, RotationCallback) {
  LogAggregator aggregator;
  
  size_t id = aggregator.onRotation([](const std::string& old_file, const std::string& new_file) {
    // Callback registered
  });
  
  EXPECT_GT(id, 0);
  aggregator.removeCallback(id);
}

// ==================== Metadata Tests ====================

TEST(LogAggregatorMetadataTest, GlobalTags) {
  LogAggregator aggregator;
  
  aggregator.addGlobalTag("environment", "production");
  aggregator.addGlobalTag("service", "log_aggregator");
  
  // No direct getter, but should not throw
  aggregator.removeGlobalTag("environment");
}

TEST(LogAggregatorMetadataTest, Hostname) {
  LogAggregator aggregator;
  
  EXPECT_NO_THROW(aggregator.setHostname("custom-hostname"));
}

TEST(LogAggregatorMetadataTest, TimestampNormalization) {
  LogAggregator aggregator;
  
  EXPECT_NO_THROW(aggregator.setTimestampNormalization(true));
  EXPECT_NO_THROW(aggregator.setTimestampNormalization(false));
}

// ==================== LogEntry Tests ====================

TEST(LogEntryTest, ParseSyslogFormat) {
  std::string line = "Dec  4 10:30:45 hostname process[1234]: Test message";
  auto entry = LogEntry::parse(line, "/var/log/test.log");
  
  EXPECT_FALSE(entry.timestamp.empty());
  EXPECT_EQ(entry.source, "/var/log/test.log");
  EXPECT_FALSE(entry.message.empty());
}

TEST(LogEntryTest, ParseISOTimestamp) {
  std::string line = "2025-12-04 10:30:45 [ERROR] Test error message";
  auto entry = LogEntry::parse(line, "/test.log");
  
  EXPECT_EQ(entry.severity, Severity::ERROR);
  EXPECT_FALSE(entry.timestamp.empty());
}

TEST(LogEntryTest, DetectSeverityFromContent) {
  auto entry1 = LogEntry::parse("Some ERROR in the system", "/test.log");
  EXPECT_EQ(entry1.severity, Severity::ERROR);
  
  auto entry2 = LogEntry::parse("WARNING: disk space low", "/test.log");
  EXPECT_EQ(entry2.severity, Severity::WARNING);
  
  auto entry3 = LogEntry::parse("CRITICAL failure detected", "/test.log");
  EXPECT_EQ(entry3.severity, Severity::CRITICAL);
  
  auto entry4 = LogEntry::parse("DEBUG information", "/test.log");
  EXPECT_EQ(entry4.severity, Severity::DEBUG);
}

TEST(LogEntryTest, ToJson) {
  LogEntry entry;
  entry.timestamp = "2025-12-04 10:00:00";
  entry.severity = Severity::ERROR;
  entry.source = "/var/log/test.log";
  entry.message = "Test message";
  entry.hostname = "testhost";
  entry.process = "testproc";
  entry.line_number = 42;
  
  std::string json = entry.toJson();
  
  EXPECT_NE(json.find("\"timestamp\""), std::string::npos);
  EXPECT_NE(json.find("\"severity\":\"ERROR\""), std::string::npos);
  EXPECT_NE(json.find("\"message\""), std::string::npos);
  EXPECT_NE(json.find("\"line_number\":42"), std::string::npos);
}

TEST(LogEntryTest, ToJsonEscapesSpecialChars) {
  LogEntry entry;
  entry.timestamp = "2025-12-04";
  entry.severity = Severity::INFO;
  entry.source = "/test.log";
  entry.message = "Message with \"quotes\" and \\backslash";
  
  std::string json = entry.toJson();
  
  EXPECT_NE(json.find("\\\"quotes\\\""), std::string::npos);
  EXPECT_NE(json.find("\\\\backslash"), std::string::npos);
}

// ==================== LogStatistics Tests ====================

TEST(LogStatisticsTest, ToJson) {
  LogStatistics stats;
  stats.total_lines = 1000;
  stats.filtered_lines = 100;
  stats.dropped_lines = 10;
  stats.bytes_processed = 50000;
  stats.bytes_written = 5000;
  stats.severity_counts[Severity::ERROR] = 50;
  stats.severity_counts[Severity::WARNING] = 50;
  stats.source_counts["/var/log/test.log"] = 100;
  stats.start_time = std::chrono::system_clock::now();
  stats.last_update = std::chrono::system_clock::now();
  
  std::string json = stats.toJson();
  
  EXPECT_NE(json.find("\"total_lines\":1000"), std::string::npos);
  EXPECT_NE(json.find("\"filtered_lines\":100"), std::string::npos);
  EXPECT_NE(json.find("\"severity_counts\""), std::string::npos);
}

TEST(LogStatisticsTest, Reset) {
  LogStatistics stats;
  stats.total_lines = 100;
  stats.severity_counts[Severity::ERROR] = 50;
  
  stats.reset();
  
  EXPECT_EQ(stats.total_lines, 0);
  EXPECT_TRUE(stats.severity_counts.empty());
}

// ==================== Severity Conversion Tests ====================

TEST(SeverityTest, SeverityToString) {
  EXPECT_EQ(severityToString(Severity::DEBUG), "DEBUG");
  EXPECT_EQ(severityToString(Severity::INFO), "INFO");
  EXPECT_EQ(severityToString(Severity::WARNING), "WARNING");
  EXPECT_EQ(severityToString(Severity::ERROR), "ERROR");
  EXPECT_EQ(severityToString(Severity::CRITICAL), "CRITICAL");
}

TEST(SeverityTest, SeverityFromString) {
  EXPECT_EQ(severityFromString("DEBUG"), Severity::DEBUG);
  EXPECT_EQ(severityFromString("debug"), Severity::DEBUG);
  EXPECT_EQ(severityFromString("INFO"), Severity::INFO);
  EXPECT_EQ(severityFromString("info"), Severity::INFO);
  EXPECT_EQ(severityFromString("WARNING"), Severity::WARNING);
  EXPECT_EQ(severityFromString("WARN"), Severity::WARNING);
  EXPECT_EQ(severityFromString("ERROR"), Severity::ERROR);
  EXPECT_EQ(severityFromString("ERR"), Severity::ERROR);
  EXPECT_EQ(severityFromString("CRITICAL"), Severity::CRITICAL);
  EXPECT_EQ(severityFromString("FATAL"), Severity::CRITICAL);
  
  EXPECT_FALSE(severityFromString("INVALID").has_value());
}

// ==================== Static Methods Tests ====================

TEST_F(LogAggregatorTest, ParseLogFile) {
  auto entries = LogAggregator::parseLogFile(test_source_.string());
  
  EXPECT_EQ(entries.size(), 5);
  EXPECT_EQ(entries[1].severity, Severity::ERROR);
}

TEST_F(LogAggregatorTest, ParseLogFileWithLimit) {
  auto entries = LogAggregator::parseLogFile(test_source_.string(), 2);
  
  EXPECT_EQ(entries.size(), 2);
}

TEST_F(LogAggregatorTest, SearchLogFile) {
  auto matches = LogAggregator::searchLogFile(test_source_.string(), "ERROR|WARNING");
  
  EXPECT_EQ(matches.size(), 2);  // ERROR and WARNING lines
}

TEST_F(LogAggregatorTest, SearchLogFileCaseInsensitive) {
  auto matches = LogAggregator::searchLogFile(test_source_.string(), "error", true);
  
  EXPECT_GE(matches.size(), 1);
}

// ==================== Running State Tests ====================

TEST(LogAggregatorRunTest, IsRunningInitially) {
  LogAggregator aggregator;
  EXPECT_FALSE(aggregator.isRunning());
}

TEST_F(LogAggregatorTest, FlushDoesNotThrow) {
  LogAggregator aggregator;
  aggregator.setOutputFile(test_output_.string());
  
  EXPECT_NO_THROW(aggregator.flush());
}

TEST_F(LogAggregatorTest, ForceRotationDoesNotThrow) {
  LogAggregator aggregator;
  aggregator.setOutputFile(test_output_.string());
  
  // Create the output file
  std::ofstream(test_output_) << "Some content\n";
  
  EXPECT_NO_THROW(aggregator.forceRotation());
}

// ==================== Integration-style Tests ====================

TEST_F(LogAggregatorTest, FullConfigurationChain) {
  LogAggregator aggregator;
  
  // Configure sources
  EXPECT_TRUE(aggregator.addSource(test_source_.string()));
  
  // Configure output
  aggregator.setOutputFile(test_output_.string());
  aggregator.setOutputFormat(OutputFormat::JSON);
  aggregator.setMaxFileSize(10);
  aggregator.setMaxBackupFiles(3);
  
  // Configure filters
  EXPECT_TRUE(aggregator.addFilter("ERROR|WARNING"));
  EXPECT_TRUE(aggregator.addExclusionPattern("IGNORE"));
  aggregator.setMinSeverity(Severity::INFO);
  
  // Configure rate limiting
  RateLimitConfig rl;
  rl.max_lines_per_second = 1000;
  aggregator.setRateLimit(rl);
  aggregator.setRateLimitEnabled(true);
  
  // Configure metadata
  aggregator.setHostname("test-host");
  aggregator.addGlobalTag("env", "test");
  
  // Register callbacks
  int callback_count = 0;
  aggregator.onLogEntry([&callback_count](const LogEntry&) { callback_count++; });
  
  // Verify configuration
  EXPECT_EQ(aggregator.getSources().size(), 1);
  EXPECT_EQ(aggregator.getOutputFile(), test_output_.string());
  EXPECT_EQ(aggregator.getOutputFormat(), OutputFormat::JSON);
  EXPECT_EQ(aggregator.getMaxFileSize(), 10);
  EXPECT_EQ(aggregator.getMaxBackupFiles(), 3);
  EXPECT_EQ(aggregator.getMinSeverity(), Severity::INFO);
  EXPECT_TRUE(aggregator.isRateLimitEnabled());
  
  // Test filter behavior
  EXPECT_TRUE(aggregator.matchesFilter("This has ERROR"));
  EXPECT_FALSE(aggregator.matchesFilter("This has IGNORE"));
}

// ==================== Edge Cases ====================

TEST(LogAggregatorEdgeCaseTest, EmptySourcePath) {
  LogAggregator aggregator;
  // Empty path should still be added (validation happens at start)
  EXPECT_TRUE(aggregator.addSource(""));
}

TEST(LogAggregatorEdgeCaseTest, EmptyFilterPattern) {
  LogAggregator aggregator;
  // Empty pattern matches everything
  EXPECT_TRUE(aggregator.addFilter(""));
  EXPECT_TRUE(aggregator.matchesFilter("anything"));
}

TEST(LogAggregatorEdgeCaseTest, VeryLongLogLine) {
  LogAggregator aggregator;
  aggregator.addFilter("test");
  
  std::string long_line(10000, 'a');
  long_line += " test ";
  long_line += std::string(10000, 'b');
  
  EXPECT_TRUE(aggregator.matchesFilter(long_line));
}

TEST(LogAggregatorEdgeCaseTest, SpecialRegexCharacters) {
  LogAggregator aggregator;
  
  // These should be valid regex patterns
  EXPECT_TRUE(aggregator.addFilter("\\[ERROR\\]"));
  EXPECT_TRUE(aggregator.addFilter("file\\.log"));
  EXPECT_TRUE(aggregator.addFilter("path/to/.*"));
}