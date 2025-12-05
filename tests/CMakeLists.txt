include(GoogleTest)

add_executable(log_aggregator_tests test_motor_control_pwm_rpi5.cpp)
target_link_libraries(log_aggregator_tests PRIVATE log_aggregator gtest_main)
target_compile_features(log_aggregator_tests PRIVATE cxx_std_17)

if(ENABLE_COVERAGE)
  target_compile_options(motor_control_pwm_rpi5_tests PRIVATE --coverage)
  target_link_options(motor_control_pwm_rpi5_tests PRIVATE --coverage)
endif()

gtest_discover_tests(log_aggregator_tests)