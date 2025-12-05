add_library(log_aggregator STATIC)
target_sources(log_aggregator
  PRIVATE
    motor_control_pwm_rpi5.cpp
)
target_include_directories(log_aggregator
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)
target_compile_features(log_aggregator PUBLIC cxx_std_17)

# Install
install(TARGETS log_aggregator
  EXPORT log_aggregatorTargets
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/../include/
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)