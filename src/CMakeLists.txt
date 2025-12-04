add_library(motor_control_pwm_rpi5 STATIC)
target_sources(motor_control_pwm_rpi5
  PRIVATE
    motor_control_pwm_rpi5.cpp
)
target_include_directories(motor_control_pwm_rpi5
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)
target_compile_features(motor_control_pwm_rpi5 PUBLIC cxx_std_17)

# Install
install(TARGETS motor_control_pwm_rpi5
  EXPORT motor_control_pwm_rpi5Targets
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/../include/
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)