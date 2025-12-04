add_executable(motor_control_pwm_rpi5_app main.cpp)
target_link_libraries(motor_control_pwm_rpi5_app PRIVATE motor_control_pwm_rpi5)
target_compile_features(motor_control_pwm_rpi5_app PRIVATE cxx_std_17)

# Install
install(TARGETS motor_control_pwm_rpi5_app
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)