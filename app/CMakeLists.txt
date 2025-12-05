add_executable(log_aggregator_app main.cpp)
target_link_libraries(log_aggregator_app PRIVATE log_aggregator)
target_compile_features(log_aggregator_app PRIVATE cxx_std_17)

# Install
install(TARGETS log_aggregator_app
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)