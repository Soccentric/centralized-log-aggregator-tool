cmake_minimum_required(VERSION 3.20)
project(motor_control_pwm_rpi5 VERSION 1.0.0 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Options
option(BUILD_SHARED_LIBS "Build shared libraries" OFF)
option(BUILD_TESTING "Build tests" ON)
option(ENABLE_COVERAGE "Enable code coverage" OFF)
option(ENABLE_CLANG_TIDY "Enable clang-tidy" OFF)

# Include CMake modules
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

# Dependencies
include(FetchContent)
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
FetchContent_MakeAvailable(googletest)

if(ENABLE_CLANG_TIDY)
  find_program(CLANG_TIDY_EXE NAMES clang-tidy)
  if(CLANG_TIDY_EXE)
    set(CMAKE_CXX_CLANG_TIDY "${CLANG_TIDY_EXE}")
  endif()
endif()

# Subdirectories
add_subdirectory(src)
if(BUILD_TESTING)
  enable_testing()
  add_subdirectory(tests)
endif()
add_subdirectory(app)
add_subdirectory(docs)

# Install
include(GNUInstallDirs)
install(EXPORT motor_control_pwm_rpi5Targets
  FILE motor_control_pwm_rpi5Targets.cmake
  NAMESPACE motor_control_pwm_rpi5::
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/motor_control_pwm_rpi5
)

# Packaging
include(CPack)