cmake_minimum_required(VERSION 3.15)
project(test_exe)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Add executable
add_executable(test_exe WIN32 test.cpp)

# Set output directory
set_target_properties(test_exe PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin/$<CONFIG>
)

# Set Windows subsystem
set_target_properties(test_exe PROPERTIES
    WIN32_EXECUTABLE TRUE
)
