cmake_minimum_required(VERSION 3.10)
project(AntiCheatSystem)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Add include directories
include_directories(${CMAKE_SOURCE_DIR}/include)

# Find required libraries
find_package(nlohmann_json REQUIRED)

# Source files - corrected filename
set(SOURCES
    src/main.cpp
    src/core/DetectionEngine.cpp
    src/core/ProcessScanner.cpp
    src/core/DLLInjectionDetection.cpp
    src/core/MemoryScanner.cpp
    src/network/ReportSender.cpp
    src/utils/WinUtils.cpp
    src/utils/Crypto.cpp
)

# Create executable
add_executable(${PROJECT_NAME} ${SOURCES})

# Link libraries - added crypt32 for crypto functions
target_link_libraries(${PROJECT_NAME} 
    winhttp
    wintrust
    psapi
    version
    advapi32
    user32
    kernel32
    ntdll
    crypt32
    nlohmann_json::nlohmann_json
)

# Compiler specific options
if(MSVC)
    target_compile_options(${PROJECT_NAME} PRIVATE /W4)
    # Disable specific MSVC warnings for system headers
    target_compile_options(${PROJECT_NAME} PRIVATE /wd4996)  # Disable deprecated warnings
else()
    target_compile_options(${PROJECT_NAME} PRIVATE -Wall -Wextra -Wpedantic)
endif()

# Set output directory
set_target_properties(${PROJECT_NAME} PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin
)

# Set Unicode definitions
add_definitions(-DUNICODE -D_UNICODE)