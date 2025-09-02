cmake_minimum_required(VERSION 3.10 FATAL_ERROR)
project(vanissh VERSION 1.0.0 LANGUAGES CXX)

option(VANISSH_ENABLE_NATIVE "Enable native optimizations" OFF)
option(VANISSH_ENABLE_FAST_MATH "Enable fast math optimizations" OFF)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBSSH REQUIRED libssh)

# Create executable
add_executable(vanissh
    src/main.cpp
    src/base64_encoder.cpp
    src/base64_encoder.h
    src/ssh_key_generator.cpp
    src/ssh_key_generator.h
)

# Set compiler flags
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(vanissh PRIVATE
        -Wall -Wextra -Wpedantic -Wconversion -Wshadow
    )
    target_link_options(vanissh PRIVATE -flto -Wl,--strip-all)

    if(VANISSH_ENABLE_NATIVE)
        target_compile_options(vanissh PRIVATE -march=native)
    endif()

    if (VANISSH_ENABLE_FAST_MATH)
        target_compile_options(vanissh PRIVATE -O3 -ffast-math)
    endif()
endif()

# Link libraries
target_link_libraries(vanissh PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads
    ${LIBSSH_LIBRARIES}
)

# Include directories
target_include_directories(vanissh PRIVATE src ${LIBSSH_INCLUDE_DIRS})
