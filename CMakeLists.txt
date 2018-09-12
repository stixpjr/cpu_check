cmake_minimum_required (VERSION 3.2)
project (cpu_check VERSION 20180907 LANGUAGES C CXX)

# Options
# Use clang/llvm by default.
# There's unexplained SEGVs with gcc 5.5.0 with -O2
option(USE_CLANG "build with clang" ON)

# Config header
configure_file (
	"${PROJECT_SOURCE_DIR}/config.h.in"
	"${PROJECT_BINARY_DIR}/config.h"
)
include_directories("${PROJECT_BINARY_DIR}")

if (USE_CLANG)
	set(CMAKE_C_COMPILER clang)
	set(CMAKE_CXX_COMPILER clang++)
	set(CC clang)
	set(CXX clang++)
endif(USE_CLANG)

set(CMAKE_C_FLAGS_DEBUG -g)
set(CMAKE_CXX_FLAGS_DEBUG -g)
set(CMAKE_C_FLAGS_RELEASE "-Wall -O2")
set(CMAKE_CXX_FLAGS_RELEASE "-Wall -O2")
set(CMAKE_BUILD_TYPE Release)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)	# we want c11 not gnu11
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)	# we want c++11 not gnu++11

add_executable(cpu_check cpu_check.cc)
add_executable(crc32c_test crc32c_test.cc)

add_library(farmhash farmhash.cc)
add_library(crc32c crc32c.c)

include(CheckCXXCompilerFlag)
check_cxx_compiler_flag("-march=sandybridge" ARCH_SANDYBRIDGE)
if(ARCH_SANDYBRIDGE)
	target_compile_options(farmhash PUBLIC -march=sandybridge)
	target_compile_options(crc32c PUBLIC -march=sandybridge)
endif(ARCH_SANDYBRIDGE)

target_link_libraries(cpu_check crc32c farmhash)
target_link_libraries(crc32c_test crc32c)

# Needs pthreads
find_package(Threads REQUIRED)
target_link_libraries(cpu_check Threads::Threads)

# Needs zlib
find_package (ZLIB REQUIRED)
if(ZLIB_INCLUDE_DIRS)
	include_directories(${ZLIB_INCLUDE_DIRS})
endif(ZLIB_INCLUDE_DIRS)
if(ZLIB_LIBRARIES)
	target_link_libraries(cpu_check ${ZLIB_LIBRARIES})
endif(ZLIB_LIBRARIES)

# Needs OpenSSL
find_package (OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIRS})
target_link_libraries(cpu_check ${OPENSSL_LIBRARIES})

install (TARGETS cpu_check DESTINATION bin)
