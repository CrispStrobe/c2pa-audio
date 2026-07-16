cmake_minimum_required(VERSION 3.14)
project(crispasr_c2pa VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()
set(CMAKE_C_VISIBILITY_PRESET hidden)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)

set(_c2pa_sources src/capi.cpp src/c2pa_native.cpp third_party/uecc/uECC.c)

# Shared library — what the FFI bindings (Dart/C#/Python/Go) load.
add_library(crispasr_c2pa SHARED ${_c2pa_sources})
target_include_directories(crispasr_c2pa PUBLIC include PRIVATE src third_party/uecc)

# Static library — for consumers that link at build time (cgo, C/C++).
add_library(crispasr_c2pa_static STATIC ${_c2pa_sources})
target_include_directories(crispasr_c2pa_static PUBLIC include PRIVATE src third_party/uecc)
set_target_properties(crispasr_c2pa_static PROPERTIES OUTPUT_NAME crispasr_c2pa)

# Silence vendored micro-ecc warnings.
if (NOT MSVC)
    set_source_files_properties(third_party/uecc/uECC.c PROPERTIES COMPILE_OPTIONS "-w")
endif()

# Tiny C smoke test (sign -> verify round-trip through the C ABI).
option(CRISPASR_C2PA_BUILD_TESTS "Build the C ABI smoke test" ON)
if (CRISPASR_C2PA_BUILD_TESTS)
    enable_testing()
    add_executable(c2pa_capi_test test/c2pa_capi_test.c)
    target_link_libraries(c2pa_capi_test PRIVATE crispasr_c2pa_static)
    target_compile_definitions(c2pa_capi_test PRIVATE
        CRISPASR_C2PA_TEST_ASSETS="${CMAKE_CURRENT_SOURCE_DIR}/test/assets")
    add_test(NAME c2pa_capi_test COMMAND c2pa_capi_test)
endif()

install(TARGETS crispasr_c2pa crispasr_c2pa_static
        LIBRARY DESTINATION lib ARCHIVE DESTINATION lib RUNTIME DESTINATION bin)
install(FILES include/crispasr_c2pa.h DESTINATION include)
