cmake_minimum_required(VERSION 3.16)
project(portablizer_shim CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ── Microsoft Detours ──────────────────────────────────────────────────────
# Either install via vcpkg: vcpkg install detours
# Or set DETOURS_DIR to the Detours root
if(DEFINED ENV{DETOURS_DIR})
    set(DETOURS_INCLUDE_DIR "$ENV{DETOURS_DIR}/include")
    set(DETOURS_LIB_DIR     "$ENV{DETOURS_DIR}/lib.X64")
else()
    find_package(detours CONFIG REQUIRED)
endif()

# ── nlohmann/json ──────────────────────────────────────────────────────────
# Single-header: download json.hpp from https://github.com/nlohmann/json
# Or: vcpkg install nlohmann-json
find_package(nlohmann_json CONFIG QUIET)

# ── Shim DLL ──────────────────────────────────────────────────────────────
add_library(portablizer_shim SHARED
    portablizer_shim.cpp
)

target_include_directories(portablizer_shim PRIVATE
    ${DETOURS_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(portablizer_shim PRIVATE
    detours
    shell32
    shlwapi
    advapi32
)

if(TARGET nlohmann_json::nlohmann_json)
    target_link_libraries(portablizer_shim PRIVATE nlohmann_json::nlohmann_json)
endif()

target_compile_definitions(portablizer_shim PRIVATE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    _CRT_SECURE_NO_WARNINGS
)

# ── withdll.exe launcher ─────────────────────────────────────────────────
# withdll is bundled with Detours. Build it from Detours source if needed:
# https://github.com/microsoft/Detours/tree/main/samples/withdll

# ── Install ───────────────────────────────────────────────────────────────
install(TARGETS portablizer_shim
    RUNTIME DESTINATION tools/bin
    LIBRARY DESTINATION tools/bin
)
