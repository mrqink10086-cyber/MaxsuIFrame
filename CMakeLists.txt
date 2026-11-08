cmake_minimum_required(VERSION 3.21)

if(NOT DEFINED CMAKE_TOOLCHAIN_FILE AND DEFINED ENV{VCPKG_ROOT} AND NOT "$ENV{VCPKG_ROOT}" STREQUAL "")
	set(CMAKE_TOOLCHAIN_FILE "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake" CACHE FILEPATH "vcpkg toolchain")
endif()

project(MaxsuIFrame VERSION 2.0.0 LANGUAGES CXX RC)
if(PROJECT_SOURCE_DIR STREQUAL PROJECT_BINARY_DIR)
	message(FATAL_ERROR "In-source builds are not allowed.")
endif()

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
set(COMMONLIBSSE_NG_PATH "${CMAKE_CURRENT_SOURCE_DIR}/../CommonLibSSE-NG-ng" CACHE PATH "Local CommonLibSSE-NG source directory")
set(SKSEPluginAuthor "maxsu" CACHE STRING "Plugin author")
set(ENABLE_SKYRIM_SE OFF CACHE BOOL "Build for SE" FORCE)
set(ENABLE_SKYRIM_AE ON CACHE BOOL "Build for AE" FORCE)
set(ENABLE_SKYRIM_VR OFF CACHE BOOL "Build for VR" FORCE)
set(BUILD_TESTS OFF CACHE BOOL "Build CommonLibSSE tests")
set(COMMONLIB_PREBUILT OFF CACHE STRING "Build the selected local CommonLibSSE sources" FORCE)
add_subdirectory("${COMMONLIBSSE_NG_PATH}" CommonLibSSE EXCLUDE_FROM_ALL)
include("${COMMONLIBSSE_NG_PATH}/cmake/CommonLibSSE.cmake")
find_package(nlohmann_json CONFIG REQUIRED)

configure_file(cmake/Version.h.in include/Version.h @ONLY)
configure_file(cmake/Version.rc.in version.rc @ONLY)
add_commonlibsse_plugin(${PROJECT_NAME}
	AUTHOR "${SKSEPluginAuthor}"
	MINIMUM_SKSE_VERSION 2.2.6
	COMPATIBLE_RUNTIMES 1.6.1170.0
	STRUCT_DEPENDENT
	SOURCES
		src/main.cpp
		src/Functions.cpp
		src/InvincibleFrames.cpp
		"${CMAKE_CURRENT_BINARY_DIR}/version.rc"
)
target_include_directories(${PROJECT_NAME} PRIVATE src "${CMAKE_CURRENT_BINARY_DIR}/include")
target_link_libraries(${PROJECT_NAME} PRIVATE nlohmann_json::nlohmann_json)
target_compile_definitions(${PROJECT_NAME} PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)
target_precompile_headers(${PROJECT_NAME} PRIVATE src/PCH.h)
if(MSVC)
	target_compile_options(${PROJECT_NAME} PRIVATE /W4 /permissive- /Zc:__cplusplus /Zc:preprocessor /utf-8)
endif()
install(TARGETS ${PROJECT_NAME} RUNTIME DESTINATION SKSE/Plugins)
