# SPDX-License-Identifier: GPL-2.0-or-later
#
# Standalone build of the AI Inspector unit tests (no Wireshark SDK needed).
# The plugins themselves are built in-tree with Wireshark: see
# tools/build-development.sh.
cmake_minimum_required(VERSION 3.20)
include(cmake/AIInspectorVersion.cmake)
project(AIInspectorTests VERSION ${AI_INSPECTOR_VERSION} LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)

find_package(Qt6 REQUIRED COMPONENTS Core Widgets Network Test)
find_package(Python3 REQUIRED COMPONENTS Interpreter)
enable_testing()

add_executable(unit_util tests/unit_util.cpp)
target_include_directories(unit_util PRIVATE native/common)
target_compile_options(unit_util PRIVATE -Wall -Wextra)
add_test(NAME unit_util COMMAND unit_util)

add_executable(ui_tests
    tests/ui_tests.cpp
    native/ui/ai_client.cpp native/ui/ai_client.h
    native/ui/panel.cpp native/ui/panel.h
    native/ui/charts.cpp native/ui/charts.h
    native/ui/chat_view.cpp native/ui/chat_view.h
    native/ui/dashboard.cpp native/ui/dashboard.h
    native/ui/redactor.cpp native/ui/redactor.h
    native/ui/settings.cpp native/ui/settings.h)
target_include_directories(ui_tests PRIVATE native/ui native/common)
target_compile_definitions(ui_tests PRIVATE PLUGIN_VERSION="${AI_INSPECTOR_VERSION}" AI_INSPECTOR_TESTS_DIR="${CMAKE_CURRENT_SOURCE_DIR}/tests")
target_compile_options(ui_tests PRIVATE -Wall -Wextra)
target_link_libraries(ui_tests PRIVATE Qt6::Core Qt6::Widgets Qt6::Network Qt6::Test)
add_test(NAME ui_tests COMMAND ui_tests)
set_tests_properties(ui_tests PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen" TIMEOUT 180)
