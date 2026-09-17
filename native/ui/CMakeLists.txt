# SPDX-License-Identifier: GPL-2.0-or-later
# AI Inspector Qt UI plugin. Built in-tree through CUSTOM_PLUGIN_SRC_DIR;
# see tools/build-development.sh.
include(WiresharkPlugin)

include("${CMAKE_CURRENT_LIST_DIR}/../../cmake/AIInspectorVersion.cmake")
set_module_info(ai_inspector ${AI_INSPECTOR_VERSION_MAJOR} ${AI_INSPECTOR_VERSION_MINOR} ${AI_INSPECTOR_VERSION_PATCH} 0)
set(AI_INSPECTOR_UI_DIR "${CMAKE_CURRENT_LIST_DIR}")
set(AI_INSPECTOR_COMMON_DIR "${CMAKE_CURRENT_LIST_DIR}/../common")

find_package(Qt6 REQUIRED COMPONENTS Core Widgets Network)
set(CMAKE_AUTOMOC ON)

set(PLUGIN_FILES
	${AI_INSPECTOR_UI_DIR}/plugin.c
	${AI_INSPECTOR_UI_DIR}/ai_inspector_ui.cpp
	${AI_INSPECTOR_UI_DIR}/panel.cpp
	${AI_INSPECTOR_UI_DIR}/panel.h
	${AI_INSPECTOR_UI_DIR}/ai_client.cpp
	${AI_INSPECTOR_UI_DIR}/ai_client.h
	${AI_INSPECTOR_UI_DIR}/charts.cpp
	${AI_INSPECTOR_UI_DIR}/charts.h
	${AI_INSPECTOR_UI_DIR}/chat_view.cpp
	${AI_INSPECTOR_UI_DIR}/chat_view.h
	${AI_INSPECTOR_UI_DIR}/dashboard.cpp
	${AI_INSPECTOR_UI_DIR}/dashboard.h
	${AI_INSPECTOR_UI_DIR}/redactor.cpp
	${AI_INSPECTOR_UI_DIR}/settings.cpp
	${AI_INSPECTOR_UI_DIR}/settings.h
	${AI_INSPECTOR_UI_DIR}/selftest.cpp
	${AI_INSPECTOR_UI_DIR}/selftest.h
)
set_source_files_properties(${AI_INSPECTOR_UI_DIR}/plugin.c PROPERTIES SKIP_AUTOGEN ON)

add_wireshark_plugin_library(ai_inspector ui)
set_target_properties(ai_inspector PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED ON AUTOMOC ON)
target_include_directories(ai_inspector PRIVATE "${AI_INSPECTOR_UI_DIR}" "${AI_INSPECTOR_COMMON_DIR}")
target_link_libraries(ai_inspector epan uiqt_plugin Qt6::Core Qt6::Widgets Qt6::Network)
install_plugin(ai_inspector ui)
