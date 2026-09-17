# SPDX-License-Identifier: GPL-2.0-or-later
# AI Inspector analysis engine (epan plugin). Built in-tree through
# CUSTOM_PLUGIN_SRC_DIR; see tools/build-development.sh.
include(WiresharkPlugin)

include("${CMAKE_CURRENT_LIST_DIR}/../../cmake/AIInspectorVersion.cmake")
set_module_info(ai_inspector_engine ${AI_INSPECTOR_VERSION_MAJOR} ${AI_INSPECTOR_VERSION_MINOR} ${AI_INSPECTOR_VERSION_PATCH} 0)
set(AI_INSPECTOR_COMMON_DIR "${CMAKE_CURRENT_LIST_DIR}/../common")

set(PLUGIN_FILES
	${CMAKE_CURRENT_LIST_DIR}/plugin.c
	${CMAKE_CURRENT_LIST_DIR}/ai_inspector_engine.cpp
)
set_source_files_properties(${PLUGIN_FILES} PROPERTIES COMPILE_FLAGS "${WERROR_COMMON_FLAGS}")

add_wireshark_plugin_library(ai_inspector_engine epan)
set_target_properties(ai_inspector_engine PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED ON)
target_include_directories(ai_inspector_engine PRIVATE "${AI_INSPECTOR_COMMON_DIR}")
target_link_libraries(ai_inspector_engine epan)
install_plugin(ai_inspector_engine epan)
