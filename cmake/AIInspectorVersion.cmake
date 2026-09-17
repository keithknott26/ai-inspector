# SPDX-License-Identifier: GPL-2.0-or-later
#
# Single source of truth for the AI Inspector version.
# Bump these numbers (and add a CHANGELOG.md entry) when releasing.
# The value reaches C/C++ code as the PLUGIN_VERSION define (see
# native/common/ai_inspector_version.h) and Wireshark's plugin list.
set(AI_INSPECTOR_VERSION_MAJOR 1)
set(AI_INSPECTOR_VERSION_MINOR 1)
set(AI_INSPECTOR_VERSION_PATCH 0)
set(AI_INSPECTOR_VERSION "${AI_INSPECTOR_VERSION_MAJOR}.${AI_INSPECTOR_VERSION_MINOR}.${AI_INSPECTOR_VERSION_PATCH}")

# Wireshark source revision the plugins are developed and tested against.
# tools/fetch-wireshark.sh checks out exactly this commit.
set(AI_INSPECTOR_WIRESHARK_COMMIT "c910cf86a6bd8a805addd07253d0e19165a46904")
