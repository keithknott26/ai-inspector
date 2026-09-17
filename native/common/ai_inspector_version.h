/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * AI Inspector version string. The build defines PLUGIN_VERSION from
 * cmake/AIInspectorVersion.cmake (via Wireshark's set_module_info() for the
 * plugins, and explicitly for the standalone tests).
 */
#ifndef AI_INSPECTOR_VERSION_H
#define AI_INSPECTOR_VERSION_H

#ifndef PLUGIN_VERSION
#define PLUGIN_VERSION "0.0.0-dev"
#endif

#define AI_INSPECTOR_VERSION PLUGIN_VERSION

#endif
