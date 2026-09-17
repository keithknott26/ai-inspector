/* SPDX-License-Identifier: GPL-2.0-or-later
 * AI Inspector Qt user interface - plugin registration.
 *
 * Hand-written equivalent of the plugin.c that Wireshark's make-plugin-reg.py
 * generates, so the plugin can be built from sources outside plugins/ via
 * CUSTOM_PLUGIN_SRC_DIR. Wireshark loads the Qt UI plugin, checks
 * plugin_want_major/minor against its own version, and calls plugin_register().
 */
#include "config.h"

#define WS_BUILD_DLL
#include "ws_symbol_export.h"
#include <wsutil/plugins.h>
#include "ui/plugins/include/uiqt_plugin.h"

void uiqt_register_ai_inspector(void);

#include <wsutil/plugin_exports.h>

WS_DLL_PUBLIC_DEF const char plugin_version[] = PLUGIN_VERSION;
WS_DLL_PUBLIC_DEF const int plugin_want_major = VERSION_MAJOR;
WS_DLL_PUBLIC_DEF const int plugin_want_minor = VERSION_MINOR;

uint32_t plugin_describe(void)
{
    return WS_PLUGIN_DESC_UI;
}

void plugin_register(void)
{
    static qtui_plugin plug;

    plug.register_qtui_module = uiqt_register_ai_inspector;
    uiqt_register_plugin(&plug);
}
