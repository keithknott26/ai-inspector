/* SPDX-License-Identifier: GPL-2.0-or-later
 * AI Inspector analysis engine - plugin registration.
 *
 * Hand-written equivalent of the plugin.c that Wireshark's make-plugin-reg.py
 * generates, so the plugin can be built from sources outside plugins/ via
 * CUSTOM_PLUGIN_SRC_DIR. Wireshark loads the epan plugin, checks
 * plugin_want_major/minor against its own version, and calls plugin_register().
 */
#include "config.h"

#define WS_BUILD_DLL
#include "ws_symbol_export.h"
#include <wsutil/plugins.h>
#include <epan/proto.h>

void proto_register_ai_inspector_engine(void);
void proto_reg_handoff_ai_inspector_engine(void);

#include <wsutil/plugin_exports.h>

WS_DLL_PUBLIC_DEF const char plugin_version[] = PLUGIN_VERSION;
WS_DLL_PUBLIC_DEF const int plugin_want_major = VERSION_MAJOR;
WS_DLL_PUBLIC_DEF const int plugin_want_minor = VERSION_MINOR;

uint32_t plugin_describe(void)
{
    return WS_PLUGIN_DESC_DISSECTOR | WS_PLUGIN_DESC_TAP_LISTENER;
}

void plugin_register(void)
{
    static proto_plugin plug;

    plug.register_protoinfo = proto_register_ai_inspector_engine;
    plug.register_handoff = proto_reg_handoff_ai_inspector_engine;
    proto_register_plugin(&plug);
}
