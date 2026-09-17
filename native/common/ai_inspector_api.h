/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * AI Inspector - C ABI between the analysis engine (epan plugin) and the
 * Qt user interface (ui plugin).
 *
 * The engine registers the tap AI_INSPECTOR_TAP_NAME and queues an ai_inspector_tap_data_t
 * for every frame on the first dissection pass. Listeners obtain the engine API
 * table from it. All returned strings are UTF-8 JSON/text owned by the caller
 * and must be released with api->free_string(). Call only from the thread that
 * performs dissection (the GUI thread in Wireshark).
 */
#ifndef AI_INSPECTOR_API_H
#define AI_INSPECTOR_API_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define AI_INSPECTOR_TAP_NAME "ai_inspector"
#define AI_INSPECTOR_API_ABI  1

typedef struct ai_inspector_engine_api {
    uint32_t abi;               /* AI_INSPECTOR_API_ABI */
    const char *version;        /* engine version string */
    /* Monotonic identifier that changes whenever capture state is reset. */
    uint64_t (*generation)(void);
    /* Capture summary: counts, protocols, findings, inventory (JSON object). */
    char *(*summary_json)(uint32_t max_findings);
    /* Findings stored for one frame (JSON array). */
    char *(*frame_findings_json)(uint32_t frame);
    /* Human-readable report (plain text). */
    char *(*report_text)(void);
    void (*free_string)(char *s);
} ai_inspector_engine_api_t;

typedef struct ai_inspector_tap_data {
    uint32_t abi;               /* AI_INSPECTOR_API_ABI */
    uint32_t frame;
    uint32_t findings;          /* findings stored for this frame */
    uint8_t worst_severity;     /* 0 when none */
    bool first_pass;
    const ai_inspector_engine_api_t *api;
} ai_inspector_tap_data_t;

#ifdef __cplusplus
}
#endif

#endif
