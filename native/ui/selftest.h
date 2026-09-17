// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once

#include "panel.h"

#include <functional>

namespace aiinspector {
// Starts the in-application integration self-test (AI_INSPECTOR_UI_SELFTEST=1).
void startIntegrationSelfTest(const Host &host, std::function<InspectorPanel *()> openPanel);
}
