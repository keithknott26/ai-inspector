-- SPDX-License-Identifier: GPL-2.0-or-later
-- Stock-TShark fixture for the native engine's repeated-field output contract.
-- Use only in tests without the real AI Inspector engine loaded.
local fixture = Proto("mcp_fixture", "MCP fixture")
local id = ProtoField.string("ai_inspector.id", "Finding ID")
local severity = ProtoField.uint8("ai_inspector.severity", "Severity", base.DEC)
local category = ProtoField.string("ai_inspector.category", "Category")
local finding = ProtoField.string("ai_inspector.finding", "Finding")
fixture.fields = {id, severity, category, finding}

function fixture.dissector(buffer, pinfo, tree)
    if pinfo.number ~= 1 then return end
    local root = tree:add(fixture, buffer())
    local first = root:add(finding, "SSL 2.0/3.0 negotiated (POODLE, broken)")
    first:add(id, "test.first")
    first:add(severity, 4)
    first:add(category, "security")
    local second = root:add(finding, 'Quote "ok", pipe | and tab\tend')
    second:add(id, "test.second")
    second:add(severity, 2)
    second:add(category, "protocol")
end

register_postdissector(fixture)
