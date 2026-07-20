#!/usr/bin/env python3
import pathlib
import re
import sys


def function_body(text: str, signature: str) -> str:
    start = -1
    search_from = 0
    while True:
        start = text.index(signature, search_from)
        after_signature = start + len(signature)
        brace = text.index("{", after_signature)
        semicolon = text.find(";", after_signature, brace)
        if semicolon < 0:
            break
        search_from = after_signature
    depth = 0
    for pos in range(brace, len(text)):
        if text[pos] == "{":
            depth += 1
        elif text[pos] == "}":
            depth -= 1
            if depth == 0:
                return text[brace + 1:pos]
    raise AssertionError(f"unterminated function: {signature}")


def braced_block(text: str, brace: int) -> tuple[str, int]:
    depth = 0
    for pos in range(brace, len(text)):
        if text[pos] == "{":
            depth += 1
        elif text[pos] == "}":
            depth -= 1
            if depth == 0:
                return text[brace + 1:pos], pos + 1
    raise AssertionError("unterminated block")


root = pathlib.Path(sys.argv[1]).resolve()
main = (root / "linux-user/main.c").read_text(encoding="utf-8")
options = (root / "target/i386/latx/include/latx-options.h").read_text(
    encoding="utf-8"
)
options_c = (root / "target/i386/latx/latx-options.c").read_text(
    encoding="utf-8"
)
elfloader = (root / "target/i386/latx/context/elfloader.c").read_text(
    encoding="utf-8"
)
diagnostics = (
    root / "target/i386/latx/context/kzt_lazy_diagnostics.c"
).read_text(encoding="utf-8")

# The lazy diagnostics flag is independent and closed by default.
assert re.search(r"\bint\s+option_kzt_lazy_diagnostics\s*=\s*0\s*;", options_c)
assert not re.search(r"\bint\s+option_kzt_lazy_diagnostics\s*=", main)
assert re.search(
    r'"LATX_KZT_LAZY_DIAGNOSTICS"\s*,\s*true\s*,\s*'
    r'handle_arg_latx_kzt_lazy_diagnostics',
    main,
)
assert "ENVFUN(LATX_KZT_LAZY_DIAGNOSTICS" in options
handler = function_body(
    main, "static void handle_arg_latx_kzt_lazy_diagnostics(const char *arg)"
)
assert "option_kzt_lazy_diagnostics" in handler
assert "kzt_registry_diagnostics" not in handler
assert "option_kzt_lazy_diagnostics" not in function_body(
    diagnostics, "int kzt_lazy_diagnostics_emit_production("
)

resolver = function_body(
    elfloader, "static void KztLazyBindingCompleteResolver(void)"
)
armed_start = resolver.index("if (pending->armed)")
armed_brace = resolver.index("{", armed_start)
armed, _ = braced_block(resolver, armed_brace)

# The option conditional is the sole diagnostics gate on the completion path.
gate = re.search(r"if\s*\(\s*option_kzt_lazy_diagnostics\s*\)\s*\{", armed)
assert gate is not None
enabled_brace = armed.index("{", gate.start())
enabled, enabled_end = braced_block(armed, enabled_brace)
else_match = re.match(r"\s*else\s*\{", armed[enabled_end:])
assert else_match is not None
disabled_brace = armed.index("{", enabled_end + else_match.start())
disabled, _ = braced_block(armed, disabled_brace)

assert "pending_snapshot = *pending;" in enabled
assert re.search(
    r"pending_snapshot\.symbol\s*=\s*pending->symbol\s*\?\s*"
    r"pending_snapshot\.symbol_storage\s*:\s*NULL\s*;",
    enabled,
    re.S,
)
assert re.search(
    r"pending_snapshot\.version\s*=\s*pending->version\s*\?\s*"
    r"pending_snapshot\.version_storage\s*:\s*NULL\s*;",
    enabled,
    re.S,
)
assert enabled.index("pending_snapshot = *pending;") < enabled.index(
    "kzt_production_lazy_complete("
)
assert enabled.index("kzt_production_lazy_complete(") < enabled.index(
    "kzt_lazy_diagnostics_emit_production("
)
assert re.search(
    r"kzt_lazy_diagnostics_emit_production\s*\(\s*"
    r"&pending_snapshot\s*,\s*&result\s*,",
    enabled,
    re.S,
)
assert "kzt_production_lazy_complete(" in disabled
for forbidden in ("pending_snapshot", "diagnostic", "emit"):
    assert forbidden not in disabled

# Record construction consumes only the pre-clear pending snapshot and the
# existing completion result; it must not rediscover or reroute the binding.
record = function_body(diagnostics, "int kzt_lazy_diagnostic_record_build(")
assert "record->slot_before = pending->unresolved_stub;" in record
assert "record->slot_after_guest = binding_result->slot_before;" in record
assert "record->selected_second_target = binding_result->slot_after;" in record
for forbidden in (
    "owner",
    "provider",
    "wrapper",
    "bridge",
    "planner",
    "route_guest_target",
    "compare_exchange",
):
    assert forbidden not in record

print("WI-256 lazy diagnostics source contract: PASS")
