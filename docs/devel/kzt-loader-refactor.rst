KZT Loader Refactor Plan
========================

Purpose
-------

The KZT loader refactor is a staged redesign of how LATX observes guest ELF
objects and decides whether guest GOT entries should be redirected to native
wrapper bridges.

The existing loader path works, but it mixes several responsibilities in a
small number of places:

* observing guest loader events;
* rebuilding object identity from host-side state;
* loading wrapper dependencies;
* resolving symbols through ``maplib``;
* deciding whether a GOT slot should be patched;
* applying the GOT write immediately or through lazy binding.

That makes the code hard to reason about.  It also makes correctness depend on
host-side reconstruction of guest loader decisions, including global symbol
searches and dependency expansion that may not match the guest loader's final
result.

The refactor separates those responsibilities and moves the design toward one
rule: guest loader state should be the authoritative source for guest object
identity, while host-side wrapper state should only be used to find native
bridge targets.

Why This Refactor Is Needed
---------------------------

The old path has several structural problems.

Guest object identity is implicit
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Many decisions depend on knowing which guest object owns an address, but the
old loader path often derives that identity indirectly from ``elfheader_t``,
``maplib`` results, or repeated global symbol lookups.  This makes it hard to
tell whether a GOT value points into the object the guest loader actually
selected.

Symbol resolution is repeated in the wrong layer
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The guest loader already resolves dependencies and symbol bindings.  Repeating
that work through LATX global ``maplib`` search can select a different owner
from the one represented by the current guest GOT value.  The result is a
cross-object mismatch risk that is especially visible for wrapper selection.

Patch decisions are not first-class data
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Historically, relocation code directly wrote GOT slots after resolving a
target.  That makes it difficult to inspect why a slot was patched, which
object owned the old target, which wrapper was selected, or why a patch was
skipped.

Loader synchronization is too centralized
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The private glibc hook currently carries too much responsibility.  Even if a
small hook remains necessary, it should only publish loader events.  Object
tracking, dynamic parsing, symbol comparison, and patch planning should live in
separate modules.

Feasibility
-----------

The redesign is feasible because the guest process already exposes enough
runtime information to build safer boundaries:

* ``link_map`` records provide object names, load addresses, and dynamic table
  pointers.
* ``l_ld`` points to the in-memory Dynamic Table, so symbol, relocation, and
  version information can be parsed without relying on ELF section headers.
* Existing GOT values can be mapped back to guest object load ranges.
* Wrapper libraries can still be queried for native bridge addresses.
* The old ``maplib`` path can remain as a fallback while each new boundary is
  validated.

The key engineering choice is to avoid a flag-day rewrite.  Each stage adds a
new explicit boundary while preserving the old behavior until the replacement
has enough observability.

Design Principles
-----------------

The staged design follows these principles:

* Record guest object identity once and pass it through explicit APIs.
* Parse guest loader data from memory instead of reopening guest ELF files.
* Represent every GOT patch as a decision before writing the slot.
* Prefer the guest-selected final owner when choosing a wrapper target.
* Keep ``maplib`` fallback paths until the new path has been compared in
  realistic workloads.
* Keep lazy binding separate from normal relocation cleanup.
* Reduce the glibc hook to an event source after module boundaries are stable.

Stages
------

Stage 1: Guest object registry
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Introduce a ``GuestObjectRegistry`` that records guest objects observed from
loader callbacks.  The registry owns object identity: name, base address, load
range, and dynamic table address.

The callback should only register object information and then call the legacy
compatibility path.  This establishes a clean identity layer without changing
the loader's external behavior.

Stage 2: In-memory dynamic parser
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Parse the guest Dynamic Table from ``l_ld``.  The parser should build a view
of symbols, relocations, version indices, version needs, version definitions,
and string-table entries.

Initially, the in-memory parser should run in parallel with the legacy
file-based parser.  Differences should be asserted in tests or logged in
runtime comparison paths.  Only after the comparison is stable should the old
``fopen()`` and section-header dependency be removed.

Stage 3: Patch planner
~~~~~~~~~~~~~~~~~~~~~~

Introduce a planner record for every GOT modification.  A patch decision should
include:

* the guest object;
* relocation address and relocation type;
* symbol name and version;
* old GOT target;
* old owner and old guest object;
* ``maplib`` bridge and owner;
* guest-owner bridge and owner, if available;
* selected target source;
* decision reason.

At this stage, the planner does not need to change target selection.  Its main
job is to make the existing behavior observable and testable.

Stage 4: Guest-owner target selection
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Use the current guest GOT value to identify the guest object that owns the
resolved target.  Then resolve the same symbol through that object's wrapper
library.

The safe rule is:

* if the guest-owner probe succeeds, it may replace repeated global
  ``maplib`` resolution for that slot;
* if the probe fails, the existing ``maplib`` fallback remains authoritative.

This stage should cover normal relocation paths first.  Lazy binding remains a
separate stage.

Stage 5: Remove ordinary guest dependency side loading
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Stop using ``LoadNeededLibs()`` to recursively load ordinary x86 guest
dependencies through the wrapper path.  Host-side loading should be limited to
native wrapper dependencies, or delegated to host ``dlopen()`` when suitable.

This stage depends on stages 1 through 4 because guest object identity and
patch target decisions must already be explicit before removing the side path.

Stage 6: Simplify lazy binding
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Let the guest loader perform lazy binding first where possible, then patch the
slot after the guest binding result is visible.

If a first-call immediate replacement path is still required, it should be a
dedicated module rather than extra policy inside generic relocation code.

Stage 7: Refactor dlopen/dlsym/dlclose
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Make guest loader handles authoritative.  Remove synthetic handle behavior,
duplicate reference counting, and reload paths that bypass the guest loader's
state.

Stage 8: Replace private glibc hook responsibilities
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

After the previous boundaries are stable, reduce or replace the private glibc
hook.  Possible event sources include ``r_debug`` notifications, RELRO
``mprotect`` transitions, QEMU mmap/loader events, or a small version-isolated
fallback hook.

Even if a hook remains, it should publish events only.  It should not own guest
object parsing, dependency loading, or GOT patch planning.

Patch Series Organization
-------------------------

A reviewable implementation series should be grouped by design boundary rather
than by mechanical helper extraction.  The recommended grouping is:

1. Documentation and roadmap.
2. Guest object registry.
3. In-memory dynamic parser and dual-track comparison.
4. Patch planner records and GOT write routing.
5. Guest-owner target comparison.
6. Guest-owner target selection.

Each patch should contain a commit body explaining:

* which stage it belongs to;
* which old behavior is preserved as fallback;
* what new boundary or data model is introduced;
* what validation is expected for that stage.

Progress reports, latest CTS numbers, and temporary rollout notes should be
kept outside this design document because they change as the series evolves.
