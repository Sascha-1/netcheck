# Netcheck design philosophy and contributing guide

Netcheck is written to the standard of mission-critical diagnostic software.
Every line is expected to be read, audited, and maintained by someone who
depends on its output to make security decisions.  This document states the
principles that govern every design choice in the codebase, and the rules
that follow from them.  The ADRs in `docs/adr/` document individual
decisions; this document explains the philosophy that connects them.

---

## Core values

**Correctness over convenience.**  The right result matters more than the
easy result.  If encoding a value correctly requires a factory method, a
`__post_init__` check, and an ADR, it requires all three.  Shortcuts that
produce plausible-looking but semantically imprecise output are rejected.

**Readability and extensibility over compactness and speed.**  Code is read
far more often than it is written.  Netcheck runs a handful of times per
user session on a handful of interfaces; execution time is irrelevant.
Functions are written to be understood on first reading, not to minimise
line count.  A five-line guard with an explanatory comment is better than a
one-line expression that requires decoding.

**Deterministic over heuristic.**  Given the same system state, the tool must
produce the same output every time.  Timing-based measurements, probabilistic
classifications, and best-guess inference are rejected wherever a
deterministic alternative exists.

**Single source of truth.**  No fact is represented in more than one place.
The version string, the public DNS server list, the installation logic -- each
lives in exactly one canonical location and is referenced everywhere else.
Duplication is treated as a defect, not a convenience.

**One stable environment, done correctly.**  Netcheck targets Debian 13
(Trixie) and later.  Wide coverage of every Linux distribution and DNS resolver stack is
not a goal.  Supporting `systemd-resolved` well -- with full per-interface
configured-vs-active distinction -- produces better results than supporting
every resolver stack approximately.

**Minimal dependencies.**  The sole third-party runtime dependency is
`requests`.  Its inclusion is justified in ADR-006 by three concrete
capabilities unavailable in the standard library.  Any further dependency
would require the same level of justification.  Dependencies are managed by
`apt`, not `pip`, to keep the installation model simple and avoid conflicts
with system-managed packages.

---

## 1. Explicit over implicit

Dependencies, failure modes, and data absences must all be visible in the
code -- not inferred from context, not hidden in falsy checks.

**Dependencies** are passed as Protocol arguments rather than imported
directly.  A function that runs a system command has a `CommandRunner`
parameter; a function that reads sysfs has a `SysfsReader` parameter.  The
dependency is visible in the type signature to callers, to mypy, and to
readers.  This is why `unittest.mock.patch` is banned: it patches names, not
objects, and makes dependencies invisible at the call site (ADR-001).

**Absence reasons** are represented explicitly in the type.  `DataStatus`
distinguishes `OK`, `UNAVAILABLE`, `ERROR`, and `NOT_APPLICABLE` so that the
display layer and JSON exporter never have to infer why a field is `None`.
Collapsing these into a single `None` is not simplicity; it is information
loss (ADR-008).

**Runner contract** is checked with `if output is None`, not `if not output`.
An empty string from a successful command is `UNAVAILABLE`; `None` is `ERROR`.
These are different facts and must be written differently.

---

## 2. Encode invariants in types, not prose

Every constraint on a domain object is enforced at construction time.
`DeviceInfo`, `IPConfig`, and `VPNInfo` each have `__post_init__` checks that
raise `ValueError` when `status=OK` is paired with a `None` data field.  The
invariant cannot be violated by a caller who forgets the constraint; the
constructor refuses to produce an inconsistent object.  A comment that states
a constraint is not a substitute for code that enforces it.

Factory methods (`ok()`, `unavailable()`, `error()`, `not_applicable()`) make
construction paths explicit.  Callers do not assign `status` and `data`
separately; they call the factory that represents the situation they are
encoding.  The factory name is the documentation.

All domain dataclasses use `frozen=True`.  Post-construction updates -- DNS
leak status, VPN underlay flags -- are made via `dataclasses.replace`, which
produces a new object and leaves the original unchanged.  Every field update
in the codebase is visible and grep-able; no reference to intermediate state
escapes (ADR-002).

---

## 3. Deterministic over heuristic

Given the same system state, Netcheck must produce the same output every time.

DNS leak detection is configuration-based: it classifies each interface's
active DNS server by comparing it against known categories derived from the
system's own configuration.  It does not time queries, contact external
services, or make probabilistic inferences.  The same `resolvectl` output
always produces the same classification (ADR-003).

Interface type detection follows a fixed priority chain: ModemManager
membership, sysfs symlinks, kernel link types, name prefixes -- in that order,
with no ambiguity and no scoring.  Given the same sysfs state, the same type
is always assigned.

---

## 4. Conservative failure modes

When classification is uncertain, the tool errs toward the more informative
result, not the more reassuring one.

This principle applies pervasively:

- An unknown DNS server is `WARN`, not silently `OK`.
- A DNS-provider interface with no active server during VPN activity is
  `DORMANT` -- a positive security signal, not a failure.
- An interface that is structurally or operationally excluded from DNS leak
  detection is `NOT_APPLICABLE`, not `DORMANT`.  Two conditions produce this:
  the interface type is not a DNS provider (loopback, VPN, bridge, virtual,
  unknown -- these never act as DNS providers and cannot step aside for a VPN);
  or the interface is a DNS-provider type but has no DNS activity in its
  current state (no SIM, failed modem) -- `DORMANT` would imply prior DNS
  activity that never occurred.
- When no VPN interface is active system-wide, DNS leak detection has nothing
  to compare against.  Every interface that would otherwise be classified
  receives `NO_VPN`, not `NOT_APPLICABLE`.  The two are distinct:
  `NOT_APPLICABLE` is a statement about this interface's participation in DNS
  routing and can be assigned regardless of VPN state; `NO_VPN` is a
  system-level statement that the VPN precondition is not met at all.
- An empty string from `CommandRunner.run()` is `UNAVAILABLE`, not `ERROR`,
  because the command succeeded -- it found nothing, which is a normal
  operational outcome.

The rule: if the tool does not know, it says so in the most specific way
available.  It never invents confidence it does not have.

---

## 5. Single source of truth

No fact is represented in more than one place.

`DataStatus` was introduced for `DeviceInfo` and `RoutingInfo` and extended
to `IPConfig` and `VPNInfo` rather than a new vocabulary being invented for
each case.  The version string lives in `src/netcheck/config/__init__.py` and is
referenced by everything else.  Installation logic lives in the Makefile and
nowhere else.  The `PUBLIC_DNS_SERVERS` reference set lives in
`src/netcheck/config/__init__.py`; it is not duplicated in test fixtures.

Duplication forces maintenance: two representations of the same fact will
eventually diverge.  When they do, the divergence is silent, and the tool
produces inconsistent output.

---

## 6. Clear architectural boundaries

Netcheck has four layers.  Each layer depends only on layers below it; no
upward dependencies exist.

```
src/netcheck/output/        -- pure readers: table and JSON rendering
src/netcheck/orchestrator   -- composition: builds domain objects, calls network layer
src/netcheck/network/       -- I/O and analysis: DNS, egress, interfaces, routing, VPN
src/netcheck/core/          -- domain model: enums, dataclasses (no I/O, no imports from above)
src/netcheck/utils/         -- I/O protocols and system implementations
```

**The domain model** (`src/netcheck/core/`) has no knowledge of how it is rendered
or collected.  It can be constructed in tests without instantiating any I/O
infrastructure.

**The output layer** (`src/netcheck/output/`) receives a finalised list of
`InterfaceInfo` objects and renders them without modification.  It never calls
`dataclasses.replace`.  It is a pure reader.

**Each system boundary** (subprocess, sysfs, HTTP) is crossed in exactly one
place: `CommandRunner`, `SysfsReader`, and `HttpClient` respectively.  No
module outside these three imports `subprocess`, reads `/sys`, or calls
`requests` directly.  Changing how the tool talks to the OS requires changing
exactly one file per boundary.

**The composition root** (`src/netcheck/__main__.py`) is the one place where
concrete implementations are wired together.  The Protocol injection
discipline cannot apply here by definition; it is the place where injection
begins.

---

## 7. Focused scope

netcheck targets Debian 13 (Trixie) and later.  It requires `systemd-resolved`.  It
does not attempt to support `resolvconf`, `dnsmasq`, or a static
`/etc/resolv.conf`.

This is a deliberate choice.  `systemd-resolved` is the only DNS stack on
Linux that exposes the configured-vs-active server distinction through an
unprivileged, per-interface, stable CLI -- the distinction that makes accurate
leak detection possible at all (ADR-005).  Supporting resolver stacks that
cannot provide this distinction would require either producing incorrect
results or maintaining fundamentally different code paths.  Neither is
acceptable.

Doing one thing correctly is better than doing many things approximately.
Excluded configurations are documented and rejected cleanly, not handled
silently with degraded output.

---

## 8. Readability and extensibility over compactness

The next reader is the primary audience.

Every public function has a full docstring: what it does, what its arguments
mean, what it returns or raises.  Every non-obvious decision has a comment
explaining the reasoning, not just the mechanism.  The ADR that documents a
decision is referenced at the code site where the decision is implemented.

`StrEnum` is used instead of the `(str, Enum)` mixin pattern because the
mixin diverges between runtime behaviour and static types -- it works at
runtime but is wrong under mypy strict.  That divergence is unacceptable even
when the practical impact is small (ADR-007).

All source files are ASCII-only.  No Unicode, no curly quotes, no em-dashes.
This is not an aesthetic preference; it is a guarantee that the source can
be read, grepped, and diffed by any tool on any terminal without
encoding-related surprises.

The linter is configured to match the codebase (e.g. `max-returns = 12` in
`pyproject.toml`) rather than suppressed inline.  Inline suppressions hide
decisions; configuration changes document them.  When an inline suppression
is unavoidable, it carries a co-located comment explaining the design intent.

---

## 9. The test suite is specification

Protocol fakes (`FakeCommandRunner`, `FakeSysfsReader`, `FakeHttpClient`)
implement the same Protocol interfaces as their production counterparts.
They record calls and return fixture data.  They are plain classes that can
be read, extended, and reasoned about without knowledge of any mocking
framework.  The fake is the specification of the interface it implements.

Tests that exercise a single module pass only the fakes that module depends
on.  A test that passes a `FakeCommandRunner` is documenting that the module
under test uses `CommandRunner` and no other I/O dependency.  If the module
acquires a new I/O dependency, the test must be updated -- which is the
intended signal.

Integration tests are marked `@pytest.mark.integration` and excluded from the
default `make check` run.  They exist to verify that the parsing logic handles
real system output correctly; they are not a substitute for unit tests and do
not run in CI against a controlled environment.

---

## 10. Dependency discipline

Netcheck has one runtime dependency outside the standard library: `requests`
(ADR-006).  It is installed via `apt`, not pip, because mixing package
managers on a system Python installation is a source of silent breakage.
The installation instructions are explicit about this.

Every external dependency is isolated behind a Protocol.  `requests` is
wrapped by `HttpClient`; no module outside `src/netcheck/utils/http.py` imports
it.  If the dependency were replaced, only one file and its tests would change.

New dependencies must be justified with the same rigour applied to `requests`
in ADR-006: what specific capability does it provide that the standard library
does not, and why is that capability worth the maintenance cost?

---

## Contributing

### Before submitting any change

Every pull request must pass `make check` with zero warnings before review:

```bash
make check   # mypy (strict) + pylint (10.0/10 required) + encoding + pytest
```

If `make check` is not green, the change is not ready.

### Rules

**Rule 1: All public functions must have a full docstring.**
Every module-level function, method, and class in `src/netcheck/` must have a
docstring that states what it does, what its arguments mean, and what it
returns or raises.  Test methods are exempt (class-level docstrings explain
what each group tests; per-method names are self-documenting).

**Rule 2: Invariants belong in code, not prose.**
Every constraint on a domain object must be enforced by `__post_init__` or
the type system -- not described only in a comment.  A comment that says
"this field must not be None when status is OK" is not a substitute for a
`__post_init__` check that raises `ValueError` when the constraint is
violated.

**Rule 3: No `unittest.mock`.**
The test suite uses `FakeCommandRunner`, `FakeSysfsReader`, and
`FakeHttpClient` from `tests/fakes.py`.  These fakes implement the same
Protocol interfaces as the production implementations and are the only
approved way to intercept I/O in tests.  `unittest.mock.patch` is banned.

If a new I/O dependency is needed, add it as a Protocol in
`src/netcheck/utils/`, write a `System*` production implementation, and write a
`Fake*` implementation in `tests/fakes.py`.

**Rule 4: Integration tests must be marked.**
Any test that makes real system calls must be decorated with
`@pytest.mark.integration`.  The default `make check` run excludes these
tests via the `-m "not integration"` filter in `pyproject.toml`.

**Rule 5: ASCII only.**
All source files, comments, and docstrings must contain only ASCII characters
(code points 0--127).  No Unicode, no curly quotes, no em-dashes.

**Rule 6: Domain model changes require a commit rationale.**
Any change to `src/netcheck/core/enums.py` or `src/netcheck/core/models.py` must
include in the commit message a brief explanation of why the change is
necessary.  The domain model is the foundation everything else builds on;
silent changes are hard to audit later.

### Architecture Decision Records

Before making structural changes, read the ADRs in `docs/adr/`.  They
document the key design decisions and the reasoning behind each:

- `ADR-001` -- Protocol injection over monkeypatching
- `ADR-002` -- Frozen domain models and `dataclasses.replace`
- `ADR-003` -- Configuration-based DNS leak detection
- `ADR-004` -- `.pth` installation over pip packaging
- `ADR-005` -- `systemd-resolved` as the required DNS resolver interface
- `ADR-006` -- `requests` over `urllib.request` for HTTP
- `ADR-007` -- `StrEnum` over the `(str, Enum)` mixin pattern
- `ADR-008` -- `DataStatus` on `IPConfig` and `VPNInfo`

### Git hooks

A commit-msg hook in `.githooks/commit-msg` enforces Rule 6 automatically.
Install it once after cloning:

```bash
git config core.hooksPath .githooks
```

After installation, any commit that modifies `src/netcheck/core/enums.py` or
`src/netcheck/core/models.py` without the word "rationale" in the commit message
will be rejected with an explanatory error.

The hook has no effect on commits that do not touch either domain model file.
