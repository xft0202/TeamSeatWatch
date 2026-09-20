## Agent skills

### Issue tracker

Specs and issues use local Markdown under `.scratch/`. Read `docs/agents/issue-tracker.md` before publishing or fetching work items.

### Triage labels

Use the default Matt Pocock triage vocabulary. Read `docs/agents/triage-labels.md` when assigning status.

### Engineering quality

Treat every change as part of a long-maintained, production-quality open-source product. Before planning, implementation, or review, read the engineering quality requirements in `docs/project-charter.md`; assess product behavior, architecture, data ownership, security, failure recovery, operations, compatibility, and contributor experience. Record risks and verification evidence, not only feature completion.

### Implementation authorization

Implement only after the system owner explicitly authorizes coding for a defined ticket or scope. Planning instructions, ready labels, unblocked dependencies, and task reminders are not coding authorization. Preserve planning-only status until that authorization is recorded.

### Project-specific delivery

Optimize for this repository's accepted ticket, domain model, ADRs, existing seams, and dependency graph. A generic framework or reusable solution is wrong when a smaller TeamSeatWatch-specific change satisfies the current acceptance criteria and preserves established ownership.

- Freeze the implementation scope after reading the ticket and completing the first Standards/Spec review. Later passes verify named findings and P0/P1 regressions only; they do not restart broad design exploration.
- Use one writer and one fresh Standards/Spec review pair per ticket, followed by at most one finding-focused fix and re-review pass. Treat subagent launch, runtime, or output failures as infrastructure failures: report them, preserve the verified worktree, and stop spawning review loops.
- Finish the current dependency ticket through gates, commit, merge, push, and worktree cleanup before starting dependent tickets. Parallelize only independent tickets named by the dependency graph.
- Keep status reports tied to completion evidence, current blockers, and the next ticket step. Do not branch into environment, tooling, or product work outside the active ticket.
- Use risk-based verification. Run the smallest test set that proves the changed boundary and its direct dependents; do not run unrelated packages, browsers, containers, vulnerability scans, or the full verification suite by reflex. Reuse still-valid evidence when a fast-forward merge or documentation-only change leaves tested code unchanged. Run the full suite only for release verification, toolchain/build changes, or a change whose impact genuinely spans every gate, and state that reason before starting it.

### Domain docs

This is a single-context project. Read `CONTEXT.md` and relevant `docs/adr/` decisions before planning or implementation. Follow `docs/agents/domain.md`.

### Architecture and code quality

This is a production system, not a feature checklist. A ticket is incomplete until its architecture and code quality are defensible as well as its behavior.

- **Trace before changing.** Follow the real flow end to end, identify the current source of truth, ownership, callers, side effects, failure boundaries, and concurrency rules before choosing a seam.
- **Make ownership explicit.** Each module owns one coherent invariant and its resources. Keep domain rules out of HTTP/SQL/platform adapters; keep side effects at explicit boundaries; make transaction, lease, retry, and shutdown ownership visible.
- **Prefer deep, stable interfaces.** A good abstraction hides a difficult invariant or policy behind a small interface. Reuse existing seams, standard library facilities, and generated contracts before adding wrappers, factories, repositories, generic managers, or one-use interfaces. If an abstraction has one trivial implementation and hides no real complexity, delete it.
- **Keep one source of truth.** Do not duplicate DTOs, state machines, status vocabularies, persistence facts, configuration, or policy in parallel layers. Derive projections from authoritative facts and map errors once at the boundary.
- **Design for failure and change.** Review stale data, partial success, retries, cancellation, crashes, lease loss, concurrent writers, recovery, secret exposure, compatibility, and operational cleanup. Enforce security and invariants at the narrowest shared boundary, not in every caller.
- **Use domain language precisely.** Names, states, comments, APIs, migrations, tests, and UI copy must preserve the distinctions in `CONTEXT.md`, accepted ADRs, and the ticket. Never collapse unknown, weak evidence, terminal facts, or infrastructure failures into a convenient success/failure flag.
- **Write boring, readable code.** Favor clear control flow, narrow responsibilities, explicit data ownership, wrapped typed errors, bounded queries, and human-readable comments for non-obvious reasons and invariants. Avoid cleverness, hidden globals, magic strings, speculative flexibility, and compatibility shims without a documented need.
- **Prove the design.** Add the smallest regression and integration checks for state transitions, persistence constraints, concurrency, failure recovery, security boundaries, generated contracts, and user-visible states. Run architecture-sensitive gates, not only a happy-path unit test.
- **Review on two axes.** Before calling work complete, ask both “does the behavior match the spec?” and “would this remain understandable, testable, and safe to change six months from now?” Any unresolved architectural or quality concern keeps the ticket in progress, even when business tests pass.
