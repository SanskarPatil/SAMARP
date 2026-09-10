# Git Workflow

**Project:** Cyber Sentinel — PS26145

Four people and multiple AI agents share one repository for twenty-four hours. This file defines how that happens without losing work. Ownership is in `agents.md`; agent behavioural rules are in `CLAUDE.md`.

---

## 1. Repository Rules

- One repository, three track directories, three shared contracts.
- **Commit early and often.** A twenty-four-hour window has no time for a lost afternoon.
- **Never commit** credentials, keys, venue network details, captured production traffic, or malware binaries from capture datasets.
- Large binary assets — PCAPs, model artifacts, GeoLite2 — are vendored deliberately and hashed. Record hashes in the scenario manifest, not just in git.
- The working tree must build. If a commit breaks the build for another track, fix it or revert it; do not leave it for the next person.

---

## 2. Branch Strategy

```text
main
develop
feature/ingestion-replay
feature/detection-ddos
feature/detection-dga
feature/dashboard
fix/replay-clock
fix/schema-parity
```

- `main` is demo-ready at all times after the Hour-12 checkpoint. It is what a cold boot pulls.
- `develop` is the integration branch.
- Feature branches are named `feature/<track-area>` and are short-lived — hours, not days.
- Fix branches are named `fix/<symptom>`.
- Merge into `develop` early and often; merge into `main` at each gate.

---

## 3. Ownership

Branch ownership follows track ownership from `agents.md`:

| Prefix | Owner |
|---|---|
| `feature/ingestion-*`, `feature/flow-*`, `feature/sensor-*` | Track A |
| `feature/detection-*`, `feature/model-*`, `feature/eval-*` | Track B |
| `feature/dashboard-*`, `feature/api-*`, `feature/export-*` | Track C |

**Do not commit to another track's branch.** Raise a handoff instead.

---

## 4. Commit Convention

```text
feat(ingest): add tcpreplay harness
feat(detection): add DGA feature extractor
feat(ui): add incident evidence drawer
fix(ingest): handle partial EVE lines
test(schema): add alert contract tests
docs: update architecture
```

Scopes: `ingest`, `sensor`, `flow`, `features`, `detection`, `model`, `eval`, `alerts`, `api`, `ui`, `export`, `schema`, `config`, `scenarios`, `docs`.

Keep commits logically focused. One commit does one thing, so a revert removes one thing.

---

## 5. Pull / Rebase Rules

- **Pull before you start.** Pull before you push.
- Rebase your own unpushed work to keep history readable.
- **Never rebase or rewrite history that another person has already pulled.**
- Resolve your own conflicts in your own files. Do not resolve a conflict in someone else's file to make your merge go through.

---

## 6. Shared Contract Changes

Three files are shared interfaces between tracks, plus their supporting configuration:

```text
schemas/normalized_event.schema.json     owner: Track A
schemas/alert.schema.json                owner: Track B
features/feature_order.py                owner: Track B
config/dedup_keys.yaml                   owner: Track B
config/address_plan.yaml                 owner: Track A
config/thresholds.yaml                   owner: Track B (latency block: Track A)
```

**A contract change is never a side effect of another change.** It follows this procedure, in order:

1. **Discussion and coordination** — the contract owner and every consuming track agree the change is necessary.
2. **Schema update** — the contract file changes.
3. **Contract-test update** — in the same commit, so drift cannot pass.
4. **Consumer update** — every consuming track updates.
5. **Verification** — contract tests and feature-parity tests pass, and the actual output is reported.

A contract change lands as one reviewed merge, not as five independent commits across three branches.

**`FEATURE_ORDER` deserves special care.** Training and inference must import the same object; a silent reorder produces a model scoring against the wrong features, which no test outside `tests/parity/` will catch and no amount of debugging the detector will explain.

---

## 7. Conflict Resolution

| Situation | What to do |
|---|---|
| Conflict in your own track's file | Resolve it yourself |
| Conflict in a shared contract | **Both owners review together.** Never resolve unilaterally |
| Conflict in generated or vendored assets | Regenerate from source; do not hand-merge a PCAP, a model artifact or a lockfile |
| Two tracks changed the same schema field | Stop. This is a coordination failure, not a merge problem — run the section 6 procedure from step 1 |
| A merge broke another track's tests | The person whose change broke it fixes it. Do not weaken the test to go green |

---

## 8. Testing Before Commit

Before committing:

- Run the tests relevant to what you changed, and **look at the output**.
- If you touched a schema, `FEATURE_ORDER` or a dedup key, run the contract tests.
- If you touched ingestion or features, run the parity tests.
- If you touched an API route, run the route contract test that asserts no non-`GET` route exists on Plane B.

Before merging into `develop`: contract tests and the tests for the tracks you touched.

Before merging into `main` at a gate: the full gate checklist from `implementation_plan.md` section 8.

**Never commit a change that you have not run.** Reporting "should work" as done is the failure mode this rule exists to prevent.

---

## 9. Emergency Fixes

During a gate failure the normal flow is too slow. The emergency path:

1. Branch from `main` as `fix/<symptom>`.
2. Make the **smallest possible change**. An emergency is not the time for a refactor.
3. Run the test that proves the symptom is gone.
4. Merge to `main` and to `develop` in the same session, so the two do not diverge.
5. **Record it in `bugs.md`** — symptom, reproduction, root cause, fix, regression test. An emergency fix without a recorded root cause becomes the same emergency again at hour 20.

If a gate failure requires all four people (the Hour-6 spine failure), everyone works on `main` directly and coordinates verbally. That is the one exception, and it ends when the gate is green.

---

## 10. Feature Freeze Rules

**From Hour 19, `main` is frozen to a narrow set of changes.**

Allowed:

- Documentation.
- Bug fixes with a recorded root cause.
- Evidence corrections.
- Demo stability fixes.
- Filling measured numbers into the README, deck and evaluation report.

Not allowed:

- New detectors.
- New models.
- Architecture changes.
- New dependencies.
- New major UI features.

**No new detector work after the Hour-16 kill gate**, even before the freeze. After Hour 22, the repository is buffer only: final cold boot, final rehearsal, verify the backup. Do not touch working architecture.

Every commit after Hour 19 should be explainable in one sentence as a fix, a document, or a number.

---

## 11. Useful Commands

```bash
# start work
git pull --rebase origin develop
git switch -c feature/detection-slowloris

# see what you are about to commit
git status
git diff --staged

# focused commit
git add detectors/ddos.py tests/detectors/test_slowloris.py
git commit -m "feat(detection): add Slowloris concurrency and duration gates"

# keep up to date without rewriting shared history
git fetch origin
git rebase origin/develop

# integrate
git switch develop
git merge --no-ff feature/detection-slowloris
git push origin develop

# gate merge
git switch main
git merge --no-ff develop
git push origin main

# inspect before a risky operation
git log --oneline --graph --decorate -20
git diff main..develop --stat
```

---

## Hard Rules

- **Never force-push a shared branch.**
- **Never reset another developer's work.**
- **Do not silently rewrite shared contracts.**
- **Run relevant tests before committing**, and report the actual result.
- **Keep commits logically focused.**
- **Coordinate changes to frozen schemas and `FEATURE_ORDER`** before making them.
- **Commit or push only when asked** — this applies to AI agents in particular.
