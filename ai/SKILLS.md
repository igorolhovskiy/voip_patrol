# VoIP Patrol — AI Agent Skills Index

This folder contains instruction files for AI coding assistants (Claude Code, Codex, etc.) working with VoIP Patrol. Read this file first to decide which files to load for your task.

## What VoIP Patrol does

VoIP Patrol is a SIP/VoIP test automation tool. It reads an XML scenario file, executes SIP actions (outbound calls, inbound accept, registrations, messages, transfers), validates results against expectations, and writes a JSON Lines report. It runs as a Docker container and exits with a structured code so CI/CD pipelines can fail without parsing JSON.

## Skill files

| File | Read it when… |
| ---- | ------------- |
| [`scenarios.md`](scenarios.md) | Writing or modifying XML test scenarios; understanding how actions, waits, and checks work; diagnosing unexpected exit codes 2 or 3 |
| [`docker-usage.md`](docker-usage.md) | Building the Docker image locally; running a scenario by hand; understanding volume mounts, env vars, and output files |
| [`ci-github-actions.md`](ci-github-actions.md) | Integrating voip_patrol into a GitHub Actions workflow |
| [`ci-gitlab-ci.md`](ci-gitlab-ci.md) | Integrating voip_patrol into a GitLab CI/CD pipeline |
| [`ci-jenkins.md`](ci-jenkins.md) | Integrating voip_patrol into a Jenkins declarative or scripted pipeline |

## Task → file routing

| Task | Files to read |
| ---- | ------------- |
| Write a new test scenario | `scenarios.md` |
| Modify an existing scenario | `scenarios.md` |
| Run tests locally | `docker-usage.md` |
| Add to GitHub Actions | `ci-github-actions.md`, `docker-usage.md` |
| Add to GitLab CI | `ci-gitlab-ci.md`, `docker-usage.md` |
| Add to Jenkins | `ci-jenkins.md`, `docker-usage.md` |
| Debug exit code 2 | `scenarios.md` → section "Understanding exit codes" |
| Debug exit code 3 | `scenarios.md` → section "Task count and exit code 3" |
| Build the image | `docker-usage.md` |

## Exit codes — quick reference

| Code | Meaning | Typical cause |
| ---- | ------- | ------------- |
| `0` | All tasks ran, all passed | — |
| `1` | Fatal infrastructure error | Transport init failed, PJSIP exception |
| `2` | All tasks ran, ≥1 test returned FAIL | Wrong expected_cause_code, header check failure, wrong codec, etc. |
| `3` | Task count mismatch | An `accept` got no call; an `accept fail_on_accept="true"` got a call it shouldn't have; missing `match_account` in accept action |

Exit codes 2 and 3 are distinct signals: **2** = something happened but was wrong; **3** = expected event did not happen (or unexpected one did).

## Project layout (key paths)

```
voip_patrol/          ← project root (this folder)
├── src/voip_patrol/  ← C++ source
├── xml/              ← example XML scenarios
├── ai_docs/          ← this folder
└── README.md         ← full parameter reference for all action types
```

At the workspace level:
```
build_image.sh        ← builds the Docker image tagged voip_patrol_local
entry.sh              ← container entrypoint; controls the run via env vars
xml/                  ← your XML scenarios (mounted as /xml inside container)
output/               ← JSON results land here (mounted as /output)
voice_ref_files/      ← WAV files for playback (mounted as /voice_ref_files)
```

## Non-obvious conventions

- The `accept` action requires `match_account`, **not** `account`. Using `account=` is silently ignored and causes exit code 3 with `total tasks: 101`.
- `VP_ENV_*` values in XML are substituted from environment variables at runtime. Use them for credentials.
- `<action type="wait" complete="true"/>` must appear after action types that produce tasks (`call`, `accept`, `register`, `message`, `accept_message`, `bxfer`). Without it, the process exits before tests finish.
- `--net=host` is required for real SIP testing so that the container's SIP and RTP ports are reachable from the network.
