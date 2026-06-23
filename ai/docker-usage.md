# Docker Usage

## Building the image

From the workspace root (the directory containing `build_image.sh`):

```bash
./build_image.sh
```

This produces a local image tagged `voip_patrol_local`. The build compiles PJSIP and voip_patrol from source inside Docker — it takes several minutes on a cold build.

Verify the build:
```bash
docker run --rm voip_patrol_local /git/voip_patrol/voip_patrol --help
```

The output should show `voip_patrol version: X.Y.Z` and the list of CLI flags.

## Running a scenario via entry.sh (standard method)

The container entrypoint is `entry.sh`, which reads environment variables and calls the binary. This is the method CI/CD pipelines should use.

```bash
docker run --rm \
  --net=host \
  -v $(pwd)/xml:/xml \
  -v $(pwd)/output:/output \
  -v $(pwd)/voice_ref_files:/voice_ref_files \
  -e XML_CONF=my_scenario \
  -e RESULT_FILE=result.json \
  -e PORT=5060 \
  -e LOG_LEVEL=2 \
  -e LOG_LEVEL_FILE=10 \
  voip_patrol_local
```

### entry.sh environment variables

| Variable | Default | Description |
| -------- | ------- | ----------- |
| `XML_CONF` | _(required)_ | Scenario filename **without** `.xml` extension. Loaded from `/xml/${XML_CONF}.xml` |
| `RESULT_FILE` | `result.json` | Output filename. Written to `/output/${RESULT_FILE}` |
| `PORT` | `5060` | SIP listening port. TLS uses `PORT+1` |
| `LOG_LEVEL` | _(none)_ | Console log verbosity: `0`=errors only, `2`=info, `10`=debug |
| `LOG_LEVEL_FILE` | _(none)_ | File log verbosity (same scale) |

`VP_ENV_*` variables are also passed through to the binary and substituted into scenario XML values:

```bash
-e VP_ENV_SIP_USER=alice \
-e VP_ENV_SIP_PASS=secret \
```

## Volume mounts

| Host path | Container path | Purpose |
| --------- | -------------- | ------- |
| `./xml` | `/xml` | XML scenario files (read-only) |
| `./output` | `/output` | JSON result + voip_patrol log (write) |
| `./voice_ref_files` | `/voice_ref_files` | WAV files for playback (read-only) |

The output directory must be writable by the process inside the container. On Linux with rootless Podman, add `:z` for SELinux labeling:

```bash
-v $(pwd)/output:/output:z
```

## Running the binary directly (bypassing entry.sh)

Use `--entrypoint` to call the binary with custom arguments, useful for quick local tests:

```bash
docker run --rm \
  --net=host \
  --entrypoint /git/voip_patrol/voip_patrol \
  -v $(pwd)/xml:/xml \
  -v $(pwd)/output:/output \
  voip_patrol_local \
  --conf /xml/my_scenario.xml \
  --output /output/result.json \
  --log-level-console 2
```

### Binary CLI flags

| Flag | Description |
| ---- | ----------- |
| `-c` / `--conf` | Path to XML scenario file |
| `-o` / `--output` | Path to JSON output file |
| `-l` / `--log` | Path to voip_patrol log file (separate from pjsua log) |
| `-p` / `--port` | SIP port (default 5070 in binary; entry.sh default is 5060) |
| `--log-level-console` | Console log level 0–10 |
| `--log-level-file` | File log level 0–10 |
| `--ip-addr` | Public SIP/RTP IP to advertise |
| `--bound-addr` | IP interface to bind transports to |
| `--rtp-port` | Starting port of RTP range (default 4000) |
| `--rtp-port-end` | End of RTP port range (default 14000) |
| `--tls-calist` | TLS CA list file (PEM) |
| `--tls-cert` | TLS certificate file (PEM) |
| `--tls-privkey` | TLS private key file (PEM) |
| `--tls-verify-server` | Verify server TLS certificate |
| `--tls-verify-client` | Verify client TLS certificate |
| `--tcp` | Use TCP only (no UDP) |
| `--udp` | Use UDP only (no TCP) |
| `--graceful-shutdown` | Wait a few seconds before shutting down |

## Output files

After a run, the output directory contains:

| File | Description |
| ---- | ----------- |
| `result.json` (or `RESULT_FILE`) | JSON Lines — one object per test + scenario summary |
| `result.json.pjsua` | Low-level PJSIP logs (useful for SIP trace debugging) |

### Reading result.json

Each line is a standalone JSON object. The last line is always the scenario summary:

```json
{"scenario": {"state":"end", "result":"PASS", "name":"my_scenario.xml", "time":"...", "total tasks":"2", "completed tasks":"2"}}
```

Intermediate lines are per-test results:

```json
{"1/2": {"label": "call to bob", "result": "PASS", "result_text": "Main test passed", "cause_code": 200, "expected_cause_code": 200, ...}}
{"2/2": {"label": "call to charlie", "result": "FAIL", "result_text": "No info", "cause_code": 486, "expected_cause_code": 200, ...}}
```

The `result_text` field explains why a test failed. `cause_code` is the actual SIP response code; `expected_cause_code` is what was configured.

## Exit code handling

The `docker run` exit code is the voip_patrol exit code. Check it with `$?` immediately after the run:

```bash
docker run ... voip_patrol_local
EXIT=$?
if [ $EXIT -ne 0 ]; then
  echo "Tests failed with exit code $EXIT"
  cat output/result.json
  exit $EXIT
fi
```

| Code | Meaning |
| ---- | ------- |
| `0` | All tests passed |
| `1` | Fatal error (transport/PJSIP) |
| `2` | ≥1 test FAILED |
| `3` | Task count mismatch |

## Networking

`--net=host` is needed when voip_patrol talks to a real SIP server on the local network or when the container acts as a SIP server. Without it:

- The container's SIP port is unreachable from outside
- NAT in the container breaks RTP media negotiation
- SIP registrations may succeed but calls fail silently

In GitHub Actions and GitLab CI, `--net=host` works on Linux runners. For macOS runners or Docker Desktop, network bridging is needed instead — see platform-specific CI files.

## TLS setup

```bash
docker run --rm \
  --net=host \
  -v $(pwd)/xml:/xml \
  -v $(pwd)/output:/output \
  -v $(pwd)/tls:/tls \
  -e XML_CONF=tls_scenario \
  -e PORT=5060 \
  -e VP_ENV_SIP_PASS=secret \
  voip_patrol_local \
  # entry.sh does not pass TLS flags; use --entrypoint for TLS
```

TLS flags are not exposed through `entry.sh`. For TLS scenarios, run the binary directly with `--entrypoint`:

```bash
docker run --rm \
  --net=host \
  --entrypoint /git/voip_patrol/voip_patrol \
  -v $(pwd)/xml:/xml \
  -v $(pwd)/output:/output \
  -v $(pwd)/tls:/tls \
  voip_patrol_local \
  --conf /xml/tls_scenario.xml \
  --output /output/result.json \
  --tls-calist /tls/ca_list.pem \
  --tls-cert /tls/certificate.pem \
  --tls-privkey /tls/key.pem \
  --tls-verify-server \
  --port 5060 \
  --log-level-console 2
```
