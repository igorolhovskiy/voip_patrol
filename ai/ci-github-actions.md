# GitHub Actions Integration

## Prerequisites

- The `voip_patrol_local` Docker image must be built and available on the runner, **or** the workflow must build it as a step.
- The runner must be Linux-based for `--net=host` to work.
- SIP credentials should be stored as GitHub Actions secrets, not in XML files.

## Minimal single-scenario workflow

```yaml
name: VoIP Tests

on:
  push:
    branches: [main]
  pull_request:

jobs:
  voip-test:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Build voip_patrol image
        run: ./build_image.sh

      - name: Create output directory
        run: mkdir -p output

      - name: Run VoIP scenario
        run: |
          docker run --rm \
            --net=host \
            -v ${{ github.workspace }}/xml:/xml \
            -v ${{ github.workspace }}/output:/output \
            -v ${{ github.workspace }}/voice_ref_files:/voice_ref_files \
            -e XML_CONF=my_scenario \
            -e RESULT_FILE=result.json \
            -e PORT=5060 \
            -e LOG_LEVEL=2 \
            -e LOG_LEVEL_FILE=10 \
            -e VP_ENV_SIP_USER=${{ secrets.SIP_USER }} \
            -e VP_ENV_SIP_PASS=${{ secrets.SIP_PASS }} \
            voip_patrol_local

      - name: Upload test results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: voip-patrol-results
          path: output/
```

`if: always()` on the upload step is important — it ensures results are uploaded even when the test step fails (exit code 2 or 3).

## Multiple scenarios in sequence

```yaml
      - name: Run scenario A
        run: |
          docker run --rm --net=host \
            -v ${{ github.workspace }}/xml:/xml \
            -v ${{ github.workspace }}/output:/output \
            -e XML_CONF=scenario_a \
            -e RESULT_FILE=scenario_a.json \
            -e VP_ENV_SIP_USER=${{ secrets.SIP_USER }} \
            -e VP_ENV_SIP_PASS=${{ secrets.SIP_PASS }} \
            voip_patrol_local

      - name: Run scenario B
        run: |
          docker run --rm --net=host \
            -v ${{ github.workspace }}/xml:/xml \
            -v ${{ github.workspace }}/output:/output \
            -e XML_CONF=scenario_b \
            -e RESULT_FILE=scenario_b.json \
            -e VP_ENV_SIP_USER=${{ secrets.SIP_USER }} \
            -e VP_ENV_SIP_PASS=${{ secrets.SIP_PASS }} \
            voip_patrol_local
```

Each `docker run` step fails independently. If scenario A fails with exit 2, scenario B is still skipped by default (unless you add `if: always()` to subsequent steps). Decide per-scenario whether failures should block the rest.

## Matrix strategy for parallel scenarios

```yaml
jobs:
  voip-test:
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false   # run all scenarios even if one fails
      matrix:
        scenario:
          - name: outbound_calls
            result: outbound.json
          - name: registration
            result: registration.json
          - name: inbound_tls
            result: inbound_tls.json

    steps:
      - uses: actions/checkout@v4

      - name: Build image
        run: ./build_image.sh

      - name: Create output dir
        run: mkdir -p output

      - name: Run ${{ matrix.scenario.name }}
        run: |
          docker run --rm \
            --net=host \
            -v ${{ github.workspace }}/xml:/xml \
            -v ${{ github.workspace }}/output:/output \
            -v ${{ github.workspace }}/voice_ref_files:/voice_ref_files \
            -e XML_CONF=${{ matrix.scenario.name }} \
            -e RESULT_FILE=${{ matrix.scenario.result }} \
            -e VP_ENV_SIP_USER=${{ secrets.SIP_USER }} \
            -e VP_ENV_SIP_PASS=${{ secrets.SIP_PASS }} \
            voip_patrol_local

      - name: Upload ${{ matrix.scenario.name }} results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: results-${{ matrix.scenario.name }}
          path: output/${{ matrix.scenario.result }}
```

`fail-fast: false` lets all scenarios run so you see the full picture, not just the first failure.

## Caching the Docker image build

PJSIP compilation is slow (~10 min cold). Cache the build context:

```yaml
      - name: Cache Docker layers
        uses: actions/cache@v4
        with:
          path: /tmp/.buildx-cache
          key: voip-patrol-${{ hashFiles('voip_patrol/src/**', 'Dockerfile', 'pjproject/**/*.c', 'pjproject/**/*.h') }}
          restore-keys: |
            voip-patrol-

      - name: Build image
        run: ./build_image.sh
```

Alternatively, push the built image to a container registry and pull it in CI instead of rebuilding:

```yaml
      - name: Pull voip_patrol image
        run: docker pull ghcr.io/${{ github.repository }}/voip_patrol:latest
        # Tag it so the run command matches
        run: docker tag ghcr.io/${{ github.repository }}/voip_patrol:latest voip_patrol_local
```

## Handling exit codes explicitly

If you need to differentiate exit code 2 (test failures) from exit code 3 (task mismatch) in the workflow:

```yaml
      - name: Run scenario and capture exit code
        id: voip
        continue-on-error: true
        run: |
          docker run --rm --net=host \
            -v ${{ github.workspace }}/xml:/xml \
            -v ${{ github.workspace }}/output:/output \
            -e XML_CONF=my_scenario \
            -e RESULT_FILE=result.json \
            -e VP_ENV_SIP_USER=${{ secrets.SIP_USER }} \
            -e VP_ENV_SIP_PASS=${{ secrets.SIP_PASS }} \
            voip_patrol_local
          echo "voip_exit=$?" >> $GITHUB_OUTPUT

      - name: Report result
        run: |
          EXIT=${{ steps.voip.outputs.voip_exit }}
          case $EXIT in
            0) echo "All tests passed" ;;
            2) echo "::error::Tests failed — check result.json" ; exit 2 ;;
            3) echo "::error::Task mismatch — a test did not run or unexpected call arrived" ; exit 3 ;;
            *) echo "::error::Fatal voip_patrol error (exit $EXIT)" ; exit $EXIT ;;
          esac

      - name: Upload results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: voip-results
          path: output/
```

## Secrets setup

In GitHub repository settings → Secrets and variables → Actions, add:

| Secret name | Example value | Used as |
| ----------- | ------------- | ------- |
| `SIP_USER` | `alice` | `VP_ENV_SIP_USER` |
| `SIP_PASS` | `secret123` | `VP_ENV_SIP_PASS` |

Reference in the workflow as `${{ secrets.SIP_USER }}`. These values are masked in logs.

## Network notes for GitHub Actions

GitHub-hosted Linux runners support `--net=host`. This makes the SIP port on the runner directly reachable.

If you run against a SIP server on the public internet, ensure the runner's IP is not blocked by the server's firewall. The outbound IP of GitHub-hosted runners changes per run — if the SIP server has an allowlist, use a self-hosted runner with a stable IP instead.
