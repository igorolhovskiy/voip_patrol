# GitLab CI/CD Integration

## Prerequisites

- A GitLab runner with Docker available (shell executor + Docker, or Docker-in-Docker).
- SIP credentials stored as CI/CD variables (masked), not in XML files.
- Linux runner — `--net=host` is required for real SIP traffic.

## Execution modes

### Shell executor (recommended for SIP testing)

The runner executes commands directly on the host OS, which has Docker installed. `--net=host` works transparently.

```yaml
voip_test:
  stage: test
  tags:
    - shell-docker   # runner tag for a shell executor with Docker
  script:
    - mkdir -p output
    - ./build_image.sh
    - |
      docker run --rm \
        --net=host \
        -v "$CI_PROJECT_DIR/xml:/xml" \
        -v "$CI_PROJECT_DIR/output:/output" \
        -v "$CI_PROJECT_DIR/voice_ref_files:/voice_ref_files" \
        -e XML_CONF=my_scenario \
        -e RESULT_FILE=result.json \
        -e PORT=5060 \
        -e LOG_LEVEL=2 \
        -e LOG_LEVEL_FILE=10 \
        -e "VP_ENV_SIP_USER=$VP_ENV_SIP_USER" \
        -e "VP_ENV_SIP_PASS=$VP_ENV_SIP_PASS" \
        voip_patrol_local
  artifacts:
    when: always
    paths:
      - output/
    expire_in: 7 days
```

### Docker-in-Docker executor

Use when only Docker-based runners are available. `--net=host` maps to the DinD daemon's network, not the real host — SIP to external servers still works, but the container is not reachable from outside.

```yaml
voip_test:
  stage: test
  image: docker:latest
  services:
    - docker:dind
  variables:
    DOCKER_HOST: tcp://docker:2376
    DOCKER_TLS_CERTDIR: "/certs"
  script:
    - mkdir -p output
    - ./build_image.sh
    - |
      docker run --rm \
        --net=host \
        -v "$CI_PROJECT_DIR/xml:/xml" \
        -v "$CI_PROJECT_DIR/output:/output" \
        -v "$CI_PROJECT_DIR/voice_ref_files:/voice_ref_files" \
        -e XML_CONF=my_scenario \
        -e RESULT_FILE=result.json \
        -e "VP_ENV_SIP_USER=$VP_ENV_SIP_USER" \
        -e "VP_ENV_SIP_PASS=$VP_ENV_SIP_PASS" \
        voip_patrol_local
  artifacts:
    when: always
    paths:
      - output/
    expire_in: 7 days
```

## Complete pipeline example

```yaml
stages:
  - build
  - test

variables:
  IMAGE_TAG: voip_patrol_local

build_image:
  stage: build
  tags:
    - shell-docker
  script:
    - ./build_image.sh
  # Cache the built image across pipeline runs by saving/loading a tarball.
  # Omit this block if builds are fast enough to skip caching.
  cache:
    key: voip-patrol-image-$CI_COMMIT_REF_SLUG
    paths:
      - .docker-cache/

voip_outbound:
  stage: test
  tags:
    - shell-docker
  needs: [build_image]
  script:
    - mkdir -p output
    - |
      docker run --rm \
        --net=host \
        -v "$CI_PROJECT_DIR/xml:/xml" \
        -v "$CI_PROJECT_DIR/output:/output" \
        -v "$CI_PROJECT_DIR/voice_ref_files:/voice_ref_files" \
        -e XML_CONF=outbound_calls \
        -e RESULT_FILE=outbound.json \
        -e PORT=5060 \
        -e LOG_LEVEL=2 \
        -e "VP_ENV_SIP_USER=$VP_ENV_SIP_USER" \
        -e "VP_ENV_SIP_PASS=$VP_ENV_SIP_PASS" \
        voip_patrol_local
  artifacts:
    when: always
    paths:
      - output/outbound.json
    expire_in: 30 days

voip_registration:
  stage: test
  tags:
    - shell-docker
  needs: [build_image]
  script:
    - mkdir -p output
    - |
      docker run --rm \
        --net=host \
        -v "$CI_PROJECT_DIR/xml:/xml" \
        -v "$CI_PROJECT_DIR/output:/output" \
        -e XML_CONF=registration \
        -e RESULT_FILE=registration.json \
        -e PORT=5060 \
        -e LOG_LEVEL=2 \
        -e "VP_ENV_SIP_USER=$VP_ENV_SIP_USER" \
        -e "VP_ENV_SIP_PASS=$VP_ENV_SIP_PASS" \
        voip_patrol_local
  artifacts:
    when: always
    paths:
      - output/registration.json
    expire_in: 30 days
```

The two test jobs run in parallel (both in the `test` stage) and both upload artifacts regardless of outcome (`when: always`).

## Handling exit codes

GitLab CI fails a job when a script command returns a non-zero exit code. `docker run` propagates the voip_patrol exit code automatically.

To add context to the failure message:

```yaml
  script:
    - mkdir -p output
    - |
      docker run --rm --net=host \
        -v "$CI_PROJECT_DIR/xml:/xml" \
        -v "$CI_PROJECT_DIR/output:/output" \
        -e XML_CONF=my_scenario \
        -e RESULT_FILE=result.json \
        -e "VP_ENV_SIP_USER=$VP_ENV_SIP_USER" \
        -e "VP_ENV_SIP_PASS=$VP_ENV_SIP_PASS" \
        voip_patrol_local
      EXIT=$?
      case $EXIT in
        0) echo "All VoIP tests passed" ;;
        2) echo "VoIP tests FAILED — check output/result.json" ; exit 2 ;;
        3) echo "Task mismatch — an expected test did not run" ; exit 3 ;;
        *) echo "Fatal voip_patrol error (exit $EXIT)" ; exit $EXIT ;;
      esac
```

## CI/CD variables

Set these in GitLab → Settings → CI/CD → Variables. Mark them **Masked** to prevent log exposure.

| Variable | Description |
| -------- | ----------- |
| `VP_ENV_SIP_USER` | SIP authentication username |
| `VP_ENV_SIP_PASS` | SIP authentication password |

Variables prefixed with `VP_ENV_` are substituted into scenario XML values at runtime (see `scenarios.md`).

## Running only on specific branches

```yaml
voip_test:
  stage: test
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
    - if: $CI_MERGE_REQUEST_ID
  ...
```

Or limit to manual trigger for integration tests that hit a real SIP server:

```yaml
voip_test:
  stage: test
  when: manual
  allow_failure: false
  ...
```

## Artifacts and result inspection

GitLab stores artifacts per job. To inspect a failed run:

1. Open the pipeline → failed job
2. Click **Browse** on the artifacts panel
3. Download `output/result.json`
4. Each JSON line is one test; look for `"result": "FAIL"` and read `"result_text"` and `"cause_code"` vs `"expected_cause_code"`

The `.pjsua` log file (e.g. `result.json.pjsua`) contains the raw SIP message trace. Include it in artifacts for deeper debugging:

```yaml
  artifacts:
    when: always
    paths:
      - output/
    expire_in: 7 days
```

`output/` includes both `result.json` and `result.json.pjsua`.
