# Jenkins Integration

## Prerequisites

- Jenkins agent with Docker installed and the Jenkins process in the `docker` group.
- Linux agent — `--net=host` is required for real SIP traffic.
- SIP credentials stored as Jenkins Credentials (Secret Text or Username+Password), not in Jenkinsfiles or XML files.
- The `voip_patrol_local` Docker image must be built on the agent or pre-loaded.

## Declarative pipeline — single scenario

```groovy
pipeline {
    agent { label 'linux-docker' }

    environment {
        SIP_USER = credentials('sip-username')   // Jenkins credential ID
        SIP_PASS = credentials('sip-password')
    }

    stages {
        stage('Build image') {
            steps {
                sh './build_image.sh'
            }
        }

        stage('VoIP test') {
            steps {
                sh 'mkdir -p output'
                sh '''
                    docker run --rm \
                      --net=host \
                      -v "${WORKSPACE}/xml:/xml" \
                      -v "${WORKSPACE}/output:/output" \
                      -v "${WORKSPACE}/voice_ref_files:/voice_ref_files" \
                      -e XML_CONF=my_scenario \
                      -e RESULT_FILE=result.json \
                      -e PORT=5060 \
                      -e LOG_LEVEL=2 \
                      -e LOG_LEVEL_FILE=10 \
                      -e "VP_ENV_SIP_USER=${SIP_USER}" \
                      -e "VP_ENV_SIP_PASS=${SIP_PASS}" \
                      voip_patrol_local
                '''
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'output/**', allowEmptyArchive: true
        }
    }
}
```

`archiveArtifacts` in the `always` block ensures results are saved even on failure.

## Declarative pipeline — multiple scenarios in parallel

```groovy
pipeline {
    agent none   // allocate agents per stage

    environment {
        SIP_USER = credentials('sip-username')
        SIP_PASS = credentials('sip-password')
    }

    stages {
        stage('Build') {
            agent { label 'linux-docker' }
            steps {
                sh './build_image.sh'
                // Stash the image as a tarball so parallel stages can load it
                sh 'docker save voip_patrol_local | gzip > voip_patrol_local.tar.gz'
                stash name: 'docker-image', includes: 'voip_patrol_local.tar.gz'
                stash name: 'xml-files', includes: 'xml/**,voice_ref_files/**'
            }
        }

        stage('Tests') {
            parallel {
                stage('Outbound calls') {
                    agent { label 'linux-docker' }
                    steps {
                        unstash 'docker-image'
                        unstash 'xml-files'
                        sh 'docker load < voip_patrol_local.tar.gz'
                        sh 'mkdir -p output'
                        sh '''
                            docker run --rm --net=host \
                              -v "${WORKSPACE}/xml:/xml" \
                              -v "${WORKSPACE}/output:/output" \
                              -v "${WORKSPACE}/voice_ref_files:/voice_ref_files" \
                              -e XML_CONF=outbound_calls \
                              -e RESULT_FILE=outbound.json \
                              -e "VP_ENV_SIP_USER=${SIP_USER}" \
                              -e "VP_ENV_SIP_PASS=${SIP_PASS}" \
                              voip_patrol_local
                        '''
                    }
                    post {
                        always { archiveArtifacts 'output/outbound.json' }
                    }
                }

                stage('Registration') {
                    agent { label 'linux-docker' }
                    steps {
                        unstash 'docker-image'
                        unstash 'xml-files'
                        sh 'docker load < voip_patrol_local.tar.gz'
                        sh 'mkdir -p output'
                        sh '''
                            docker run --rm --net=host \
                              -v "${WORKSPACE}/xml:/xml" \
                              -v "${WORKSPACE}/output:/output" \
                              -e XML_CONF=registration \
                              -e RESULT_FILE=registration.json \
                              -e "VP_ENV_SIP_USER=${SIP_USER}" \
                              -e "VP_ENV_SIP_PASS=${SIP_PASS}" \
                              voip_patrol_local
                        '''
                    }
                    post {
                        always { archiveArtifacts 'output/registration.json' }
                    }
                }
            }
        }
    }
}
```

## Handling exit codes explicitly

```groovy
stage('VoIP test') {
    steps {
        sh 'mkdir -p output'
        script {
            def exitCode = sh(
                returnStatus: true,
                script: '''
                    docker run --rm --net=host \
                      -v "${WORKSPACE}/xml:/xml" \
                      -v "${WORKSPACE}/output:/output" \
                      -e XML_CONF=my_scenario \
                      -e RESULT_FILE=result.json \
                      -e "VP_ENV_SIP_USER=${SIP_USER}" \
                      -e "VP_ENV_SIP_PASS=${SIP_PASS}" \
                      voip_patrol_local
                '''
            )
            switch (exitCode) {
                case 0:
                    echo 'All VoIP tests passed'
                    break
                case 2:
                    error('VoIP tests FAILED — check output/result.json for details')
                    break
                case 3:
                    error('Task count mismatch — an expected test did not run, or an unexpected call arrived')
                    break
                default:
                    error("Fatal voip_patrol error (exit ${exitCode})")
            }
        }
    }
}
```

`returnStatus: true` prevents `sh` from throwing on non-zero exit, letting the `switch` block provide a descriptive error message.

## Scripted pipeline equivalent

```groovy
node('linux-docker') {
    withCredentials([
        string(credentialsId: 'sip-username', variable: 'SIP_USER'),
        string(credentialsId: 'sip-password', variable: 'SIP_PASS')
    ]) {
        try {
            stage('Build') {
                sh './build_image.sh'
            }

            stage('Test') {
                sh 'mkdir -p output'
                sh """
                    docker run --rm --net=host \\
                      -v "${WORKSPACE}/xml:/xml" \\
                      -v "${WORKSPACE}/output:/output" \\
                      -v "${WORKSPACE}/voice_ref_files:/voice_ref_files" \\
                      -e XML_CONF=my_scenario \\
                      -e RESULT_FILE=result.json \\
                      -e VP_ENV_SIP_USER=\${SIP_USER} \\
                      -e VP_ENV_SIP_PASS=\${SIP_PASS} \\
                      voip_patrol_local
                """
            }
        } finally {
            archiveArtifacts artifacts: 'output/**', allowEmptyArchive: true
        }
    }
}
```

Note the `\\` line continuation and `\${VAR}` escaping inside `"""` GString blocks.

## Credentials setup

In Jenkins → Manage Jenkins → Credentials → (global) → Add Credential:

| Kind | ID | Usage |
| ---- | -- | ----- |
| Secret text | `sip-username` | SIP auth user → `VP_ENV_SIP_USER` |
| Secret text | `sip-password` | SIP auth password → `VP_ENV_SIP_PASS` |

Or use a single **Username with password** credential and bind it:

```groovy
withCredentials([usernamePassword(
    credentialsId: 'sip-credentials',
    usernameVariable: 'SIP_USER',
    passwordVariable: 'SIP_PASS'
)]) { ... }
```

## Image caching strategy

PJSIP compilation takes several minutes. Options:

**Option 1 — Stash/unstash tarball** (shown in parallel example above): build once, load on each agent. Adds ~30s tarball transfer but saves full rebuild time.

**Option 2 — Pre-build on a dedicated agent**: Run `./build_image.sh` as a cron job on each agent that will run voip_patrol. The image is already present when the pipeline runs.

**Option 3 — Push to a private registry**:

```groovy
stage('Build and push') {
    steps {
        sh './build_image.sh'
        sh 'docker tag voip_patrol_local registry.example.com/voip_patrol:latest'
        withCredentials([usernamePassword(credentialsId: 'registry-creds', ...)]) {
            sh 'docker login registry.example.com -u $USERNAME -p $PASSWORD'
            sh 'docker push registry.example.com/voip_patrol:latest'
        }
    }
}

stage('Test') {
    steps {
        sh 'docker pull registry.example.com/voip_patrol:latest'
        sh 'docker tag registry.example.com/voip_patrol:latest voip_patrol_local'
        // run as normal
    }
}
```

## Triggering on demand vs. on commit

For integration tests that hit a real SIP server, it is common to not run them on every commit:

```groovy
// Declarative: run only on main or when triggered manually
when {
    anyOf {
        branch 'main'
        triggeredBy 'UserIdCause'
    }
}
```

Or configure a separate Jenkins job/pipeline triggered by a webhook or scheduled:

```groovy
triggers {
    cron('H 2 * * 1-5')   // nightly on weekdays
}
```
