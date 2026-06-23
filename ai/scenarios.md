# Writing VoIP Patrol Test Scenarios

Scenarios are XML files that define a sequence of SIP actions. VoIP Patrol executes them top-to-bottom, collects results, and writes a JSON Lines report.

## XML structure

```xml
<?xml version="1.0"?>
<config>
  <actions>
    <action type="ACTION_TYPE" param1="value1" param2="value2"/>
    <action type="wait" complete="true"/>
  </actions>
</config>
```

Rules:
- Every file must have `<config><actions>…</actions></config>`.
- Actions are executed in order, top to bottom.
- `call`, `accept`, `register`, `message`, `accept_message`, and `bxfer` are **task actions** — they produce a test result and count toward the pass/fail verdict.
- `wait`, `codec`, `turn`, `hold`, and `unhold` are **control actions** — they do not produce results.
- Always end a scenario with a `wait` action, otherwise the process exits before tasks finish.

## Action types

### `call` — make an outbound SIP call

Minimum required parameters: `caller`, `callee`, `expected_cause_code`.

```xml
<action type="call"
    label="call to pbx"
    transport="udp"
    expected_cause_code="200"
    caller="alice@pbx.example.com"
    callee="bob@pbx.example.com"
    auth_username="alice"
    password="secret"
    realm="pbx.example.com"
    hangup="10"
/>
```

Key parameters:

| Parameter | Type | Notes |
| --------- | ---- | ----- |
| `caller` | string | `user@host` — used in From unless `from` is set |
| `callee` | string | `user@host` — request URI |
| `expected_cause_code` | int | SIP code the call must end with (200, 486, 603, …) |
| `transport` | string | `udp`, `tcp`, `tls`, `sips`, `udp6`, `tcp6`, `tls6` |
| `auth_username` | string | Authentication user |
| `password` | string | Authentication password |
| `realm` | string | Auth realm; empty = accept any realm |
| `hangup` | int | Seconds after answer before BYE; sends CANCEL if not yet answered |
| `max_duration` | int | Fails if call exceeds this many seconds |
| `wait_until` | string | Block the scenario at this call state before next action: `CALLING`, `EARLY`, `CONNECTING`, `CONFIRMED`, `DISCONNECTED` |
| `rtp_stats` | bool | Include RTP jitter/loss/MOS in JSON output |
| `play` | string | Path to WAV to stream, or `echo` to loop received audio |
| `record` | string | Path to write recorded audio; `auto` = `/srv/<call_id>_<remote>.wav` |
| `srtp` | string | Comma-separated: `sdes`, `dtls`, `force` |
| `call_count` | int | Repeat this call N times |

### `accept` — receive an inbound call

**Critical:** use `match_account`, not `account`. Using `account=` is silently ignored and produces exit code 3 with a task count of 101.

```xml
<action type="accept"
    label="receive call from alice"
    match_account="default"
    expected_cause_code="200"
    call_count="1"
    hangup="10"
    code="200"
    reason="OK"
/>
```

`match_account` resolves to:
- `default` — catches all incoming calls
- A username registered with a `register` action — matches calls to that account
- A user part of the called URI — matches calls to a specific extension

Key parameters:

| Parameter | Type | Notes |
| --------- | ---- | ----- |
| `match_account` | string | **Required.** `default` or a registered account name |
| `call_count` | int | Number of calls to accept before completing; `-1` = unlimited (never completes) |
| `expected_cause_code` | int | Expected final SIP code (usually `200`) |
| `code` | int | SIP response code to answer with |
| `reason` | string | SIP reason phrase to answer with |
| `hangup` | int | Seconds after answer before BYE |
| `ring_duration` | int | Seconds to ring before answering |
| `fail_on_accept` | bool | If `true`, any incoming call to this account counts as a test FAILURE |
| `play` | string | Path to WAV to stream on answer |
| `record` | string | Path to record received audio |

### `register` — SIP registration

```xml
<action type="register"
    label="register alice"
    transport="udp"
    account="alice"
    username="alice"
    auth_username="alice"
    password="secret"
    registrar="pbx.example.com"
    realm="pbx.example.com"
    expected_cause_code="200"
/>
```

After a `register` action, use `match_account="alice"` in a subsequent `accept` to route calls to that registration.

### `wait` — control execution flow

```xml
<!-- Wait until ALL tasks complete (or timeout after 30s) -->
<action type="wait" complete="true" ms="30000"/>

<!-- Wait exactly 5 seconds then continue regardless -->
<action type="wait" ms="5000"/>

<!-- Wait until all tasks reach their wait_until state -->
<action type="wait"/>

<!-- Wait forever (server mode) -->
<action type="wait" ms="-1"/>
```

| Parameter | Type | Notes |
| --------- | ---- | ----- |
| `complete` | bool | Wait for all tasks to finish |
| `ms` | int | Millisecond timeout; `-1` = forever; omit to wait for `wait_until` states only |

### `codec` — configure codecs

```xml
<action type="codec" disable="all"/>
<action type="codec" enable="opus" priority="250"/>
<action type="codec" enable="pcma" priority="249"/>
```

Place codec actions before `call` or `accept` actions. Priority 0 = disabled; 1–255 = active (higher = preferred).

### `message` / `accept_message` — SIP MESSAGE

```xml
<action type="message"
    label="send message"
    transport="udp"
    expected_cause_code="202"
    text="Hello"
    from="alice@pbx.example.com"
    to_uri="bob@pbx.example.com"
    username="alice"
    password="secret"
/>

<action type="accept_message"
    account="bob"
    message_count="1"
/>
```

### `bxfer` — blind transfer (REFER)

```xml
<action type="bxfer"
    label="transfer alice to charlie"
    caller="alice@pbx.example.com"
    to_uri="charlie@pbx.example.com"
    expected_cause_code="200"
/>
```

`caller` must match an account with an active call. Issue this after `wait_until="CONFIRMED"` on the call you want to transfer.

### `hold` / `unhold`

```xml
<action type="hold" caller="alice@pbx.example.com"/>
<action type="wait" ms="5000"/>
<action type="unhold" caller="alice@pbx.example.com"/>
```

### `turn` — STUN/TURN/ICE configuration

```xml
<action type="turn"
    enabled="true"
    server="turn.example.com:3478"
    username="user"
    password="pass"
/>
```

## Common scenario patterns

### Pattern: single outbound call

```xml
<config>
  <actions>
    <action type="call"
        label="call to voicemail"
        transport="udp"
        expected_cause_code="200"
        caller="test@pbx.example.com"
        callee="voicemail@pbx.example.com"
        auth_username="VP_ENV_USERNAME"
        password="VP_ENV_PASSWORD"
        realm="pbx.example.com"
        hangup="10"
        rtp_stats="true"
    />
    <action type="wait" complete="true" ms="30000"/>
  </actions>
</config>
```

### Pattern: register then accept one call

Use when you need to verify that a registered extension can receive calls.

```xml
<config>
  <actions>
    <action type="register"
        label="register alice"
        transport="udp"
        account="alice"
        username="alice"
        auth_username="alice"
        password="VP_ENV_PASSWORD"
        registrar="pbx.example.com"
        realm="pbx.example.com"
        expected_cause_code="200"
    />
    <action type="wait" complete="true" ms="5000"/>

    <action type="accept"
        label="receive inbound call"
        match_account="alice"
        expected_cause_code="200"
        call_count="1"
        hangup="15"
        code="200"
        reason="OK"
    />

    <!-- This call triggers the accept -->
    <action type="call"
        label="call alice"
        transport="udp"
        expected_cause_code="200"
        caller="caller@pbx.example.com"
        callee="alice@pbx.example.com"
        auth_username="caller"
        password="VP_ENV_CALLER_PASSWORD"
        realm="pbx.example.com"
        hangup="10"
    />

    <action type="wait" complete="true" ms="30000"/>
  </actions>
</config>
```

### Pattern: call that should NOT be answered (fail_on_accept)

Use when you want to assert that certain calls are blocked or not reaching a destination.

```xml
<config>
  <actions>
    <!-- If this account receives any call, the test fails -->
    <action type="accept"
        label="should never ring"
        match_account="default"
        fail_on_accept="true"
    />

    <action type="call"
        label="call that should be blocked"
        transport="udp"
        expected_cause_code="403"
        caller="blocked@pbx.example.com"
        callee="target@pbx.example.com"
        auth_username="blocked"
        password="secret"
        realm="pbx.example.com"
        hangup="5"
    />

    <action type="wait" complete="true" ms="15000"/>
  </actions>
</config>
```

`fail_on_accept="true"` decrements the task counter, so the accept itself does not count as a task to complete. Only the call counts. If the call ends with 403 as expected, exit code is 0. If the call somehow reaches the accept account, the test fails and exits 2.

### Pattern: sequential calls with wait_until

Use when you need call 2 to start only after call 1 is confirmed (prevents flooding).

```xml
<config>
  <actions>
    <action type="call"
        label="call 1"
        transport="udp"
        wait_until="CONFIRMED"
        expected_cause_code="200"
        caller="alice@pbx.example.com"
        callee="bob@pbx.example.com"
        hangup="10"
    />
    <!-- Block here until call 1 reaches CONFIRMED state -->
    <action type="wait"/>

    <action type="call"
        label="call 2"
        transport="udp"
        expected_cause_code="200"
        caller="charlie@pbx.example.com"
        callee="dave@pbx.example.com"
        hangup="10"
    />
    <action type="wait" complete="true" ms="30000"/>
  </actions>
</config>
```

### Pattern: header validation

```xml
<config>
  <actions>
    <action type="accept"
        match_account="default"
        expected_cause_code="200"
        call_count="1"
        hangup="5"
        code="200"
    >
        <!-- Header must exist -->
        <check-header name="X-Tenant-ID"/>
        <!-- Header must have exact value -->
        <check-header name="X-Tenant-ID" value="acme"/>
        <!-- Header must match regex -->
        <check-header name="From" regex="^.*sip:\+1\d{10}@.*$"/>
        <!-- Header must NOT match regex -->
        <check-header name="To" regex="premium" fail_on_match="true"/>
        <!-- Check RURI (not a real header, but supported) -->
        <check-header name="RURI" regex="^INVITE sip:\d{4}@.*"/>
    </action>
    <action type="wait" complete="true" ms="20000"/>
  </actions>
</config>
```

### Pattern: SDP body validation

```xml
<action type="accept"
    match_account="default"
    expected_cause_code="200"
    call_count="1"
    hangup="5"
    code="200"
>
    <!-- INVITE SDP must contain opus -->
    <check-message method="INVITE" regex="m=audio.*RTP/AVP.*opus.*"/>
    <!-- INVITE SDP must NOT contain pcmu -->
    <check-message method="INVITE" regex="pcmu" fail_on_match="true"/>
</action>
```

### Pattern: blind transfer test

```xml
<config>
  <actions>
    <!-- Call to transfer -->
    <action type="call"
        label="initial call"
        transport="udp"
        wait_until="CONFIRMED"
        expected_cause_code="200"
        caller="alice@pbx.example.com"
        callee="bob@pbx.example.com"
        auth_username="alice"
        password="secret"
        realm="pbx.example.com"
        hangup="30"
    />
    <action type="wait"/>  <!-- wait until CONFIRMED -->

    <action type="bxfer"
        label="transfer to charlie"
        caller="alice@pbx.example.com"
        to_uri="charlie@pbx.example.com"
        expected_cause_code="200"
    />

    <action type="wait" complete="true" ms="30000"/>
  </actions>
</config>
```

## Environment variable substitution

Any parameter value starting with `VP_ENV_` is replaced by the environment variable of the same name at runtime.

```xml
<action type="call"
    auth_username="VP_ENV_SIP_USER"
    password="VP_ENV_SIP_PASS"
    ...
/>
```

Set before running:
```bash
export VP_ENV_SIP_USER=alice
export VP_ENV_SIP_PASS=secret123
```

This allows the same XML file to be used across environments without modification.

## Understanding exit codes

### Exit code 2 — test FAIL

Returned when all tasks ran but at least one produced a `"result": "FAIL"` in the JSON output. Common causes:

- `expected_cause_code` doesn't match the actual SIP response code
- A `check-header` assertion failed
- `expected_duration` or `expected_codec` didn't match
- `fail_on_accept` triggered (unexpected call arrived)
- MOS below `min_mos`

To diagnose: inspect `result.json`. Each task line has `"result"` and `"result_text"` fields explaining the failure.

### Exit code 3 — task count mismatch

Returned when `total_tasks_count != json_result_count` — i.e., expected N task results but only M completed.

Common causes:

| Cause | Symptom in result.json |
| ----- | ---------------------- |
| `accept` configured but no call arrived | `total tasks: 1, completed tasks: 0` |
| `accept fail_on_accept="true"` received a call | `total tasks: 0, completed tasks: 1` (json_result > total) |
| `accept` using `account=` instead of `match_account=` | `total tasks: 101, completed tasks: 0` |
| `call` action timed out before `wait` expired | depends on timing |

The `total tasks: 101` pattern specifically means you wrote `account="..."` instead of `match_account="..."` in an `accept` action — fix that parameter name.

## Common mistakes

| Mistake | Effect | Fix |
| ------- | ------ | --- |
| `account="default"` in `accept` | Exit 3, total tasks: 101 | Use `match_account="default"` |
| Missing `<action type="wait" complete="true"/>` | Process exits before tasks finish, results incomplete | Add wait at end |
| `ms="complete"` instead of `complete="true"` | `ms` is parsed as 0 (integer); wait exits immediately | Use `complete="true"` as a separate attribute |
| `call_count="-1"` on `accept` with `wait complete="true"` | Wait never completes (unlimited accept never finishes) | Use a specific `call_count` or `wait ms="X"` timeout |
| No `hangup` on `call` with `expected_cause_code="200"` | Call stays up until max transaction timer | Add `hangup="N"` |
| Wrong `realm` | Auth fails, 403/407 instead of 200 | Use empty `realm=""` to accept any, or set correct value |
