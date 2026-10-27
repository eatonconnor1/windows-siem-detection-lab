# INC-001: Repeated Failed Logons Against a Single Account

**Status:** Closed. Controlled lab test, no real compromise.
**Scenario:** 1 of 3
**Detections involved:** built-in rule 60122, built-in rule 60204, custom rule 100100
**Time zone:** Times are local lab time (EDT, UTC-4) unless marked UTC.

## 1. Summary

I generated failed Windows logons against a nonexistent account (`labtest_fake`) on a lab endpoint and observed how Wazuh alerted on them. Every failure produced a level-5 alert from built-in rule 60122. The built-in multiple-failure rule (60204, level 10) fired for a 10-failure burst but not for a 6-failure burst, so a smaller burst produced only level-5 alerts. I wrote custom rule 100100, which fired on a 6-failure burst and did not fire on a 3-failure negative test.

## 2. Environment and scope

- **Endpoint:** physical Windows 10 Education laptop (hostname sanitized as `LAB-ENDPOINT`), monitored with Wazuh agent 4.14.9. The endpoint was a physical machine, not a VM, because the host has 8 GB of RAM.
- **Wazuh server:** Wazuh 4.14.9 OVA in VirtualBox on the same laptop, reachable over a host-only network.
- **Event source:** Windows Security log, event ID 4625 (failed logon).
- **Activity generated:** `net use \\localhost\IPC$ /user:labtest_fake WrongPass123`, repeated in loops. The account does not exist and the password is a dummy value. No external target was involved.

## 3. Timeline

| Local time | UTC | What happened |
|---|---|---|
| 18:15:19 | 22:15:19 | Test A start: 6 failed logons begin |
| 18:15:30 to 18:15:34 | 22:15:30 to 22:15:34 | 6 alerts from rule 60122 (level 5). No correlation alert. |
| 18:15:43 | 22:15:43 | Test A end |
| 18:41:35 | 22:41:35 | Test B start: 10 failed logons |
| 18:41:45 to 18:41:49 | 22:41:45 to 22:41:49 | 9 alerts from rule 60122 plus 1 alert from rule 60204 (level 10) at about 18:41:49 |
| 18:41:58 | 22:41:58 | Test B end |
| about 18:52 | 22:52 | Manager restarted with custom rule 100100 |
| about 18:55 | about 22:55 | Test C: 6 failed logons (the Windows Security log shows 6 events of ID 4625 between 18:55:00 and 18:56:00) |
| 18:55:12 to 18:55:16 | 22:55:12 to 22:55:16 | 5 alerts from rule 60122 plus 1 alert from custom rule 100100 (level 10) at 18:55:16 |
| 18:58:11 | 22:58:11 | Test D (negative test) start: 3 failed logons |
| 18:58:17 to 18:58:21 | 22:58:17 to 22:58:21 | 3 alerts from rule 60122. Rule 100100 did not fire. |

Alert times come from the Wazuh server clock and event times from the endpoint clock. In the one 4625 event I inspected they differed by under a second, so the timeline uses alert times only where the event time wasn't inspected.

## 4. Evidence

- Windows Security log counts of event 4625 for the three bursts, checked directly with PowerShell: 10 (18:41), 6 (18:55), 3 (18:58). These match the number of failures I ran.
- Event fields from one 4625 event: target account `labtest_fake`, logon type 3 (network), status `0xc000006d`, substatus `0xc0000064` (the user name does not exist), source address `::1` (IPv6 loopback), event time 22:15:34 UTC.
- Screenshots in `evidence/`: `06a-scenario1-test-run.png`, `06b-scenario1-wazuh-alerts.png`, `07-scenario1-rule60204-fired.png`, `08-scenario-10-failures-60122.png`, `09-scenario-10-failure-test-run.png`, `10-scenario1-custom-rule-100100-fired.png`, `11-scenario-negative-test-60122.png`.
- Sanitized sample alerts in `tests/samples/`: `alert-60122.json`, `alert-60204.json`, `alert-100100.json`.
- Custom rule: `rules/custom-rules.xml`.

## 5. Analysis

**Confirmed:**
- Each failed logon produced a Windows 4625 event and a Wazuh alert.
- Built-in rule 60204 did not alert on 6 failures in about 24 seconds and did alert on 10 failures in about 23 seconds. Its definition requires 8 matching failures (variable `MS_FREQ`) within 240 seconds from the same source address.
- Custom rule 100100 alerted on a burst of 6 failures against one account and stayed quiet on 3.

**Observed pattern, not proven:** in each burst that triggered a correlation rule, the count of level-5 alerts was one less than the number of failures (9 of 10, and 5 of 6). I believe the triggering event is reported as the correlation alert instead of a separate level-5 alert, but I did not verify this in Wazuh's internals.

**Interpretation:** the substatus value means the account name does not exist, which looks more like guessing usernames than guessing a password. All failures came from the loopback address, so source-based analysis was not meaningful in this lab. A burst like this would be consistent with a brute-force attempt, but the evidence here only shows repeated failures, not intent.

**Benign explanations in a real environment:** a user or service with a stale saved password, a mapped drive with old credentials, or a misconfigured scheduled task. The Windows log also held two other 4625 events from earlier on Oct 22 (12:43 AM and 3:57 AM) that were not part of these tests and that I did not investigate.

## 6. Detection evaluation

| Test | Failures generated | Rule 60122 alerts | Correlation alert | Result |
|---|---|---|---|---|
| A | 6 | 6 | none seen | Built-in rule 60204 did not fire |
| B | 10 | 9 | 60204 (built-in) x1 | Pass |
| C | 6 | 5 | 100100 (custom) x1 | Pass |
| D (negative) | 3 | 3 | none from 100100 | Pass |

- **Gap found:** the built-in rule needs 8 failures within 240 seconds, so a smaller or slower burst gets only level-5 alerts. Custom rule 100100 (5 failures within 120 seconds, grouped by account name) closed this gap for the burst I tested.
- **Not recorded:** whether 60204 also fired during Test C.
- **Not tested:** the minimum count that triggers 100100 (it fired at 6 and not at 3), a slow burst spread over more than 120 seconds, and failures against several different accounts.
- **False positives:** none observed in four controlled runs. That is not evidence about real-world noise.

## 7. ATT&CK mapping

**T1110 (Brute Force)**, which is the mapping Wazuh gives rule 60204 and the one I used for rule 100100. The observed behavior (repeated failed authentication against an account) fits the technique's description, but a loopback test against a nonexistent account does not prove an attack, so I treat the mapping as a hypothesis for an analyst to investigate.

## 8. Recommended response

In a real environment an analyst would:
1. Identify the source address and check whether it is internal, external, or a known system.
2. Check whether the targeted account exists and whether any successful logons (event 4624) followed the failures.
3. Check for account lockouts and for failures against other accounts from the same source.
4. Confirm with the account or system owner whether the activity was expected.
5. Block the source or reset credentials if the activity is unauthorized.

In this lab no action was needed, because the account is fictional and the source was the lab machine itself.

## 9. Lessons and limitations

- Built-in correlation thresholds can leave short bursts at low severity. A lower threshold is more sensitive but needs tuning for service accounts and users who mistype passwords.
- All testing used one nonexistent account, one source address (`::1`), and four short runs. This does not establish detection accuracy against real attacks.
- Additional telemetry that would raise confidence: source IP and workstation names from real network logons, successful logons (4624) for correlation, and account lockout events (4740).
