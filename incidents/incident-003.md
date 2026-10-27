# INC-003: Local User Account Creation

**Status:** Closed. Controlled lab test, no real compromise.
**Scenario:** 3 of 3
**Detections involved:** built-in rule 60109 (level 8), custom rule 100102 (level 8)
**Time zone:** Times are local lab time (EDT, UTC-4) unless marked UTC.

## 1. Summary

I created a temporary local account (`labtest_user3`) on the lab endpoint and observed how Wazuh alerted on it. The built-in rule 60109 ("User account enabled or created") produced two identical-looking alerts for a single account creation, one for the creation event and one for the account-enabled event that followed it 43 milliseconds later, and it tags both with T1098 (Account Manipulation). I wrote custom rule 100102, which alerts only on the creation event and maps it to T1136.001 (Create Account: Local Account). In a second test with a create, disable, enable, and delete cycle, the custom rule fired once on the creation and the built-in rule fired on the two enable events.

## 2. Environment and scope

- **Endpoint:** physical Windows 10 Education laptop (hostname sanitized as `LAB-ENDPOINT`, user sanitized as `labuser`), Wazuh agent 4.14.9.
- **Wazuh server:** Wazuh 4.14.9 OVA in VirtualBox on the same laptop.
- **Event source:** Windows Security log, event IDs 4720 (account created) and 4722 (account enabled). I enabled success and failure auditing for the "User Account Management" subcategory with `auditpol` before the first test. I did not check what the setting was before.
- **Activity generated** from an administrator PowerShell window:
  - `net user labtest_user3 * /add`. The `*` makes Windows prompt for the password, so the password never appears in a command line.
  - Test 2 also ran `net user labtest_user3 /active:no`, `/active:yes`, and `/delete`.
- The account was deleted at the end of each test. A later `net user` listing no longer showed it.

## 3. Timeline

| Local time | UTC | What happened |
|---|---|---|
| just before 04:42:54 | | `auditpol` enabled account-management auditing |
| 04:42:54 | 08:42:54 | Baseline test begins (built-in rules only) |
| 04:44:21 | 08:44:21.494 | Windows event 4720: account created (event record 9063749) |
| 04:44:21 | 08:44:21.537 | Windows event 4722: account enabled (event record 9063750), 43 ms later |
| 04:44:21 | | Two alerts from rule 60109 (level 8), both stamped 04:44:21.211 on the server clock |
| 04:44:31 | 08:44:31 | Baseline test ends. The account was deleted afterward. |
| 04:53:34 | 08:53:34 | Wazuh manager restarted with custom rule 100102 (no errors from `wazuh-analysisd -t`) |
| 04:54:13 | 08:54:13 | Test 2 begins: create, disable, enable, delete |
| 04:54:22 | | Alert from custom rule 100102 (level 8) for the creation |
| 04:54:22 | | Alert from rule 60109 for event ID 4722, in the same second as the 100102 alert |
| 04:54:32 | | Second alert from rule 60109 for event ID 4722, about 10 seconds later |
| 04:54:41 | 08:54:41 | Test 2 ends |
| about 05:05 | | `net user` listing checked: `labtest_user3` is gone |

Wazuh alert timestamps come from the server clock. In the baseline, the alert stamp was about 0.3 seconds earlier than the Windows event time.

## 4. Evidence

- Event 4720 fields: subject account is my administrator account (sanitized), new account `labtest_user3`, old account-control value `0x0`, new value `0x15` (Account Disabled, Password Not Required, Normal Account), primary group ID 513, password last set `<never>`.
- The subject's logon ID in the 4720 event (`0x1A539E`) matches the logon ID on the Sysmon process events from the administrator PowerShell window used in Scenario 2, so both activities came from the same logon session.
- Event 4722 fields: the same subject and target account, 43 ms after the 4720.
- A direct Windows check (`Get-WinEvent` for event ID 4720) showed one new event at 4:44:21 AM, inside the baseline test window.
- Rule 60109's definition matches four event IDs: 624, 626, 4720, and 4722.
- Screenshots in `evidence/`: `14-scenario3-baseline-test-run.png`, `15-scenario3-baseline-alerts.png`, `16-scenario3-custom-test-run.png`, `17-scenario3-custom-alerts.png`, `17a-scenario3-60109-alerts-by-event-id.png`.
- Sanitized sample alerts in `tests/samples/`: `alert-60109-4720.json` (built-in rule on the creation event) and `alert-100102.json` (custom rule).
- Custom rule: `rules/custom-rules.xml`.

## 5. Analysis

**Confirmed:**
- One `net user /add` command produced two Windows events (4720 and 4722) and, with only the built-in rule, two alerts with the same description and level.
- Wazuh maps rule 60109 to T1098 (Account Manipulation), which describes changes to an existing account. Creating a new local account is T1136.001.
- The custom rule fired once per creation in Test 2, and the two 60109 alerts in Test 2 were both for event ID 4722.

**Consistent with the evidence, not separately verified:**
- The event 4720 shows the account created in a disabled state, and the 4722 event 43 ms later is consistent with Windows enabling it as part of the same command. I did not investigate why the account is created that way.
- The two 4722 alerts in Test 2 were stamped about 10 seconds apart (04:54:22 and 04:54:32). The first coincides with the creation and the second is consistent with my manual `/active:yes` later in the run, which fits the automatic enable at creation plus my manual enable. I did not count the Windows events for the second test.
- Because the creation event produced a 100102 alert and not a third 60109 alert, the custom rule appears to replace the built-in alert for that event. The screenshot 17-scenario3-custom-alerts.png shows this directly: the only 4720 alert in the second test is 100102, and both 60109 alerts at 04:54 are for 4722. This is one test.

**Authorization:** the creation was an authorized test by me. The events alone cannot show whether an account creation is legitimate. An analyst would need to compare it against a change request or the account owner's confirmation.

## 6. Detection evaluation

| Run | Actions | Alerts |
|---|---|---|
| Baseline | create, delete | rule 60109 x2 (level 8, T1098), one per event (4720 and 4722) |
| Test 2 | create, disable, enable, delete | rule 100102 x1 (level 8, T1136.001); rule 60109 x2, both for 4722 |

- **Pass:** custom rule 100102 alerted once on the creation event and carried the more accurate technique.
- **Noise found:** the built-in rule produces duplicate-looking alerts for one creation, and its ATT&CK mapping does not match account creation.
- **Gap found:** the account-disable step (`/active:no`) produced no alert from rule 60109, which does not list the disable event.
- **Not checked:** whether any other rule alerted on disable or delete events (4725 and 4726).
- **Not tested:** adding the new account to the Administrators group (event 4732), which matters more for persistence; accounts created through other tools; domain accounts. I left the severity at level 8 because the custom rule improves precision and mapping, not priority.
- **False positives:** none observed. A real environment has legitimate account creation from onboarding and software installs.

## 7. ATT&CK mapping

**T1136.001 (Create Account: Local Account)**, tactic Persistence. It fits an account being created on the local machine. Wazuh's built-in rule uses T1098 (Account Manipulation), which fits changes to existing accounts better. Because this was an authorized test, the mapping describes the behavior the rule watches for, not an attack.

## 8. Recommended response

In a real environment an analyst would:
1. Check whether the creation matches a change request or onboarding task, and confirm with the account that created it.
2. Review how that administrator session was established (logon events) and what process created the account (process events around the same time).
3. Check for follow-on activity: group membership changes, logons by the new account, and password or privilege changes.
4. Disable and then delete the account if it is unauthorized, and reset the creating account's credentials if it may be compromised.

In this lab the account was my own test account and I deleted it after each run.

## 9. Lessons and limitations

- Built-in rules that cover several event types can emit duplicate alerts for one action, which adds noise for an analyst. Narrowing a rule to one event ID reduces it.
- The built-in ATT&CK mapping should be checked against what the rule actually detects before it is reported.
- The test covered one local account on one machine in two runs. It does not show coverage for domain environments, other account-creation methods, or real attacker behavior.
- Additional telemetry that would raise confidence: group-membership changes (4732), account deletion and disable events (4725, 4726), and process creation records for the tool that made the change.
