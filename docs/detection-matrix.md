# Detection Matrix

Every detection tested in this lab, with the data source it needs, the test used, and what actually happened. "Built-in" rules ship with Wazuh 4.14.9. "Custom" rules are mine and live in `rules/custom-rules.xml`.

Result key: **Pass** = behaved as intended in my tests. **Needs refinement** = fired, but with a documented problem. Three or four controlled runs per scenario do not establish accuracy against real attacks.

## Summary

| Use case | Rule | Type | Level | ATT&CK | Result |
|---|---|---|---|---|---|
| Failed logon (single event) | 60122 | Built-in | 5 | none shown in my alerts | Pass |
| Repeated failed logons | 60204 | Built-in | 10 | T1110 (Wazuh's mapping) | Needs refinement: no alert at 6 failures, alert at 10 |
| Repeated failed logons | 100100 | Custom | 10 | T1110 | Pass: fired at 6 failures, not at 3 |
| PowerShell started by PowerShell | 92027 | Built-in | 4 | T1059.001 | Needs refinement: low severity, ignores the command line |
| PowerShell with execution policy bypass | 100101 | Custom | 10 | T1059.001 | Pass: fired with the flag, not without |
| Account created or enabled | 60109 | Built-in | 8 | T1098 (Wazuh's mapping) | Needs refinement: duplicate alerts, mapping mismatch |
| Account created | 100102 | Custom | 8 | T1136.001 | Pass: one alert per creation |

## Scenario 1: Repeated failed logons

- **Purpose:** detect bursts of failed authentication against one account.
- **Data source and configuration:** Windows Security log, event ID 4625. Wazuh collects the Security channel by default, and failure auditing was already producing 4625 events.
- **Test procedure:** `net use \\localhost\IPC$ /user:labtest_fake WrongPass123` repeated in a loop against a nonexistent account. Expected: one alert per failure, and a higher-level alert when a burst crosses the correlation threshold.

| Run | Failures | 60122 alerts | Correlation alert | Result |
|---|---|---|---|---|
| A | 6 | 6 | none seen | built-in 60204 did not fire |
| B | 10 | 9 | 60204 x1 | pass |
| C | 6 | 5 | 100100 x1 | pass (custom rule deployed) |
| D (negative) | 3 | 3 | none from 100100 | pass |

- **Severity rationale:** 100100 is level 10 to match the built-in correlation rule. I chose the level, and it has not been tuned against realistic traffic.
- **Rule details:** 60204 needs 8 failures within 240 seconds from the same source address. 100100 needs 5 matching 60122 alerts within 120 seconds for the same account name. I did not test the exact minimum count for 100100.
- **Known false positives:** none observed in the lab. Stale credentials, mapped drives, and service accounts would trigger it in real environments.
- **Gaps:** a slow burst longer than 120 seconds, failures spread across several accounts, and source-IP analysis (every failure came from `::1`).
- **Report:** [incident-001](../incidents/incident-001.md)

## Scenario 2: PowerShell with execution policy bypass

- **Purpose:** flag PowerShell launched with a flag that skips the execution policy.
- **Data source and configuration:** Sysmon Event ID 1 (process creation), SwiftOnSecurity configuration, collected through the `Microsoft-Windows-Sysmon/Operational` channel (see README setup).
- **Test procedure:** from an administrator PowerShell window, `powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Write-Output '<marker>'"` for the positive test, and the same command without `-ExecutionPolicy Bypass` for the negative test. The command only prints text.

| Run | Bypass flag | 92027 (built-in, level 4) | 100101 (custom, level 10) |
|---|---|---|---|
| Baseline | yes | fired | not yet deployed |
| Positive | yes | no separate alert seen | fired |
| Negative | no | fired | did not fire |

- **Severity rationale:** level 10 so it stands above the built-in level 4 alert. I chose it, and it has not been tuned.
- **Known false positives:** administrators, installers, and deployment tools often use `-ExecutionPolicy Bypass` legitimately. A production rule would need exclusions.
- **Gaps:** `pwsh.exe`, `Set-ExecutionPolicy`, encoded commands, renamed copies of `powershell.exe`, and flag spellings I did not test. The built-in rule also requires a PowerShell parent process, from its definition.
- **Report:** [incident-002](../incidents/incident-002.md)

## Scenario 3: Local account creation

- **Purpose:** alert on creation of a new local user account.
- **Data source and configuration:** Windows Security log, event IDs 4720 (created) and 4722 (enabled). Account-management auditing enabled with `auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable`.
- **Test procedure:** `net user labtest_user3 * /add` (password prompted, not on the command line), then `/delete`. Test 2 added `/active:no` and `/active:yes` between creation and deletion.

| Run | Actions | Alerts |
|---|---|---|
| Baseline | create, delete | 60109 x2 (one for 4720, one for 4722) |
| Test 2 | create, disable, enable, delete | 100102 x1; 60109 x2 (both 4722) |

- **Severity rationale:** level 8, the same as the built-in rule. The custom rule improves precision and the ATT&CK mapping, not priority.
- **Known false positives:** none observed. Onboarding and software installs create accounts legitimately.
- **Gaps:** no alert from 60109 on the disable event, and I did not check other rules for disable or delete events (4725, 4726). Not tested: group-membership changes (4732), other account-creation tools, and domain accounts.
- **Report:** [incident-003](../incidents/incident-003.md)

## Noise register (documented, not tuned)

These built-in alerts appeared while testing. I recorded them and did not suppress them.

| Rule | Level | What I observed | Confidence |
|---|---|---|---|
| 92213 "Executable file dropped in folder commonly used by malware" | 15 | Fired when PowerShell started and wrote a throwaway `__PSScriptPolicyTest_*.ps1` file to the Temp folder. Also fired on Disk Cleanup unpacking a DLL. | Confirmed for the PowerShell pattern: opening a new window produced a new alert |
| 92205 "Powershell process created an executable file in Windows root folder" | 9 | SYSTEM-level PowerShell wrote the same kind of test file shortly after the agent started. | Believed to be the agent's startup activity; not confirmed |
| 61634 "Sysmon - Suspicious Process - taskhost.exe" | 12 | Fired on `backgroundTaskHost.exe` from the Phone Link app. The rule matches the text `taskhost.exe` inside the path. | One event inspected |
| 204 "Agent event queue is flooded" | 12 | Appeared with a large batch of alerts after the Wazuh VM had been powered off for about a day. | Believed to be a delivery backlog; not confirmed |
