# INC-002: PowerShell Launched with Execution Policy Bypass

**Status:** Closed. Controlled lab test, no real compromise.
**Scenario:** 2 of 3
**Detections involved:** built-in rule 92027 (level 4), custom rule 100101 (level 10)
**Time zone:** Times are local lab time (EDT, UTC-4) unless marked UTC.

## 1. Summary

I ran a harmless PowerShell command that only prints a text marker, once with the `-ExecutionPolicy Bypass` flag and once without. The built-in rule 92027 alerted at level 4 because a PowerShell process had started a PowerShell process, and it never examines the command line, so it cannot tell a Bypass launch from any other. I wrote custom rule 100101 (level 10), which matches the Bypass flag in the Sysmon process-creation event. It fired on the Bypass run and did not fire on the run without the flag.

## 2. Environment and scope

- **Endpoint:** physical Windows 10 Education laptop (hostname sanitized as `LAB-ENDPOINT`, user sanitized as `labuser`), Wazuh agent 4.14.9, running Windows PowerShell (`powershell.exe`).
- **Wazuh server:** Wazuh 4.14.9 OVA in VirtualBox on the same laptop.
- **Event source:** Sysmon Event ID 1 (process creation) from the `Microsoft-Windows-Sysmon/Operational` channel, using the SwiftOnSecurity Sysmon configuration.
- **Activity generated** from an administrator PowerShell window. The command only prints text:
  - Baseline: `powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Write-Output 'LAB-S2-TEST'"`
  - Positive test: the same command with the marker `LAB-S2-TEST-2`
  - Negative test: `powershell.exe -NoProfile -Command "Write-Output 'LAB-S2-NEG'"` (no Bypass flag)

## 3. Timeline

| Local time | UTC | What happened |
|---|---|---|
| 04:18:54 | 08:18:54 | Baseline run begins (built-in rules only) |
| 04:18:57 | 08:18:57 | Alert from rule 92027 (level 4). Sysmon event time 08:18:58.976 UTC. |
| 04:20:15 | 08:20:15 | Baseline run ends |
| 04:30:41 | 08:30:41 | Wazuh manager restarted with custom rule 100101 (no errors from `wazuh-analysisd -t`) |
| 04:31:41 | 08:31:41 | Positive test begins |
| 04:32:16 | 08:32:16 | Sysmon event for the Bypass launch (event time 08:32:16.221 UTC). Alert from custom rule 100101 (level 10) stamped 04:32:15. |
| 04:32:23 | 08:32:23 | Positive test ends |
| 04:34:27 | 08:34:27 | Negative test begins |
| 04:34:32 | 08:34:32 | Sysmon event for the launch without Bypass (event time 08:34:32.211 UTC). Alert from rule 92027 (level 4) stamped 04:34:31. Rule 100101 did not fire. |
| 04:34:36 | 08:34:36 | Negative test ends |

Wazuh alert timestamps come from the server clock and ran 0.5 to 1.6 seconds earlier than the Sysmon event times from the endpoint clock. This timeline uses the Sysmon event time wherever I inspected it.

## 4. Evidence

- Sysmon Event ID 1 fields for the positive-test event:
  - Image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
  - Command line: `"powershell.exe" -NoProfile -ExecutionPolicy Bypass -Command "Write-Output 'LAB-S2-TEST-2'"`
  - Parent image: the same `powershell.exe` (my administrator PowerShell window, whose own command line had no arguments)
  - Integrity level: High; user: `LAB-ENDPOINT\labuser`; working directory: `C:\WINDOWS\system32\`
- Dashboard check over the last hour with the search `rule.id:100101 OR rule.id:92027`: exactly three alerts, in this order: 92027 (about 04:18), 100101 (about 04:32), 92027 (about 04:34).
- Screenshots in `evidence/`: `12-scenario2-test-run.png`, `12b-scenario2-baseline-alerts.png`, `13a-scenario2-rule-100101-added.png`, `13b-scenario2-positive-test-run.png`, `13-scenario2-positive-and-negative.png`.
- Sanitized sample alerts in `tests/samples/`: `alert-92027.json`, `alert-100101.json`.
- Custom rule: `rules/custom-rules.xml`.

## 5. Analysis

**Confirmed from the rule definitions and events:**
- Rule 92027 requires both the process and its parent to be `powershell.exe` and ignores the command line.    All three runs had a PowerShell parent, so its pattern applies to all three. It alerted on the baseline and negative runs, and for the Bypass run only the custom alert appeared.
- Rule 100101 is a child of Wazuh's Sysmon process-creation rule 61603. It requires the image to end in `powershell.exe` and the command line to contain `-ep` or `-ex...` followed by `bypass` (case-insensitive).
- In the Bypass run, only the custom alert appeared: no separate 92027 alert was seen for that event. In this single sample, the custom rule's alert replaced the built-in one. I did not test whether that always happens.

**Not established:** the event shows that an elevated PowerShell session started another PowerShell with a flag that skips the execution policy. It says nothing about intent. The command itself only printed text.

**Benign explanations in a real environment:** administrators, installers, software deployment tools, and scheduled tasks commonly start PowerShell with `-ExecutionPolicy Bypass`.

## 6. Detection evaluation

| Run | Bypass flag | Rule 92027 (built-in, level 4) | Rule 100101 (custom, level 10) |
|---|---|---|---|
| Baseline | yes | fired | not yet deployed |
| Positive test | yes | no separate alert seen | fired |
| Negative test | no | fired | did not fire |

- **Gap found:** the built-in rule is low severity and blind to the command line. From its definition it also requires a PowerShell parent, so PowerShell started from another program would not match it. Custom rule 100101 has no parent condition.
- **Not tested:** `pwsh.exe` (PowerShell 7), `Set-ExecutionPolicy`, encoded commands, other flag spellings than the one I ran, and renamed copies of `powershell.exe`. The tests are one positive and one negative sample, so this is not a measure of coverage.
- **False positives:** none observed from rule 100101 in these runs. Real environments would likely produce some.

### Related noise seen during this work

These are separate from the scenario but affect how useful PowerShell alerts are:
- **Rule 92213 (level 15, T1105, "Executable file dropped in folder commonly used by malware")** fired when a new PowerShell window opened. Two of the three alerts I inspected were PowerShell writing a throwaway `__PSScriptPolicyTest_*.ps1` file to the Temp folder, and the third was Disk Cleanup (`cleanmgr.exe`) unpacking a DLL. A test I ran (opening a new PowerShell window) produced a new alert, so I consider the PowerShell cause confirmed for that pattern.
- **Rule 92205 (level 9, T1105)** fired on a SYSTEM-level PowerShell writing the same kind of test file, shortly after the agent started. I believe this is the agent's own startup activity but did not confirm it.
- **Rule 61634 (level 12, T1055, "Suspicious Process - taskhost.exe")** fired on `backgroundTaskHost.exe` from the Phone Link app. Its definition matches the text `taskhost.exe` inside the image path, so I believe this is a substring false positive. I inspected one event.

- **Rule 92213 also fired for the negative-test run.** The alert's Sysmon process GUID matches the negative test's PowerShell process, and it arrived about 0.2 seconds after that process started (file written 08:34:32.408 UTC, process created 08:34:32.211 UTC). In that run the highest-severity alert was this false positive, not anything related to the test. Sample: `tests/samples/alert-92213.json`.

## 7. ATT&CK mapping

**T1059.001 (Command and Scripting Interpreter: PowerShell).** Both the built-in rule and my custom rule use this technique. It fits because PowerShell was executed, but a harmless print command is not an attack, so the mapping describes the behavior the rule watches for, not what happened here.

## 8. Recommended response

In a real environment an analyst would:
1. Identify who launched the process and from where, using the parent process chain.
2. Look at what the PowerShell session actually ran (command line, script path, or script content if logging allows).
3. Check the same process for network connections (Sysmon event 3), file creations (event 11), and child processes.
4. Ask the user or system owner whether the activity was expected, for example a deployment or admin script.
5. Isolate the host and collect evidence if the activity is unexpected.

In this lab no action was needed.

## 9. Lessons and limitations

- Matching on command-line behavior produces a more useful alert than matching on process relationships alone, but it will also match legitimate admin activity, so a production rule needs exclusions (known deployment tools, signed script paths, specific parent processes).
- Execution policy is a safety feature, not a security boundary, so a Bypass flag is a signal to investigate and not proof of malice.
- PowerShell Script Block Logging (Windows event 4104) would record what a script actually ran. I did not enable it, so this lab can show that a Bypass launch happened but not what it executed.
- The rule was tuned against a single positive and a single negative sample.
