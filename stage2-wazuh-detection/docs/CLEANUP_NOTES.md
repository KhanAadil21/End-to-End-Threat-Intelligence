# Repo vs live manager: cleanup notes (2026-10-14)

The rule files in `rules/` started as copies of the live files on the Wazuh manager. All 51 live rules were confirmed firing. Before publishing I fixed naming, tags and comments. This page lists every change, so the manager can be brought in line and re-tested.

**Detection logic is unchanged except for two rules: 100014 and 100019.** Everything else is text, tags or group names.

## Changes that need a wazuh-logtest re-run

| Rule | Live version | Repo version | Why |
|---|---|---|---|
| 100014 | `<field name="input">mkdir\|ssh\|cd\|wget\|...\|cat</field>` (OSRegex, no word boundaries) | pcre2 with word boundaries. `cd`, `cat` and `mkdir` removed, `ssh` kept | `cd` matched inside almost any command, so most commands jumped to level 12 and the baseline/escalation split stopped meaning anything |
| 100019 | ID was 100020 | ID is 100019 | 100020 sat in Heralding's old slot. The Cowrie block is 100010-100019 |

Re-test 100014 with a harmless command (`ls -la`, which should stay at 100013) and a dangerous one (`wget http://example.com/x`, which should fire 100014).

## MITRE tags

Wazuh only maps technique IDs. Tactic IDs (TA####) in a `<mitre>` block are dropped with a warning in ossec.log.

| Rule(s) | Live | Repo |
|---|---|---|
| 100016 | T1105, TA003 | T1105 |
| 100021 | TA0006 | T1110, T1021.005 |
| 100022-100028 | TA0006 | T1110 |
| 100029 | T1110, TA0006 | T1110 |
| 100030 | TA0006, T1021.001 | T1110, T1021.001 |
| 100031 | T1046, TA0007 | T1046 |
| 100032 | none (comment said T1046) | T1046 |
| 100062, 100065 | T0888, T0836 | T0888 (comment says when to switch to T0836) |
| 100074 | TA0006 | T1110 |
| 100075 | T1071.002, TA0011 | T1595 (inbound scanner traffic, not FTP C2) |
| 100076 | T1595.002, TA0043 | T1595.002 |
| 100014 | T1105, T1222, T1027, T1059, T1098 | T1059 replaced by T1059.004 |

## Group names

| Live | Repo |
|---|---|
| `dangeroud_command` | `dangerous_command` |
| `protocol interaction` (100042, has a space) | `protocol_interaction` |
| `protocol_interface` (100062, 100065) | `protocol_interaction` |
| `dionaea, credential_attempt` (leading space) | `dionaea,credential_attempt,` |
| `dionaea, bruteforce` | `dionaea,brute_force,` |
| `Kamstrup`, `Kamstrup_management`, `Kamstrup_protocol`, `IEC104` | lowercase |
| Cowrie rules with no `cowrie` group (100013-100019) | `cowrie` added to all ten |
| Wrapper names like `Heralding_VNC`, `Dionaea_command_interaction`, `conpot_IEC104` | lowercase, one wrapper per family |

The Heralding brute force rule (100029) is still in a separate wrapper that is **not** called `heralding`. A wrapper name becomes a group on the rule, and 100029 counts the `heralding` group, so a shared wrapper would make it count its own alerts.

Check saved dashboard searches or visualisations that filter on the old names before pushing these to the manager.

## Description text

- Typos fixed: "obeserved", "honeyot", "deteceted", "successfull, attacked gained", "anamalous".
- `$(src_ip)` or `$(source_ip)` added wherever it was missing.
- Heralding descriptions name the service directly (VNC, SMTPS...) instead of `$(protocol)`. `protocol` is a reserved field and may come out blank.
- 100065 said "management interface" but covers the meter interface.

## Comments

- Header comments rewritten in plain first-person notes with the same block on every rule: ID, purpose, author, date, log source, ATT&CK, false positive matrix.
- Comments that disagreed with the rule were fixed: 100030 said level 12 (rule is 4), 100077 said "twice" (rule counts 5), 100029 said it counts 100020-100024, the 100065 header said 100062.
- Removed the Windows header line naming the old agent ID and agent name.
- Cowrie log path corrected from `tpot-admin` to `tpotadmin`.

## Judgment calls left as live

These are worth revisiting, but they match what is running and was tested:

- **IEC104 levels.** 100050/100051 are at level 7, while every other connection lifecycle rule is at 3.
- **100013 level.** It is at 10, which is loud for a baseline that fires on every command.
- **100030 level.** It is at 4, below the emulated RDP connect rule (100031 at 5).
- **100074/100075 order.** 100074 sits above 100075. A credentialed FTP session may be reported as 100074 only, in which case 100076 never sees it.
