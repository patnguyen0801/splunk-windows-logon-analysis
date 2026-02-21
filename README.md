# Splunk Lab: Windows Logon Activity Analysis

## Objective
Analyze Windows Security logs in Splunk to identify logon activity and privileged access events.

## Environment
- Splunk Enterprise (local)
- Splunk Universal Forwarder
- Windows Security Event Logs
- Index: main
- Sourcetype: wineventlog

## Events Investigated
- 4624 – Successful Logon
- 4672 – Special privileges assigned to new logon
- 4634 – Logoff
- 4648 – Logon using explicit credentials

## SPL Query

```spl
index=main sourcetype=wineventlog LogName=Security 
(EventCode=4624 OR EventCode=4672 OR EventCode=4634 OR EventCode=4648)
| stats count by EventCode
| sort -count
