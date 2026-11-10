# Failed Logon Dashboard: Methodology

This folder holds `failed-logon-dashboard.xlsx`, an Excel workbook that analyses Windows
failed-logon events (Event ID 4625) exported from AWS CloudWatch Logs Insights. The write-up
of the exercise is in
[`failed-logon-excel-dashboard.md`](../incident-reports/windows/failed-logon-excel-dashboard.md).
This file explains how the workbook is built so that anyone can follow, check or rebuild it.

All data comes from my own deliberate tests on an isolated lab VM. It demonstrates a method,
not real attack activity.

## 1. Data source

The events were exported from CloudWatch Logs Insights (log group
`/soc-home-lab/windows-security`, region `ap-southeast-2`, time range of the last 6 months)
using this query, then downloaded with Actions, Download table (CSV):

```
fields @timestamp, ComputerName, TargetUserName, LogonType, SubStatus, IpAddress
| filter EventCode = 4625
| sort @timestamp asc
| limit 1000
```

The events reached CloudWatch through the PowerShell script in
[`scripts/ship-4625-to-cloudwatch.ps1`](../scripts/ship-4625-to-cloudwatch.ps1). The export
returned 18 rows. Timestamps are in UTC.

## 2. Sheets

| Sheet | Purpose |
|---|---|
| `Summary` | The one-page view: four headline figures, charts, a plain-English takeaway, notes and limitations |
| `log-analytics-results-2026-11-1` | The exported data plus the helper columns that do the analysis |
| `Meaning` | A small lookup table that turns `SubStatus` codes into plain English |
| `By Username`, `By Hour`, `By Reason` | Three pivot tables that feed the charts |

## 3. Data sheet columns

The headers are in row 2 and the 18 data rows are rows 3 to 20, starting in column B.

| Column | Header | Source or formula | Purpose |
|---|---|---|---|
| B to G | Timestamp, ComputerName, TargetUserName, LogonType, SubStatus, IpAddress | Exported from CloudWatch | Raw event fields |
| H | Time (UTC) | `=B3` | The timestamp as a real date and time |
| I | Time (Sydney) | `=H3+11/24` | Sydney time (see limitations) |
| J | Hour | `=HOUR(I3)` | Hour of day in Sydney time, for the by-hour chart |
| K | Bucket | `=FLOOR(H3, "0:05")` | Puts each event in a 5-minute window |
| L | In Bucket | `=COUNTIF($K$3:$K$20,K3)` | How many events share this row's window |
| M | Alert | `=IF(L3>=3, "ALERT", "")` | Flags windows with 3 or more failures |
| N | Window Weight | `=IF(M3="ALERT",1/L3,0)` | Lets alert windows be counted rather than rows |
| O | Meaning | `=XLOOKUP(F3,Meaning!$B$3:$B$5,Meaning!$C$3:$C$5,"Unknown")` | Plain-English reason for each failure |

## 4. Design decisions

- **5-minute windows with a threshold of 3.** This reproduces the CloudWatch alarm and the
  earlier Splunk and Python detections, so the same rule has now been applied in four tools.
- **A weight column to count windows.** If you count rows flagged `ALERT` you get 17, because
  every row in a flagged window is flagged. Giving each flagged row a weight of 1 divided by
  its window's size makes each flagged window add up to exactly 1, so the total is 3.
- **A lookup table for status codes.** Raw codes such as `0xc000006a` mean nothing to a
  manager. Keeping the meanings in their own sheet means they can be edited in one place.
- **Sydney time as its own column.** The export is in UTC, but the hour chart should match
  when the tests were actually run, so the original UTC value is kept and the Sydney value
  is added beside it.

## 5. Summary sheet figures

| Figure | Formula | Result |
|---|---|---|
| Total failed logons | `=ROWS('log-analytics-results-2026-11-1'!B3:B20)` | 18 |
| Alert windows | `=ROUND(SUM('log-analytics-results-2026-11-1'!N3:N20),0)` | 3 |
| Distinct usernames | `=SUMPRODUCT(1/COUNTIF(D3:D20,D3:D20))` on the data sheet | 5 |
| Non-existent username attempts | `=COUNTIF('log-analytics-results-2026-11-1'!F3:F20,"0xc0000064")` | 4 |

## 6. Status code lookup

| SubStatus | Meaning in the workbook |
|---|---|
| `0xc000006a` | Wrong password, account exists |
| `0xc0000064` | Username does not exist |
| `0xc0000071` | Password expired (forced password change) |

The label for `0xc0000071` comes from Windows prompting me to change my password at that time.
I did not check the event's failure reason text in Event Viewer.

## 7. Pivot tables

All three pivots count the `Timestamp` field and group by one other field:

| Pivot | Rows | Result |
|---|---|---|
| By Username | `TargetUserName` | `kal` 14, and `cheese`, `fakeuser`, `guest123` and `johndoe` 1 each |
| By Hour | `Hour` | Hour 5: 9, hour 6: 6, hour 22: 3 |
| By Reason | `Meaning` | Wrong password 13, username does not exist 4, password expired 1 |

## 8. Checks

- Each pivot's grand total is 18, matching the row count.
- The window weights add up to 3, matching the three bursts: six failures on 5 October, three
  on 6 October and eight on 9 November (UTC dates).
- The lone password-change failure sits in a window of its own with a count of 1, so it is
  not flagged.

## 9. Updating the workbook

1. Run the Logs Insights query again and download the new CSV.
2. Paste the new rows into the data sheet below the existing ones and copy the helper
   formulas (columns H to O) down.
3. Extend the cell ranges in the formulas (`3:20`) and the pivot source to cover the new
   rows.
4. Right-click each pivot and choose Refresh. Pivots do not update by themselves.

## 10. Limitations

- Only 18 events from one VM, all generated by me, so the charts show the method and not
  real attack patterns.
- Fixed 5-minute windows can split a burst: three failures straddling a boundary would be
  counted as two and one and would not flag. The CloudWatch alarm's fixed period has the same
  weakness.
- The Sydney offset of 11 hours is hard-coded for daylight saving and would be 10 hours in
  winter.
- Formulas use fixed cell ranges, not named tables, so they do not grow automatically.
- Excel displays the raw `Timestamp` column in an odd time format and rounds the display of
  seconds in `Time (UTC)`. The underlying values keep the milliseconds.
- Personal metadata (last-modified-by name and local folder path) was removed from the
  uploaded file.
