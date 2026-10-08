<#
.SYNOPSIS
    Ships Windows Security Event ID 4625 (failed logon) records to AWS CloudWatch Logs.

.DESCRIPTION
    Reads recent 4625 events with Get-WinEvent, flattens the useful fields into a
    JSON message per event (so CloudWatch Logs Insights discovers the fields
    automatically), and sends them with "aws logs put-log-events".

    A small state file records the timestamp of the last event shipped, so
    re-running the script does not send duplicates.

    Requires: an elevated PowerShell session (the Security log needs it) and the
    AWS CLI configured with permission to write to the target log group.

.EXAMPLE
    .\ship-4625-to-cloudwatch.ps1
    .\ship-4625-to-cloudwatch.ps1 -LookbackMinutes 240
#>

param(
    [string]$LogGroup  = "/soc-home-lab/windows-security",
    [string]$LogStream = "Windows11-Victim",
    [string]$Region    = "ap-southeast-2",
    [int]$LookbackMinutes = 60
)

$ErrorActionPreference = "Stop"
$stateFile = Join-Path $env:TEMP "ship-4625-last-timestamp.txt"

# Work out where to start reading: last shipped event, or the lookback window.
$startTime = (Get-Date).AddMinutes(-$LookbackMinutes)
if (Test-Path $stateFile) {
    $saved = [datetime]::Parse((Get-Content $stateFile -Raw).Trim(), $null,
                               [System.Globalization.DateTimeStyles]::RoundtripKind)
    if ($saved -gt $startTime) { $startTime = $saved }
}

# Get-WinEvent throws when nothing matches, so treat that as "no events".
$rawEvents = Get-WinEvent -FilterHashtable @{
    LogName   = "Security"
    Id        = 4625
    StartTime = $startTime
} -ErrorAction SilentlyContinue

if (-not $rawEvents) {
    Write-Host "No new 4625 events since $startTime. Nothing to ship."
    return
}

# put-log-events needs events in chronological order.
$rawEvents = $rawEvents | Where-Object { $_.TimeCreated -gt $startTime } |
             Sort-Object TimeCreated

if (-not $rawEvents) {
    Write-Host "No new 4625 events since $startTime. Nothing to ship."
    return
}

$logEvents = @()
foreach ($e in $rawEvents) {
    # Pull the named fields out of the event XML.
    $xml  = [xml]$e.ToXml()
    $data = @{}
    foreach ($d in $xml.Event.EventData.Data) { $data[$d.Name] = $d.'#text' }

    $message = [ordered]@{
        EventCode            = 4625
        ComputerName         = $e.MachineName
        TimeCreated          = $e.TimeCreated.ToUniversalTime().ToString("o")
        TargetUserName       = $data["TargetUserName"]
        TargetDomainName     = $data["TargetDomainName"]
        LogonType            = [int]$data["LogonType"]
        Status               = $data["Status"]
        SubStatus            = $data["SubStatus"]
        WorkstationName      = $data["WorkstationName"]
        IpAddress            = $data["IpAddress"]
        ProcessName          = $data["ProcessName"]
    }

    $logEvents += @{
        timestamp = [DateTimeOffset]::new($e.TimeCreated).ToUnixTimeMilliseconds()
        message   = ($message | ConvertTo-Json -Compress)
    }
}

# A single PutLogEvents call may not span more than 24 hours or hold more than
# 10,000 events, so split the events into batches that respect both limits.
$batches = @()
$current = @()
foreach ($ev in $logEvents) {
    if ($current.Count -gt 0 -and
        ((($ev.timestamp - $current[0].timestamp) -ge (23 * 3600 * 1000)) -or
         $current.Count -ge 1000)) {
        $batches += ,$current
        $current = @()
    }
    $current += $ev
}
if ($current.Count -gt 0) { $batches += ,$current }

$payloadFile = Join-Path $env:TEMP "cwl-payload.json"
$shipped = 0
foreach ($batch in $batches) {
    # Write the payload without a BOM; the AWS CLI rejects a BOM-prefixed JSON file.
    $json = ConvertTo-Json -InputObject $batch -Depth 4
    [System.IO.File]::WriteAllText($payloadFile, $json, (New-Object System.Text.UTF8Encoding($false)))

    aws logs put-log-events `
        --log-group-name  $LogGroup `
        --log-stream-name $LogStream `
        --log-events      "file://$payloadFile" `
        --region          $Region

    if ($LASTEXITCODE -ne 0) {
        throw "put-log-events failed (exit code $LASTEXITCODE). State file not updated."
    }
    $shipped += $batch.Count
}

# Remember the newest event shipped so the next run starts after it.
$newest = ($rawEvents | Select-Object -Last 1).TimeCreated
$newest.ToString("o") | Set-Content $stateFile

Write-Host "Shipped $shipped event(s) in $($batches.Count) batch(es) to $LogGroup / $LogStream."
Remove-Item $payloadFile -ErrorAction SilentlyContinue
