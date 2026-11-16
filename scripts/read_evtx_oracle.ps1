param(
    [Parameter(Mandatory = $true)][string]$InputFile,
    [Parameter(Mandatory = $true)][string]$OutputFile,
    [ValidateRange(1, 10000)][int]$MaxRecords = 10000
)
$ErrorActionPreference = 'Stop'
$watch = [Diagnostics.Stopwatch]::StartNew()
$source = (Resolve-Path -LiteralPath $InputFile).ProviderPath
if ([IO.Path]::GetExtension($source) -ine '.evtx') { throw 'An explicit EVTX file is required.' }
$destination = [IO.Path]::GetFullPath($OutputFile)
if ((Test-Path -LiteralPath $destination) -or $source.Equals($destination, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Output must be a new file distinct from the input.'
}
$liveDirectory = [IO.Path]::GetFullPath((Join-Path $env:SystemRoot 'System32\winevt\Logs')).TrimEnd('\') + '\'
if ($source.StartsWith($liveDirectory, [StringComparison]::OrdinalIgnoreCase)) { throw 'Current-host log directories are not allowed.' }
$events = @(Get-WinEvent -Path $source -Oldest -MaxEvents ($MaxRecords + 1) -ErrorAction Stop)
if ($events.Count -gt $MaxRecords) { throw 'The native-reader record budget was exceeded.' }
$records = @($events | ForEach-Object {
    $event = $_
    [xml]$xml = $event.ToXml()
    $data = [ordered]@{}
    foreach ($node in $xml.SelectNodes('/*[local-name()="Event"]/*[local-name()="EventData"]/*[local-name()="Data"]')) {
        $name = $node.GetAttribute('Name')
        if ($name) { $data[$name] = $node.InnerText }
    }
    # Security 1102 (and System 104) use a namespaced UserData/LogFileCleared
    # payload, not EventData/Data. Keep that actual native XML shape explicit.
    foreach ($node in $xml.SelectNodes('/*[local-name()="Event"]/*[local-name()="UserData"]/*[local-name()="LogFileCleared"]/*')) {
        $data[$node.LocalName] = $node.InnerText
    }
    [pscustomobject]@{
        event_code = [int]$event.Id
        record_id = [long]$event.RecordId
        channel = [string]$event.LogName
        provider = [string]$event.ProviderName
        hostname = ([string]$event.MachineName).ToLowerInvariant()
        timestamp_source = [string]$xml.Event.System.TimeCreated.SystemTime
        event_data = $data
    }
})
$watch.Stop()
$process = [Diagnostics.Process]::GetCurrentProcess()
$process.Refresh()
$result = [ordered]@{
    schema = 1
    reader = 'Windows Get-WinEvent -Path / EventRecord.ToXml'
    powershell_version = $PSVersionTable.PSVersion.ToString()
    os_version = [Environment]::OSVersion.Version.ToString()
    elapsed_seconds = $watch.Elapsed.TotalSeconds
    reader_peak_working_set_bytes = $process.PeakWorkingSet64
    records = $records
}
# CreateNew also rejects a destination created after the initial guard.
$stream = [IO.File]::Open($destination, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
try {
    $writer = [IO.StreamWriter]::new($stream, [Text.UTF8Encoding]::new($false))
    try { $writer.Write(($result | ConvertTo-Json -Depth 10)) }
    finally { $writer.Dispose() }
}
finally { $stream.Dispose() }
