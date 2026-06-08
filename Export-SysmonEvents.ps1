<#
.SYNOPSIS
    Exporta eventos de Sysmon desde Windows Event Log a JSON estructurado.
.DESCRIPTION
    Script parametrizable para exportar telemetria Sysmon.
    Generado para: Tarea Individual - Modulo IV UMSA Postgrado Informatica
.PARAMETER OutputPath
    Ruta del archivo JSON de salida.
.PARAMETER MaxEvents
    Numero maximo de eventos a exportar (default: 1000).
.PARAMETER StartTime
    Fecha de inicio del rango (opcional, formato: "yyyy-MM-dd HH:mm").
.PARAMETER EndTime
    Fecha de fin del rango (opcional, formato: "yyyy-MM-dd HH:mm").
.EXAMPLE
    .\Export-SysmonEvents.ps1 -OutputPath "C:\Asignacion-Sysmon\sample-events.json" -MaxEvents 500
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$OutputPath,

    [Parameter(Mandatory=$false)]
    [int]$MaxEvents = 1000,

    [Parameter(Mandatory=$false)]
    [string]$StartTime = "",

    [Parameter(Mandatory=$false)]
    [string]$EndTime = ""
)

# --- Verificar privilegios de administrador ---
$currentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Este script requiere privilegios de Administrador."
    exit 1
}

Write-Host "X" -Verbose | Out-Null # Forzar inicializacion de consola

Write-Host " "
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "     Export-SysmonEvents.ps1 - UMSA       " -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host " "

# --- Construir filtro XPath ---
$logName = "Microsoft-Windows-Sysmon/Operational"
$xpathQuery = "*"

if ($StartTime -ne "" -or $EndTime -ne "") {
    $conditions = @()
    if ($StartTime -ne "") {
        $startDt = [datetime]::ParseExact($StartTime, "yyyy-MM-dd HH:mm", $null)
        $startUtc = $startDt.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.000Z")
        $conditions += "@SystemTime >= '$startUtc'"
    }
    if ($EndTime -ne "") {
        $endDt = [datetime]::ParseExact($EndTime, "yyyy-MM-dd HH:mm", $null)
        $endUtc = $endDt.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.000Z")
        $conditions += "@SystemTime <= '$endUtc'"
    }
    $xpathQuery = "*[System[TimeCreated[$($conditions -join ' and ')]]]"
}

Write-Host "[*] Conectando al canal: $logName" -ForegroundColor Yellow
Write-Host "[*] Maximo de eventos: $MaxEvents" -ForegroundColor Yellow
Write-Host "[*] Ruta de salida: $OutputPath" -ForegroundColor Yellow
Write-Host " "

# --- Extraer eventos ---
try {
    $rawEvents = Get-WinEvent -LogName $logName -MaxEvents $MaxEvents -ErrorAction Stop
    Write-Host "[+] Eventos recuperados del log: $($rawEvents.Count)" -ForegroundColor Green
} catch {
    Write-Error "No se pudo acceder al log de Sysmon: $_"
    exit 1
}

# --- Funcion: parsear campos del mensaje XML ---
function Parse-SysmonEventData {
    param([System.Diagnostics.Eventing.Reader.EventLogRecord]$Event)

    $eventXml = [xml]$Event.ToXml()
    $eventData = @{}

    # Extraer campos EventData
    $nodes = $eventXml.Event.EventData.Data
    foreach ($node in $nodes) {
        $name = $node.Name
        $value = $node.'#text'
        if ($name -and $value) {
            $eventData[$name] = $value
        }
    }

    # Construir objeto plano unificado
    $obj = [ordered]@{
        EventID          = [int]$Event.Id
        TimeCreated      = $Event.TimeCreated.ToString("o")  # ISO 8601
        Computer         = $Event.MachineName
        Channel          = $Event.LogName
        RecordId         = [int]$Event.RecordId
        ProviderName     = $Event.ProviderName
        RuleName         = $eventData["RuleName"]
        UtcTime          = $eventData["UtcTime"]
        ProcessGuid      = $eventData["ProcessGuid"]
        ProcessId        = $eventData["ProcessId"]
        Image            = $eventData["Image"]
        CommandLine      = $eventData["CommandLine"]
        CurrentDirectory = $eventData["CurrentDirectory"]
        User             = $eventData["User"]
        LogonGuid        = $eventData["LogonGuid"]
        LogonId          = $eventData["LogonId"]
        TerminalSessionId = $eventData["TerminalSessionId"]
        IntegrityLevel   = $eventData["IntegrityLevel"]
        Hashes           = $eventData["Hashes"]
        ParentProcessGuid = $eventData["ParentProcessGuid"]
        ParentProcessId  = $eventData["ParentProcessId"]
        ParentImage      = $eventData["ParentImage"]
        ParentCommandLine = $eventData["ParentCommandLine"]
        ParentUser       = $eventData["ParentUser"]
        Protocol         = $eventData["Protocol"]
        Initiated        = $eventData["Initiated"]
        SourceIp         = $eventData["SourceIp"]
        SourceHostname   = $eventData["SourceHostname"]
        SourcePort       = $eventData["SourcePort"]
        DestinationIp    = $eventData["DestinationIp"]
        DestinationHostname = $eventData["DestinationHostname"]
        DestinationPort  = $eventData["DestinationPort"]
        EventType        = $eventData["EventType"]
        TargetObject     = $eventData["TargetObject"]
        Details          = $eventData["Details"]
        NewName          = $eventData["NewName"]
    }

    # Eliminar campos nulos para JSON mas limpio
    $clean = [ordered]@{}
    foreach ($key in $obj.Keys) {
        if ($null -ne $obj[$key]) {
            $clean[$key] = $obj[$key]
        }
    }

    return $clean
}

# --- Procesar todos los eventos ---
Write-Host "[*] Procesando y transformando eventos..." -ForegroundColor Yellow
$parsedEvents = @()
$errorCount = 0

foreach ($event in $rawEvents) {
    try {
        $parsed = Parse-SysmonEventData -Event $event
        $parsedEvents += $parsed
    } catch {
        $errorCount++
    }
}

Write-Host "[+] Eventos procesados correctamente: $($parsedEvents.Count)" -ForegroundColor Green
if ($errorCount -gt 0) {
    Write-Host "[!] Eventos con error de parseo: $errorCount" -ForegroundColor Red
}

# --- Construir objeto de salida con metadatos ---
$metadata = [ordered]@{
    ExportMetadata = [ordered]@{
        Hostname         = $env:COMPUTERNAME
        ExportedAt       = (Get-Date).ToString("o")
        ExportedBy       = $env:USERNAME
        TotalEvents      = $parsedEvents.Count
        MaxEventsParam   = $MaxEvents
        SysmonLogChannel = $logName
        ScriptVersion    = "1.0"
        Note             = "Exportado para Tarea Individual - UMSA Modulo IV"
    }
    Events = $parsedEvents
}

# --- Guardar JSON ---
try {
    $jsonOutput = $metadata | ConvertTo-Json -Depth 10 -Compress:$false
    $jsonOutput | Out-File -FilePath $OutputPath -Encoding UTF8 -Force
    Write-Host "[+] Archivo JSON guardado en: $OutputPath" -ForegroundColor Green
} catch {
    Write-Error "No se pudo guardar el archivo JSON: $_"
    exit 1
}

# --- Validar que el JSON es parseable ---
try {
    $testParse = Get-Content $OutputPath -Raw | ConvertFrom-Json
    Write-Host "[+] Validacion JSON: CORRECTO (parseable)" -ForegroundColor Green
} catch {
    Write-Error "El JSON generado NO es valido: $_"
    exit 1
}

# --- Resumen por EventID ---
Write-Host " "
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "          RESUMEN POR EventID             " -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

$eventIDMap = @{
    1  = "ProcessCreate"
    2  = "FileCreationTimeChanged"
    3  = "NetworkConnect"
    4  = "SysmonServiceStateChanged"
    5  = "ProcessTerminated"
    7  = "ImageLoaded"
    10 = "ProcessAccess"
    11 = "FileCreate"
    12 = "RegistryObjectCreate/Delete"
    13 = "RegistryValueSet"
    14 = "RegistryObjectRename"
    15 = "FileCreateStreamHash"
    17 = "PipeEvent"
    22 = "DNSEvent"
    25 = "ProcessTampering"
}

$groupedByID = $parsedEvents | Group-Object -Property EventID | Sort-Object -Property Name
foreach ($group in $groupedByID) {
    $eid = $group.Name
    $desc = if ($eventIDMap.ContainsKey([int]$eid)) { $eventIDMap[[int]$eid] } else { "Unknown" }
    Write-Host "  EventID $eid ($desc) -> Total: $($group.Count) eventos" -ForegroundColor White
}

$fileSizeKB = [math]::Round((Get-Item $OutputPath).Length / 1KB, 1)
Write-Host " "
Write-Host "[*] Tamano del archivo: $fileSizeKB KB" -ForegroundColor Yellow
Write-Host "[*] Exportacion completada." -ForegroundColor Cyan
Write-Host " "