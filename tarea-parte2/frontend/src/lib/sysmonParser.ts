export type Severity = 'Critical' | 'High' | 'Medium' | 'Low';

export interface SysmonEvent {
  Id: number;
  RecordId: number;
  ProviderName: string;
  ProviderId: string;
  LogName: string;
  ProcessId: number;
  ThreadId: number;
  MachineName: string;
  UserId: string;
  TimeCreated: string;
  LevelDisplayName: string;
  OpcodeDisplayName: string;
  TaskDisplayName: string;
  KeywordsDisplayNames: string[];
  Message: string;
  Properties: Array<{ Name: string; Value: any }>;
}

export interface Alert {
  id: string;
  eventId: number;
  timestamp: string;
  severity: Severity;
  ruleName: string;
  indicator: string;
  mitre: string;
  owasp: string;
  rawEvent: SysmonEvent;
}

// Helper to extract properties easily
const getProp = (event: any, name: string): string => {
  if (event[name] !== undefined) return String(event[name]);
  if (event.Properties && Array.isArray(event.Properties)) {
    const prop = event.Properties.find((p: any) => p.Name === name);
    return prop ? String(prop.Value) : '';
  }
  return '';
};

const getEventId = (e: any): number => {
  return Number(e.EventID || e.Id || 0);
};

// 1. PowerShell con -EncodedCommand o -enc
export const ruleEncodedCommand = (e: SysmonEvent): Alert | null => {
  if (getEventId(e) === 1) {
    const cmdline = getProp(e, 'CommandLine').toLowerCase();
    if (cmdline.includes('powershell') && (cmdline.includes('-encodedcommand') || cmdline.includes('-enc '))) {
      return {
        id: crypto.randomUUID(),
        eventId: getEventId(e),
        timestamp: e.TimeCreated,
        severity: 'High',
        ruleName: 'PowerShell Encoded Command',
        indicator: getProp(e, 'CommandLine'),
        mitre: 'T1059.001 / T1027',
        owasp: 'A03:2021-Injection',
        rawEvent: e,
      };
    }
  }
  return null;
};

// 2. PowerShell con -WindowStyle Hidden o -w hidden
export const ruleHiddenWindow = (e: SysmonEvent): Alert | null => {
  if (getEventId(e) === 1) {
    const cmdline = getProp(e, 'CommandLine').toLowerCase();
    if (cmdline.includes('powershell') && (cmdline.includes('-windowstyle hidden') || cmdline.includes('-w hidden'))) {
      return {
        id: crypto.randomUUID(),
        eventId: getEventId(e),
        timestamp: e.TimeCreated,
        severity: 'Medium',
        ruleName: 'PowerShell Hidden Window',
        indicator: getProp(e, 'CommandLine'),
        mitre: 'T1059.001 / T1564',
        owasp: 'A04:2021-Insecure Design',
        rawEvent: e,
      };
    }
  }
  return null;
};

// 3. PowerShell Invoke-Expression, DownloadString
export const ruleDownloadPayload = (e: SysmonEvent): Alert | null => {
  if (getEventId(e) === 1) {
    const cmdline = getProp(e, 'CommandLine').toLowerCase();
    if (cmdline.includes('powershell') && (
        cmdline.includes('invoke-expression') || cmdline.includes('iex ') ||
        cmdline.includes('downloadstring') || cmdline.includes('downloadfile'))) {
      return {
        id: crypto.randomUUID(),
        eventId: getEventId(e),
        timestamp: e.TimeCreated,
        severity: 'High',
        ruleName: 'PowerShell Download/Execute Payload',
        indicator: getProp(e, 'CommandLine'),
        mitre: 'T1059.001 / T1105',
        owasp: 'A08:2021-Software and Data Integrity Failures',
        rawEvent: e,
      };
    }
  }
  return null;
};

// 4. PowerShell desde rutas %TEMP%, %APPDATA%, %PUBLIC%
export const ruleSuspiciousPath = (e: SysmonEvent): Alert | null => {
  if (getEventId(e) === 1) {
    const img = getProp(e, 'Image').toLowerCase();
    const curDir = getProp(e, 'CurrentDirectory').toLowerCase();
    if (img.includes('powershell') && (
        curDir.includes('\\temp') || curDir.includes('\\appdata') || curDir.includes('\\public'))) {
      return {
        id: crypto.randomUUID(),
        eventId: getEventId(e),
        timestamp: e.TimeCreated,
        severity: 'High',
        ruleName: 'PowerShell execution from suspicious path',
        indicator: getProp(e, 'CurrentDirectory'),
        mitre: 'T1059.001 / T1036',
        owasp: 'A01:2021-Broken Access Control',
        rawEvent: e,
      };
    }
  }
  return null;
};

// 5. Conexión RDP entrante no RFC1918
const isPrivateIP = (ip: string) => {
  const parts = ip.split('.');
  if (parts.length !== 4) return false;
  if (parts[0] === '10') return true;
  if (parts[0] === '172' && parseInt(parts[1]) >= 16 && parseInt(parts[1]) <= 31) return true;
  if (parts[0] === '192' && parts[1] === '168') return true;
  if (parts[0] === '127') return true;
  return false;
};

export const ruleRdpInbound = (e: SysmonEvent): Alert | null => {
  if (getEventId(e) === 3) {
    const destPort = getProp(e, 'DestinationPort');
    const sourceIp = getProp(e, 'SourceIp');
    if (destPort === '3389' && !isPrivateIP(sourceIp) && sourceIp && sourceIp.includes('.')) {
      return {
        id: crypto.randomUUID(),
        eventId: getEventId(e),
        timestamp: e.TimeCreated,
        severity: 'Critical',
        ruleName: 'Inbound RDP from Public IP',
        indicator: `Source IP: ${sourceIp}`,
        mitre: 'T1021.001',
        owasp: 'A07:2021-Identification and Authentication Failures',
        rawEvent: e,
      };
    }
  }
  return null;
};

// 6. Conexión RDP saliente a IPs públicas
export const ruleRdpOutbound = (e: SysmonEvent): Alert | null => {
  if (getEventId(e) === 3) {
    const destPort = getProp(e, 'DestinationPort');
    const destIp = getProp(e, 'DestinationIp');
    if (destPort === '3389' && !isPrivateIP(destIp) && destIp && destIp.includes('.')) {
      return {
        id: crypto.randomUUID(),
        eventId: getEventId(e),
        timestamp: e.TimeCreated,
        severity: 'High',
        ruleName: 'Outbound RDP to Public IP',
        indicator: `Destination IP: ${destIp}`,
        mitre: 'T1021.001 / T1570',
        owasp: 'A01:2021-Broken Access Control',
        rawEvent: e,
      };
    }
  }
  return null;
};

// 7. Modificación de clave HKCU o HKLM \...\Run o \RunOnce
export const ruleRegistryRunKeys = (e: SysmonEvent): Alert | null => {
  const id = getEventId(e);
  if (id === 12 || id === 13 || id === 14) {
    const target = getProp(e, 'TargetObject').toLowerCase();
    if (target.includes('\\currentversion\\run') || target.includes('\\currentversion\\runonce')) {
      return {
        id: crypto.randomUUID(),
        eventId: getEventId(e),
        timestamp: e.TimeCreated,
        severity: 'High',
        ruleName: 'Persistence via Run/RunOnce Registry Keys',
        indicator: getProp(e, 'TargetObject'),
        mitre: 'T1547.001',
        owasp: 'A08:2021-Software and Data Integrity Failures',
        rawEvent: e,
      };
    }
  }
  return null;
};

// 8. Creación o modificación de servicio Windows
export const ruleWindowsServices = (e: SysmonEvent): Alert | null => {
  const id = getEventId(e);
  if (id === 12 || id === 13 || id === 14) {
    const target = getProp(e, 'TargetObject').toLowerCase();
    if (target.includes('\\services\\') && (target.includes('imagepath') || target.includes('start'))) {
      return {
        id: crypto.randomUUID(),
        eventId: getEventId(e),
        timestamp: e.TimeCreated,
        severity: 'High',
        ruleName: 'Windows Service Creation/Modification',
        indicator: getProp(e, 'TargetObject'),
        mitre: 'T1543.003',
        owasp: 'A08:2021-Software and Data Integrity Failures',
        rawEvent: e,
      };
    }
  }
  return null;
};

// 9. (Bonus) Modificación en \Image File Execution Options\
export const ruleIfeo = (e: SysmonEvent): Alert | null => {
  const id = getEventId(e);
  if (id === 12 || id === 13 || id === 14) {
    const target = getProp(e, 'TargetObject').toLowerCase();
    if (target.includes('image file execution options')) {
      return {
        id: crypto.randomUUID(),
        eventId: getEventId(e),
        timestamp: e.TimeCreated,
        severity: 'Critical',
        ruleName: 'Image File Execution Options (IFEO) Injection',
        indicator: getProp(e, 'TargetObject'),
        mitre: 'T1546.012',
        owasp: 'A08:2021-Software and Data Integrity Failures',
        rawEvent: e,
      };
    }
  }
  return null;
};

// 10. (Bonus) Múltiples ejecuciones de PowerShell en menos de 60 segundos
let recentPowershellExecutions: number[] = [];
export const ruleHeuristicPowershell = (e: SysmonEvent): Alert | null => {
  if (getEventId(e) === 1) {
    const img = getProp(e, 'Image').toLowerCase();
    if (img.includes('powershell')) {
      const timeMs = new Date(e.TimeCreated).getTime();
      recentPowershellExecutions.push(timeMs);
      
      recentPowershellExecutions = recentPowershellExecutions.filter(t => timeMs - t <= 60000);
      
      if (recentPowershellExecutions.length >= 3) {
        recentPowershellExecutions = [];
        return {
          id: crypto.randomUUID(),
          eventId: getEventId(e),
          timestamp: e.TimeCreated,
          severity: 'Medium',
          ruleName: 'Rapid PowerShell Execution Burst',
          indicator: '>= 3 PowerShell processes within 60s',
          mitre: 'T1059 (Heuristics)',
          owasp: 'A04:2021-Insecure Design',
          rawEvent: e,
        };
      }
    }
  }
  return null;
};

// 11. (Bonus) Limpieza de Logs
export const ruleClearLogs = (e: SysmonEvent): Alert | null => {
  if (getEventId(e) === 1) {
    const cmdline = getProp(e, 'CommandLine').toLowerCase();
    if (cmdline.includes('wevtutil cl') || cmdline.includes('clear-eventlog')) {
      return {
        id: crypto.randomUUID(),
        eventId: getEventId(e),
        timestamp: e.TimeCreated,
        severity: 'High',
        ruleName: 'Event Log Clearing (Defense Evasion)',
        indicator: getProp(e, 'CommandLine'),
        mitre: 'T1070.001',
        owasp: 'A09:2021-Security Logging and Monitoring Failures',
        rawEvent: e,
      };
    }
  }
  return null;
};

const ALL_RULES = [
  ruleEncodedCommand,
  ruleHiddenWindow,
  ruleDownloadPayload,
  ruleSuspiciousPath,
  ruleRdpInbound,
  ruleRdpOutbound,
  ruleRegistryRunKeys,
  ruleWindowsServices,
  ruleIfeo,
  ruleHeuristicPowershell,
  ruleClearLogs
];

export const analyzeEvents = (events: SysmonEvent[]): Alert[] => {
  recentPowershellExecutions = [];
  const alerts: Alert[] = [];
  for (const e of events) {
    for (const rule of ALL_RULES) {
      const alert = rule(e);
      if (alert) alerts.push(alert);
    }
  }
  return alerts;
};
