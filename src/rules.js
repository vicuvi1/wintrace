// Detection rules. Two kinds:
//  - single-event rules: one event is enough (log cleared, LSASS access, encoded PowerShell, …)
//  - correlation rules: patterns across events and time (brute force, spraying, kerberoasting bursts, …)
// Every alert carries the ids of the events that triggered it, so the UI can show the evidence.
import { field as f, isDefender, isEventlogSvc, isPowerShell, isPublicIp, isSecurity, isSysmon, exeName, user } from "./describe.js";

const PRIV_GROUPS = /^(administrators|domain admins|enterprise admins|schema admins|account operators|backup operators|server operators|remote desktop users|dnsadmins|group policy creator owners|administratoren|administrateurs)$/i;
const SYSTEM_ACCOUNTS = /^(system|local service|network service|anonymous logon|-|)$|\$$/i;
const LSASS_OK_SOURCES = /\\(msmpeng|svchost|wininit|csrss|lsm|services|wmiprvse|taskmgr|vmtoolsd|mrt|sense\w*|csfalcon\w*|cb\w*|sysmon64?)\.exe$/i;
const LSASS_ACCESS = /^0x(1010|1410|1418|1438|143a|1f0fff|1f1fff|1f2fff|1f3fff|1fffff|40|1400)$/i;
const DCSYNC_GUIDS = /1131f6aa-9c07-11d1-f79f-00c04fc2dcd2|1131f6ad-9c07-11d1-f79f-00c04fc2dcd2|89e95b76-444d-4c62-991a-0facbeda640c/i;

// Text rules run on every "command-ish" field: process command lines, PowerShell script blocks,
// service image paths and scheduled-task commands.
export const COMMAND_RULES = [
  { id: "mimikatz", sev: "critical", title: "Mimikatz credential theft", mitre: ["T1003.001"], re: /mimikatz|sekurlsa::|lsadump::|kerberos::(golden|ptt)|privilege::debug|Invoke-Mimikatz/i, story: "ran Mimikatz to steal credentials" },
  { id: "lsass_minidump", sev: "critical", title: "LSASS memory dump (comsvcs MiniDump)", mitre: ["T1003.001"], re: /comsvcs(\.dll)?[\s,]+(#\s*24|MiniDump)/i, story: "dumped LSASS memory with comsvcs.dll" },
  { id: "procdump_lsass", sev: "critical", title: "LSASS memory dump (procdump)", mitre: ["T1003.001"], re: /procdump(64)?(\.exe)?\b[^\r\n]*\blsass/i, story: "dumped LSASS memory with procdump" },
  { id: "sam_hive", sev: "high", title: "Registry hive saved (SAM/SYSTEM/SECURITY)", mitre: ["T1003.002"], re: /reg(\.exe)?\s+save\s+"?hklm\\(sam|system|security)/i, story: "saved the SAM/SYSTEM registry hives to extract password hashes" },
  { id: "ntds", sev: "critical", title: "Active Directory database (NTDS.dit) extraction", mitre: ["T1003.003"], re: /ntdsutil[^\r\n]*\bifm|ntds\.dit/i, story: "copied the Active Directory database (NTDS.dit)" },
  { id: "shadow_delete", sev: "critical", title: "Shadow copies / backups deleted", mitre: ["T1490"], re: /vssadmin(\.exe)?\s+delete\s+shadows|wmic(\.exe)?\s+shadowcopy\s+delete|wbadmin(\.exe)?\s+delete\s+(catalog|systemstatebackup)|bcdedit(\.exe)?[^\r\n]*recoveryenabled\s+no/i, story: "deleted shadow copies so files can't be restored (typical right before ransomware)" },
  { id: "wevtutil_clear", sev: "critical", title: "Event log cleared from the command line", mitre: ["T1070.001"], re: /wevtutil(\.exe)?\s+(cl|clear-log)\b|Clear-EventLog/i, story: "cleared event logs from the command line" },
  { id: "defender_tamper", sev: "high", title: "Microsoft Defender disabled or excluded", mitre: ["T1562.001"], re: /Set-MpPreference[^\r\n]*-Disable(RealtimeMonitoring|BehaviorMonitoring|IOAVProtection|ScriptScanning)\s+(\$true|1)|Add-MpPreference[^\r\n]*-Exclusion(Path|Process|Extension)|sc(\.exe)?\s+(stop|config)\s+WinDefend|DisableAntiSpyware/i, story: "turned off or blinded Microsoft Defender" },
  { id: "firewall_off", sev: "high", title: "Windows Firewall disabled", mitre: ["T1562.004"], re: /netsh(\.exe)?\s+(advfirewall\s+set\s+\w+\s+state\s+off|firewall\s+set\s+opmode\s+disable)|Set-NetFirewallProfile[^\r\n]*-Enabled\s+False/i, story: "disabled the Windows Firewall" },
  { id: "amsi_bypass", sev: "high", title: "AMSI bypass attempt", mitre: ["T1562.001"], re: /AmsiUtils|amsiInitFailed|AmsiScanBuffer/i, story: "tried to bypass AMSI (PowerShell malware scanning)" },
  { id: "encoded_ps", sev: "high", title: "Encoded PowerShell command", mitre: ["T1059.001", "T1027"], re: /powershell(\.exe)?[^\r\n]*\s-(e|ec|en|enc|enco|encod|encode|encoded|encodedcommand)\s+[A-Za-z0-9+/=]{16,}/i, story: "ran an obfuscated (base64-encoded) PowerShell command" },
  { id: "download_cradle", sev: "high", title: "PowerShell download cradle", mitre: ["T1059.001", "T1105"], re: /(DownloadString|DownloadFile|DownloadData)\s*\(|(IEX|Invoke-Expression)[^\r\n]*(Net\.WebClient|Invoke-WebRequest|iwr\s|curl\s|wget\s|irm\s)|Start-BitsTransfer[^\r\n]*http/i, story: "downloaded and ran code from the internet with PowerShell" },
  { id: "certutil_download", sev: "high", title: "certutil used to download a file", mitre: ["T1105"], re: /certutil(\.exe)?[^\r\n]*-(urlcache|verifyctl)[^\r\n]*https?:/i, story: "abused certutil to download a file" },
  { id: "certutil_decode", sev: "medium", title: "certutil used to decode a file", mitre: ["T1140"], re: /certutil(\.exe)?[^\r\n]*\s-decode(hex)?\s/i, story: "decoded a hidden payload with certutil" },
  { id: "bitsadmin", sev: "medium", title: "bitsadmin download job", mitre: ["T1197", "T1105"], re: /bitsadmin(\.exe)?[^\r\n]*\/(transfer|addfile)[^\r\n]*https?:/i, story: "used BITS to download a file" },
  { id: "mshta", sev: "high", title: "mshta running remote or inline script", mitre: ["T1218.005"], re: /mshta(\.exe)?\s+["']?(https?:|javascript:|vbscript:)/i, story: "used mshta to run a remote script" },
  { id: "regsvr32", sev: "high", title: "regsvr32 Squiblydoo (remote scriptlet)", mitre: ["T1218.010"], re: /regsvr32(\.exe)?[^\r\n]*\/i:\s*https?:|regsvr32[^\r\n]*scrobj\.dll/i, story: "used regsvr32 to run a remote scriptlet" },
  { id: "rundll32_script", sev: "high", title: "rundll32 running script or URL", mitre: ["T1218.011"], re: /rundll32(\.exe)?[^\r\n]*(javascript:|mshtml,RunHTMLApplication|https?:\/\/)/i, story: "abused rundll32 to run script code" },
  { id: "wmic_exec", sev: "medium", title: "WMI used to start a process", mitre: ["T1047"], re: /wmic(\.exe)?[^\r\n]*process\s+call\s+create|Invoke-WmiMethod[^\r\n]*Win32_Process|Invoke-CimMethod[^\r\n]*Win32_Process/i, story: "used WMI to start a process" },
  { id: "net_user_add", sev: "medium", title: "Account created with net user /add", mitre: ["T1136.001"], re: /net1?(\.exe)?\s+user\s+\S+\s+\S*\s*\/add/i, story: "created a user account from the command line" },
  { id: "net_admin_add", sev: "high", title: "User added to Administrators from the command line", mitre: ["T1098"], re: /net1?(\.exe)?\s+(localgroup|group)\s+"?(administrators|domain admins|enterprise admins|remote desktop users)"?\s+\S+\s+\/add/i, story: "added an account to an admin group from the command line" },
  { id: "schtasks_create", sev: "medium", title: "Scheduled task created from the command line", mitre: ["T1053.005"], re: /schtasks(\.exe)?\s+\/create/i, story: "created a scheduled task for persistence" },
  { id: "ad_recon_tools", sev: "high", title: "Active Directory recon tool (BloodHound / AdFind)", mitre: ["T1087.002", "T1069.002"], re: /sharphound|bloodhound|adfind(\.exe)?|Invoke-BloodHound|Get-DomainUser|Get-NetUser/i, story: "ran Active Directory reconnaissance tooling" },
  { id: "rubeus", sev: "high", title: "Kerberos attack tool (Rubeus / Invoke-Kerberoast)", mitre: ["T1558.003"], re: /Rubeus(\.exe)?\s+(kerberoast|asreproast|dump|tgtdeleg|s4u|ptt|golden|silver)|Invoke-Kerberoast|Invoke-Rubeus/i, story: "ran a Kerberos attack tool to steal crackable service tickets" },
  { id: "psexec", sev: "medium", title: "PsExec remote execution", mitre: ["T1569.002", "T1021.002"], re: /psexec(64)?(\.exe)?\s+[^\r\n]*\\\\[\w.-]+/i, story: "used PsExec to run commands on another machine" },
];

// low-severity reconnaissance commands; several in a short time become a "discovery burst"
export const RECON = [
  { re: /\bwhoami(\.exe)?\b/i, what: "whoami", mitre: "T1033" },
  { re: /\bnet1?(\.exe)?\s+(user|group|localgroup)\b[^\r\n]*\/domain|\bnet1?(\.exe)?\s+group\s+"?domain admins/i, what: "net group/user /domain", mitre: "T1087.002" },
  { re: /\bnltest(\.exe)?\s+[^\r\n]*\/(dclist|domain_trusts|dsgetdc)/i, what: "nltest", mitre: "T1482" },
  { re: /\bsysteminfo(\.exe)?\b/i, what: "systeminfo", mitre: "T1082" },
  { re: /\bipconfig(\.exe)?\s+\/all/i, what: "ipconfig /all", mitre: "T1016" },
  { re: /\bquser(\.exe)?\b|\bquery\s+user\b/i, what: "quser", mitre: "T1033" },
  { re: /\barp(\.exe)?\s+-a\b/i, what: "arp -a", mitre: "T1016" },
  { re: /\bnet1?(\.exe)?\s+(view|share|session)\b/i, what: "net view/share", mitre: "T1087.002" },
  { re: /\bGet-AD(User|Group|Computer|Domain)\b/i, what: "Get-AD*", mitre: "T1087.002" },
];

const OFFICE = /\\(winword|excel|powerpnt|outlook|onenote|msaccess|mspub)\.exe$/i;
const SHELLS = /\\(cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin)\.exe$/i;

function decodePsBase64(cmd) {
  const m = /\s-(?:e|ec|en|enc|enco|encod|encode|encoded|encodedcommand)\s+([A-Za-z0-9+/=]{16,})/i.exec(cmd);
  if (!m) return "";
  try {
    const bin = atob(m[1]);
    const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
    return new TextDecoder("utf-16le").decode(bytes).replace(/\0/g, "");
  } catch {
    return "";
  }
}

// The text an event "executes", if any
function commandText(e, D) {
  if (isSysmon(e) && e.id === 1) return f(e, "CommandLine") || f(e, "Image");
  if (isSecurity(e) && e.id === 4688) return f(e, "CommandLine") || f(e, "NewProcessName");
  if (isPowerShell(e) && (e.id === 4104 || e.id === 4103)) return f(e, "ScriptBlockText") || f(e, "Payload");
  if (isPowerShell(e) && (e.id === 400 || e.id === 600)) return D.cmd;
  if ((e.id === 7045 && /Service Control Manager/i.test(e.provider)) || (isSecurity(e) && e.id === 4697)) return f(e, "ImagePath") || f(e, "ServiceFileName");
  if (isSecurity(e) && (e.id === 4698 || e.id === 4702)) return D.cmd;
  return "";
}

const SEV_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

export function detect(events, described) {
  const alerts = [];
  const add = (a) => alerts.push({ count: 1, ...a, host: a.host ?? "", user: a.user ?? "", ip: a.ip ?? "" });
  const D = (e) => described[e.idx];
  const at = (e) => ({ time: e.time, ts: e.ts, host: e.computer });

  for (const e of events) {
    const d = D(e);
    const txt = commandText(e, d);

    // --- command-line / script content
    if (txt) {
      for (const r of COMMAND_RULES) {
        if (r.id === "encoded_ps" && isPowerShell(e)) continue; // script blocks are already decoded
        if (r.re.test(txt)) {
          const decoded = r.id === "encoded_ps" ? decodePsBase64(txt) : "";
          let sev = r.sev;
          if (decoded && COMMAND_RULES.some((x) => x.id !== "encoded_ps" && x.re.test(decoded))) sev = "critical";
          add({ rule: r.id, title: r.title, severity: sev, mitre: r.mitre, events: [e.idx], ...at(e), user: d.actor, detail: txt.replace(/\s+/g, " ").slice(0, 400), decoded, story: r.story, key: `${r.id}|${e.computer}` });
        }
      }
    }

    // --- Office application spawning a shell (macro / exploit)
    const parent = isSysmon(e) && e.id === 1 ? f(e, "ParentImage") : isSecurity(e) && e.id === 4688 ? f(e, "ParentProcessName") : "";
    const child = isSysmon(e) && e.id === 1 ? f(e, "Image") : isSecurity(e) && e.id === 4688 ? f(e, "NewProcessName") : "";
    if (OFFICE.test(parent) && SHELLS.test(child)) {
      add({ rule: "office_child", title: `${exeName(parent)} started ${exeName(child)}`, severity: "high", mitre: ["T1566.001", "T1204.002"], events: [e.idx], ...at(e), user: d.actor, detail: txt || child, story: `opened a malicious Office document: ${exeName(parent)} launched ${exeName(child)}`, key: `office|${e.computer}|${child}` });
    }

    // --- single events
    if ((isSecurity(e) || isEventlogSvc(e)) && e.id === 1102) {
      add({ rule: "log_cleared", title: "Security log cleared", severity: "critical", mitre: ["T1070.001"], events: [e.idx], ...at(e), user: d.actor, detail: d.detail, story: "cleared the Security event log to hide their tracks" });
    }
    if (isEventlogSvc(e) && e.id === 104) {
      add({ rule: "log_cleared", title: `${f(e, "Channel") || "System"} log cleared`, severity: "critical", mitre: ["T1070.001"], events: [e.idx], ...at(e), user: d.actor, detail: d.detail, story: `cleared the ${f(e, "Channel") || "System"} event log` });
    }
    if (isSecurity(e) && e.id === 4719) {
      add({ rule: "audit_policy", title: "Audit policy changed", severity: "high", mitre: ["T1562.002"], events: [e.idx], ...at(e), user: d.actor, detail: d.detail, story: "changed the audit policy so fewer events get logged" });
    }
    if ((e.id === 7045 && /Service Control Manager/i.test(e.provider)) || (isSecurity(e) && e.id === 4697)) {
      const img = f(e, "ImagePath") || f(e, "ServiceFileName");
      const name = f(e, "ServiceName");
      const psexec = /psexesvc|paexec|remcom|csexec/i.test(`${img} ${name}`);
      const bad = psexec || /%comspec%|cmd(\.exe)?\s+\/c|powershell|\\temp\\|\\users\\public\\|\\programdata\\|admin\$|\\\\127\.0\.0\.1\\|rundll32|mshta|regsvr32|-enc\b|\.bat\b|\.vbs\b/i.test(img);
      add({ rule: psexec ? "psexec_service" : "service_installed", title: psexec ? `PsExec-style service installed (${name})` : `New service installed: ${name}`, severity: bad ? "high" : "low", mitre: psexec ? ["T1569.002", "T1021.002", "T1543.003"] : ["T1543.003"], events: [e.idx], ...at(e), user: d.actor, detail: img, story: psexec ? `installed the ${name} service: remote command execution, PsExec-style` : `installed a new service "${name}"${bad ? " that runs a suspicious command" : ""}`, key: `svc|${e.computer}|${name}|${img}` });
    }
    if (isSecurity(e) && e.id === 4698) {
      const bad = COMMAND_RULES.some((r) => r.re.test(d.cmd)) || /\\temp\\|\\users\\public\\|appdata|powershell|cmd(\.exe)?\s+\/c|mshta|rundll32|regsvr32|https?:/i.test(d.cmd);
      add({ rule: "task_created", title: `Scheduled task created: ${f(e, "TaskName")}`, severity: bad ? "high" : "low", mitre: ["T1053.005"], events: [e.idx], ...at(e), user: d.actor, detail: d.cmd, story: `created the scheduled task ${f(e, "TaskName")}${bad ? " to run a suspicious command" : ""}`, key: `task|${e.computer}|${f(e, "TaskName")}` });
    }
    if (isSecurity(e) && e.id === 4720) {
      add({ rule: "user_created", title: `User account created: ${d.target}`, severity: "medium", mitre: ["T1136.001"], events: [e.idx], ...at(e), user: d.actor, detail: d.detail, story: `created a new account "${d.target}"`, target: d.target });
    }
    if (isSecurity(e) && [4728, 4732, 4756].includes(e.id) && PRIV_GROUPS.test(f(e, "TargetUserName"))) {
      add({ rule: "priv_group_add", title: `${d.target} added to ${f(e, "TargetUserName")}`, severity: "high", mitre: ["T1098"], events: [e.idx], ...at(e), user: d.actor, detail: `${d.target} → ${f(e, "TargetUserName")} (by ${d.actor})`, story: `added "${d.target}" to the ${f(e, "TargetUserName")} group`, target: d.target, key: `grp|${e.computer}|${d.target}|${f(e, "TargetUserName")}` });
    }
    if (isSecurity(e) && e.id === 4768 && f(e, "PreAuthType") === "0" && /^0x0$/i.test(f(e, "Status") || "0x0")) {
      add({ rule: "asrep_roast", title: "AS-REP roasting (no Kerberos pre-authentication)", severity: "high", mitre: ["T1558.004"], events: [e.idx], ...at(e), user: f(e, "TargetUserName"), ip: d.ip, detail: `TGT issued without pre-auth for ${f(e, "TargetUserName")}${d.ip ? ` to ${d.ip}` : ""}`, story: `requested a Kerberos ticket for ${f(e, "TargetUserName")} without pre-authentication, so the password can be cracked offline`, key: `asrep|${f(e, "TargetUserName")}` });
    }
    if (isSecurity(e) && e.id === 4624) {
      const lt = f(e, "LogonType");
      const tu = f(e, "TargetUserName");
      if (lt === "9" && /seclogo/i.test(f(e, "LogonProcessName"))) {
        add({ rule: "pth_seclogo", title: "Pass-the-hash logon (new credentials, seclogo)", severity: "high", mitre: ["T1550.002"], events: [e.idx], ...at(e), user: d.actor, detail: d.detail, story: `used stolen credentials (pass-the-hash) as ${user(f(e, "TargetOutboundDomainName"), f(e, "TargetOutboundUserName")) || d.actor}`, key: `pth9|${e.computer}|${d.actor}` });
      } else if (lt === "3" && /ntlm/i.test(f(e, "AuthenticationPackageName")) && f(e, "KeyLength") === "0" && !SYSTEM_ACCOUNTS.test(tu) && d.ip) {
        add({ rule: "pth_ntlm", title: "NTLM network logon without session key (possible pass-the-hash)", severity: "medium", mitre: ["T1550.002"], events: [e.idx], ...at(e), user: d.actor, ip: d.ip, detail: d.detail, story: `logged on to ${e.computer} over the network as ${d.actor} with an NTLM logon typical of pass-the-hash`, key: `pthntlm|${e.computer}|${d.actor}|${d.ip}` });
      }
      if (lt === "10" && d.ip && isPublicIp(d.ip)) {
        add({ rule: "rdp_external", title: "Remote Desktop logon from the internet", severity: "medium", mitre: ["T1133", "T1021.001"], events: [e.idx], ...at(e), user: d.actor, ip: d.ip, detail: d.detail, story: `logged in over Remote Desktop from ${d.ip} as ${d.actor}`, key: `rdp|${e.computer}|${d.ip}|${d.actor}` });
      }
    }
    if (isSecurity(e) && e.id === 4662 && DCSYNC_GUIDS.test(f(e, "Properties")) && !/\$$/.test(f(e, "SubjectUserName"))) {
      add({ rule: "dcsync", title: "DCSync: directory replication requested by a non-DC account", severity: "critical", mitre: ["T1003.006"], events: [e.idx], ...at(e), user: d.actor, detail: d.detail, story: `${d.actor} asked the domain controller to replicate password hashes (DCSync), the way Mimikatz steals every password in the domain`, key: `dcsync|${d.actor}` });
    }
    if (isSecurity(e) && (e.id === 5140 || e.id === 5145) && /\\(admin|c)\$$/i.test(f(e, "ShareName")) && d.ip) {
      const exe = /\.(exe|dll|bat|ps1|vbs)$/i.test(f(e, "RelativeTargetName"));
      const psexec = /psexesvc|paexec|remcom/i.test(f(e, "RelativeTargetName"));
      add({ rule: "admin_share", title: psexec ? "PsExec binary copied over ADMIN$" : `Admin share accessed: ${f(e, "ShareName")}`, severity: psexec || exe ? "high" : "medium", mitre: ["T1021.002"], events: [e.idx], ...at(e), user: d.actor, ip: d.ip, detail: `${f(e, "ShareName")}\\${f(e, "RelativeTargetName")} from ${d.ip}`, story: psexec ? `copied PsExec's service binary to ${e.computer} over the ADMIN$ share` : `accessed the ${f(e, "ShareName")} admin share on ${e.computer} from ${d.ip}`, key: `share|${e.computer}|${d.ip}|${psexec || exe}` });
    }

    // --- Sysmon
    if (isSysmon(e) && e.id === 10 && /\\lsass\.exe$/i.test(f(e, "TargetImage")) && LSASS_ACCESS.test(f(e, "GrantedAccess")) && !LSASS_OK_SOURCES.test(f(e, "SourceImage"))) {
      add({ rule: "lsass_access", title: `LSASS memory read by ${exeName(f(e, "SourceImage"))}`, severity: "critical", mitre: ["T1003.001"], events: [e.idx], ...at(e), user: d.actor, detail: `${f(e, "SourceImage")} opened lsass.exe with access ${f(e, "GrantedAccess")}`, story: `read the memory of LSASS (where Windows keeps passwords) using ${exeName(f(e, "SourceImage"))}`, key: `lsass|${e.computer}|${f(e, "SourceImage")}` });
    }
    if (isSysmon(e) && (e.id === 12 || e.id === 13) && /\\(Software\\(WOW6432Node\\)?Microsoft\\Windows\\CurrentVersion\\(Run|RunOnce|RunServices)|Winlogon\\(Userinit|Shell))\\/i.test(f(e, "TargetObject"))) {
      add({ rule: "run_key", title: "Autostart registry key set", severity: "high", mitre: ["T1547.001"], events: [e.idx], ...at(e), user: d.actor, detail: `${f(e, "TargetObject")} = ${f(e, "Details")}`, story: `added a Run key so ${exeName(f(e, "Details")) || "a program"} starts at every logon`, key: `run|${e.computer}|${f(e, "TargetObject")}` });
    }
    if (isSysmon(e) && e.id === 11 && /\\Start Menu\\Programs\\Startup\\/i.test(f(e, "TargetFilename"))) {
      add({ rule: "startup_folder", title: "File dropped in the Startup folder", severity: "high", mitre: ["T1547.001"], events: [e.idx], ...at(e), user: d.actor, detail: f(e, "TargetFilename"), story: `dropped ${exeName(f(e, "TargetFilename"))} in the Startup folder for persistence` });
    }
    if (isSysmon(e) && e.id === 3 && /\\(powershell|pwsh|rundll32|regsvr32|mshta|certutil|bitsadmin|wscript|cscript|msbuild|installutil)\.exe$/i.test(f(e, "Image")) && isPublicIp(f(e, "DestinationIp"))) {
      add({ rule: "lolbin_network", title: `${exeName(f(e, "Image"))} connected to the internet`, severity: "high", mitre: ["T1071.001"], events: [e.idx], ...at(e), user: d.actor, ip: f(e, "DestinationIp"), detail: d.detail, story: `${exeName(f(e, "Image"))} called out to ${f(e, "DestinationHostname") || f(e, "DestinationIp")}:${f(e, "DestinationPort")}, a likely command-and-control channel`, key: `net|${e.computer}|${f(e, "Image")}|${f(e, "DestinationIp")}` });
    }
    if (isSysmon(e) && e.id === 8 && /\\(lsass|explorer|svchost|winlogon)\.exe$/i.test(f(e, "TargetImage"))) {
      add({ rule: "remote_thread", title: `Code injected into ${exeName(f(e, "TargetImage"))}`, severity: "high", mitre: ["T1055"], events: [e.idx], ...at(e), user: d.actor, detail: d.detail, story: `injected code into ${exeName(f(e, "TargetImage"))}` });
    }

    // --- Defender
    if (isDefender(e) && (e.id === 1116 || e.id === 1117)) {
      add({ rule: "defender_detection", title: `Defender: ${f(e, "Threat Name") || f(e, "ThreatName") || "malware detected"}`, severity: "high", mitre: [], events: [e.idx], ...at(e), user: d.actor, detail: d.detail, story: `triggered a Microsoft Defender detection (${f(e, "Threat Name") || f(e, "ThreatName") || "malware"})`, key: `def|${e.computer}|${f(e, "Threat Name")}` });
    }
    if (isDefender(e) && [5001, 5010, 5012].includes(e.id)) {
      add({ rule: "defender_disabled", title: "Defender real-time protection turned off", severity: "high", mitre: ["T1562.001"], events: [e.idx], ...at(e), detail: d.detail, story: "turned off Microsoft Defender real-time protection" });
    }
  }

  correlate(events, described, add);
  return mergeAlerts(alerts);
}

// --------------------------------------------------------------------------- correlations
function correlate(events, described, add) {
  const D = (e) => described[e.idx];
  const MIN = 60_000;

  // Brute force & spraying on 4625 (and 4771 Kerberos pre-auth failures)
  const fails = events.filter((e) => isSecurity(e) && (e.id === 4625 || e.id === 4771));
  const byKey = new Map();
  for (const e of fails) {
    const src = D(e).ip || f(e, "WorkstationName") || "unknown source";
    const k = `${e.computer}|${src}`;
    if (!byKey.has(k)) byKey.set(k, []);
    byKey.get(k).push(e);
  }
  const attackers = [];
  for (const [k, list] of byKey) {
    const [host, src] = k.split("|");
    // sliding 10-minute window for guessing, 30 minutes for spraying
    for (let i = 0, j = 0; j < list.length; j++) {
      while (list[j].ts - list[i].ts > 10 * MIN) i++;
      const win = list.slice(i, j + 1);
      if (win.length >= 10) {
        const users = new Set(win.map((e) => D(e).actor.toLowerCase()));
        const spray = users.size >= 5;
        const all = list.filter((e) => e.ts >= win[0].ts - 30 * MIN && e.ts <= win[win.length - 1].ts + 30 * MIN);
        const allUsers = [...new Set(all.map((e) => D(e).actor))];
        add({
          rule: spray ? "password_spray" : "brute_force",
          title: spray ? `Password spraying: ${allUsers.length} accounts from ${src}` : `Brute force: ${all.length} failed logons for ${allUsers[0]} from ${src}`,
          severity: "high",
          mitre: [spray ? "T1110.003" : "T1110.001"],
          events: all.map((e) => e.idx),
          time: all[0].time, ts: all[0].ts, host, ip: src, user: allUsers.slice(0, 5).join(", "),
          detail: `${all.length} failed logons in ${Math.max(1, Math.round((all[all.length - 1].ts - all[0].ts) / MIN))} min against ${allUsers.slice(0, 8).join(", ")}${allUsers.length > 8 ? "…" : ""}`,
          story: spray ? `tried common passwords against ${allUsers.length} accounts from ${src} (password spraying, ${all.length} attempts)` : `guessed passwords for ${allUsers[0]} from ${src}: ${all.length} failed logons`,
          key: `bf|${host}|${src}`,
        });
        attackers.push({ host, src, users: new Set(allUsers.map((u) => u.toLowerCase())), last: all[all.length - 1].ts, first: all[0].ts });
        break;
      }
    }
  }
  // ...followed by a successful logon from the same source = the attacker got in
  for (const a of attackers) {
    const ok = events.find((e) => isSecurity(e) && e.id === 4624 && e.ts >= a.first && e.ts - a.last <= 60 * MIN && (D(e).ip === a.src || f(e, "WorkstationName") === a.src) && !SYSTEM_ACCOUNTS.test(f(e, "TargetUserName")));
    if (ok) {
      add({ rule: "bruteforce_success", title: `Brute force succeeded: ${D(ok).actor} logged in from ${a.src}`, severity: "critical", mitre: ["T1110.001", "T1078"], events: [ok.idx], time: ok.time, ts: ok.ts, host: ok.computer, ip: a.src, user: D(ok).actor, detail: D(ok).title + " · " + D(ok).detail, story: `got in: logged on successfully as ${D(ok).actor} from the same address ${a.src}` });
    }
  }

  // Kerberoasting: RC4 service tickets for user (non-machine) SPNs
  const rc4 = events.filter((e) => isSecurity(e) && e.id === 4769 && /^0x(17|18)$/i.test(f(e, "TicketEncryptionType")) && !/\$$/.test(f(e, "ServiceName")) && !/^krbtgt$/i.test(f(e, "ServiceName")) && /^0x0$/i.test(f(e, "Status") || "0x0"));
  const byUser = new Map();
  for (const e of rc4) {
    const u = D(e).actor.toLowerCase();
    if (!byUser.has(u)) byUser.set(u, []);
    byUser.get(u).push(e);
  }
  for (const list of byUser.values()) {
    const services = [...new Set(list.map((e) => f(e, "ServiceName")))];
    const burst = services.length >= 3;
    add({
      rule: "kerberoast", title: burst ? `Kerberoasting: ${services.length} RC4 service tickets requested by ${D(list[0]).actor}` : `RC4 Kerberos service ticket for ${services[0]}`,
      severity: burst ? "high" : "medium", mitre: ["T1558.003"], events: list.map((e) => e.idx), time: list[0].time, ts: list[0].ts, host: list[0].computer, user: D(list[0]).actor, ip: D(list[0]).ip,
      detail: `weak RC4 tickets for ${services.slice(0, 8).join(", ")}${services.length > 8 ? "…" : ""}`,
      story: burst ? `requested crackable RC4 tickets for ${services.length} service accounts (${services.slice(0, 3).join(", ")}…), the classic Kerberoasting attack` : `requested a crackable RC4 ticket for ${services[0]}`,
      key: `kerb|${D(list[0]).actor}`,
    });
  }

  // Discovery burst: 4+ different recon commands on one host within 10 minutes
  const recon = [];
  for (const e of events) {
    const txt = isSysmon(e) && e.id === 1 ? f(e, "CommandLine") : isSecurity(e) && e.id === 4688 ? f(e, "CommandLine") || f(e, "NewProcessName") : "";
    if (!txt) continue;
    const r = RECON.find((x) => x.re.test(txt));
    if (r) recon.push({ e, r });
  }
  const byHost = new Map();
  for (const x of recon) {
    if (!byHost.has(x.e.computer)) byHost.set(x.e.computer, []);
    byHost.get(x.e.computer).push(x);
  }
  for (const [host, list] of byHost) {
    for (let i = 0, j = 0; j < list.length; j++) {
      while (list[j].e.ts - list[i].e.ts > 10 * MIN) i++;
      const win = list.slice(i, j + 1);
      const kinds = [...new Set(win.map((x) => x.r.what))];
      if (kinds.length >= 4) {
        add({ rule: "discovery_burst", title: `Discovery burst on ${host}: ${kinds.length} recon commands`, severity: "medium", mitre: [...new Set(win.map((x) => x.r.mitre))], events: win.map((x) => x.e.idx), time: win[0].e.time, ts: win[0].e.ts, host, user: D(win[0].e).actor, detail: kinds.join(", "), story: `looked around the network and domain (${kinds.join(", ")}): hands-on-keyboard reconnaissance`, key: `recon|${host}` });
        break;
      }
    }
  }

  // Backdoor admin: an account created and then put in a privileged group within an hour
  for (const c of events.filter((e) => isSecurity(e) && e.id === 4720)) {
    const name = f(c, "TargetUserName").toLowerCase();
    const sid = f(c, "TargetSid");
    const g = events.find((e) => isSecurity(e) && [4728, 4732, 4756].includes(e.id) && PRIV_GROUPS.test(f(e, "TargetUserName")) && e.ts >= c.ts && e.ts - c.ts <= 60 * MIN && ((sid && f(e, "MemberSid") === sid) || (name && D(e).target.toLowerCase().includes(name))));
    if (g) {
      add({ rule: "backdoor_admin", title: `Backdoor admin account: ${f(c, "TargetUserName")}`, severity: "critical", mitre: ["T1136.001", "T1098"], events: [c.idx, g.idx], time: c.time, ts: c.ts, host: c.computer, user: D(c).actor, detail: `${f(c, "TargetUserName")} created and added to ${f(g, "TargetUserName")} ${Math.round((g.ts - c.ts) / 1000)}s later`, story: `created "${f(c, "TargetUserName")}" and made it an administrator: a backdoor account to come back later` });
    }
  }
}

function mergeAlerts(alerts) {
  const merged = new Map();
  const out = [];
  for (const a of alerts) {
    if (!a.key) {
      out.push(a);
      continue;
    }
    const m = merged.get(a.key);
    if (m) {
      m.count += a.count;
      m.events.push(...a.events);
      if (SEV_RANK[a.severity] > SEV_RANK[m.severity]) m.severity = a.severity;
      if (a.decoded && !m.decoded) m.decoded = a.decoded;
    } else {
      merged.set(a.key, a);
      out.push(a);
    }
  }
  out.forEach((a) => (a.events = [...new Set(a.events)]));
  return out.sort((x, y) => x.ts - y.ts);
}
