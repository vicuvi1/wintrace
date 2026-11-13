// Plain-English one-liners for the timeline, plus the entity fields (user / ip / process)
// pulled out of each event. Covers Security, System, Sysmon, PowerShell, Defender, RDP, Task Scheduler.

export const LOGON_TYPES = {
  0: "system", 2: "interactive (keyboard)", 3: "network", 4: "batch", 5: "service", 7: "unlock",
  8: "network cleartext", 9: "new credentials (runas /netonly)", 10: "remote desktop", 11: "cached interactive",
};

export const KRB_ENC = { "0x1": "DES-CBC-CRC", "0x3": "DES-CBC-MD5", "0x11": "AES128", "0x12": "AES256", "0x17": "RC4-HMAC", "0x18": "RC4-HMAC-EXP" };

const FAIL_STATUS = {
  "0xc000006a": "wrong password", "0xc0000064": "user does not exist", "0xc000006d": "bad username or password",
  "0xc0000234": "account locked out", "0xc0000072": "account disabled", "0xc000006f": "outside allowed hours",
  "0xc0000070": "workstation restriction", "0xc0000071": "password expired", "0xc0000193": "account expired",
};

export const isSysmon = (e) => /sysmon/i.test(e.provider) || /sysmon/i.test(e.channel);
export const isSecurity = (e) => /security-auditing/i.test(e.provider) || e.channel === "Security";
export const isPowerShell = (e) => /powershell/i.test(e.provider) || /powershell/i.test(e.channel);
export const isDefender = (e) => /defender/i.test(e.provider) || /defender/i.test(e.channel);
export const isEventlogSvc = (e) => /eventlog/i.test(e.provider);

const v = (e, k) => {
  const x = e.data[k];
  return x == null || x === "-" ? "" : String(x).trim();
};
export const field = v;

export const user = (domain, name) => {
  if (!name) return "";
  if (name.includes("@")) return name.split("@")[0]; // UPN form (user@REALM) used by Kerberos events
  return domain && !/^(NT AUTHORITY|-|)$/i.test(domain) ? `${domain}\\${name}` : name;
};
const base = (p) => String(p || "").split(/[\\/]/).pop();
export const exeName = base;

// IPv4 "public" check (RFC 1918, loopback, link-local, CGNAT are private; 0/8 unspecified)
export function isPublicIp(ip) {
  const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(String(ip || "").replace(/^::ffff:/, ""));
  if (!m) return /^[0-9a-f:]+$/i.test(ip || "") && !/^(::1|fe80|fc|fd|::$)/i.test(ip || "") && String(ip).includes(":");
  const [a, b] = [Number(m[1]), Number(m[2])];
  return !(a === 10 || a === 127 || a === 0 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254) || (a === 100 && b >= 64 && b <= 127));
}

/** @returns {{title:string, detail:string, category:string, actor:string, target:string, ip:string, process:string, cmd:string}} */
export function describe(e, ctx = {}) {
  const d = (k) => v(e, k);
  const out = { title: `Event ${e.id}`, detail: "", category: "other", actor: "", target: "", ip: "", process: "", cmd: "" };
  const subj = user(d("SubjectDomainName"), d("SubjectUserName"));
  const targ = user(d("TargetDomainName"), d("TargetUserName"));
  const ip = d("IpAddress") || d("SourceNetworkAddress") || d("ClientAddress") || d("SourceIp") || d("Address");
  if (ip && !/^(::1|127\.0\.0\.1|-)$/.test(ip)) out.ip = ip.replace(/^::ffff:/, "");

  if (isSysmon(e)) {
    const img = d("Image");
    out.process = base(img);
    out.actor = d("User");
    switch (e.id) {
      case 1:
        out.cmd = d("CommandLine");
        return { ...out, category: "process", title: `Process started: ${base(img)}`, detail: `${out.cmd || img}${d("ParentImage") ? `  ← parent ${base(d("ParentImage"))}` : ""}` };
      case 3:
        out.ip = d("DestinationIp");
        return { ...out, category: "network", title: `Network connection by ${base(img)}`, detail: `${d("SourceIp")}:${d("SourcePort")} → ${d("DestinationIp")}:${d("DestinationPort")}${d("DestinationHostname") ? ` (${d("DestinationHostname")})` : ""}` };
      case 5: return { ...out, category: "process", title: `Process ended: ${base(img)}`, detail: img };
      case 7: return { ...out, category: "process", title: `Image loaded into ${base(img)}`, detail: d("ImageLoaded") };
      case 8: return { ...out, category: "injection", title: `Remote thread created in ${base(d("TargetImage"))}`, detail: `${base(d("SourceImage"))} → ${d("TargetImage")}`, process: base(d("SourceImage")) };
      case 10: return { ...out, category: "credential", title: `${base(d("SourceImage"))} opened ${base(d("TargetImage"))}`, detail: `access ${d("GrantedAccess")}  ${d("SourceImage")} → ${d("TargetImage")}`, process: base(d("SourceImage")), actor: d("SourceUser") || out.actor };
      case 11: return { ...out, category: "file", title: `File created by ${base(img)}`, detail: d("TargetFilename") };
      case 12: case 13: case 14:
        return { ...out, category: "registry", title: `Registry ${e.id === 13 ? "value set" : "key changed"} by ${base(img)}`, detail: `${d("TargetObject")}${d("Details") ? ` = ${d("Details")}` : ""}` };
      case 22: return { ...out, category: "network", title: `DNS query by ${base(img)}`, detail: `${d("QueryName")} → ${d("QueryResults")}` };
      case 23: case 26: return { ...out, category: "file", title: `File deleted by ${base(img)}`, detail: d("TargetFilename") };
      default: return { ...out, category: "sysmon", title: `Sysmon event ${e.id}`, detail: img };
    }
  }

  if (isPowerShell(e)) {
    if (e.id === 4104) {
      const sb = d("ScriptBlockText");
      return { ...out, category: "powershell", title: "PowerShell script block executed", detail: sb.replace(/\s+/g, " ").slice(0, 220), cmd: sb };
    }
    if (e.id === 4103) return { ...out, category: "powershell", title: "PowerShell command invoked", detail: (d("Payload") || d("ContextInfo")).replace(/\s+/g, " ").slice(0, 220) };
    if (e.id === 400 || e.id === 600 || e.id === 403) {
      const hc = (d("Data2") || d("HostApplication") || d("Data1") || "").replace(/\s+/g, " ");
      const m = /HostApplication=([^\r\n]+?)(?:\s+EngineVersion=|$)/i.exec(hc);
      return { ...out, category: "powershell", title: e.id === 403 ? "PowerShell engine stopped" : "PowerShell engine started", detail: (m ? m[1] : hc).slice(0, 220), cmd: m ? m[1] : "" };
    }
  }

  if (isDefender(e)) {
    if (e.id === 1116 || e.id === 1117) return { ...out, category: "malware", title: e.id === 1116 ? "Defender detected malware" : "Defender acted on malware", detail: `${d("Threat Name") || d("ThreatName")} · ${d("Path")} · ${d("Action Name") || ""}`.replace(/ · $/, "") };
    if ([5001, 5010, 5012].includes(e.id)) return { ...out, category: "defense", title: "Defender protection turned off", detail: `event ${e.id}` };
    if (e.id === 5007) return { ...out, category: "defense", title: "Defender configuration changed", detail: `${d("New Value") || d("NewValue")}` };
  }

  if (/TerminalServices-RemoteConnectionManager/i.test(e.provider) && e.id === 1149) {
    out.ip = d("Param3") || out.ip;
    return { ...out, category: "logon", title: "Remote Desktop connection authenticated", detail: `${user(d("Param2"), d("Param1"))} from ${d("Param3")}`, actor: user(d("Param2"), d("Param1")) };
  }
  if (/TerminalServices-LocalSessionManager/i.test(e.provider) && [21, 22, 24, 25].includes(e.id)) {
    out.ip = d("Address") || out.ip;
    return { ...out, category: "logon", title: { 21: "RDP session logon", 22: "RDP shell started", 24: "RDP session disconnected", 25: "RDP session reconnected" }[e.id], detail: `${d("User")} from ${d("Address")}`, actor: d("User") };
  }
  if (/TaskScheduler/i.test(e.provider) && [106, 140, 141, 200, 201].includes(e.id)) {
    return { ...out, category: "persistence", title: { 106: "Scheduled task registered", 140: "Scheduled task updated", 141: "Scheduled task deleted", 200: "Scheduled task action started", 201: "Scheduled task action finished" }[e.id], detail: `${d("TaskName")}${d("ActionName") ? ` → ${d("ActionName")}` : ""}`, actor: d("UserContext") || d("UserName") };
  }

  // ---- System log
  if (e.id === 7045 && /Service Control Manager/i.test(e.provider)) {
    return { ...out, category: "persistence", title: `Service installed: ${d("ServiceName")}`, detail: `${d("ImagePath")}  (start: ${d("StartType")}, account: ${d("AccountName")})`, actor: d("AccountName"), cmd: d("ImagePath") };
  }
  if (e.id === 7036 && /Service Control Manager/i.test(e.provider)) return { ...out, category: "service", title: `Service ${d("param2") || "state changed"}: ${d("param1")}`, detail: "" };
  if (e.id === 7040 && /Service Control Manager/i.test(e.provider)) return { ...out, category: "service", title: `Service start type changed: ${d("param1")}`, detail: `${d("param2")} → ${d("param3")}` };
  if (e.id === 104 && isEventlogSvc(e)) return { ...out, category: "defense", title: `Event log cleared: ${d("Channel") || d("BackupPath") || "System"}`, detail: `by ${user(d("SubjectDomainName"), d("SubjectUserName"))}`, actor: user(d("SubjectDomainName"), d("SubjectUserName")) };
  if ((e.id === 6005 || e.id === 6006) && /EventLog/i.test(e.provider)) return { ...out, category: "system", title: e.id === 6005 ? "Event log service started (boot)" : "Event log service stopped (shutdown)", detail: "" };

  // ---- Security log
  switch (e.id) {
    case 4624: {
      const lt = Number(d("LogonType"));
      return { ...out, category: "logon", actor: targ, title: `Logon success: ${targ || "?"} (${LOGON_TYPES[lt] || `type ${lt}`})`, detail: `${d("AuthenticationPackageName")}${d("LogonProcessName") ? `/${d("LogonProcessName")}` : ""}${out.ip ? ` from ${out.ip}` : ""}${d("WorkstationName") ? ` · ${d("WorkstationName")}` : ""}` };
    }
    case 4625: {
      const st = (d("SubStatus") && d("SubStatus") !== "0x0" ? d("SubStatus") : d("Status")).toLowerCase();
      return { ...out, category: "logon-fail", actor: targ, title: `Logon failed: ${targ || "?"}`, detail: `${FAIL_STATUS[st] || st}${out.ip ? ` from ${out.ip}` : ""} (${LOGON_TYPES[Number(d("LogonType"))] || "type " + d("LogonType")})` };
    }
    case 4634: case 4647: return { ...out, category: "logon", actor: targ, title: `Logoff: ${targ}`, detail: "" };
    case 4648: return { ...out, category: "logon", actor: subj, target: targ, title: `Explicit credentials used: ${subj} as ${targ}`, detail: `target server ${d("TargetServerName")}${d("ProcessName") ? ` via ${base(d("ProcessName"))}` : ""}` };
    case 4672: return { ...out, category: "privilege", actor: subj, title: `Admin privileges assigned to ${subj}`, detail: d("PrivilegeList").replace(/\s+/g, " ").slice(0, 160) };
    case 4688: out.process = base(d("NewProcessName")); out.cmd = d("CommandLine");
      return { ...out, category: "process", actor: subj, title: `Process started: ${out.process}`, detail: `${out.cmd || d("NewProcessName")}${d("ParentProcessName") ? `  ← parent ${base(d("ParentProcessName"))}` : ""}` };
    case 4697: return { ...out, category: "persistence", actor: subj, title: `Service installed: ${d("ServiceName")}`, detail: d("ServiceFileName"), cmd: d("ServiceFileName") };
    case 4698: case 4702: {
      const cmd = (/<Command>([\s\S]*?)<\/Command>/i.exec(d("TaskContent")) || [])[1] || "";
      const args = (/<Arguments>([\s\S]*?)<\/Arguments>/i.exec(d("TaskContent")) || [])[1] || "";
      return { ...out, category: "persistence", actor: subj, title: `Scheduled task ${e.id === 4698 ? "created" : "updated"}: ${d("TaskName")}`, detail: `${cmd} ${args}`.trim(), cmd: `${cmd} ${args}`.trim() };
    }
    case 4699: return { ...out, category: "persistence", actor: subj, title: `Scheduled task deleted: ${d("TaskName")}`, detail: "" };
    case 4719: return { ...out, category: "defense", actor: subj, title: "Audit policy changed", detail: `${d("CategoryId")} ${d("SubcategoryGuid")} ${d("AuditPolicyChanges")}` };
    case 4720: return { ...out, category: "account", actor: subj, target: targ, title: `User account created: ${targ}`, detail: `by ${subj}` };
    case 4722: return { ...out, category: "account", actor: subj, target: targ, title: `User account enabled: ${targ}`, detail: `by ${subj}` };
    case 4723: case 4724: return { ...out, category: "account", actor: subj, target: targ, title: `Password ${e.id === 4724 ? "reset" : "change attempt"}: ${targ}`, detail: `by ${subj}` };
    case 4725: return { ...out, category: "account", actor: subj, target: targ, title: `User account disabled: ${targ}`, detail: `by ${subj}` };
    case 4726: return { ...out, category: "account", actor: subj, target: targ, title: `User account deleted: ${targ}`, detail: `by ${subj}` };
    case 4728: case 4732: case 4756: {
      const member = d("MemberName").replace(/^CN=([^,]+).*/, "$1") || ctx.sids?.[d("MemberSid")] || d("MemberSid");
      return { ...out, category: "account", actor: subj, target: member, title: `Added to group ${targ}: ${member}`, detail: `by ${subj}` };
    }
    case 4729: case 4733: case 4757: return { ...out, category: "account", actor: subj, title: `Removed from group ${targ}`, detail: d("MemberName") || d("MemberSid") };
    case 4738: return { ...out, category: "account", actor: subj, target: targ, title: `User account changed: ${targ}`, detail: `by ${subj}` };
    case 4740: return { ...out, category: "logon-fail", target: targ, title: `Account locked out: ${targ}`, detail: `caller ${d("SubjectUserName") || d("TargetDomainName")}` };
    case 4768: return { ...out, category: "kerberos", actor: targ, title: `Kerberos TGT requested: ${targ}`, detail: `pre-auth ${d("PreAuthType")} · enc ${KRB_ENC[d("TicketEncryptionType").toLowerCase()] || d("TicketEncryptionType")} · status ${d("Status")}${out.ip ? ` · ${out.ip}` : ""}` };
    case 4769: return { ...out, category: "kerberos", actor: targ, target: d("ServiceName"), title: `Kerberos service ticket: ${d("ServiceName")}`, detail: `for ${targ} · enc ${KRB_ENC[d("TicketEncryptionType").toLowerCase()] || d("TicketEncryptionType")}${out.ip ? ` · ${out.ip}` : ""}` };
    case 4771: return { ...out, category: "logon-fail", actor: targ, title: `Kerberos pre-auth failed: ${targ}`, detail: `status ${d("Status")}${out.ip ? ` · ${out.ip}` : ""}` };
    case 4776: return { ...out, category: "logon", actor: d("TargetUserName"), title: `NTLM credential validation: ${d("TargetUserName")}`, detail: `workstation ${d("Workstation")} · status ${d("Status")}` };
    case 4662: return { ...out, category: "directory", actor: subj, title: `Directory object accessed by ${subj}`, detail: `${d("ObjectType")} ${d("Properties").replace(/\s+/g, " ").slice(0, 120)}` };
    case 5140: return { ...out, category: "share", actor: subj, title: `Network share accessed: ${d("ShareName")}`, detail: `${out.ip ? `from ${out.ip}` : ""}` };
    case 5145: return { ...out, category: "share", actor: subj, title: `Share file access: ${d("ShareName")}\\${d("RelativeTargetName")}`, detail: `${out.ip ? `from ${out.ip}` : ""}` };
    case 1102: return { ...out, category: "defense", actor: user(d("SubjectDomainName"), d("SubjectUserName")), title: "Security log cleared", detail: `by ${user(d("SubjectDomainName"), d("SubjectUserName"))}` };
    case 1100: return { ...out, category: "system", title: "Event logging service shut down", detail: "" };
    case 4608: return { ...out, category: "system", title: "Windows is starting up", detail: "" };
    case 4616: return { ...out, category: "system", actor: subj, title: "System time changed", detail: `${d("PreviousTime")} → ${d("NewTime")}` };
    case 4946: case 4947: return { ...out, category: "defense", actor: subj, title: `Firewall rule ${e.id === 4946 ? "added" : "changed"}: ${d("RuleName")}`, detail: "" };
    case 4950: return { ...out, category: "defense", title: "Firewall setting changed", detail: `${d("SettingType")} ${d("SettingValue")}` };
  }
  if (d("Message")) out.detail = d("Message").replace(/\s+/g, " ").slice(0, 200);
  return out;
}
