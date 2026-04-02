# Compliance Frameworks Reference

SOC 2 Trust Service Criteria, framework section number mappings, incident response playbook, and audit report structure.

## Table of Contents

- [SOC 2 Trust Service Criteria](#soc-2-trust-service-criteria)
- [Compliance Section Number References](#compliance-section-number-references)
- [Incident Response Playbook](#incident-response-playbook)
- [Security Audit Report Structure](#security-audit-report-structure)

## SOC 2 Trust Service Criteria

### Common Criteria (CC1-CC9)

| Criteria | Name | Key Controls |
|----------|------|-------------|
| CC1 | Control Environment | Security policies, organizational structure, board oversight |
| CC2 | Communication and Information | Internal/external communication of security policies, change management |
| CC3 | Risk Assessment | Risk identification, analysis of changes, fraud considerations |
| CC4 | Monitoring Activities | Ongoing evaluations, deficiency remediation, audit committee oversight |
| CC5 | Control Activities | Policies and procedures, technology controls, segregation of duties |
| CC6 | Logical and Physical Access | Access provisioning, authentication, removal of access, physical security |
| CC7 | System Operations | Infrastructure monitoring, incident management, change management, backup |
| CC8 | Change Management | Change authorization, testing, approval, implementation |
| CC9 | Risk Mitigation | Risk mitigation activities, vendor management, business continuity |

### Additional Criteria

| Criteria | Name | Key Controls |
|----------|------|-------------|
| Availability | System availability | Capacity planning, disaster recovery, BCP, monitoring |
| Processing Integrity | System processing | Data completeness, accuracy, timeliness, authorization |
| Confidentiality | Information confidentiality | Data classification, encryption, access controls, retention |
| Privacy | Personal information | Collection notice, consent, use/retention/disposal, access, disclosure |

## Compliance Section Number References

Use these specific section references when citing compliance implications:

### PCI-DSS v4.0

| Requirement | Topic | Example Citation |
|-------------|-------|-----------------|
| 1.x | Network segmentation | "PCI-DSS Req 1.3.1 (restrict inbound traffic)" |
| 2.x | Secure configurations | "PCI-DSS Req 2.2.1 (system hardening standards)" |
| 3.x | Stored data protection | "PCI-DSS Req 3.4.1 (render PAN unreadable)" |
| 4.x | Encryption in transit | "PCI-DSS Req 4.2.1 (strong cryptography for transmission)" |
| 5.x | Malware protection | "PCI-DSS Req 5.2 (anti-malware mechanisms)" |
| 6.x | Secure development | "PCI-DSS Req 6.2.4 (software engineering techniques for injection prevention)" |
| 7.x | Access control | "PCI-DSS Req 7.2.1 (access control model)" |
| 8.x | Authentication | "PCI-DSS Req 8.3.6 (password complexity)" |
| 10.x | Logging and monitoring | "PCI-DSS Req 10.2.1 (audit log content)" |
| 11.x | Security testing | "PCI-DSS Req 11.3.1 (internal vulnerability scans)" |
| 12.x | Security policies | "PCI-DSS Req 12.1.1 (security policy review)" |

### HIPAA

| Section | Topic | Example Citation |
|---------|-------|-----------------|
| §164.308 | Administrative safeguards | "HIPAA §164.308(a)(1)(ii)(A) (risk analysis)" |
| §164.310 | Physical safeguards | "HIPAA §164.310(a)(1) (facility access controls)" |
| §164.312(a) | Access control | "HIPAA §164.312(a)(1) (unique user identification)" |
| §164.312(b) | Audit controls | "HIPAA §164.312(b) (audit controls)" |
| §164.312(c) | Integrity | "HIPAA §164.312(c)(1) (data integrity)" |
| §164.312(d) | Authentication | "HIPAA §164.312(d) (person or entity authentication)" |
| §164.312(e) | Transmission security | "HIPAA §164.312(e)(1) (encryption in transit)" |

### GDPR

| Article | Topic | Example Citation |
|---------|-------|-----------------|
| Art. 5 | Data processing principles | "GDPR Art. 5(1)(f) (integrity and confidentiality)" |
| Art. 25 | Data protection by design | "GDPR Art. 25(1) (data protection by design and default)" |
| Art. 32 | Security of processing | "GDPR Art. 32(1)(a) (encryption of personal data)" |
| Art. 33 | Breach notification | "GDPR Art. 33(1) (72-hour breach notification)" |
| Art. 35 | Impact assessment | "GDPR Art. 35 (data protection impact assessment)" |

### NIST Cybersecurity Framework

| Function | Category | Example Citation |
|----------|----------|-----------------|
| Identify | Asset Management | "NIST CSF ID.AM-1 (physical device inventory)" |
| Protect | Data Security | "NIST CSF PR.DS-1 (data at rest protection)" |
| Protect | Access Control | "NIST CSF PR.AC-1 (identity and credential management)" |
| Detect | Anomalies | "NIST CSF DE.AE-1 (network baseline established)" |
| Respond | Response Planning | "NIST CSF RS.RP-1 (response plan executed)" |
| Recover | Recovery Planning | "NIST CSF RC.RP-1 (recovery plan executed)" |

### OWASP ASVS v4.0

| Chapter | Topic | Example Citation |
|---------|-------|-----------------|
| V1 | Architecture | "OWASP ASVS V1.2.1 (authentication architecture)" |
| V2 | Authentication | "OWASP ASVS V2.1.1 (password length requirements)" |
| V3 | Session Management | "OWASP ASVS V3.2.1 (session binding)" |
| V4 | Access Control | "OWASP ASVS V4.1.1 (access control at trusted service layer)" |
| V5 | Validation | "OWASP ASVS V5.2.1 (output encoding)" |
| V8 | Data Protection | "OWASP ASVS V8.1.1 (sensitive data identification)" |
| V9 | Communications | "OWASP ASVS V9.1.1 (TLS for all connections)" |
| V14 | Configuration | "OWASP ASVS V14.2.1 (component integrity)" |

## Incident Response Playbook

### Response Sequence

```
DETECT → CONTAIN → INVESTIGATE → REMEDIATE → RECOVER → LEARN
```

| Phase | Actions | Timeline |
|-------|---------|----------|
| **Detect** | Identify incident type, severity, scope. Activate response team. | 0-1 hours |
| **Contain** | Isolate affected systems, disable compromised accounts, block malicious IPs, preserve evidence. | 1-4 hours |
| **Investigate** | Determine initial access vector, map lateral movement, identify data exfiltration, document IOCs. | 4-48 hours |
| **Remediate** | Remove malware/backdoors, close exploited vulnerabilities, reset credentials, apply patches. | 1-7 days |
| **Recover** | Restore from clean backups, rebuild compromised systems, verify integrity, gradually restore services. | 1-14 days |
| **Learn** | Post-mortem analysis, root cause documentation, lessons learned, update controls and response plan. | Within 30 days |

### Evidence Collection Checklist

- [ ] Memory dumps from affected systems
- [ ] Disk images for forensic analysis
- [ ] Authentication logs (successful and failed)
- [ ] Application and web server logs
- [ ] Network traffic captures (PCAP)
- [ ] DNS query logs
- [ ] Firewall and IDS/IPS logs
- [ ] Database access logs

## Security Audit Report Structure

```
1. Executive Summary
   - Scope, methodology, key findings, overall risk rating

2. Detailed Findings
   - For each finding: ID, title, severity, CVSS, evidence, description, recommendation

3. Compliance Matrix
   - Map findings to applicable framework requirements (PCI-DSS, SOC 2, etc.)

4. Risk Assessment
   - Overall risk posture, threat landscape, business impact

5. Remediation Recommendations
   - Prioritized fix list, effort estimates, verification steps

6. Technical Appendices
   - Raw scan data, configuration snapshots, evidence screenshots
```
