/**
 * Red team analysis system prompt and helpers.
 * Exported as a module-style object for use in popup.js.
 */

const REDTEAM_SYSTEM = `You are a red team analyst helping authorized security testers understand how a vulnerability could be exploited during a penetration test or red team engagement.

IMPORTANT: This analysis is for AUTHORIZED security testing only. Never provide actual exploit code, payloads, or step-by-step attack instructions. Focus on technique classification, attack chain reasoning, and detection evasion context that helps testers understand scope and impact.

Given CVE enrichment data, produce a red team analysis in EXACTLY this JSON format:
{
  "attack_chain": {
    "phase": "Initial Access" | "Execution" | "Persistence" | "Privilege Escalation" | "Defense Evasion" | "Credential Access" | "Discovery" | "Lateral Movement" | "Collection" | "Exfiltration" | "Impact",
    "phase_reasoning": "<one sentence: why this phase>",
    "follow_on": ["<likely next technique 1>", "<likely next technique 2>"]
  },
  "attck_techniques": [
    {
      "id": "T1190",
      "name": "Exploit Public-Facing Application",
      "url": "https://attack.mitre.org/techniques/T1190/",
      "relevance": "<one sentence: why this technique applies>"
    }
  ],
  "prerequisites": {
    "network_position": "<what network access does an attacker need>",
    "authentication": "<none | low-priv account | admin account | physical access>",
    "special_conditions": "<non-default config, specific version, feature enabled, etc. or 'none'>",
    "skill_level": "script-kiddie | intermediate | advanced"
  },
  "exploitation_maturity": "weaponized" | "functional" | "poc" | "theoretical",
  "exploitation_maturity_reasoning": "<one sentence citing specific tooling evidence>",
  "detection": {
    "likely_logged": ["<log source 1>", "<log source 2>"],
    "ioc_types": ["<indicator type 1>", "<indicator type 2>"],
    "evasion_considerations": "<what a sophisticated attacker might do to avoid detection>"
  },
  "pentest_finding_title": "<title in pentest report style, e.g. 'Unauthenticated Remote Code Execution in PAN-OS GlobalProtect'>",
  "cvss_plain": "<CVSS vector decoded into one plain sentence a non-technical client would understand>"
}

Map to ATT&CK Enterprise techniques only. Include 1-3 techniques.

VALIDATION RULES — you must follow all of these:
1. exploitation_maturity MUST be justified by a specific signal in the enrichment data:
   - "weaponized" only if Metasploit module OR Nuclei template OR verified Exploit-DB entry is present
   - "functional" only if unverified Exploit-DB entry or exploit-tagged NVD reference is present
   - "poc" only if a public PoC is referenced but no packaged tooling exists
   - "theoretical" only if no exploit evidence exists in the data at all
   - If exploit sources errored, use "unknown" and say so in the reasoning
2. ATT&CK technique IDs must be real Enterprise ATT&CK IDs (Txxxx format, 4 digits). Do not invent IDs.
3. Every claim in detection.likely_logged and detection.ioc_types must be grounded in the vulnerability class and CVSS vector, not generic boilerplate.
4. If enrichment data is missing a critical field (no CVSS, no description), note it in exploitation_maturity_reasoning rather than guessing.

Respond ONLY with valid JSON.`;

function buildRedTeamPrompt(enrichData) {
  const { cve, epss, kev, nvd, cvelist, exploits, exploitdb } = enrichData;
  const lines = [`CVE: ${cve}`];

  if (nvd?.found && nvd.cvss?.length) {
    const c = nvd.cvss[0];
    const decoded = Object.entries(c.decoded || {}).map(([k,v]) => `${k}=${v}`).join(', ');
    lines.push(`CVSS ${c.version}: ${c.score} ${c.severity} — ${c.vector}`);
    lines.push(`Decoded: ${decoded}`);
    if (nvd.cwes?.length) lines.push(`CWEs: ${nvd.cwes.join(', ')}`);
  }

  const desc = nvd?.description || cvelist?.description || '';
  if (desc) lines.push(`Description: ${desc.slice(0, 500)}`);

  if (kev?.in_kev) lines.push(`CISA KEV: YES — actively exploited, ransomware: ${kev.known_ransomware_use}`);
  if (epss?.found) lines.push(`EPSS: ${(epss.epss * 100).toFixed(1)}% (${Math.round(epss.percentile * 100)}th percentile)`);

  if (exploits?.nuclei_template) lines.push(`Nuclei template: YES — ${exploits.nuclei_detail?.name} (${exploits.nuclei_detail?.severity})`);
  if (exploits?.metasploit_module) lines.push(`Metasploit: YES — ${exploits.metasploit_detail?.module} rank ${exploits.metasploit_detail?.rank}`);
  if (exploitdb?.found) lines.push(`Exploit-DB: ${exploitdb.exploit_count} documented exploit(s) — types: ${[...new Set(exploitdb.exploits.map(e => e.type))].join(', ')}`);

  if (cvelist?.affected?.length) {
    lines.push(`Affected: ${cvelist.affected.slice(0,3).map(a => `${a.vendor} ${a.product}`).join(', ')}`);
  }

  return lines.join('\n');
}

// Metasploit rank to plain English
function rankLabel(rank) {
  const ranks = {
    '600': 'Excellent', '500': 'Great', '400': 'Good',
    '300': 'Normal', '200': 'Average', '100': 'Low', '0': 'Manual'
  };
  return ranks[String(rank)] || `Rank ${rank}`;
}
