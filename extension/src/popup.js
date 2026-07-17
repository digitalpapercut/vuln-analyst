/**
 * popup.js — agent orchestration, SSVC reasoning, rendering
 *
 * Flow:
 *   1. Detect CVE from page (via storage) or manual input
 *   2. Fetch enrichment bundle via background.js
 *   3. LLM call with enrichment + SSVC methodology → verdict
 *   4. Render triage, research, and write-up panels
 */

// ─── state ──────────────────────────────────────────────────────────────────
let currentCVE = null;
let enrichData = null;
let triageResult = null;
let settings = null;

// ─── init ───────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', async () => {
  settings = await msg('GET_SETTINGS');

  // Pre-fill from detected CVE on page
  const stored = await chrome.storage.local.get('detected_cve');
  if (stored.detected_cve) {
    $('cveInput').value = stored.detected_cve;
  }

  $('analyzeBtn').addEventListener('click', startAnalysis);
  $('cveInput').addEventListener('keydown', e => { if (e.key === 'Enter') startAnalysis(); });
  $('openOptions').addEventListener('click', () => chrome.runtime.openOptionsPage());

  // Tab switching
  document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => switchTab(tab.dataset.tab));
  });
});

// ─── helpers ────────────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);

function msg(type, payload = {}) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage({ type, ...payload }, res => {
      if (chrome.runtime.lastError) return reject(new Error(chrome.runtime.lastError.message));
      if (!res.ok) return reject(new Error(res.error));
      resolve(res.settings ?? res.data ?? res.text ?? true);
    });
  });
}

function showPanel(id) {
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  $(id)?.classList.add('active');
}

function switchTab(name) {
  document.querySelectorAll('.tab').forEach(t => t.classList.toggle('active', t.dataset.tab === name));
  showPanel(`panel-${name}`);
}

function setLoading(message) {
  $('loadingMsg').textContent = message;
  showPanel('panel-loading');
  $('tabs').style.display = 'none';
}

function epssColor(score) {
  if (score >= 0.5)  return 'sig-high';
  if (score >= 0.1)  return 'sig-med';
  if (score > 0)     return 'sig-low';
  return 'sig-none';
}

function epssLabel(score, percentile) {
  if (score === undefined || score === null) return '—';
  return `${(score * 100).toFixed(1)}% · p${Math.round(percentile * 100)}`;
}

function escHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// ─── analysis entry point ───────────────────────────────────────────────────
async function startAnalysis() {
  const cve = $('cveInput').value.trim().toUpperCase();
  if (!/^CVE-\d{4}-\d{4,}$/.test(cve)) {
    $('cveInput').style.borderColor = 'var(--act)';
    setTimeout(() => $('cveInput').style.borderColor = '', 1500);
    return;
  }

  currentCVE = cve;
  $('analyzeBtn').disabled = true;
  settings = await msg('GET_SETTINGS');

  if (!settings.apiKey) {
    showNoKeyState();
    $('analyzeBtn').disabled = false;
    return;
  }

  try {
    setLoading('Fetching EPSS, CISA KEV, NVD, exploit signals…');
    enrichData = await msg('FETCH_ENRICHMENT', { cve });

    setLoading('Running SSVC triage analysis…');
    triageResult = await runSSVCTriage(enrichData, settings);

    renderAll();
    $('tabs').style.display = 'flex';
    switchTab('triage');
  } catch (e) {
    showError(e.message);
  } finally {
    $('analyzeBtn').disabled = false;
  }
}

// ─── SSVC triage via LLM ───────────────────────────────────────────────────
async function runSSVCTriage(data, cfg) {
  const system = buildSSVCSystemPrompt();
  const userMsg = buildEnrichmentSummary(data);

  const text = await msg('CALL_LLM', {
    messages: [{ role: 'user', content: userMsg }],
    system,
    provider: cfg.provider,
    model: cfg.model,
    apiKey: cfg.apiKey,
  });

  return parseTriageResponse(text, data);
}

function buildSSVCSystemPrompt() {
  return `You are a vulnerability analyst using the CISA SSVC decision tree.

Given enrichment data for a CVE, produce a triage analysis in EXACTLY this JSON format:
{
  "decision": "ACT" | "ATTEND" | "TRACK_STAR" | "TRACK",
  "exploitation": "active" | "poc" | "none",
  "exploitation_evidence": "<one sentence citing specific evidence>",
  "automatable": "yes" | "no",
  "automatable_reasoning": "<one sentence citing CVSS vector>",
  "technical_impact": "total" | "partial",
  "technical_impact_reasoning": "<one sentence>",
  "mission_context_needed": true | false,
  "summary": "<2-3 sentences: what it is, why the decision, the single most important driver>",
  "would_change": ["<condition 1>", "<condition 2>"],
  "title": "<short vulnerability name, 5 words max>"
}

Rules:
- exploitation=active ONLY if in CISA KEV or credible confirmed exploitation reporting
- exploitation=poc if Nuclei template OR Metasploit module OR exploit-tagged references exist
- A Metasploit module or Nuclei template also strongly supports automatable=yes
- technical_impact=total for RCE, auth bypass to admin, full credential exposure
- mission_context_needed=true when the decision depends on whether asset is internet-facing
- Respond ONLY with valid JSON. No markdown, no explanation outside the JSON.`;
}

function buildEnrichmentSummary(data) {
  const { cve, epss, kev, nvd, cvelist, exploits } = data;
  const lines = [`CVE: ${cve}`];

  if (epss?.found) {
    lines.push(`EPSS: ${(epss.epss * 100).toFixed(2)}% (${Math.round(epss.percentile * 100)}th percentile) as of ${epss.date}`);
  }

  if (kev?.in_kev) {
    lines.push(`CISA KEV: YES — added ${kev.date_added}, due ${kev.due_date}, ransomware: ${kev.known_ransomware_use}`);
    lines.push(`KEV required action: ${kev.required_action}`);
  } else {
    lines.push(`CISA KEV: NOT LISTED`);
  }

  if (nvd?.found && nvd.cvss?.length) {
    const c = nvd.cvss[0];
    const decoded = Object.entries(c.decoded || {}).map(([k,v]) => `${k}=${v}`).join(', ');
    lines.push(`CVSS: ${c.score} ${c.severity} (${c.vector})`);
    lines.push(`Decoded: ${decoded}`);
    if (nvd.cwes?.length) lines.push(`CWEs: ${nvd.cwes.join(', ')}`);
  }

  if (nvd?.found) {
    lines.push(`Description: ${(nvd.description || '').slice(0, 400)}`);
  } else if (cvelist?.found) {
    lines.push(`Description: ${(cvelist.description || '').slice(0, 400)}`);
  }

  if (exploits) {
    if (exploits.nuclei_template) {
      lines.push(`Nuclei template: YES — ${exploits.nuclei_detail?.name || ''} (severity: ${exploits.nuclei_detail?.severity || 'unknown'})`);
    } else {
      lines.push(`Nuclei template: NO`);
    }
    if (exploits.metasploit_module) {
      lines.push(`Metasploit module: YES — ${exploits.metasploit_detail?.module || ''} (rank: ${exploits.metasploit_detail?.rank || 'unknown'})`);
    } else {
      lines.push(`Metasploit module: NO`);
    }
  }

  const edb = data.exploitdb;
  if (edb?.found) {
    lines.push(`Exploit-DB: ${edb.exploit_count} documented exploit(s) — types: ${[...new Set(edb.exploits.map(e => e.type))].join(', ')}`);
    const verified = edb.exploits.filter(e => e.verified);
    if (verified.length) lines.push(`  Verified exploits: ${verified.length} (${verified.map(e => e.title.slice(0,60)).join('; ')})`);
  } else {
    lines.push('Exploit-DB: no documented exploits found');
  }

  if (cvelist?.cisa_adp_ssvc) {
    lines.push(`CISA ADP SSVC assessment: ${JSON.stringify(cvelist.cisa_adp_ssvc)}`);
  }

  if (nvd?.found) {
    const exploitRefs = (nvd.references || []).filter(r => r.tags?.includes('Exploit'));
    if (exploitRefs.length) lines.push(`Exploit-tagged references: ${exploitRefs.length} found`);
  }

  return lines.join('\n');
}

function parseTriageResponse(text, data) {
  try {
    const cleaned = text.replace(/```json|```/g, '').trim();
    return JSON.parse(cleaned);
  } catch {
    // Fallback: extract decision from text
    const decisionMatch = text.match(/\b(ACT|ATTEND|TRACK_STAR|TRACK)\b/);
    return {
      decision: decisionMatch?.[1] || 'TRACK',
      summary: text.slice(0, 500),
      exploitation: data.kev?.in_kev ? 'active' : 'none',
      automatable: 'no',
      technical_impact: 'partial',
      mission_context_needed: true,
      would_change: [],
      title: '',
      parse_error: true,
    };
  }
}

// ─── rendering ──────────────────────────────────────────────────────────────
function renderAll() {
  renderTriage();
  renderEnrich();
  renderComms();
  renderRedTeam();
}

function renderTriage() {
  const t = triageResult;
  const d = enrichData;
  const epss = d.epss;
  const kev = d.kev;
  const exploits = d.exploits;

  const decisionDisplay = t.decision === 'TRACK_STAR' ? 'TRACK*' : t.decision;
  const badgeClass = { ACT: 'badge-ACT', ATTEND: 'badge-ATTEND', TRACK_STAR: 'badge-TRACKS', TRACK: 'badge-TRACK' }[t.decision] || 'badge-TRACK';
  const title = escHtml(t.title || '');
  const nvdDesc = d.nvd?.found ? (d.nvd.description || '').slice(0, 120) : (d.cvelist?.description || '').slice(0, 120);

  const exploitVal = exploits?.weaponized_tooling_public
    ? `<span class="sig-exploit">Public tool</span>`
    : exploits?.nuclei_template || exploits?.metasploit_module
      ? `<span class="sig-exploit">Yes</span>`
      : `<span class="sig-none">None found</span>`;

  const kevVal = kev?.in_kev
    ? `<span class="sig-kev">In KEV ${kev.date_added ? `(${kev.date_added})` : ''}</span>`
    : `<span class="sig-none">Not listed</span>`;

  const epssVal = epss?.found
    ? `<span class="${epssColor(epss.epss)}">${epssLabel(epss.epss, epss.percentile)}</span>`
    : `<span class="sig-none">—</span>`;

  const wouldChange = (t.would_change || []).map(c =>
    `<li>${escHtml(c)}</li>`).join('');

  const inputs = [
    { label: 'Exploitation', value: escHtml(t.exploitation || '—'), color: t.exploitation === 'active' ? 'sig-high' : t.exploitation === 'poc' ? 'sig-med' : 'sig-none' },
    { label: 'Automatable', value: escHtml(t.automatable || '—'), color: t.automatable === 'yes' ? 'sig-high' : 'sig-none' },
    { label: 'Tech Impact', value: escHtml(t.technical_impact || '—'), color: t.technical_impact === 'total' ? 'sig-high' : 'sig-med' },
    { label: 'Mission', value: t.mission_context_needed ? '<span class="sig-med">Needed ↓</span>' : 'Provided', color: '' },
  ].map(i => `
    <div class="input-chip">
      <span class="chip-label">${i.label}</span>
      <span class="chip-value ${i.color}">${i.value}</span>
    </div>`).join('');

  $('panel-triage').innerHTML = `
    <div class="verdict-card">
      <div class="verdict-header">
        <span class="verdict-badge ${badgeClass}">${decisionDisplay}</span>
        <span class="verdict-cve">${escHtml(currentCVE)}</span>
        <span class="verdict-title">${title}</span>
      </div>
      <div class="signals">
        <div class="signal"><span class="signal-label">EPSS</span><span class="signal-value">${epssVal}</span></div>
        <div class="signal"><span class="signal-label">KEV</span><span class="signal-value">${kevVal}</span></div>
        <div class="signal"><span class="signal-label">Exploit Tool</span><span class="signal-value">${exploitVal}</span></div>
      </div>
    </div>

    <div class="section-label">SSVC Decision Inputs</div>
    <div class="inputs-grid">${inputs}</div>

    ${t.mission_context_needed ? renderContextForm() : ''}

    <div class="section">
      <div class="section-label">What this means</div>
      <div class="section-body"><p>${escHtml(t.summary || '')}</p></div>
    </div>

    ${t.exploitation_evidence ? `
    <div class="section">
      <div class="section-label">Exploitation evidence</div>
      <div class="section-body"><p>${escHtml(t.exploitation_evidence)}</p>${t.automatable_reasoning ? `<p>${escHtml(t.automatable_reasoning)}</p>` : ''}</div>
    </div>` : ''}

    ${wouldChange ? `
    <div class="section">
      <div class="section-label">Would change this decision</div>
      <ul class="change-list">${wouldChange}</ul>
    </div>` : ''}

    <div class="section">
      <div class="section-label">Sources</div>
      <div class="sources">
        ${epss?.found ? `<span class="source-tag fresh">EPSS ${epss.date}</span>` : ''}
        ${kev?.in_kev ? `<span class="source-tag fresh">CISA KEV ${kev.date_added}</span>` : '<span class="source-tag">CISA KEV (not listed)</span>'}
        ${d.nvd?.found ? `<span class="source-tag fresh">NVD</span>` : ''}
        ${d.cvelist?.found ? `<span class="source-tag fresh">cvelistV5</span>` : ''}
        ${exploits?.nuclei_template ? `<span class="source-tag fresh">Nuclei templates</span>` : ''}
        ${exploits?.metasploit_module ? `<span class="source-tag fresh">Metasploit</span>` : ''}
      </div>
    </div>`;

  if (t.mission_context_needed) {
    document.getElementById('refineBtn')?.addEventListener('click', refineWithContext);
  }
}

function renderContextForm() {
  return `
    <div class="context-form">
      <p>The verdict may change based on your environment. Answer these to refine:</p>
      <div class="form-row">
        <label class="form-label">Asset exposure</label>
        <select id="ctx-exposure">
          <option value="">Select…</option>
          <option value="internet-facing">Internet-facing</option>
          <option value="internal">Internal network only</option>
          <option value="isolated">Air-gapped / isolated</option>
        </select>
      </div>
      <div class="form-row">
        <label class="form-label">Mission impact if compromised or offline</label>
        <select id="ctx-mission">
          <option value="">Select…</option>
          <option value="high">High — mission-essential system</option>
          <option value="medium">Medium — supporting system</option>
          <option value="low">Low — minimal impact</option>
        </select>
      </div>
      <div class="form-row">
        <label class="form-label">Compensating controls (optional)</label>
        <textarea id="ctx-controls" placeholder="e.g. WAF rule blocking exploit path, feature disabled, network segmentation…" rows="2"></textarea>
      </div>
      <button class="btn" id="refineBtn" style="width:100%;margin-top:4px">Refine with context</button>
    </div>`;
}

async function refineWithContext() {
  const exposure = document.getElementById('ctx-exposure')?.value;
  const mission  = document.getElementById('ctx-mission')?.value;
  const controls = document.getElementById('ctx-controls')?.value;
  if (!exposure || !mission) return;

  document.getElementById('refineBtn').disabled = true;
  document.getElementById('refineBtn').textContent = 'Analyzing…';

  try {
    const context = `Environmental context:\n- Exposure: ${exposure}\n- Mission impact: ${mission}\n${controls ? `- Controls: ${controls}` : ''}`;
    const system = buildSSVCSystemPrompt() + '\n\nApply the provided environmental context to finalize the Mission & Well-being input and re-render the SSVC decision.';
    const text = await msg('CALL_LLM', {
      messages: [
        { role: 'user', content: buildEnrichmentSummary(enrichData) },
        { role: 'assistant', content: JSON.stringify(triageResult) },
        { role: 'user', content: context },
      ],
      system,
      provider: settings.provider,
      model: settings.model,
      apiKey: settings.apiKey,
    });
    triageResult = parseTriageResponse(text, enrichData);
    triageResult.mission_context_needed = false;
    renderTriage();
  } catch (e) {
    document.getElementById('refineBtn').textContent = `Error: ${e.message}`;
    document.getElementById('refineBtn').disabled = false;
  }
}

function renderEnrich() {
  const d = enrichData;
  const nvd = d.nvd;
  const cvelist = d.cvelist;
  const epss = d.epss;
  const kev = d.kev;
  const osv = d.osv;
  const exploits = d.exploits;

  const desc = nvd?.description || cvelist?.description || 'No description available.';
  const cvss = nvd?.cvss?.[0];
  const decodedParts = cvss?.decoded
    ? Object.entries(cvss.decoded).map(([k,v]) => `<span class="source-tag">${k.replace(/_/g,' ')}: ${v}</span>`).join('')
    : '';

  const affected = (cvelist?.affected || []).slice(0, 6).map(a =>
    `<div style="padding:4px 0;border-bottom:1px solid var(--border);font-size:12px">
      <span style="color:var(--accent2)">${escHtml(a.vendor || '')} ${escHtml(a.product || '')}</span>
      ${a.versions?.length ? `<span style="color:var(--muted);margin-left:6px">${a.versions.slice(0,3).map(v => escHtml(v.version || v.lessThan || '')).join(', ')}</span>` : ''}
    </div>`).join('');

  const aliases = [...(osv?.aliases || []), ...(osv?.related || [])].slice(0, 8)
    .map(a => `<span class="source-tag">${escHtml(a)}</span>`).join('');

  $('panel-enrich').innerHTML = `
    <div class="section">
      <div class="section-label">Description</div>
      <div class="section-body"><p>${escHtml(desc.slice(0, 600))}${desc.length > 600 ? '…' : ''}</p></div>
    </div>

    ${cvss ? `
    <div class="section">
      <div class="section-label">CVSS ${cvss.version} — ${cvss.score} ${cvss.severity}</div>
      <div class="sources" style="margin-bottom:6px">${decodedParts}</div>
    </div>` : ''}

    ${nvd?.cwes?.length ? `
    <div class="section">
      <div class="section-label">Weakness (CWE)</div>
      <div class="section-body"><p>${escHtml(nvd.cwes.join(', '))}</p></div>
    </div>` : ''}

    ${d.exploitdb?.found ? `
    <div class="section">
      <div class="section-label">⚠ Exploit-DB entries (${d.exploitdb.exploit_count})</div>
      <div class="section-body">
        ${d.exploitdb.exploits.slice(0,5).map(e =>
          `<p><a href="${escHtml(e.url)}" target="_blank" style="color:var(--accent2)">${escHtml(e.title.slice(0,80))}</a>
          <span style="color:var(--muted)"> · ${escHtml(e.type)} · ${escHtml(e.platform)} · ${e.verified ? '<span style="color:var(--attend)">verified</span>' : 'unverified'}</span></p>`
        ).join('')}
      </div>
    </div>` : ''}

    ${exploits?.weaponized_tooling_public ? `
    <div class="section">
      <div class="section-label">⚠ Public exploit tooling</div>
      <div class="section-body">
        ${exploits.nuclei_template ? `<p>Nuclei template: ${escHtml(exploits.nuclei_detail?.name || '')} (${escHtml(exploits.nuclei_detail?.severity || '')})</p>` : ''}
        ${exploits.metasploit_module ? `<p>Metasploit: ${escHtml(exploits.metasploit_detail?.module || '')} [rank: ${escHtml(exploits.metasploit_detail?.rank || '')}]</p>` : ''}
      </div>
    </div>` : ''}

    ${kev?.in_kev ? `
    <div class="section">
      <div class="section-label">CISA KEV</div>
      <div class="section-body">
        <p>Added: ${escHtml(kev.date_added)} · Due: ${escHtml(kev.due_date)}</p>
        <p>Ransomware: ${escHtml(kev.known_ransomware_use)}</p>
        <p>Required action: ${escHtml(kev.required_action || '')}</p>
      </div>
    </div>` : ''}

    ${affected ? `
    <div class="section">
      <div class="section-label">Affected versions</div>
      ${affected}
    </div>` : ''}

    ${aliases ? `
    <div class="section">
      <div class="section-label">Identifier aliases</div>
      <div class="sources">${aliases}</div>
    </div>` : ''}

    <div class="section">
      <div class="section-label">Data fetched</div>
      <div class="section-body" style="color:var(--muted);font-size:11px">${escHtml(d.fetched_at)}</div>
    </div>`;
}

function renderComms() {
  const t = triageResult;
  $('panel-comms').innerHTML = `
    <div class="section">
      <div class="section-label">Generate write-up</div>
      <div class="section-body" style="margin-bottom:10px">
        <p>Choose the format and audience. The write-up uses your triage evidence — no hallucinated data.</p>
      </div>
      <div class="form-row">
        <label class="form-label">Format</label>
        <select id="comms-format">
          <option value="exec">Executive summary (≤200 words)</option>
          <option value="ticket">Remediation ticket</option>
          <option value="accept">Risk-acceptance / deferral memo</option>
        </select>
      </div>
      <div class="form-row">
        <label class="form-label">Additional context (optional)</label>
        <textarea id="comms-context" rows="2" placeholder="Asset name, team, patch window, compensating controls…"></textarea>
      </div>
      <button class="btn" id="genCommsBtn" style="width:100%">Generate</button>
    </div>
    <div id="comms-output"></div>`;

  $('genCommsBtn').addEventListener('click', generateComms);
}

async function generateComms() {
  const format = $('comms-format').value;
  const context = $('comms-context').value;
  $('genCommsBtn').disabled = true;
  $('genCommsBtn').textContent = 'Generating…';

  const formatInstructions = {
    exec: 'Write an executive summary in ≤200 words. Lead with business exposure (what could happen, to which system, how likely). No CVSS jargon in the first sentence. End with one clear ask and date.',
    ticket: `Write a remediation ticket. Include:
Title: [DECISION] CVE in Component — Action by Date
Body: affected asset and versions, fixed version or workaround, why now (one line of exploitation evidence), validation step.`,
    accept: `Write a risk-acceptance memo. Include:
- Finding (CVE, asset, severity, exploitation status with date)
- Decision (accept/defer to date, decision owner)
- Rationale (specific compensating controls or business constraint)
- Conditions that void this acceptance
- Review date`,
  };

  try {
    const text = await msg('CALL_LLM', {
      messages: [{
        role: 'user',
        content: `CVE: ${currentCVE}
SSVC Decision: ${triageResult.decision}
Summary: ${triageResult.summary}
Exploitation: ${triageResult.exploitation} — ${triageResult.exploitation_evidence || ''}
EPSS: ${enrichData.epss?.found ? `${(enrichData.epss.epss*100).toFixed(1)}% (${Math.round(enrichData.epss.percentile*100)}th percentile) as of ${enrichData.epss.date}` : 'not scored'}
KEV: ${enrichData.kev?.in_kev ? `yes, added ${enrichData.kev.date_added}` : 'not listed'}
${context ? `Additional context: ${context}` : ''}

${formatInstructions[format]}`,
      }],
      system: 'You are a security analyst writing practitioner communications. VALIDATION RULES: (1) Only cite metrics that appear explicitly in the data provided — never estimate or interpolate missing values, use "not available" instead. (2) Every number must include its source and date, e.g. "EPSS 0.94 as of 2026-07-16 per FIRST.org". (3) If the SSVC decision is not provided, do not invent one. (4) Do not add context, threat actor names, or exploitation details not present in the enrichment data. Be specific, use plain language for non-technical audiences in exec summaries.',
      provider: settings.provider,
      model: settings.model,
      apiKey: settings.apiKey,
    });

    $('comms-output').innerHTML = `
      <div class="section" style="margin-top:12px">
        <div class="section-label">Generated write-up</div>
        <div class="section-body" style="white-space:pre-wrap;background:var(--surface);padding:10px;border-radius:var(--radius);border:1px solid var(--border)">${escHtml(text)}</div>
      </div>
      <button class="btn btn-ghost" id="copyComms" style="width:100%;margin-top:8px">Copy to clipboard</button>`;

    $('copyComms').addEventListener('click', () => {
      navigator.clipboard.writeText(text);
      $('copyComms').textContent = 'Copied!';
      setTimeout(() => $('copyComms').textContent = 'Copy to clipboard', 2000);
    });
  } catch (e) {
    $('comms-output').innerHTML = `<p style="color:var(--act);padding:8px 0;font-size:12px">Error: ${escHtml(e.message)}</p>`;
  } finally {
    $('genCommsBtn').disabled = false;
    $('genCommsBtn').textContent = 'Generate';
  }
}


// ─── red team panel ─────────────────────────────────────────────────────────
function renderRedTeam() {
  $('panel-redteam').innerHTML = `
    <div class="disclaimer-box">
      ⚠ For authorized security testing only. This tab provides technique classification and attack chain context — not exploit code or attack instructions.
    </div>
    <div class="section">
      <div class="section-label">ATT&CK Analysis</div>
      <div class="section-body" style="margin-bottom:10px">
        <p>Maps this vulnerability to MITRE ATT&CK techniques, attack chain phase, prerequisites, and detection context for authorized engagements.</p>
      </div>
      <button class="btn" id="genRedTeamBtn" style="width:100%">Generate Red Team Analysis</button>
    </div>
    <div id="redteam-output"></div>`;
  $('genRedTeamBtn').addEventListener('click', generateRedTeam);
}

async function generateRedTeam() {
  $('genRedTeamBtn').disabled = true;
  $('genRedTeamBtn').textContent = 'Analyzing…';
  $('redteam-output').innerHTML = '';

  try {
    const prompt = buildRedTeamPrompt(enrichData);
    const text = await msg('CALL_LLM', {
      messages: [{ role: 'user', content: prompt }],
      system: REDTEAM_SYSTEM,
      provider: settings.provider,
      model: settings.model,
      apiKey: settings.apiKey,
    });

    let analysis;
    try {
      analysis = JSON.parse(text.replace(/```json|```/g, '').trim());
    } catch {
      $('redteam-output').innerHTML = `<p style="color:var(--act);font-size:12px;padding:8px 0">Parse error — raw response:<br><pre style="font-size:10px;white-space:pre-wrap">${escHtml(text.slice(0,500))}</pre></p>`;
      return;
    }

    const matClass = { weaponized:'mat-weaponized', functional:'mat-functional', poc:'mat-poc', theoretical:'mat-theoretical' }[analysis.exploitation_maturity] || 'mat-poc';
    const techniques = (analysis.attck_techniques || []).map(t =>
      `<div class="attck-badge"><a href="${escHtml(t.url)}" target="_blank">${escHtml(t.id)}</a><span style="color:var(--text)">${escHtml(t.name)}</span></div>`
    ).join('');

    const followOn = (analysis.attack_chain?.follow_on || []).map(f =>
      `<li>${escHtml(f)}</li>`).join('');

    const prereqs = [
      { label: 'Network position', value: analysis.prerequisites?.network_position },
      { label: 'Auth required', value: analysis.prerequisites?.authentication },
      { label: 'Special conditions', value: analysis.prerequisites?.special_conditions },
      { label: 'Skill level', value: analysis.prerequisites?.skill_level },
    ].map(p => `
      <div class="input-chip">
        <span class="chip-label">${escHtml(p.label)}</span>
        <span class="chip-value" style="font-size:11px;color:var(--text)">${escHtml(p.value || '—')}</span>
      </div>`).join('');

    const logged = (analysis.detection?.likely_logged || []).map(l => `<span class="source-tag">${escHtml(l)}</span>`).join('');
    const iocs = (analysis.detection?.ioc_types || []).map(i => `<span class="source-tag">${escHtml(i)}</span>`).join('');

    $('redteam-output').innerHTML = `
      <div class="section" style="margin-top:12px">
        <div class="section-label">Finding title</div>
        <div class="section-body" style="font-weight:600">${escHtml(analysis.pentest_finding_title || '')}</div>
      </div>

      <div class="section">
        <div class="section-label">Attack chain phase</div>
        <div class="phase-badge">${escHtml(analysis.attack_chain?.phase || '')}</div>
        <div class="section-body"><p>${escHtml(analysis.attack_chain?.phase_reasoning || '')}</p></div>
        ${followOn ? `<div class="section-label" style="margin-top:8px">Likely follow-on</div><ul class="change-list">${followOn}</ul>` : ''}
      </div>

      <div class="section">
        <div class="section-label">ATT&CK techniques</div>
        <div>${techniques}</div>
        ${(analysis.attck_techniques || []).map(t =>
          `<p style="font-size:11px;color:var(--muted);margin-top:4px">${escHtml(t.id)}: ${escHtml(t.relevance)}</p>`
        ).join('')}
      </div>

      <div class="section">
        <div class="section-label">Exploitation maturity</div>
        <span class="maturity-badge ${matClass}">${escHtml(analysis.exploitation_maturity || '')}</span>
        <p style="font-size:12px;color:var(--muted);margin-top:4px">${escHtml(analysis.exploitation_maturity_reasoning || '')}</p>
      </div>

      <div class="section">
        <div class="section-label">Prerequisites</div>
        <div class="prereq-grid">${prereqs}</div>
      </div>

      <div class="section">
        <div class="section-label">Detection context</div>
        <div class="section-body">
          ${logged ? `<p style="margin-bottom:4px"><span style="color:var(--muted);font-size:11px">Likely logged:</span><br>${logged}</p>` : ''}
          ${iocs ? `<p style="margin-bottom:4px"><span style="color:var(--muted);font-size:11px">IOC types:</span><br>${iocs}</p>` : ''}
          ${analysis.detection?.evasion_considerations ? `<p style="font-size:12px;margin-top:6px"><span style="color:var(--muted)">Evasion considerations:</span> ${escHtml(analysis.detection.evasion_considerations)}</p>` : ''}
        </div>
      </div>

      <div class="section">
        <div class="section-label">Plain-language severity</div>
        <div class="section-body"><p>${escHtml(analysis.cvss_plain || '')}</p></div>
      </div>

      <button class="btn btn-ghost" id="copyFinding" style="width:100%;margin-top:4px">Copy finding title</button>`;

    $('copyFinding').addEventListener('click', () => {
      navigator.clipboard.writeText(analysis.pentest_finding_title || '');
      $('copyFinding').textContent = 'Copied!';
      setTimeout(() => $('copyFinding').textContent = 'Copy finding title', 2000);
    });

  } catch (e) {
    $('redteam-output').innerHTML = `<p style="color:var(--act);padding:8px 0;font-size:12px">Error: ${escHtml(e.message)}</p>`;
  } finally {
    $('genRedTeamBtn').disabled = false;
    $('genRedTeamBtn').textContent = 'Generate Red Team Analysis';
  }
}

// ─── error / no-key states ──────────────────────────────────────────────────
function showError(message) {
  $('panel-triage').innerHTML = `
    <div class="empty">
      <div class="empty-icon">⚠</div>
      <h3>Something went wrong</h3>
      <p>${escHtml(message)}</p>
      <button class="btn" style="margin-top:12px" onclick="location.reload()">Retry</button>
    </div>`;
  $('tabs').style.display = 'flex';
  showPanel('panel-triage');
}

function showNoKeyState() {
  $('panel-triage').innerHTML = `
    <div class="empty">
      <div class="empty-icon">🔑</div>
      <h3>API key needed</h3>
      <p>Add your Anthropic or OpenAI-compatible API key in settings to enable analysis.</p>
      <button class="btn" style="margin-top:12px" id="goSettings">Open settings</button>
    </div>`;
  $('tabs').style.display = 'flex';
  showPanel('panel-triage');
  $('goSettings').addEventListener('click', () => chrome.runtime.openOptionsPage());
}
