/**
 * background.js — service worker for Vuln Analyst Agent
 *
 * All external API calls live here (MV3: content scripts can't fetch
 * cross-origin). The content script and popup communicate via
 * chrome.runtime.sendMessage / onMessage.
 *
 * Message types:
 *   FETCH_ENRICHMENT  { cve }          → enrichment bundle
 *   CALL_LLM          { messages, system, provider, model, apiKey }  → text
 *   GET_SETTINGS      {}               → stored settings
 *   SAVE_SETTINGS     { settings }     → void
 */

const UA = 'vuln-analyst-agent-extension/1.0 (open-source)';
const CACHE_TTL_MS = 6 * 60 * 60 * 1000; // 6h for KEV/exploit indexes

// ─── message router ────────────────────────────────────────────────────────
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  (async () => {
    try {
      switch (msg.type) {
        case 'FETCH_ENRICHMENT':
          sendResponse({ ok: true, data: await fetchEnrichment(msg.cve) });
          break;
        case 'CALL_LLM':
          sendResponse({ ok: true, text: await callLLM(msg) });
          break;
        case 'GET_SETTINGS':
          sendResponse({ ok: true, settings: await getSettings() });
          break;
        case 'SAVE_SETTINGS':
          await saveSettings(msg.settings);
          sendResponse({ ok: true });
          break;
        default:
          sendResponse({ ok: false, error: `unknown message type: ${msg.type}` });
      }
    } catch (e) {
      sendResponse({ ok: false, error: e.message });
    }
  })();
  return true; // keep channel open for async response
});

// ─── settings ──────────────────────────────────────────────────────────────
async function getSettings() {
  const result = await chrome.storage.local.get('settings');
  return result.settings || {
    provider: 'anthropic',
    apiKey: '',
    model: '',
    nvdApiKey: '',
  };
}

async function saveSettings(settings) {
  await chrome.storage.local.set({ settings });
}

// ─── enrichment bundle ─────────────────────────────────────────────────────
async function fetchEnrichment(cve) {
  const id = cve.trim().toUpperCase();
  const cacheKey = `enrich_${id}`;
  const cached = await chrome.storage.local.get(cacheKey);
  if (cached[cacheKey] && Date.now() - cached[cacheKey].ts < CACHE_TTL_MS) {
    return { ...cached[cacheKey].data, cached: true };
  }

  const [epss, kev, nvd, cvelist, osv, exploits, edb] = await Promise.allSettled([
    fetchEPSS(id),
    fetchKEV(id),
    fetchNVD(id),
    fetchCVEList(id),
    fetchOSV(id),
    fetchExploitSignals(id),
    fetchExploitDB(id),
  ]);

  const data = {
    cve: id,
    epss:     epss.status     === 'fulfilled' ? epss.value     : { error: epss.reason?.message },
    kev:      kev.status      === 'fulfilled' ? kev.value      : { error: kev.reason?.message },
    nvd:      nvd.status      === 'fulfilled' ? nvd.value      : { error: nvd.reason?.message },
    cvelist:  cvelist.status  === 'fulfilled' ? cvelist.value  : { error: cvelist.reason?.message },
    osv:      osv.status      === 'fulfilled' ? osv.value      : { error: osv.reason?.message },
    exploits: exploits.status === 'fulfilled' ? exploits.value : { error: exploits.reason?.message },
    exploitdb: edb.status === 'fulfilled' ? edb.value : { error: edb.reason?.message },
    fetched_at: new Date().toISOString(),
  };

  await chrome.storage.local.set({ [cacheKey]: { data, ts: Date.now() } });
  return data;
}

// ─── data sources ──────────────────────────────────────────────────────────
async function fetchEPSS(cve) {
  const r = await fetch(`https://api.first.org/data/v1/epss?cve=${cve}`, {
    headers: { 'User-Agent': UA }
  });
  if (!r.ok) throw new Error(`EPSS ${r.status}`);
  const d = await r.json();
  const row = (d.data || [])[0];
  if (!row) return { found: false };
  return {
    found: true,
    epss: parseFloat(row.epss),
    percentile: parseFloat(row.percentile),
    date: row.date,
    model_date: d.access,
  };
}

async function fetchKEV(cve) {
  const r = await fetch(
    'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    { headers: { 'User-Agent': UA } }
  );
  if (!r.ok) throw new Error(`KEV ${r.status}`);
  const d = await r.json();
  const entry = (d.vulnerabilities || []).find(v => v.cveID === cve);
  if (!entry) return { in_kev: false };
  return {
    in_kev: true,
    date_added: entry.dateAdded,
    due_date: entry.dueDate,
    known_ransomware_use: entry.knownRansomwareCampaignUse,
    required_action: entry.requiredAction,
    vendor: entry.vendorProject,
    product: entry.product,
    name: entry.vulnerabilityName,
  };
}

async function fetchNVD(cve) {
  const settings = await getSettings();
  const headers = { 'User-Agent': UA };
  if (settings.nvdApiKey) headers['apiKey'] = settings.nvdApiKey;
  const r = await fetch(
    `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cve}`,
    { headers }
  );
  if (!r.ok) throw new Error(`NVD ${r.status}`);
  const d = await r.json();
  const item = (d.vulnerabilities || [])[0]?.cve;
  if (!item) return { found: false };

  const desc = (item.descriptions || []).find(x => x.lang === 'en')?.value || '';
  const metrics = item.metrics || {};
  const cvss = [];
  for (const key of ['cvssMetricV40','cvssMetricV31','cvssMetricV30','cvssMetricV2']) {
    for (const m of (metrics[key] || [])) {
      const cd = m.cvssData || {};
      cvss.push({
        version: cd.version,
        score: cd.baseScore,
        severity: cd.baseSeverity,
        vector: cd.vectorString,
        decoded: decodeVector(cd.vectorString || ''),
      });
    }
  }
  const cwes = [...new Set(
    (item.weaknesses || []).flatMap(w =>
      (w.description || []).filter(d => d.lang === 'en').map(d => d.value)
    )
  )];

  return {
    found: true,
    status: item.vulnStatus,
    published: item.published,
    last_modified: item.lastModified,
    description: desc,
    cvss,
    cwes,
    references: (item.references || []).slice(0, 10).map(r => ({
      url: r.url,
      tags: r.tags || [],
    })),
  };
}

async function fetchCVEList(cve) {
  const year = cve.split('-')[1];
  const num = cve.split('-')[2];
  const bucket = num.length <= 3 ? '0xxx' : num.slice(0, -3) + 'xxx';
  const url = `https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/${year}/${bucket}/${cve}.json`;
  const r = await fetch(url, { headers: { 'User-Agent': UA } });
  if (r.status === 404) return { found: false };
  if (!r.ok) throw new Error(`cvelistV5 ${r.status}`);
  const rec = await r.json();
  const cna = rec.containers?.cna || {};
  const adps = rec.containers?.adp || [];

  let ssvc = null;
  for (const adp of adps) {
    for (const m of (adp.metrics || [])) {
      if (m.other?.type === 'ssvc') ssvc = m.other.content;
    }
  }

  const desc = (cna.descriptions || []).find(d => d.lang?.startsWith('en'))?.value || '';
  return {
    found: true,
    state: rec.cveMetadata?.state,
    title: cna.title || '',
    description: desc,
    affected: (cna.affected || []).map(a => ({
      vendor: a.vendor,
      product: a.product,
      versions: a.versions || [],
    })),
    cisa_adp_ssvc: ssvc,
    date_updated: rec.cveMetadata?.dateUpdated,
  };
}

async function fetchOSV(cve) {
  const r = await fetch(`https://api.osv.dev/v1/vulns/${cve}`, {
    headers: { 'User-Agent': UA, 'Content-Type': 'application/json' }
  });
  if (r.status === 404) return { found: false };
  if (!r.ok) throw new Error(`OSV ${r.status}`);
  const d = await r.json();
  return {
    found: true,
    aliases: d.aliases || [],
    related: d.related || [],
    affected: (d.affected || []).map(a => ({
      ecosystem: a.package?.ecosystem,
      package: a.package?.name,
      ranges: a.ranges || [],
    })),
  };
}

async function fetchExploitSignals(cve) {
  // Nuclei CVE index
  let nuclei = false;
  let nucleiDetail = null;
  try {
    const r = await fetch(
      'https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json',
      { headers: { 'User-Agent': UA } }
    );
    if (r.ok) {
      const text = await r.text();
      for (const line of text.split('\n')) {
        const clean = line.trim().replace(/,$/, '');
        if (!clean || clean === '[' || clean === ']') continue;
        try {
          const rec = JSON.parse(clean);
          const id = (rec.ID || rec.Id || rec.id || '').toUpperCase();
          if (id === cve) {
            nuclei = true;
            const info = rec.Info || rec.info || {};
            nucleiDetail = {
              template: rec.file_path || rec.filePath,
              name: info.Name || info.name,
              severity: info.Severity || info.severity,
            };
            break;
          }
        } catch (_) {}
      }
    }
  } catch (_) {}

  // Metasploit index
  let metasploit = false;
  let metasploitDetail = null;
  try {
    const r = await fetch(
      'https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json',
      { headers: { 'User-Agent': UA } }
    );
    if (r.ok) {
      const data = await r.json();
      for (const [fullname, meta] of Object.entries(data)) {
        const refs = meta.references || [];
        if (refs.includes(cve) || refs.includes(`CVE-${cve}`)) {
          metasploit = true;
          metasploitDetail = {
            module: meta.fullname || fullname,
            name: meta.name,
            rank: meta.rank,
          };
          break;
        }
      }
    }
  } catch (_) {}

  return {
    nuclei_template: nuclei,
    nuclei_detail: nucleiDetail,
    metasploit_module: metasploit,
    metasploit_detail: metasploitDetail,
    weaponized_tooling_public: nuclei || metasploit,
  };
}

// ─── CVSS vector decoder ───────────────────────────────────────────────────
const V3 = {
  AV: { N:'network', A:'adjacent', L:'local', P:'physical' },
  AC: { L:'low', H:'high' },
  PR: { N:'none', L:'low', H:'high' },
  UI: { N:'none', R:'required' },
  S:  { U:'unchanged', C:'changed' },
  C:  { N:'none', L:'low', H:'high' },
  I:  { N:'none', L:'low', H:'high' },
  A:  { N:'none', L:'low', H:'high' },
};
const LABELS = {
  AV:'attack_vector', AC:'attack_complexity', PR:'privileges_required',
  UI:'user_interaction', S:'scope', C:'confidentiality', I:'integrity', A:'availability',
};
function decodeVector(vector) {
  const out = {};
  for (const part of vector.split('/')) {
    const [k, v] = part.split(':');
    if (V3[k]) out[LABELS[k]] = V3[k][v] || v;
  }
  return out;
}

// ─── LLM call ──────────────────────────────────────────────────────────────
async function callLLM({ messages, system, provider, model, apiKey }) {
  if (provider === 'anthropic' || !provider) {
    const body = {
      model: model || 'claude-sonnet-4-6',
      max_tokens: 4000,
      system,
      messages,
    };
    const r = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01',
        'anthropic-dangerous-direct-browser-access': 'true',
      },
      body: JSON.stringify(body),
    });
    if (!r.ok) {
      const err = await r.text();
      throw new Error(`Anthropic ${r.status}: ${err.slice(0, 200)}`);
    }
    const d = await r.json();
    return (d.content || []).filter(b => b.type === 'text').map(b => b.text).join('');
  }

  // OpenAI-compatible
  const body = {
    model: model || 'gpt-4o-mini',
    messages: [{ role: 'system', content: system }, ...messages],
    max_tokens: 4000,
  };
  const base = provider === 'openai'
    ? 'https://api.openai.com/v1'
    : provider; // treat as base URL for compatible endpoints
  const r = await fetch(`${base}/chat/completions`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'authorization': `Bearer ${apiKey}`,
    },
    body: JSON.stringify(body),
  });
  if (!r.ok) {
    const err = await r.text();
    throw new Error(`LLM ${r.status}: ${err.slice(0, 200)}`);
  }
  const d = await r.json();
  return d.choices?.[0]?.message?.content || '';
}

async function fetchExploitDB(cve) {
  const CSV_URL = 'https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv';
  const CACHE_KEY = 'exploitdb_csv_cache';
  const CACHE_TTL = 24 * 60 * 60 * 1000;

  let raw;
  const cached = await chrome.storage.local.get(CACHE_KEY);
  if (cached[CACHE_KEY] && Date.now() - cached[CACHE_KEY].ts < CACHE_TTL) {
    raw = cached[CACHE_KEY].data;
  } else {
    const r = await fetch(CSV_URL, { headers: { 'User-Agent': UA } });
    if (!r.ok) throw new Error(`ExploitDB CSV ${r.status}`);
    raw = await r.text();
    try {
      await chrome.storage.local.set({ [CACHE_KEY]: { data: raw, ts: Date.now() } });
    } catch (_) {}
  }

  const lines = raw.split('\n');
  const headers = lines[0].split(',').map(h => h.trim().replace(/^"|"$/g, ''));
  const idIdx = headers.indexOf('id');
  const descIdx = headers.indexOf('description');
  const dateIdx = headers.indexOf('date_published');
  const typeIdx = headers.indexOf('type');
  const platformIdx = headers.indexOf('platform');
  const verifiedIdx = headers.indexOf('verified');
  const codesIdx = headers.indexOf('codes');

  const found = [];
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i];
    if (!line.trim()) continue;
    const cols = line.split(',');
    const codes = (cols[codesIdx] || '').replace(/"/g, '');
    if (codes.toUpperCase().includes(cve)) {
      found.push({
        edb_id: (cols[idIdx] || '').trim(),
        title: (cols[descIdx] || '').trim().replace(/"/g, ''),
        date: (cols[dateIdx] || '').trim(),
        type: (cols[typeIdx] || '').trim(),
        platform: (cols[platformIdx] || '').trim(),
        verified: (cols[verifiedIdx] || '').trim() === '1',
        url: `https://www.exploit-db.com/exploits/${(cols[idIdx] || '').trim()}`,
      });
    }
  }

  return {
    found: found.length > 0,
    exploit_count: found.length,
    exploits: found,
    source: 'Exploit-DB (Offensive Security)',
  };
}
