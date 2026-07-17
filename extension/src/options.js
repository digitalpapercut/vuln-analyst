const $ = id => document.getElementById(id);

function getSettings() {
  return new Promise(resolve => {
    chrome.storage.local.get('settings', r => {
      resolve(r.settings || { provider: 'anthropic', apiKey: '', model: '', nvdApiKey: '', apiBase: '' });
    });
  });
}

function saveSettings(s) {
  return new Promise(resolve => chrome.storage.local.set({ settings: s }, resolve));
}

function toggleCustomBase() {
  $('customBaseRow').style.display = $('provider').value === 'custom' ? 'block' : 'none';
}

async function load() {
  const s = await getSettings();
  $('provider').value = s.provider || 'anthropic';
  $('apiKey').value = s.apiKey || '';
  $('model').value = s.model || '';
  $('nvdApiKey').value = s.nvdApiKey || '';
  $('apiBase').value = s.apiBase || '';
  toggleCustomBase();
}

$('provider').addEventListener('change', toggleCustomBase);

$('saveBtn').addEventListener('click', async () => {
  const s = {
    provider: $('provider').value,
    apiKey: $('apiKey').value.trim(),
    model: $('model').value.trim(),
    nvdApiKey: $('nvdApiKey').value.trim(),
    apiBase: $('apiBase').value.trim(),
  };
  await saveSettings(s);
  $('saveMsg').style.display = 'inline';
  setTimeout(() => $('saveMsg').style.display = 'none', 2500);
});

$('testBtn').addEventListener('click', async () => {
  $('testBtn').disabled = true;
  $('testResult').textContent = 'Testing…';
  $('testResult').className = 'test-result';

  const s = {
    provider: $('provider').value,
    apiKey: $('apiKey').value.trim(),
    model: $('model').value.trim(),
    apiBase: $('apiBase').value.trim(),
    nvdApiKey: $('nvdApiKey').value.trim(),
  };
  await saveSettings(s);

  try {
    const res = await new Promise((resolve, reject) => {
      chrome.runtime.sendMessage({
        type: 'CALL_LLM',
        messages: [{ role: 'user', content: 'Reply with exactly the word: OK' }],
        system: 'Reply with exactly the word: OK and nothing else.',
        provider: s.provider,
        model: s.model || 'claude-sonnet-4-6',
        apiKey: s.apiKey,
        apiBase: s.apiBase,
      }, response => {
        if (chrome.runtime.lastError) return reject(new Error(chrome.runtime.lastError.message));
        resolve(response);
      });
    });

    if (!res.ok) throw new Error(res.error);
    $('testResult').textContent = '✓ Connected';
    $('testResult').className = 'test-result ok';
  } catch (e) {
    $('testResult').textContent = `✗ ${e.message}`;
    $('testResult').className = 'test-result err';
  } finally {
    $('testBtn').disabled = false;
  }
});

load();
