/**
 * content.js — CVE detection on any page
 *
 * Scans the page for CVE IDs and notifies the popup via chrome.storage
 * so the popup can pre-populate the CVE field when it opens.
 *
 * Detection priority:
 *   1. URL (most reliable — NVD, CISA, Tenable detail pages)
 *   2. Page title
 *   3. First CVE in visible body text
 */

const CVE_RE = /CVE-\d{4}-\d{4,}/gi;

function detectCVE() {
  // 1. URL
  const fromURL = location.href.match(CVE_RE);
  if (fromURL) return fromURL[0].toUpperCase();

  // 2. Title
  const fromTitle = document.title.match(CVE_RE);
  if (fromTitle) return fromTitle[0].toUpperCase();

  // 3. Body — first visible match in headings, then paragraphs
  for (const sel of ['h1','h2','h3','h4','.cve-id','[class*="cve"]','p','td','li']) {
    for (const el of document.querySelectorAll(sel)) {
      const m = el.textContent.match(CVE_RE);
      if (m) return m[0].toUpperCase();
    }
  }
  return null;
}

const cve = detectCVE();
if (cve) {
  chrome.storage.local.set({ detected_cve: cve });
}

// Re-detect on SPA navigation (hash or history changes)
let lastURL = location.href;
const observer = new MutationObserver(() => {
  if (location.href !== lastURL) {
    lastURL = location.href;
    const found = detectCVE();
    chrome.storage.local.set({ detected_cve: found || '' });
  }
});
observer.observe(document.body, { childList: true, subtree: true });
