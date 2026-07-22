//stop looking at the source code, ya little snooper!


const AUTO_REFRESH_MIN = 15;

const HOT = /zero[- ]day|0[- ]day|actively exploited|in the wild|ransomware|critical vulnerability|emergency directive|supply[- ]chain/i;
const MED = /vulnerability|exploit|patch|breach|malware|phishing|apt|backdoor|botnet/i;
const CVE_RE = /CVE-\d{4}-\d{4,7}/i;

let items = [];
let activeSources = new Set();

const $ = id => document.getElementById(id);
const esc = s => { const d = document.createElement('div'); d.textContent = s || ''; return d.innerHTML; };


function safeUrl(u) {
  try {
    const p = new URL(u);
    return (p.protocol === 'https:' || p.protocol === 'http:') ? p.href : '';
  } catch { return ''; }
}

function safeImg(u) {
  try { return new URL(u).protocol === 'https:' ? u : ''; } catch { return ''; }
}

function relTime(date) {
  const s = Math.floor((Date.now() - date.getTime()) / 1000);
  if (s < 60) return 'just now';
  if (s < 3600) return Math.max(1, Math.floor(s / 60)) + 'm ago';
  if (s < 86400) return Math.floor(s / 3600) + 'h ago';
  return Math.floor(s / 86400) + 'd ago';
}

async function loadFromJson() {
  const res = await fetch('./feed.json?t=' + Date.now(), { cache: 'no-store' });
  if (!res.ok) throw new Error('no feed.json');
  const data = await res.json();
  items = data.items
    .map(i => ({ source: String(i.source || ''), title: String(i.title || ''), link: safeUrl(i.link), desc: String(i.desc || ''), image: safeImg(i.image), date: new Date(i.date) }))
    .filter(i => i.title && i.link);
  $('feedCount').textContent = data.sources_ok;
  $('lastPull').textContent = new Date(data.generated).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  if (data.sources_ok > 0) $('liveDot').classList.add('live');
  $('status').textContent = items.length + ' items from ' + data.sources_ok + '/' + data.sources_total +
    ' sources' + (data.failed.length ? ' - failed: ' + data.failed.join(', ') : '');
  buildChips();
  render();
}

async function loadAll() {
  $('status').textContent = 'Loading…';
  $('liveDot').classList.remove('live');
  try {
    await loadFromJson();
  } catch (e) {
    $('status').textContent = 'Could not load the feed. Refresh to try again.';
    $('feed').innerHTML = '<div class="empty">Feed unavailable. It rebuilds every 20 minutes \u2014 try again shortly.</div>';
  }
}

function render() {
  const q = $('search').value.slice(0, 200).trim().toLowerCase();
  const shown = items.filter(i =>
    activeSources.has(i.source) &&
    (!q || (i.title + ' ' + i.desc + ' ' + i.source).toLowerCase().includes(q))
  );
  const feedEl = $('feed');
  if (!shown.length) {
    feedEl.innerHTML = '<div class="empty">No items match. Clear the filter or re-enable sources above.</div>';
    return;
  }
  feedEl.innerHTML = shown.map(i => {
    const text = i.title + ' ' + i.desc;
    const sev = HOT.test(text) ? 'sev-high' : MED.test(text) ? 'sev-med' : '';
    const cve = text.match(CVE_RE);
    return `
      <article class="item ${sev} ${i.image ? 'has-thumb' : ''}">
        ${i.image ? `<img class="thumb" src="${esc(i.image)}" alt="" loading="lazy">` : ''}
        <div class="body">
        <div class="meta">
          <span class="src">${esc(i.source)}</span>
          <span>${relTime(i.date)}</span>
          ${cve ? `<span class="badge cve">${esc(cve[0].toUpperCase())}</span>` : ''}
          ${sev === 'sev-high' ? '<span class="badge hot">priority</span>' : ''}
        </div>
        <h2><a href="${esc(i.link)}" target="_blank" rel="noopener noreferrer">${esc(i.title)}</a></h2>
        ${i.desc ? `<p class="desc">${esc(i.desc)}…</p>` : ''}
        </div>
      </article>`;
  }).join('');
}

function buildChips() {
  const sources = [...new Set(items.map(i => i.source))].sort();
  activeSources = new Set(sources);
  $('chips').innerHTML = sources.map(s =>
    `<button class="chip" aria-pressed="true" data-src="${esc(s)}">${esc(s)}</button>`
  ).join('');
}

$('chips').addEventListener('click', e => {
  const b = e.target.closest('.chip');
  if (!b) return;
  const src = b.dataset.src;
  const on = b.getAttribute('aria-pressed') === 'true';
  b.setAttribute('aria-pressed', String(!on));
  on ? activeSources.delete(src) : activeSources.add(src);
  render();
});

$('feed').addEventListener('error', e => {
  if (e.target.classList?.contains('thumb')) e.target.closest('.item')?.classList.remove('has-thumb');
}, true);

$('search').addEventListener('input', render);
let lastManualRefresh = 0;
$('refreshBtn').addEventListener('click', () => {
  const now = Date.now();
  if (now - lastManualRefresh < 30000) return;  
  loadAll();
});
loadAll();
setInterval(loadAll, AUTO_REFRESH_MIN * 60 * 1000);