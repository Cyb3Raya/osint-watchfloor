//stop looking at the source code, ya little snooper!

/* ─────────────────────────────────────────────
   CONFIG — add/remove sources here.
   All feeds are free, public RSS.
   ───────────────────────────────────────────── */
const FEEDS = [
  { name: 'SANS ISC',          url: 'https://isc.sans.edu/rssfeed.xml' },
  { name: 'The Hacker News',   url: 'https://feeds.feedburner.com/TheHackersNews' },
  { name: 'BleepingComputer',  url: 'https://www.bleepingcomputer.com/feed/' },
  { name: 'Krebs on Security', url: 'https://krebsonsecurity.com/feed/' },
  { name: 'Dark Reading',      url: 'https://www.darkreading.com/rss.xml' },
  { name: 'SecurityWeek',      url: 'https://feeds.feedburner.com/securityweek' },
  { name: 'Cisco Talos',       url: 'https://blog.talosintelligence.com/rss/' },
  { name: 'Unit 42',           url: 'https://unit42.paloaltonetworks.com/feed/' },
  { name: 'Google GTIG',       url: 'https://cloudblog.withgoogle.com/topics/threat-intelligence/rss/' },
  { name: 'RF The Record',     url: 'https://therecord.media/feed' },
];

// CORS proxies for client-side fetching of cross-origin RSS.
// Tried in order per feed until one works. All free/public = flaky by
// nature; the permanent fix is your own Cloudflare Worker or a
// GitHub Action that pre-builds a feed.json server-side.
const PROXIES = [
  u => 'https://api.allorigins.win/raw?url=' + encodeURIComponent(u),
  u => 'https://corsproxy.io/?url=' + encodeURIComponent(u),
  u => 'https://api.codetabs.com/v1/proxy?quest=' + encodeURIComponent(u),
];
const FETCH_TIMEOUT_MS = 10000;

const MAX_PER_FEED = 15;
const AUTO_REFRESH_MIN = 15;

// Keywords that drive the severity edge color
const HOT = /zero[- ]day|0[- ]day|actively exploited|in the wild|ransomware|critical vulnerability|emergency directive|supply[- ]chain/i;
const MED = /vulnerability|exploit|patch|breach|malware|phishing|apt|backdoor|botnet/i;
const CVE_RE = /CVE-\d{4}-\d{4,7}/i;

/* ───────────────────────────────────────────── */
let items = [];
let activeSources = new Set(FEEDS.map(f => f.name));

const $ = id => document.getElementById(id);
const esc = s => { const d = document.createElement('div'); d.textContent = s || ''; return d.innerHTML; };

// Feeds are third-party content — treat as untrusted. Only allow http(s)
// links; blocks javascript:/data:/vbscript: URIs from a compromised feed.
function safeUrl(u) {
  try {
    const p = new URL(u);
    return (p.protocol === 'https:' || p.protocol === 'http:') ? p.href : '';
  } catch { return ''; }
}

// Thumbnails must be https — no data:, no http (mixed content), no tricks.
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

function parseFeed(xmlText, sourceName) {
  const doc = new DOMParser().parseFromString(xmlText, 'text/xml');
  const nodes = [...doc.querySelectorAll('item, entry')].slice(0, MAX_PER_FEED);
  return nodes.map(n => {
    const get = sel => n.querySelector(sel)?.textContent?.trim() || '';
    let link = get('link');
    if (!link) link = n.querySelector('link')?.getAttribute('href') || '';
    const title = get('title');
    const rawDesc = get('description') || get('summary') || '';
    const desc = rawDesc.replace(/<[^>]+>/g, '').replace(/\s+/g, ' ').slice(0, 220);
    let img = n.querySelector('thumbnail, content[medium="image"], enclosure[type^="image"]')?.getAttribute('url')
           || n.querySelector('enclosure[type^="image"]')?.getAttribute('href') || '';
    if (!img) { const m = rawDesc.match(/<img[^>]+src=["']([^"']+)["']/i); if (m) img = m[1]; }
    const dateStr = get('pubDate') || get('updated') || get('published') || get('dc\\:date');
    const date = dateStr ? new Date(dateStr) : new Date(0);
    return { source: sourceName, title, link: safeUrl(link), desc, image: safeImg(img), date };
  }).filter(i => i.title && i.link);
}

async function fetchFeed(feed) {
  let lastErr;
  for (const proxy of PROXIES) {
    try {
      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
      const res = await fetch(proxy(feed.url), { cache: 'no-store', signal: ctrl.signal });
      clearTimeout(t);
      if (!res.ok) throw new Error('HTTP ' + res.status);
      const parsed = parseFeed(await res.text(), feed.name);
      if (!parsed.length) throw new Error('empty/unparseable');
      return parsed;
    } catch (e) { lastErr = e; }
  }
  throw lastErr;
}

async function loadFromJson() {
  // Preferred path: feed.json built server-side by GitHub Actions.
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
    ' sources' + (data.failed.length ? ' — failed: ' + data.failed.join(', ') : '');
  render();
}

async function loadAll() {
  $('status').textContent = 'Loading…';
  $('liveDot').classList.remove('live');
  try { await loadFromJson(); return; } catch (e) { /* fall back to client-side */ }
  $('status').textContent = 'Pulling ' + FEEDS.length + ' feeds…';
  const results = await Promise.allSettled(FEEDS.map(fetchFeed));
  const ok = [];
  const failed = [];
  results.forEach((r, i) => {
    if (r.status === 'fulfilled') ok.push(...r.value);
    else failed.push(FEEDS[i].name);
  });
  items = ok.sort((a, b) => b.date - a.date);
  $('feedCount').textContent = FEEDS.length - failed.length;
  $('lastPull').textContent = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  if (failed.length < FEEDS.length) $('liveDot').classList.add('live');
  $('status').textContent = items.length + ' items from ' + (FEEDS.length - failed.length) + '/' + FEEDS.length +
    ' sources' + (failed.length ? ' — failed: ' + failed.join(', ') : '');
  render();
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
  $('chips').innerHTML = FEEDS.map(f =>
    `<button class="chip" aria-pressed="true" data-src="${esc(f.name)}">${esc(f.name)}</button>`
  ).join('');
  $('chips').addEventListener('click', e => {
    const b = e.target.closest('.chip');
    if (!b) return;
    const src = b.dataset.src;
    const on = b.getAttribute('aria-pressed') === 'true';
    b.setAttribute('aria-pressed', String(!on));
    on ? activeSources.delete(src) : activeSources.add(src);
    render();
  });
}

$('feed').addEventListener('error', e => {
  if (e.target.classList?.contains('thumb')) e.target.closest('.item')?.classList.remove('has-thumb');
}, true);

$('search').addEventListener('input', render);
let lastManualRefresh = 0;
$('refreshBtn').addEventListener('click', () => {
  const now = Date.now();
  if (now - lastManualRefresh < 30000) return;  // throttle: be polite to feed hosts
  lastManualRefresh = now;
  loadAll();
});
buildChips();
loadAll();
setInterval(loadAll, AUTO_REFRESH_MIN * 60 * 1000);