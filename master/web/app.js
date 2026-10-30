// keel panel: three pages (探针 / 线路 / 用户), one drawer per object.
// Plain DOM, no build step. The page re-renders from /api/state every 2 s,
// except while the user is typing or choosing in the main area.
'use strict';

const C = { ink: '#161616', muted: '#615C54', red: '#D93A2B', yellow: '#F2C230', blue: '#2A4D9B', amber: '#D9A800', danger: '#B02E22', paper: '#F6F4EF', faint: '#8F897E' };
// Exit ports are told apart by color and shape, in this order.
const EXIT_STYLE = [
  { color: C.red, shape: 'square' }, { color: C.yellow, shape: 'tri' }, { color: C.blue, shape: 'circle' },
  { color: C.ink, shape: 'circle' }, { color: C.blue, shape: 'square' }, { color: C.red, shape: 'circle' },
  { color: C.ink, shape: 'square' }, { color: C.yellow, shape: 'circle' }
];
const ISP_COLOR = { ct: [C.blue, C.blue], cu: [C.red, C.red], cm: [C.yellow, '#B08900'] };
const GB = 1024 ** 3;

// "/" is a public status page (probes only); the panel lives at /admin.
const ADMIN = location.pathname.replace(/\/+$/, '') === '/admin';

const S = {
  tab: load('tab') || 'probe',
  data: null,
  loggedIn: null,
  toast: '',
  flipped: new Set(), // probe cards showing their three-network side
  picker: null,       // { id, kind: 'rule'|'primary'|'fb', rule } inline chooser open on the lines page
  drawer: null,       // { kind, id, ... }
  draft: null         // drawer form state
};

function load(k) { try { return localStorage.getItem('keel.' + k); } catch (e) { return null; } }
function save(k, v) { try { localStorage.setItem('keel.' + k, v); } catch (e) { /* private mode */ } }

// ---------- helpers ----------

// What the panel calls a node. The code is an internal short id.
function nm(n) { return n.name || n.code; }

function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
function fmt1(v) { return v >= 100 ? v.toFixed(0) : v.toFixed(1); }
function mbps(bytesPerSec) { return fmt1((bytesPerSec || 0) / 1e6); }
function bytes(b) {
  b = b || 0;
  if (b >= 1e12) return (b / 1e12).toFixed(2) + ' TB';
  if (b >= 1e9) return (b / 1e9).toFixed(b >= 1e11 ? 0 : 1) + ' GB';
  if (b >= 1e6) return (b / 1e6).toFixed(0) + ' MB';
  return (b / 1e3).toFixed(0) + ' KB';
}
function gib(b) { const g = (b || 0) / GB; return g >= 100 ? g.toFixed(0) : g.toFixed(1); }
function pct(a, b) { return Math.max(0, Math.min(100, b ? a / b * 100 : 0)); }
function ago(ts) {
  if (!ts) return '从未';
  const d = Math.max(0, S.data.now - ts);
  if (d < 60) return d + ' 秒前';
  if (d < 3600) return Math.floor(d / 60) + ' 分钟前';
  if (d < 86400) return Math.floor(d / 3600) + ' 小时前';
  return Math.floor(d / 86400) + ' 天前';
}
function duration(s) {
  if (!s) return '—';
  if (s < 3600) return Math.floor(s / 60) + ' 分钟';
  if (s < 86400) return Math.floor(s / 3600) + ' 小时';
  return Math.floor(s / 86400) + ' 天';
}
function shape(st, size) {
  size = size || 12;
  if (st.shape === 'tri') return `<svg width="${size + 2}" height="${size}" aria-hidden="true"><polygon points="0,${size} ${size + 2},${size} ${(size + 2) / 2},0" fill="${st.color}"></polygon></svg>`;
  const r = st.shape === 'circle' ? 'border-radius:50%;' : '';
  return `<span style="width:${size}px;height:${size}px;${r}background:${st.color};display:inline-block;flex:0 0 auto"></span>`;
}
function polyline(values, w, h, pad) {
  const vals = values.filter(v => v > 0);
  if (vals.length < 2) return '';
  const lo = Math.min(...vals), hi = Math.max(...vals), span = (hi - lo) || 1;
  const step = w / (values.length - 1);
  return values.map((v, i) => v > 0 ? `${(i * step).toFixed(1)},${(h - pad - (v - lo) / span * (h - 2 * pad)).toFixed(1)}` : null)
    .filter(Boolean).join(' ');
}

// ---------- data access ----------

// By id, rebuilt with each state: pages look nodes up per user and card.
let NODES = new Map(), EXITS = new Map();
function index() {
  NODES = new Map(S.data.nodes.map(n => [n.id, n]));
  EXITS = new Map((S.data.exits || []).map((e, i) => [e.id, { e, i }]));
}
function node(id) { return NODES.get(id); }
function exit(id) { const x = EXITS.get(id); return x && x.e; }
function exitStyle(id) {
  const x = EXITS.get(id);
  return x ? EXIT_STYLE[x.i % EXIT_STYLE.length] : { color: C.faint, shape: 'circle' };
}
function isExternal(e) { return e.kind && e.kind !== 'ss'; }
function extProto(e) {
  if (e.kind !== 'vless') return 'SS ' + e.method;
  return { reality: 'VLESS Reality', tls: 'VLESS TLS', plain: 'VLESS 明文（不加密）' }[e.transport] || 'VLESS';
}
function entries() { return S.data.nodes.filter(n => n.role === 'entry'); }
function exitNodes() { return S.data.nodes.filter(n => n.role === 'exit'); }
function nodeStatus(n) {
  if (!n.online) return { kind: 'off', text: n.last_seen ? '失联 ' + ago(n.last_seen) : '未连接' };
  if (n.apply_error) return { kind: 'warn', text: '配置有误' };
  const s = n.system || {};
  if (s.cpu_pct >= 80) return { kind: 'warn', text: 'CPU 偏高' };
  if (s.mem_total && s.mem_used / s.mem_total >= 0.9) return { kind: 'warn', text: '内存偏高' };
  if (s.disk_total && s.disk_used / s.disk_total >= 0.9) return { kind: 'warn', text: '硬盘快满' };
  return { kind: 'ok', text: '在线' };
}
function statusMark(kind) {
  if (kind === 'ok') return shape({ color: C.blue, shape: 'circle' }, 10);
  if (kind === 'warn') return shape({ color: C.amber, shape: 'tri' }, 10);
  return shape({ color: C.red, shape: 'square' }, 10);
}

async function api(method, path, body) {
  const res = await fetch(path, {
    method, credentials: 'same-origin',
    headers: body ? { 'content-type': 'application/json', 'x-keel': '1' } : { 'x-keel': '1' },
    body: body ? JSON.stringify(body) : undefined
  });
  let json = {};
  try { json = await res.json(); } catch (e) { /* empty */ }
  if (res.status === 401 && path !== '/api/login') { S.loggedIn = false; render(); throw new Error(json.error || '请先登录'); }
  if (!res.ok) throw new Error(json.error || ('出错了（' + res.status + '）'));
  return json;
}

// One state request at a time. A poll joins the one in flight; anything
// else (after an edit) waits for it and asks again, so it sees its change.
// With draw false the caller renders.
let inflight = null;
async function refresh(opts = {}) {
  if (inflight && opts.poll) return inflight;
  while (inflight) await inflight;
  inflight = fetchState(opts.draw !== false, opts.poll).finally(() => { inflight = null; });
  return inflight;
}

async function fetchState(draw, poll) {
  try {
    const data = await api('GET', ADMIN ? '/api/state' : '/api/public');
    S.data = data;
    index();
    if (ADMIN) S.loggedIn = true;
    if (draw && !busy()) render(poll);
  } catch (e) { /* shown via login or kept stale */ }
}

// True while the user is typing or choosing in the main area: re-rendering
// would steal focus.
function busy() {
  const a = document.activeElement;
  if (!a || a === document.body) return false;
  if (!document.getElementById('app').contains(a)) return false;
  return a.tagName === 'INPUT' || a.tagName === 'SELECT' || a.tagName === 'TEXTAREA';
}

function flash(msg) {
  S.toast = msg;
  clearTimeout(flash.t);
  flash.t = setTimeout(() => { S.toast = ''; if (!busy()) render(); }, 6000);
}

async function act(fn, okMsg) {
  try {
    await fn();
    if (okMsg) flash(okMsg);
    await refresh({ draw: false });
    render();
    return true;
  } catch (e) {
    flash(e.message);
    render();
    return false;
  }
}

// ---------- pages ----------

// The markup on screen, and the users page's parts, from the last render.
let shown = '', shownUsers = null;

// A poll's render (poll true) leaves the page alone when its markup is the
// same, and on the users page redraws only the rows that changed: traffic
// moves a few figures, and the page can hold thousands of elements. Other
// renders redraw everything, which also resets what the user left in the
// main area.
function render(poll) {
  const root = document.getElementById('app');
  if (!ADMIN) {
    const html = S.data ? `<main class="public">${probePage()}</main>` : '';
    if (!poll || html !== shown) root.innerHTML = html;
    shown = html;
    return;
  }
  if (S.loggedIn === false || !S.data) {
    shown = ''; shownUsers = null;
    if (S.loggedIn === false) { root.innerHTML = loginPage(); S.drawer = null; renderDrawer(); } else root.innerHTML = '';
    return;
  }
  const t = S.tab;
  const tab = (id, label, mark) => `<button class="tab" data-act="tab" data-tab="${id}" aria-current="${t === id ? 'page' : 'false'}">${t === id ? mark : '<span class="mark"></span>'}${label}</button>`;
  const users = t !== 'probe' && t !== 'lines' ? usersParts() : null;
  const html = `
    <header class="top">
      <nav aria-label="主导航">
        ${tab('probe', '探针', shape({ color: C.blue, shape: 'circle' }, 10))}
        ${tab('lines', '线路', shape({ color: C.red, shape: 'square' }, 10))}
        ${tab('users', '用户', shape({ color: C.yellow, shape: 'tri' }, 10))}
      </nav>
      <button class="icon-btn" data-act="settings" aria-label="设置" title="设置"><svg width="20" height="20" viewBox="0 0 20 20" aria-hidden="true"><path d="M2 5h16M2 10h16M2 15h16" stroke="currentColor" stroke-width="1.4"/><rect x="5" y="3" width="4" height="4" fill="var(--ground)" stroke="currentColor" stroke-width="1.4"/><rect x="11" y="8" width="4" height="4" fill="var(--ground)" stroke="currentColor" stroke-width="1.4"/><rect x="7" y="13" width="4" height="4" fill="var(--ground)" stroke="currentColor" stroke-width="1.4"/></svg></button>
    </header>
    <main>${t === 'probe' ? probePage() : t === 'lines' ? linesPage() : users.head + usersList(users.rows)}</main>`;
  if (poll && html === shown) return;
  if (!(poll && users && patchUsers(users))) root.innerHTML = html;
  shown = html;
  shownUsers = users;
  // The drawer is left alone here so typing in it survives the 2 s refresh.
}

function loginPage() {
  return `<div class="login"><form data-form="login">
    <div class="sun" aria-hidden="true"></div>
    <h1>keel</h1>
    <label class="field">用户名<input name="username" autocomplete="username" autocapitalize="off" spellcheck="false" required autofocus></label>
    <label class="field">密码<input type="password" name="password" autocomplete="current-password" required></label>
    <div class="err" id="login-err"></div>
    <button class="btn solid" type="submit">进入</button>
  </form></div>`;
}

function probePage() {
  const d = S.data, nodes = d.nodes;
  const sp = d.summary.speed;
  const last = sp.length ? sp[sp.length - 1] : [0, 0];
  const totals = sp.map(p => p[0] + p[1]);
  // Scale from zero with a 1 MB/s floor, so a few KB/s of background
  // traffic draws as the flat line it is instead of filling the chart.
  const peak = Math.max(0, ...totals), top = Math.max(peak * 1.15, 1e6);
  const spark = totals.length > 1 ? totals.map((v, i) => `${(i * 300 / (totals.length - 1)).toFixed(1)},${(53 - v / top * 50).toFixed(1)}`).join(' ') : '';
  const hero = `
    <section class="hero">
      <div class="sun" aria-hidden="true"></div>
      <div class="main">
        <div class="label">实时总速率</div>
        <div style="display:flex;align-items:baseline;gap:10px"><span class="big">${mbps(last[0] + last[1])}</span><span style="font-size:20px">MB/s</span></div>
        <div class="muted" style="font-size:14px">入 ${mbps(last[0])} MB/s · 出 ${mbps(last[1])} MB/s</div>
        <svg class="spark" height="56" viewBox="0 0 300 56" preserveAspectRatio="none" role="img" aria-label="近 3 分钟总速率走势"><line x1="0" y1="53" x2="300" y2="53" stroke="#D6D1C6" stroke-width="1" vector-effect="non-scaling-stroke"></line><polyline points="${spark}" fill="none" stroke="${C.ink}" stroke-width="1.5" vector-effect="non-scaling-stroke"></polyline></svg>
        <div class="small muted">近 3 分钟 · 峰值 ${mbps(peak)} MB/s · 全部节点网卡合计</div>
      </div>
      <div class="tiles">
        <div><div class="small muted">在线</div><div class="v">${d.summary.online}/${nodes.length}</div></div>
        <div><div class="small muted">本月</div><div class="v">${bytes(d.summary.month)}</div></div>
        ${d.users ? `<div><div class="small muted">用户</div><div class="v">${d.users.length}</div></div>` : ''}
      </div>
      ${ADMIN && d.master ? hostBar(d.master) : ''}
    </section>`;
  if (!nodes.length) {
    return hero + `<div class="empty">还没有节点。去「线路」页点「添加节点」，在服务器上运行给出的那一行命令。</div>`;
  }
  const ext = d.exits ? d.exits.filter(isExternal) : [];
  const ins = nodes.filter(n => n.role === 'entry'), outs = nodes.filter(n => n.role !== 'entry');
  const group = (title, cards) => cards.length ? `<div class="section-head probe-head"><h2>${title}</h2></div><div class="grid probe">${cards.join('')}</div>` : '';
  return hero + group('入口', ins.map(probeCard)) + group('出口', outs.map(probeCard).concat(ext.map(extCard)));
}

// The machine the master runs on (admin only), along the bottom of the hero.
function hostBar(m) {
  const st = nodeStatus({ online: true, system: m });
  const meter = (label, p, text) => `<div><div class="small muted">${label}</div><div class="hv">${text}</div><div class="meter"><i style="width:${p.toFixed(0)}%;background:${p >= 80 ? C.red : C.ink}"></i></div></div>`;
  const mem = m.mem_total ? `${Math.round(m.mem_used / 1048576)}/${Math.round(m.mem_total / 1048576)}` : '—';
  const disk = m.disk_total ? `${(m.disk_used / GB).toFixed(1)}/${(m.disk_total / GB).toFixed(0)}` : '—';
  return `<div class="hostbar">
      <div class="hostname"><span class="small muted">主控机</span>${statusMark(st.kind)}<span class="small" style="color:${st.kind === 'ok' ? C.muted : C.danger}">${st.kind === 'ok' ? '正常' : esc(st.text)}</span></div>
      ${meter('CPU', m.cpu_pct || 0, m.mem_total ? Math.round(m.cpu_pct || 0) + '%' : '—')}
      ${meter('内存 MB', pct(m.mem_used, m.mem_total), mem)}
      ${meter('硬盘 G', pct(m.disk_used, m.disk_total), disk)}
      <div class="wide"><div class="small muted">进程 / 数据库</div><div class="hv">${m.rss ? bytes(m.rss) : '—'} / ${bytes(m.db_bytes || 0)}</div></div>
      <div><div class="small muted">开机</div><div class="hv">${m.uptime_s ? duration(m.uptime_s) : '—'}</div></div>
    </div>`;
}

function probeCard(n) {
  const st = nodeStatus(n), off = st.kind === 'off', s = n.system || {};
  const meter = (label, p, text) => `<div><div class="small muted">${label}</div><div style="font-size:14px">${off ? '—' : text}</div><div class="meter"><i style="width:${off ? 0 : p.toFixed(0)}%;background:${p >= 80 ? C.red : C.ink}"></i></div></div>`;
  const mem = s.mem_total ? `${Math.round(s.mem_used / 1048576)}/${Math.round(s.mem_total / 1048576)}` : '—';
  const disk = s.disk_total ? `${(s.disk_used / GB).toFixed(1)}/${(s.disk_total / GB).toFixed(0)}` : '—';
  const probes = off ? [] : (n.probes || []);
  // Three-network latency at a glance; the detail opens in the side panel.
  const strip = probes.length
    ? probes.map(p => {
      const col = (ISP_COLOR[p.name] || [C.ink])[0];
      return `<span class="isp-cell">${shape({ color: col, shape: 'circle' }, 7)}<span class="muted">${esc(p.label || p.name)}</span><b>${p.latency > 0 ? Math.round(p.latency) : '—'}</b><span class="muted">ms</span></span>`;
    }).join('') + `<span class="isp-more" aria-hidden="true">${FLIP_ICON}</span>`
    : `<span class="small muted">${off ? '失联中' : '没有三网数据'}</span>`;
  // Exits are not probed: show how each entry reaches them instead.
  const cs = n.checks || [];
  const exitStrip = cs.length
    ? cs.map(c => `<span class="isp-cell">${shape({ color: c.alive ? C.ink : C.danger, shape: 'circle' }, 7)}<span class="muted">${esc(c.name)}</span><b style="${c.alive ? '' : 'color:' + C.danger}">${c.alive && c.latency_ms > 0 ? Math.round(c.latency_ms) : c.alive ? '通' : '不通'}</b>${c.alive && c.latency_ms > 0 ? '<span class="muted">ms</span>' : ''}</span>`).join('')
    : '<span class="small muted">还没有入口检测过</span>';
  const head = `<div class="row">
        <span class="code" style="flex:0 1 auto;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(nm(n))}</span>
        <span style="flex:1 1 auto"></span>
        ${statusMark(st.kind)}
        <span style="font-size:13px;color:${off ? C.danger : C.muted}">${esc(st.text)}</span>
      </div>
      <div class="three">
        ${meter('CPU', s.cpu_pct || 0, Math.round(s.cpu_pct || 0) + '%')}
        ${meter('内存 MB', pct(s.mem_used, s.mem_total), mem)}
        ${meter('硬盘 G', pct(s.disk_used, s.disk_total), disk)}
      </div>
      <div class="three" style="font-size:14px">
        <div><div class="small muted">入 / 出 MB/s</div>${off ? '— / —' : mbps(s.rx_rate) + ' / ' + mbps(s.tx_rate)}</div>
        <div><div class="small muted">本月</div>${bytes(n.month_rx + n.month_tx)}</div>
        <div><div class="small muted">开机</div>${off ? '—' : duration(s.uptime_s)}</div>
      </div>
      <div class="isp-strip">${n.role === 'entry' ? strip : exitStrip}</div>`;
  if (n.role !== 'entry' || !probes.length) return `<div class="card ${off ? 'off' : ''}"><div class="probe-btn">${head}</div></div>`;
  const flipped = S.flipped.has(n.id);
  return `<div class="card flip ${flipped ? 'flipped' : ''}">
    <div class="flip-inner">
      <button class="face front probe-btn" data-act="probe" data-id="${n.id}" aria-label="${esc(nm(n))}：翻到三网延迟" ${flipped ? 'tabindex="-1" aria-hidden="true"' : ''}>${head}</button>
      <button class="face back probe-btn" data-act="probe" data-id="${n.id}" aria-label="${esc(nm(n))}：翻回概况" ${flipped ? '' : 'tabindex="-1" aria-hidden="true"'}>${ispBack(n, probes)}</button>
    </div>
  </div>`;
}

// The back of a probe card: one row per network, sized to the front.
function ispBack(n, probes) {
  const s = n.system || {};
  const rows = probes.map(p => {
    const col = ISP_COLOR[p.name] || [C.ink, C.ink];
    const pts = polyline(p.points, 120, 28, 3);
    const lat = p.latency > 0 ? Math.round(p.latency) : '—';
    return `<div class="isp-row">
      <span class="isp-name">${shape({ color: col[0], shape: 'circle' }, 8)}${esc(p.label || p.name)}</span>
      <span class="isp-lat"><b>${lat}</b><small>ms</small></span>
      <span class="isp-sub"><span>±${Math.round(p.jitter)} ms</span><span style="color:${p.loss >= 2 ? C.danger : 'inherit'}">重传 ${p.loss.toFixed(p.loss >= 10 ? 0 : 1)}%</span></span>
      <svg class="isp-spark" viewBox="0 0 120 28" preserveAspectRatio="none" aria-hidden="true"><polyline points="${pts}" fill="none" stroke="${col[1]}" stroke-width="1.5" vector-effect="non-scaling-stroke"></polyline></svg>
    </div>`;
  }).join('');
  const retrans = s.tcp_retrans_pct != null ? `整机重传 ${(+s.tcp_retrans_pct).toFixed(1)}%` : '';
  return `<div class="row">
      <span class="code" style="flex:0 1 auto;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(nm(n))}</span>
      <span class="muted" style="font-size:14px;flex:1 1 auto">三网 · 近 1 小时</span>
      <span class="flip-icon" aria-hidden="true">${FLIP_ICON}</span>
    </div>
    <div class="isp-rows">${rows}</div>
    <div class="small muted" style="display:flex;justify-content:space-between;gap:8px"><span>TCPing 每轮 10 次</span><span>${retrans}</span></div>`;
}

function linesPage() {
  const es = entries(), xs = exitNodes();
  const toast = S.toast ? `${shape({ color: C.blue, shape: 'circle' }, 8)}<span>${esc(S.toast)}</span>` : '';
  let html = `
    <div class="section-head">
      <h2>入口</h2>
      <button class="btn" data-act="new-node">添加节点</button>
    </div>
    <div class="toast" role="status">${toast}</div>`;
  html += es.length ? `<div class="grid entries">${es.map(entryCard).join('')}</div>`
    : `<div class="empty" style="margin-bottom:48px">还没有入口节点。</div>`;
  html += `<div class="section-head">
      <h2>出口</h2>
      <button class="btn" data-act="ext-import">导入外部出口</button>
    </div>`;
  const cards = [];
  for (const x of xs) {
    const ports = S.data.exits.filter(e => e.node_id === x.id);
    if (!ports.length) cards.push(exitNodeCard(x));
    ports.forEach(e => cards.push(exitCard(e, x)));
  }
  S.data.exits.filter(isExternal).forEach(e => cards.push(exitCard(e, null)));
  html += cards.length ? `<div class="grid exits">${cards.join('')}</div>` : `<div class="empty">还没有出口。加一个出口节点，或者粘贴 vless:// / ss:// 链接导入外部出口。</div>`;
  return html;
}

// How each entry's node last found this exit (entries check every exit
// they route to; external exits have no probe of their own).
function exitChecks(e) {
  return entries().map(n => ({ n, h: (n.health || {})['x' + e.id] })).filter(c => c.h);
}
function checkText(h) {
  return h.alive ? (h.latency_ms > 0 ? Math.round(h.latency_ms) + ' ms' : '通') : '不通';
}
function checkLine(e) {
  const cs = exitChecks(e);
  if (!cs.length) return '<span class="muted">还没有入口检测过</span>';
  return cs.map(c => `${esc(nm(c.n))} <b style="font-weight:500;${c.h.alive ? '' : 'color:' + C.danger}">${checkText(c.h)}</b>`).join(' · ');
}
function extCard(e) {
  return checkCard(e.name, '外部出口 · ' + extProto(e), exitChecks(e).map(c => ({ name: nm(c.n), alive: c.h.alive, latency_ms: c.h.latency_ms })), '');
}
function checkCard(title, sub, cs, foot, off) {
  const dead = cs.length && cs.every(c => !c.alive), some = cs.some(c => !c.alive);
  const kind = off || !cs.length ? 'off' : dead ? 'bad' : some ? 'warn' : 'ok';
  return `<div class="card ${off || dead ? 'off' : ''}" style="padding:20px;display:flex;flex-direction:column;gap:12px">
    <div class="row">
      <div style="flex:1 1 auto;min-width:0">
        <div class="code" style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(title)}</div>
        <div class="small muted" style="margin-top:4px">${esc(sub)}</div>
      </div>
      ${off || cs.length ? statusMark(kind) : ''}
    </div>
    <div class="checks">${cs.length ? cs.map(c => `<div><span class="muted">${esc(c.name)}</span><b style="${c.alive ? '' : 'color:' + C.danger}">${checkText(c)}</b></div>`).join('') : '<span class="small muted">还没有入口检测过</span>'}</div>
    <div class="small muted">${foot ? esc(foot) + ' · ' : ''}由各入口每 15 秒检测</div>
  </div>`;
}

// Exit health as this entry's node sees it: true, false, or undefined
// (not checked yet). Direct (0) is always usable.
function exitAlive(n, id) {
  if (!id) return true;
  const h = (n.health || {})['x' + id];
  return h ? h.alive : undefined;
}
function exitLabel(id) { return id ? (exit(id) || {}).name || '?' : '直连'; }
// The exit new connections take: the first in the list not marked dead.
function inUse(n, primary, fallback) {
  const list = [primary].concat(fallback || []);
  const hit = list.find(id => exitAlive(n, id) !== false);
  return hit === undefined ? primary : hit;
}
// Inline chooser: a row of chips under the button that opened it.
function pickerOpen(id, kind, rule) {
  const p = S.picker;
  return !!p && p.id === id && p.kind === kind && p.rule === (rule || '');
}
function pickBtn(n, kind, rule, cls, inner, label) {
  const open = pickerOpen(n.id, kind, rule);
  return `<button class="${cls}" data-act="pick" data-id="${n.id}" data-kind="${kind}" data-rule="${esc(rule || '')}" aria-expanded="${open}" aria-label="${esc(label)}">${inner}</button>`;
}
function exitPicker(n, kind, rule, ids, current) {
  const chips = ids.map(id => {
    const dead = exitAlive(n, id) === false;
    const mark = id ? shape(exitStyle(id), 8) : shape({ color: id === current ? C.paper : C.faint, shape: 'circle' }, 8);
    return `<button class="chip ${id ? '' : 'ghost'} ${dead ? 'dead' : ''}" aria-pressed="${id === current}" data-act="pick-do" data-id="${n.id}" data-kind="${kind}" data-rule="${esc(rule || '')}" data-value="${id}">${mark}${esc(exitLabel(id))}</button>`;
  }).join('');
  return `<div class="picker chips" role="group">${chips}</div>`;
}
const FLIP_ICON = '<svg width="14" height="14" viewBox="0 0 14 14" aria-hidden="true"><path d="M2 5.5A5 5 0 0 1 11.5 4M12 8.5A5 5 0 0 1 2.5 10" fill="none" stroke="currentColor" stroke-width="1.3"></path><path d="M11.8 1.2V4.3H8.7M2.2 12.8V9.7H5.3" fill="none" stroke="currentColor" stroke-width="1.3"></path></svg>';
const CHEVRON = '<svg class="chev" width="10" height="10" viewBox="0 0 10 10" aria-hidden="true"><path d="M1.5 3.5L5 7L8.5 3.5" fill="none" stroke="currentColor" stroke-width="1.4"></path></svg>';

const ARROW = '<svg class="arrow" width="14" height="8" viewBox="0 0 14 8" aria-hidden="true"><path d="M0 4H12M9 1L12 4L9 7" fill="none" stroke="currentColor" stroke-width="1.2"></path></svg>';
const XS = '<svg width="8" height="8" viewBox="0 0 12 12" aria-hidden="true"><path d="M1 1L11 11M11 1L1 11" stroke="currentColor" stroke-width="1.8"></path></svg>';

// A route as one chain: the exit it prefers, then backups in order. The
// link carrying traffic now is filled; dead links are dashed. rule '' is
// the default route, whose first exit is picked by the chips above it.
function chain(n, rule, primary, fallback, label) {
  fallback = fallback || [];
  const now = inUse(n, primary, fallback);
  const allDead = [primary].concat(fallback).every(id => exitAlive(n, id) === false);
  const mark = id => id ? shape(exitStyle(id), 7) : shape({ color: C.faint, shape: 'circle' }, 7);
  const cls = id => `link ${exitAlive(n, id) === false ? 'dead' : ''} ${id === now && !allDead ? 'cur' : ''}`;
  const links = [];
  if (rule) {
    const open = pickerOpen(n.id, 'primary', rule);
    links.push(`<button class="${cls(primary)} first" data-act="pick" data-id="${n.id}" data-kind="primary" data-rule="${esc(rule)}" aria-expanded="${open}" aria-label="${esc(label)} 走哪个出口，现在是 ${esc(exitLabel(primary))}">${mark(primary)}<span class="nm">${esc(exitLabel(primary))}</span>${CHEVRON}</button>`);
  }
  fallback.forEach(id => links.push(`<span class="${cls(id)}">${mark(id)}<span class="nm">${esc(exitLabel(id))}</span><button class="link-x" data-act="fb-del" data-id="${n.id}" data-rule="${esc(rule)}" data-exit="${id}" aria-label="去掉备用 ${esc(exitLabel(id))}">${XS}</button></span>`));
  const free = S.data.exits.map(e => e.id).concat([0]).filter(id => id !== primary && !fallback.includes(id));
  const fbOpen = pickerOpen(n.id, 'fb', rule);
  if (free.length) links.push(`<button class="link-add" data-act="pick" data-id="${n.id}" data-kind="fb" data-rule="${esc(rule)}" aria-expanded="${fbOpen}">${fbOpen ? '收起' : (fallback.length || rule ? '＋ 备用' : '＋ 不通时换到')}</button>`);
  const head = rule ? '' : (fallback.length ? '<span class="chain-label">不通时依次换</span>' : '');
  const warn = allDead ? `<span class="chain-warn">${shape({ color: C.red, shape: 'square' }, 7)}全都不通</span>` : '';
  const pick = rule && pickerOpen(n.id, 'primary', rule)
    ? exitPicker(n, 'primary', rule, S.data.exits.map(e => e.id).concat([0]), primary)
    : fbOpen && free.length ? exitPicker(n, 'fb', rule, free, null) : '';
  return `<div class="chain">${head}${links.join(ARROW)}${warn}</div>${pick}`;
}

function entryCard(n) {
  const st = nodeStatus(n);
  const protos = [n.anytls_on && 'AnyTLS', n.vless_on && 'Reality'].filter(Boolean).join(' · ') || '没开协议';
  const head = `<button class="name-btn" data-act="node" data-id="${n.id}"><span class="code">${esc(nm(n))}</span></button>
       <span style="flex:1 1 auto" class="small muted">${protos}</span>`;
  const chip = (id, label, style, ghost) => {
    const on = n.default_exit === id;
    const dead = exitAlive(n, id) === false;
    const mark = ghost ? shape({ color: on ? C.paper : C.faint, shape: 'circle' }, 8) : shape(style, 8);
    return `<button class="chip ${ghost ? 'ghost' : ''} ${dead ? 'dead' : ''}" aria-pressed="${on}" data-act="default-exit" data-id="${n.id}" data-exit="${id}" ${dead ? 'title="这个入口连不上它"' : ''}>${mark}${esc(label)}${dead ? '<span class="sr">（不通）</span>' : ''}</button>`;
  };
  const chips = S.data.exits.map(e => chip(e.id, e.name, exitStyle(e.id), false)).join('') + chip(0, '直连', null, true);
  const used = n.rules.map(r => r.ruleset);
  const rows = n.rules.map(r => {
    const set = S.data.rulesets.find(s => s.id === r.ruleset) || { label: r.ruleset, description: '' };
    return `<div class="route">
      <div class="route-head"><span class="rname">${esc(set.label)}</span><span class="rdesc">${esc(set.description)}</span>
        <button class="route-del" data-act="rule-del" data-id="${n.id}" data-rule="${esc(r.ruleset)}" aria-label="删除 ${esc(set.label)} 分流" title="删除这条分流">${XS}</button></div>
      ${chain(n, r.ruleset, r.exit_id, r.fallback, nm(n) + ' ' + set.label)}
    </div>`;
  }).join('');
  const free = S.data.rulesets.filter(s => !used.includes(s.id));
  const addOpen = pickerOpen(n.id, 'rule', '');
  const add = !free.length ? '' : addOpen
    ? `<div class="picker add-picker"><div class="sublabel" style="margin:0">选一类流量单独分流</div><div class="chips">${free.map(s => `<button class="chip set-chip" data-act="pick-do" data-id="${n.id}" data-kind="rule" data-rule="" data-value="${esc(s.id)}"><span>${esc(s.label)}</span>${s.description ? `<span class="d">${esc(s.description)}</span>` : ''}</button>`).join('')}</div>
        <button class="text-btn" data-act="pick" data-id="${n.id}" data-kind="rule" data-rule="">取消</button></div>`
    : pickBtn(n, 'rule', '', 'add-btn', '＋ 添加分流', `${nm(n)} 添加分流`);
  return `<div class="card entry ${st.kind === 'off' ? 'off' : ''}">
    <div class="row">${head}<span style="font-size:13px;color:${st.kind === 'off' ? C.danger : C.muted}">${esc(st.text)}</span></div>
    <div><div class="sublabel">默认出口</div><div class="chips" role="group" aria-label="${esc(nm(n))} 默认出口">${chips}</div>${chain(n, '', n.default_exit, n.default_fallback)}</div>
    <div><div class="sublabel">分流</div><div class="routes">${rows}</div>${add}</div>
  </div>`;
}

function exitCard(e, x) {
  const st = exitStyle(e.id);
  const parts = [];
  if (x) {
    parts.push(esc(nm(x)));
    if (e.quota_bytes) parts.push(`${gib(e.used)} / ${gib(e.quota_bytes)} G`, `${e.reset_day} 号重置`);
    else parts.push(`本期 ${bytes(e.used)}`);
    if (e.udp_over_tcp) parts.push('UDP 走 TCP');
    if (!x.address) parts.push('还不知道地址');
  } else {
    parts.push('外部', esc(extProto(e)));
  }
  const defaults = entries().filter(n => n.default_exit === e.id).map(nm);
  const split = [];
  for (const n of entries()) {
    const hit = n.rules.filter(r => r.exit_id === e.id).map(r => (S.data.rulesets.find(s => s.id === r.ruleset) || {}).label || r.ruleset);
    if (hit.length) split.push(nm(n) + ' ' + hit.join('/'));
  }
  const backup = entries().filter(n => (n.default_fallback || []).includes(e.id) || n.rules.some(r => (r.fallback || []).includes(e.id))).map(nm);
  const usedBy = [];
  if (defaults.length) usedBy.push('默认：' + defaults.join(' · '));
  if (split.length) usedBy.push('分流：' + split.join('，'));
  if (backup.length) usedBy.push('备用：' + backup.join(' · '));
  const bar = e.quota_bytes ? `<span style="display:block;height:3px;background:#D6D1C6"><span style="display:block;height:100%;width:${pct(e.used, e.quota_bytes).toFixed(0)}%;background:${e.used >= e.quota_bytes ? C.red : C.ink}"></span></span>` : '';
  const off = x && !x.online ? ` <span style="font-size:13px;font-weight:400;color:${C.danger}">失联</span>` : '';
  return `<button class="exit-card" ${x ? `data-act="node" data-id="${x.id}"` : `data-act="ext" data-exit="${e.id}"`}>
    <span class="title">${shape(st)}${esc(e.name)}${off}</span>
    <span class="muted" style="font-size:13px">${parts.join(' · ')}</span>
    ${bar}
    <span style="font-size:13px">${checkLine(e)}</span>
    <span style="font-size:14px">${esc(usedBy.length ? usedBy.join('；') : '没有入口在用')}</span>
  </button>`;
}

function exitNodeCard(x) {
  return `<button class="exit-card" data-act="node" data-id="${x.id}">
    <span class="title">${shape({ color: C.faint, shape: 'circle' })}${esc(nm(x))}</span>
    <span class="muted" style="font-size:13px">还没有 SS 端口，点开添加</span>
  </button>`;
}

const USTATUS = { ok: '正常', warn: '将满', over: '超额停用', expired: '已过期', disabled: '已停用' };

// The users page in parts: the head, and one [id, markup] per user, so a
// poll can redraw only the rows that changed.
function usersParts() {
  const all = entries().map(n => n.id);
  return { head: usersHead(), rows: S.data.users.map(u => [u.id, userRow(u, all)]) };
}

function usersHead() {
  return `
    <div class="section-head" style="margin-bottom:20px">
      <h2>用户</h2>
      <span>${S.data.users.some(u => !u.per_entry) ? '<button class="btn" data-act="users-per-entry">每个入口用不同凭据</button> ' : ''}<button class="btn solid" data-act="new-user">添加用户</button></span>
    </div>
    ${S.toast ? `<div class="toast" role="status">${shape({ color: C.blue, shape: 'circle' }, 8)}<span>${esc(S.toast)}</span></div>` : ''}`;
}

function userRow(u, all) {
  const p = pct(u.used, u.quota_bytes), bad = ['over', 'expired', 'disabled'].includes(u.status);
  const barColor = p >= 100 ? C.red : p >= 90 ? C.amber : C.ink;
  const nodesText = !u.entries.length ? '没有入口' : (all.length && all.every(id => u.entries.includes(id))) ? '全部入口'
    : u.entries.map(id => node(id)).filter(Boolean).map(nm).join(' · ');
  const online = u.conns ? ` · ${u.conns} 个连接` : '';
  return `<button class="user" data-act="user" data-id="${u.id}">
    <span class="n">${esc(u.name)}</span>
    <span class="bar">
      <span style="display:flex;justify-content:space-between;font-size:14px"><span>${gib(u.used)} / ${u.quota_bytes ? gib(u.quota_bytes) + ' GB' : '不限'}</span><span style="color:${bad ? C.danger : C.muted}">${USTATUS[u.status]}${online}</span></span>
      <span style="display:block;height:3px;background:#D6D1C6;margin-top:6px"><span style="display:block;height:100%;width:${u.quota_bytes ? p.toFixed(0) : 0}%;background:${barColor}"></span></span>
    </span>
    <span class="meta">到期 ${u.expire_date || '不限'} · ${u.reset_day} 号重置 · ${esc(nodesText)}</span>
  </button>`;
}

function usersList(rows) {
  return `<div class="users">${rows.map(r => r[1]).join('') || '<div class="empty">还没有用户。</div>'}</div>`;
}

// Redraws the rows whose markup changed, when the users page on screen has
// the same head and the same users in the same order; false otherwise.
function patchUsers(users) {
  const box = document.querySelector('#app .users');
  if (!box || !shownUsers || !users.rows.length || users.head !== shownUsers.head || box.children.length !== users.rows.length) return false;
  if (users.rows.some(([id], i) => box.children[i].dataset.id !== String(id))) return false;
  users.rows.forEach(([, html], i) => {
    if (html !== shownUsers.rows[i][1]) box.children[i].outerHTML = html;
  });
  return true;
}

// ---------- drawers ----------

function openDrawer(d) {
  S.drawer = d;
  S.draft = null;
  S.drawerErr = '';
  renderDrawer(true);
}
function closeDrawer() { S.drawer = null; S.draft = null; renderDrawer(); }

function renderDrawer(focus) {
  const root = document.getElementById('drawer-root');
  const d = S.drawer;
  if (!d || !S.data) { root.innerHTML = ''; return; }
  let view;
  if (d.kind === 'node') view = nodeDrawer(d);
  else if (d.kind === 'new-node') view = newNodeDrawer(d);
  else if (d.kind === 'install') view = installDrawer(d);
  else if (d.kind === 'user') view = userDrawer(d);
  else if (d.kind === 'settings') view = settingsDrawer(d);
  else if (d.kind === 'ext-import') view = extImportDrawer(d);
  else if (d.kind === 'ext') view = extDrawer(d);
  if (!view) { closeDrawer(); return; }
  root.innerHTML = `
    <button class="scrim" data-act="close" aria-label="关闭抽屉" tabindex="-1"></button>
    <aside class="drawer" role="dialog" aria-modal="true" aria-labelledby="drawer-title">
      <div class="drawer-head">${view.mark || ''}<h2 id="drawer-title">${esc(view.title)}</h2>
        <button class="icon-btn" data-act="close" aria-label="关闭" style="color:${C.ink}"><svg width="18" height="18" viewBox="0 0 18 18" aria-hidden="true"><path d="M2 2L16 16M16 2L2 16" stroke="currentColor" stroke-width="1.5"></path></svg></button>
      </div>
      <form class="drawer-body" data-form="drawer" id="drawer-form" autocomplete="off">${view.body}<button type="submit" hidden></button></form>
      <div class="err" style="padding:0 24px" role="alert">${esc(S.drawerErr || '')}</div>
      <div class="drawer-foot">${view.foot}</div>
    </aside>`;
  if (focus) {
    const first = root.querySelector('.drawer-body input, .drawer-body button, .drawer-body select');
    if (first) first.focus({ preventScroll: true });
  }
}

function field(label, name, value, opts) {
  opts = opts || {};
  const ac = { cf_token: 'off', password: 'new-password', current_password: 'current-password', username: 'username' }[name] || 'off';
  return `<label class="field ${opts.full ? 'full' : ''}">${label}<input name="${esc(name)}" value="${esc(value)}" autocomplete="${ac}" ${name === 'cf_token' ? 'data-1p-ignore data-lpignore="true"' : 'data-1p-ignore'} ${opts.type ? `type="${opts.type}"` : ''} ${opts.placeholder ? `placeholder="${esc(opts.placeholder)}"` : ''} ${opts.inputmode ? `inputmode="${opts.inputmode}"` : ''}></label>`;
}
// The sites the entry timed for borrowing (every 10 minutes): one click puts
// one in SNI, with dest following it.
function destLine(n) {
  const list = (n.dest_latency || []).slice().sort((a, b) => (a.loss_pct >= 100) - (b.loss_pct >= 100) || a.latency_ms - b.latency_ms);
  if (!list.length) return n.online ? '<div class="field full small muted">伪装站延迟：节点还在测（每 10 分钟一轮）</div>' : '';
  const chip = d => {
    const down = d.loss_pct >= 100, name = destHost(d.host);
    const label = `${esc(d.host.endsWith(':443') ? name : d.host)} <b>${down ? '不通' : Math.round(d.latency_ms) + ' ms'}</b>`;
    return isName(name) && !down
      ? `<button type="button" class="chip small-chip" data-act="dest-pick" data-v="${esc(d.host)}">${label}</button>`
      : `<span class="chip small-chip" aria-disabled="true" style="opacity:.6">${label}</span>`;
  };
  return `<div class="field full">伪装站延迟（节点实测，点一下换成它；换了以后客户端要更新订阅）
    <div class="chips" role="group" aria-label="伪装站延迟" style="margin-top:6px">${list.map(chip).join('')}</div></div>`;
}
function destHost(hostPort) { return hostPort.replace(/:\d+$/, '').replace(/^\[|\]$/g, ''); }
function isName(host) { return /[a-z]/i.test(host) && !host.includes(':'); }
// The fastest site the entry reached, as host:port; undefined if none.
function fastestDest(n) {
  const ok = (n.dest_latency || []).filter(d => d.loss_pct < 100 && isName(destHost(d.host)));
  ok.sort((a, b) => a.latency_ms - b.latency_ms);
  return ok.length ? ok[0].host : undefined;
}
// Puts a timed site in the drawer's SNI (alone: the names must be the
// borrowed site's) and lets dest follow it on 443.
function pickDest(hostPort) {
  const form = document.getElementById('drawer-form');
  const sni = form && form.querySelector('[name="reality_sni"]'), dest = form && form.querySelector('[name="reality_dest"]');
  if (!sni || !dest) return;
  sni.value = destHost(hostPort);
  dest.value = hostPort.endsWith(':443') ? '' : hostPort;
}

function sw(name, on, label) {
  return `<button type="button" class="switch" data-act="switch" data-name="${esc(name)}" aria-pressed="${!!on}" aria-label="${esc(label)}"><i></i></button><input type="hidden" name="${esc(name)}" value="${on ? 1 : 0}">`;
}

// The node's address is read-only (detected from its connection) and stays
// hidden until asked for, so it is not on screen or in a screenshot by accident.
const MASK = '••••••••••';
function addressField(n) {
  const addr = n.host || n.last_ip;
  return `<div class="field full">地址
      <div class="addr"><span class="mono" id="addr-v">${addr ? MASK : '<span class="muted">节点连上后自动识别</span>'}</span>
        ${addr ? `<button type="button" class="text-btn" data-act="addr-toggle" data-id="${n.id}">显示</button>` : ''}
      </div>
    </div>`;
}

// What the node last said about its AnyTLS certificate.
function certLine(n) {
  if (!n.anytls_acme) return '';
  const c = (n.certs || []).find(x => x.domain === n.anytls_sni);
  const day = t => new Date(t * 1000).toISOString().slice(0, 10);
  let text;
  if (!n.anytls_sni) text = `<span style="color:${C.danger}">先填域名</span>`;
  else if (!c) text = '<span class="muted">等节点上报</span>';
  else if (c.issuer === 'acme' && !c.error) text = `已签发，${day(c.not_after)} 到期，会自动续期`;
  else text = `<span style="color:${C.danger}">还没签下来：${esc(c.error || '申请中')}</span>${c.next_try ? `<span class="muted">，${day(c.next_try)} ${new Date(c.next_try * 1000).toTimeString().slice(0, 5)} 重试</span>` : ''}`;
  const how = S.data.settings.cf_token_tail ? 'Cloudflare DNS 验证' : ((n.anytls_pub || n.anytls_port) === 443 ? 'TLS-ALPN 验证（对外 443）' : 'HTTP 验证（要能从外面访问 80 端口）');
  return `<div class="full small" style="margin:-4px 0 4px">${text} <span class="muted">· ${how}</span></div>`;
}

function nodeDrawer(d) {
  const n = node(d.id);
  if (!n) return null;
  const st = nodeStatus(n);
  const isEntry = n.role === 'entry';
  let body = `<section class="sec"><div class="fields two">
      ${field('名称', 'name', n.name, { full: true })}
      ${addressField(n)}
    </div></section>`;
  if (isEntry) {
    const proto = (key, name, extra, portName, port) => `<div class="proto">
        ${sw(key, n[key], '启用 ' + name)}
        <div class="info"><div style="font-size:16px;font-weight:500">${name}</div><div class="small muted">${extra}</div></div>
        <input class="port" name="${portName}" value="${port}" inputmode="numeric" aria-label="${name} 端口">
      </div>`;
    const built = n.protocols && n.protocols.length ? n.protocols : null;
    const missing = ['anytls', 'vless'].filter(p => built && !built.includes(p) && n[p + '_on']);
    const ownCert = !!(n.anytls_cert && n.anytls_key);
    const sni0 = (n.reality_sni || '').split(',')[0];
    const fp = n.reality_fp || 'chrome';
    body += `<section class="sec" style="gap:0">
        <h3 style="margin-bottom:4px">协议</h3>
        ${proto('anytls_on', 'AnyTLS', n.anytls_acme ? '自动申请证书' : ownCert ? '自有证书，客户端校验' : '自签证书，客户端跳过校验', 'anytls_port', n.anytls_port)}
        <div class="fields two proto-opts">
          <div class="toggle-row full"><span style="font-size:14px">自动申请证书 <span class="small muted">（Let's Encrypt，要先填域名并解析到这台）</span></span>${sw('anytls_acme', n.anytls_acme, '自动申请证书')}</div>
          ${certLine(n)}
          ${field('域名 · SNI', 'anytls_sni', n.anytls_sni, { placeholder: '留空不带 SNI' })}
          ${dnsLine(n)}
          ${field('对外端口（NAT 映射才改）', 'anytls_pub', n.anytls_pub || n.anytls_port, { inputmode: 'numeric' })}
          ${field('证书文件（服务器上的路径）', 'anytls_cert', n.anytls_cert, { placeholder: n.anytls_acme ? '自动申请时不用填' : '留空用自签' })}
          ${field('私钥文件', 'anytls_key', n.anytls_key, { placeholder: '留空用自签' })}
        </div>
        ${proto('vless_on', 'VLESS Reality', 'Vision · 伪装 ' + esc(sni0), 'vless_port', n.vless_port)}
        <div class="fields two proto-opts">
          ${field('SNI（多个用逗号隔开，第一个给订阅）', 'reality_sni', n.reality_sni, { full: true })}
          ${field('目标 dest', 'reality_dest', n.reality_dest, { placeholder: '留空自动' })}
          ${destLine(n)}
          ${field('Short ID', 'reality_short_id', n.reality_short_id, { placeholder: '十六进制，逗号分隔' })}
          ${field('对外端口（NAT 映射才改）', 'vless_pub', n.vless_pub || n.vless_port, { inputmode: 'numeric' })}
          <div class="field full">客户端指纹
            <div class="chips" role="group" aria-label="客户端指纹" style="margin-top:6px">${['chrome', 'firefox', 'safari', 'ios', 'android', 'edge', 'random'].map(v => `<button type="button" class="chip small-chip" data-act="fp" data-v="${v}" aria-pressed="${v === fp}">${v}</button>`).join('')}</div>
            <input type="hidden" name="reality_fp" value="${esc(fp)}">
          </div>
          <div class="field full">公钥 <span class="mono small" style="word-break:break-all;color:var(--ink)">${esc(n.reality_public)}</span>
            <button type="button" class="text-btn" style="align-self:flex-start;padding:0" data-act="reality-regen" data-id="${n.id}">换一对密钥</button>
          </div>
        </div>
        ${missing.length ? `<p class="err" style="margin:10px 0 0">这台的 keel-node 没编进 ${missing.join('、')}，这些不会下发。</p>` : ''}
      </section>
      <section class="sec">
        <div class="toggle-row"><span>仅 IPv4 出站</span>${sw('ipv4_only', n.ipv4_only, '仅 IPv4 出站')}</div>
        <label class="field">直连名单 · 不走出口（后缀 / =精确 / ~关键词 / IP 段）<textarea name="direct_list" rows="5">${esc(n.direct_list)}</textarea></label>
      </section>`;
  } else {
    const ports = S.data.exits.filter(e => e.node_id === n.id);
    body += `<section class="sec"><h3>SS-2022 端口</h3>
      ${ports.map(e => `<div class="port-block" data-exit="${e.id}">
        <div class="fields three">
          <label class="field full">出口名称<input name="x${e.id}_name" value="${esc(e.name)}"></label>
          ${field('监听端口', `x${e.id}_port`, e.port, { inputmode: 'numeric' })}
          ${field('对外端口', `x${e.id}_pub`, e.pub_port || e.port, { inputmode: 'numeric' })}
          ${field('月额度 GB', `x${e.id}_quota`, quotaGB(e.quota_bytes), { inputmode: 'numeric', placeholder: '不限' })}
          ${field('重置日', `x${e.id}_reset`, e.reset_day, { inputmode: 'numeric' })}
        </div>
        <div class="toggle-row"><span style="font-size:14px">UDP 走 TCP <span class="small muted">（出口不通 UDP 时打开）</span></span>${sw(`x${e.id}_uot`, e.udp_over_tcp, 'UDP 走 TCP')}</div>
        <div><button type="button" class="btn small danger" data-act="exit-del" data-exit="${e.id}">删除这个端口</button></div>
      </div>`).join('')}
      <div><button type="button" class="btn small" data-act="exit-add" data-id="${n.id}">＋ 添加端口</button></div>
      <p class="small muted" style="margin:0">密钥自动生成。每个端口单独计额度，入口按名字选它。</p>
    </section>
    <section class="sec"><div class="toggle-row"><span>仅 IPv4 出站</span>${sw('ipv4_only', n.ipv4_only, '仅 IPv4 出站')}</div></section>`;
  }
  const s = n.system || {};
  const meta = [`上报 ${n.online ? ago(n.last_seen) : st.text}`];
  if (n.version) meta.push(esc(n.version));
  if (s.rss) meta.push('进程 ' + (s.rss / 1048576).toFixed(1) + ' MB');
  if (n.online && n.sent_rev && n.applied_rev !== n.sent_rev && !n.apply_error) meta.push('配置下发中');
  body += `<section class="sec">
      ${n.apply_error ? `<p class="err" style="margin:0">节点报错：${esc(n.apply_error)}</p>` : ''}
      <div style="display:flex;flex-wrap:wrap;justify-content:space-between;align-items:center;gap:8px 12px;font-size:14px">
        <span>令牌 ••••${esc(n.token_tail)}<span class="muted"> · ${meta.join(' · ')}</span></span>
        <span style="display:flex;gap:8px">
          <button type="button" class="btn small" data-act="install" data-id="${n.id}">安装命令</button>
          <button type="button" class="btn small" data-act="token" data-id="${n.id}">换令牌</button>
        </span>
      </div>
    </section>`;
  return {
    title: nm(n),
    mark: shape({ color: isEntry ? C.red : C.blue, shape: isEntry ? 'square' : 'circle' }, 16),
    body,
    foot: `<button class="btn solid" data-act="save-node" data-id="${n.id}">保存并热更新</button>
      <button class="btn danger" data-act="node-del" data-id="${n.id}">删除</button>`
  };
}

// Whether the master pointed the AnyTLS domain at this node in Cloudflare.
function dnsLine(n) {
  if (!n.dns) return '';
  return n.dns.ok
    ? `<p class="small muted full" style="margin:0">Cloudflare 已把 ${esc(n.dns.name)} 解析到本机（不走代理）</p>`
    : `<p class="err full" style="margin:0">Cloudflare 解析没成功：${esc(n.dns.error)}</p>`;
}

function newNodeDrawer(d) {
  const role = d.role || 'entry';
  if (d.install) {
    return {
      title: '添加节点', mark: shape({ color: C.red, shape: 'square' }, 16),
      body: installBody(d.install),
      foot: `<button class="btn solid" data-act="close">完成</button>`
    };
  }
  return {
    title: '添加节点', mark: shape({ color: C.red, shape: 'square' }, 16),
    body: `<section class="sec">
        <div class="seg" role="group" aria-label="节点角色">
          <button type="button" data-act="role" data-role="entry" aria-pressed="${role === 'entry'}">入口</button>
          <button type="button" data-act="role" data-role="exit" aria-pressed="${role === 'exit'}">出口</button>
        </div>
        <p class="small muted" style="margin:0">${role === 'entry' ? '入口：用户连它（AnyTLS / VLESS Reality），再按规则把流量交给出口。' : '出口：只开 SS-2022，接各个入口转来的流量，比如家宽落地。'}</p>
        <div class="fields two">
          ${field('名称', 'name', d.name || '', { placeholder: role === 'entry' ? '日本' : '英国' })}
        </div>
        ${role === 'entry' ? newEntryProtos(d) : ''}
      </section>`,
    foot: `<button class="btn solid" data-act="create-node">创建并生成安装命令</button>`
  };
}

// Protocol chips and their SNI fields for a new entry; AnyTLS is on by default.
function newEntryProtos(d) {
  const on = d.protos || ['anytls'];
  const chip = (v, label) => `<button type="button" class="chip" data-act="new-proto" data-v="${v}" aria-pressed="${on.includes(v)}">${label}</button>`;
  return `<div><div class="sublabel">协议</div><div class="chips" role="group" aria-label="协议">${chip('anytls', 'AnyTLS')}${chip('vless', 'VLESS Reality')}</div></div>
        <div class="fields two">
          ${on.includes('anytls') ? field('AnyTLS 域名 · SNI', 'anytls_sni', d.anytls_sni || '', { placeholder: '留空不带 SNI' }) : ''}
          ${on.includes('vless') ? field('Reality 伪装 SNI', 'reality_sni', d.reality_sni || '', { placeholder: 'www.apple.com' }) : ''}
        </div>
        <p class="small muted" style="margin:0">端口随机生成，证书、Short ID 等创建后点开节点再改。</p>`;
}

const EXT_HELP = `<p class="small muted" style="margin:0">一行一条：<b>vless://</b>（Reality、TLS 或明文 TCP，可带 xtls-rprx-vision；明文的话 UUID、目的地和内容在路上都看得见，尽量用 Reality 或 TLS）、<b>ss://</b>（SS-2022 或 aes-gcm / chacha20，不带插件）。也可以粘贴 3x-ui / Xray 的出站 JSON，或整份 Xray 配置，会取出里面的 vless 和 shadowsocks 出站。名称取链接 # 后面的备注。</p>`;

function extImportDrawer(d) {
  return {
    title: '导入外部出口', mark: shape({ color: C.blue, shape: 'circle' }, 16),
    body: `<section class="sec">
        <p style="margin:0;font-size:14px">外部出口是别人的服务器（比如买的家宽落地）：不装 keel，入口直接连它。导入后和自建出口一样，可以设成默认、分流或备用。</p>
        <label class="field">分享链接或出站 JSON<textarea name="link" rows="6" placeholder="vless://…  或  ss://…">${esc(d.link || '')}</textarea></label>
        <div class="fields">${field('名称（只导入一条时可选，留空用链接备注）', 'name', d.name || '', { placeholder: 'GLBB 动态' })}</div>
        ${EXT_HELP}
      </section>`,
    foot: `<button class="btn solid" data-act="ext-create">导入</button>`
  };
}

function extDrawer(d) {
  const e = exit(d.id);
  if (!e) return null;
  return {
    title: e.name, mark: shape(exitStyle(e.id), 16),
    body: `<section class="sec">
        <div class="fields two">
          ${field('名称', 'name', e.name)}
          <label class="field">协议<input value="${esc(extProto(e))}" disabled></label>
        </div>
        <label class="field">换一条链接（商家换了地址或密钥时粘贴新的，名称和线路设置不变）<textarea name="link" rows="3" placeholder="留空就不换"></textarea></label>
        ${EXT_HELP}
        <p class="small muted" style="margin:0">流量额度由商家那边控制，这里不统计。</p>
      </section>`,
    foot: `<button class="btn solid" data-act="ext-save" data-exit="${e.id}">保存并热更新</button>
      <button class="btn danger" data-act="exit-del" data-exit="${e.id}">删除</button>`
  };
}

function installBody(cmd) {
  return `<section class="sec">
      <p style="margin:0;font-size:14px">在节点机器上用 root 运行这一行。装好后它会自己连上主控，不需要在节点上开任何管理端口。</p>
      <div class="code-box" id="install-cmd">${esc(cmd)}</div>
      <div><button type="button" class="btn" data-act="copy" data-target="install-cmd">复制</button></div>
      <p class="small muted" style="margin:0">脚本会从主控下载 keel-node（先把 make node-linux 编出的 keel-node-linux-amd64 / arm64 放进主控数据目录的 dist/），装成 systemd 或 OpenRC 服务。</p>
    </section>`;
}

function installDrawer(d) {
  const n = node(d.id);
  return {
    title: n ? `${nm(n)} 安装命令` : '安装命令', mark: shape({ color: C.red, shape: 'square' }, 16),
    body: installBody(d.install) + (d.rotated ? '<p class="err">令牌已换，旧令牌立即失效，节点要用新命令重装一次。</p>' : ''),
    foot: `<button class="btn solid" data-act="close">完成</button>`
  };
}

function userDraft(u) {
  return {
    name: u ? u.name : '', plan: u ? u.plan : '',
    quota: u ? quotaGB(u.quota_bytes) : 100,
    expire: u ? u.expire_date : '', reset: u ? u.reset_day : new Date().getDate(),
    entries: u ? u.entries.slice() : entries().map(n => n.id), enabled: u ? u.enabled : true
  };
}

function userDrawer(d) {
  const u = d.id ? S.data.users.find(x => x.id === d.id) : null;
  if (d.id && !u) return null;
  const f = S.draft || (S.draft = userDraft(u));
  const chips = entries().map(n => `<button type="button" class="chip" style="min-width:60px;justify-content:center;font-size:15px;font-weight:500" data-act="user-entry" data-id="${n.id}" aria-pressed="${f.entries.includes(n.id)}">${esc(nm(n))}</button>`).join('');
  let body = `<section class="sec">
      <label class="field">名称<input name="name" value="${esc(f.name)}" placeholder="用户名" data-draft="name"></label>
      <div class="fields three">
        ${field('额度 GB', 'quota', f.quota, { inputmode: 'numeric', placeholder: '不限' })}
        ${field('到期', 'expire', f.expire, { type: 'date' })}
        ${field('重置日', 'reset', f.reset, { inputmode: 'numeric' })}
      </div>
    </section>
    <section class="sec"><h3>可用入口</h3><div class="chips">${chips || '<span class="muted">还没有入口节点</span>'}</div></section>`;
  if (u) {
    body += `<section class="sec">
      <div style="display:flex;gap:8px">
        <button type="button" class="btn small" data-act="copy" data-text="${esc(u.sub_url)}">复制订阅</button>
        <button type="button" class="btn small" data-act="sub-rotate" data-id="${u.id}">重置订阅</button>
      </div>
      <p class="small muted" style="margin:0">本期已用 ${bytes(u.used)}，${u.reset_day} 号清零${u.conns ? ' · 当前 ' + u.conns + ' 个连接' : ''}。</p>
    </section>`;
  }
  return {
    title: u ? u.name : '添加用户', mark: shape({ color: C.yellow, shape: 'tri' }, 16), body,
    foot: u
      ? `<button class="btn solid" data-act="save-user" data-id="${u.id}">保存</button>
         <button class="btn" data-act="user-reset" data-id="${u.id}">清零流量</button>
         <button class="btn" data-act="user-toggle" data-id="${u.id}">${u.enabled ? '停用' : '启用'}</button>
         <button class="btn danger" data-act="user-del" data-id="${u.id}">删除</button>`
      : `<button class="btn solid" data-act="save-user">创建</button>`
  };
}

function settingsDrawer() {
  const st = S.data.settings;
  const tz = st.tz_offset / 60;
  const targets = st.probe_targets.map(t => field(`${esc(t.label)}（IP:端口）`, `probe_${t.name}`, t.host, { full: true, placeholder: 'sh-' + t.name + '-v4.ip.zstaticcdn.com:80' })).join('');
  return {
    title: '设置', mark: shape({ color: C.ink, shape: 'circle' }, 16),
    body: `<section class="sec"><div class="fields two">
        <div class="field">时区（重置日按它算）<div class="stepper"><button type="button" data-act="tz-step" data-d="-1" aria-label="减一小时">−</button><output id="tz-label">${tzLabel(tz)}</output><button type="button" data-act="tz-step" data-d="1" aria-label="加一小时">+</button></div><input type="hidden" name="tz_offset" value="${tz * 60}"></div>
      </div></section>
      <section class="sec"><h3>三网测速目标</h3><div class="fields">${targets}</div>
        <p class="small muted" style="margin:0">默认是上海三网（Zstatic 公开的 TCPing 节点，地址由对方自动更新）。换省份就把 sh 改成对应代号。节点每 30 秒对每个目标 TCP 连 10 次，算延迟、波动和重传。留空就不测。</p></section>
      ${st.panel_acme_available ? `<section class="sec"><h3>面板证书</h3><div class="fields"><div class="field">向 Let's Encrypt 申请面板证书${sw('panel_acme', st.panel_acme, '自动申请面板证书')}</div></div>
        <p class="small muted" style="margin:0">要先在下面填好 https:// 开头的面板域名。有 Cloudflare 令牌就用 DNS 验证，否则要能从外面访问本机 80 端口。证书沿用主控原来的密钥，节点不用重装，但要先把每个节点升级（agent update），全部升级后才会申请。${st.panel_cert ? (st.panel_cert.error ? `<br><b>${esc(st.panel_cert.error)}</b>` : (st.panel_cert.not_after ? `<br>已签发 ${esc(st.panel_cert.domain)}，${new Date(st.panel_cert.not_after * 1000).toISOString().slice(0, 10)} 到期，自动续期。` : '')) : ''}</p></section>` : ''}
      <section class="sec"><h3>公开探针页</h3><div class="fields"><div class="field">在 / 显示节点状态（不用登录）${sw('public_page', st.public_page, '公开探针页')}</div></div>
        <p class="small muted" style="margin:0">打开后任何人都能看到节点名字、在线状态和流量，也能由此认出这是 keel 面板。关着时 / 返回 404。</p></section>
      <section class="sec"><h3>面板地址</h3><div class="fields">${field('节点和订阅用的地址', 'panel_url', st.panel_url || '', { full: true, placeholder: st.base_url })}</div>
        <p class="small muted" style="margin:0">留空就用浏览器当前访问的地址。放在反向代理后面时请填 https:// 开头的地址，否则安装命令和订阅可能变成明文 http://。${(st.panel_url || st.base_url || '').startsWith('http://') ? '<b>现在是 http://，节点令牌和用户凭据会明文传输。</b>' : ''}</p></section>
      ${st.fingerprint ? `<section class="sec"><h3>主控证书指纹</h3><div class="mono small" style="word-break:break-all">${esc(st.fingerprint)}</div></section>` : ''}
      <section class="sec"><h3>证书自动申请</h3><div class="fields two">
        ${field('邮箱（证书到期提醒，可不填）', 'acme_email', st.acme_email || '')}
        ${field('Cloudflare API Token', 'cf_token', '', { type: 'password', placeholder: st.cf_token_tail ? '已设置 …' + st.cf_token_tail : '可不填' })}
      </div>
      <p class="small muted" style="margin:0">填了 Token（权限：Zone → DNS → Edit 和 Zone → Zone → Read）后，入口填的 AnyTLS 域名会自动解析到节点 IP（不开小黄云）；自动申请证书也改用 DNS 验证，不用开端口，NAT 机也能签。所有节点共用，只存在主控里，不会再显示出来。${st.cf_token_tail ? '<button type="button" class="text-btn" data-act="cf-clear">清除 Token</button>' : ''}</p>
      </section>
      <section class="sec"><h3>登录</h3><div class="fields two">
        ${field('用户名', 'username', st.username, { full: true })}
        ${field('当前密码', 'current_password', '', { type: 'password' })}
        ${field('新密码（不改就留空）', 'password', '', { type: 'password' })}
      </div><p class="small muted" style="margin:0">改用户名或密码都要填当前密码。</p></section>`,
    foot: `<button class="btn solid" data-act="save-settings">保存</button>
      <button class="btn" data-act="logout">退出登录</button>`
  };
}

function tzLabel(h) { return 'UTC' + (h >= 0 ? '+' : '') + h; }

function form() {
  const f = document.getElementById('drawer-form');
  const out = {};
  if (!f) return out;
  for (const el of f.elements) if (el.name) out[el.name] = el.value;
  return out;
}
function drawerError(msg) { S.drawerErr = msg; renderDrawer(); }
// A public port field, shown filled with the listen port. Stored as 0
// ("same as listen") unless it really differs, so a port that followed the
// listen port keeps following it when that changes. null = not a number.
function pubPort(v, listen, oldPub, oldListen) {
  if ((v || '').trim() === '') return 0;
  const p = int(v);
  if (p === null) return null;
  if (p === listen || (!oldPub && p === oldListen)) return 0;
  return p;
}
function int(v) { const s = String(v).trim(); return /^\d+$/.test(s) ? parseInt(s, 10) : null; }
// GB as typed in a quota field; '' is unlimited (0). Decimals are allowed.
function quotaBytes(v) {
  const s = String(v).trim();
  if (s === '') return 0;
  return /^\d+(\.\d+)?$/.test(s) ? Math.round(parseFloat(s) * GB) : null;
}
function quotaGB(b) { return b ? String(+(b / GB).toFixed(2)) : ''; }

// Keeps typed values when the drawer re-renders for a button press.
function keepNewNode() {
  const f = form();
  for (const k of ['name', 'anytls_sni', 'reality_sni']) if (k in f) S.drawer[k] = f[k].trim();
}
function keepUserDraft() {
  if (!S.draft) return;
  const f = form();
  S.draft.name = f.name; S.draft.quota = f.quota; S.draft.expire = f.expire; S.draft.reset = f.reset;
}

// ---------- actions ----------

const actions = {
  tab(el) { S.tab = el.dataset.tab; save('tab', S.tab); S.toast = ''; render(); window.scrollTo(0, 0); },
  settings() { openDrawer({ kind: 'settings' }); },
  'tz-step'(el) {
    const inp = document.querySelector('#drawer-form [name="tz_offset"]');
    const h = Math.max(-12, Math.min(14, Math.round(+inp.value / 60) + +el.dataset.d));
    inp.value = h * 60;
    document.getElementById('tz-label').textContent = tzLabel(h);
  },
  close() { closeDrawer(); },
  pick(el) {
    const p = { id: +el.dataset.id, kind: el.dataset.kind, rule: el.dataset.rule || '' };
    S.picker = pickerOpen(p.id, p.kind, p.rule) ? null : p;
    render();
  },
  'pick-do'(el) {
    const n = node(+el.dataset.id), kind = el.dataset.kind, rid = el.dataset.rule, v = el.dataset.value;
    S.picker = null;
    if (kind === 'primary') {
      const x = +v, set = S.data.rulesets.find(s => s.id === rid);
      const r0 = n.rules.find(r => r.ruleset === rid);
      if (r0 && r0.exit_id === x) { render(); return; }
      setRules(n, n.rules.map(r => r.ruleset === rid ? { ruleset: rid, exit_id: x, fallback: r.fallback } : r), `${nm(n)} 的 ${set.label} 走 ${exitLabel(x)}。`);
    } else if (kind === 'fb') {
      changeFallback(n, rid, list => list.concat([+v]), `加了备用 ${exitLabel(+v)}，主出口不通时自动换过去。`);
    } else if (kind === 'rule') {
      const set = S.data.rulesets.find(s => s.id === v);
      // A new split starts on the first exit that is not the default.
      const first = S.data.exits.find(x => x.id !== n.default_exit);
      const target = first ? first.id : 0;
      setRules(n, n.rules.concat([{ ruleset: v, exit_id: target }]), `${nm(n)} 的 ${set.label} 走 ${exitLabel(target)}，点出口可以换。`);
    }
  },
  // Flip in place: toggle the class on the live element so the transition
  // plays, and remember it so later re-renders keep the side.
  probe(el) {
    const id = +el.dataset.id, card = el.closest('.flip');
    if (S.flipped.has(id)) S.flipped.delete(id); else S.flipped.add(id);
    const on = S.flipped.has(id);
    card.classList.toggle('flipped', on);
    card.querySelector('.front').toggleAttribute('aria-hidden', on);
    card.querySelector('.back').toggleAttribute('aria-hidden', !on);
    card.querySelector('.front').tabIndex = on ? -1 : 0;
    card.querySelector('.back').tabIndex = on ? 0 : -1;
    card.querySelector(on ? '.back' : '.front').focus({ preventScroll: true });
  },
  'default-exit'(el) {
    const n = node(+el.dataset.id), x = +el.dataset.exit;
    const label = x ? exit(x).name : '直连';
    const fallback = (n.default_fallback || []).filter(id => id !== x);
    act(() => api('PATCH', `/api/nodes/${n.id}`, { default_exit: x, default_fallback: fallback }), `${nm(n)} 默认改走 ${label}。已热更新，现有连接不断。`);
  },
  'rule-del'(el) {
    const n = node(+el.dataset.id), rid = el.dataset.rule;
    const set = S.data.rulesets.find(s => s.id === rid);
    setRules(n, n.rules.filter(r => r.ruleset !== rid), `${nm(n)} 的 ${set ? set.label : rid} 改回走默认出口。`);
  },
  'fb-del'(el) {
    const n = node(+el.dataset.id), x = +el.dataset.exit;
    changeFallback(n, el.dataset.rule, list => list.filter(id => id !== x), `去掉了备用 ${exitLabel(x)}。`);
  },
  node(el) { openDrawer({ kind: 'node', id: +el.dataset.id }); },
  'new-node'() { openDrawer({ kind: 'new-node', role: 'entry' }); },
  role(el) { keepNewNode(); S.drawer.role = el.dataset.role; renderDrawer(); },
  'new-proto'(el) {
    keepNewNode();
    const on = S.drawer.protos || ['anytls'], v = el.dataset.v;
    S.drawer.protos = on.includes(v) ? on.filter(x => x !== v) : [...on, v];
    renderDrawer();
  },
  async 'create-node'() {
    keepNewNode();
    const d = S.drawer, role = d.role || 'entry', protos = d.protos || ['anytls'];
    if (role === 'entry' && !protos.length) return drawerError('至少选一个协议');
    try {
      const r = await api('POST', '/api/nodes', { role, name: d.name || '' });
      if (role === 'entry') {
        const patch = { anytls_on: protos.includes('anytls'), vless_on: protos.includes('vless') };
        if (patch.anytls_on && d.anytls_sni) patch.anytls_sni = d.anytls_sni;
        // An empty dest follows the first SNI.
        if (patch.vless_on && d.reality_sni) Object.assign(patch, { reality_sni: d.reality_sni, reality_dest: '' });
        try { await api('PATCH', `/api/nodes/${r.id}`, patch); }
        catch (e) { S.drawer.install = r.install; await refresh(); return drawerError('节点已创建，但协议设置没存上：' + e.message + '。点开节点再改。'); }
      }
      S.drawer.install = r.install; S.drawerErr = '';
      await refresh(); renderDrawer();
    } catch (e) { drawerError(e.message); }
  },
  async install(el) {
    try { const r = await api('GET', `/api/nodes/${el.dataset.id}/install`); openDrawer({ kind: 'install', id: +el.dataset.id, install: r.install }); }
    catch (e) { drawerError(e.message); }
  },
  async token(el) {
    if (!confirm('换令牌后旧令牌立即失效，节点会断开，10 分钟后停止服务，要用新命令重装一次。继续？')) return;
    try { const r = await api('POST', `/api/nodes/${el.dataset.id}/token`); await refresh(); openDrawer({ kind: 'install', id: +el.dataset.id, install: r.install, rotated: true }); }
    catch (e) { drawerError(e.message); }
  },
  'addr-toggle'(el) {
    const n = node(+el.dataset.id), v = document.getElementById('addr-v'), show = v.textContent === MASK;
    v.textContent = show ? (n.host || n.last_ip) : MASK;
    el.textContent = show ? '隐藏' : '显示';
  },
  fp(el) {
    el.parentElement.querySelectorAll('.chip').forEach(b => b.setAttribute('aria-pressed', b === el));
    el.closest('.field').querySelector('input[name="reality_fp"]').value = el.dataset.v;
  },
  async 'reality-regen'(el) {
    if (!confirm('换密钥后，用户要重新更新订阅才能连 Reality。继续？')) return;
    try { await api('PATCH', `/api/nodes/${el.dataset.id}`, { reality_regen: true }); flash('Reality 密钥已更换，已热更新。'); await refresh(); renderDrawer(); }
    catch (e) { drawerError(e.message); }
  },
  switch(el) {
    const on = el.getAttribute('aria-pressed') !== 'true';
    el.setAttribute('aria-pressed', on);
    const input = el.parentElement.querySelector(`input[name="${el.dataset.name}"]`);
    if (input) input.value = on ? 1 : 0;
    // VLESS turned on for the first time (no client uses its SNI yet):
    // borrow the site the entry reaches fastest, unless SNI was edited.
    const n = on && el.dataset.name === 'vless_on' && S.drawer && S.drawer.kind === 'node' ? node(S.drawer.id) : null;
    const sni = document.querySelector('#drawer-form [name="reality_sni"]');
    if (n && !n.vless_on && fastestDest(n) && sni && sni.value.trim() === (n.reality_sni || '')) pickDest(fastestDest(n));
  },
  'dest-pick'(el) { pickDest(el.dataset.v); },
  async 'save-node'(el) {
    const n = node(+el.dataset.id), f = form();
    const patch = { name: f.name.trim(), ipv4_only: f.ipv4_only === '1' };
    if (n.role === 'entry') {
      Object.assign(patch, {
        anytls_on: f.anytls_on === '1', vless_on: f.vless_on === '1',
        anytls_port: int(f.anytls_port), vless_port: int(f.vless_port),
        anytls_acme: f.anytls_acme === '1',
        anytls_sni: f.anytls_sni.trim(), anytls_cert: f.anytls_cert.trim(), anytls_key: f.anytls_key.trim(),
        reality_sni: f.reality_sni.trim(), reality_dest: f.reality_dest.trim(), reality_short_id: f.reality_short_id.trim(), reality_fp: f.reality_fp,
        direct_list: f.direct_list
      });
      // A dest that just followed the old SNI follows the new one.
      const oldSni = (n.reality_sni || '').split(',')[0];
      if (patch.reality_sni !== n.reality_sni && patch.reality_dest === oldSni + ':443') patch.reality_dest = '';
      if (!patch.anytls_cert !== !patch.anytls_key) return drawerError('证书和私钥要一起填，或者都留空用自签');
      if (patch.anytls_acme && !patch.anytls_sni) return drawerError('自动申请证书要先填域名');
      if (patch.anytls_port !== null && patch.anytls_port === patch.vless_port) return drawerError('两个协议不能用同一个端口');
      patch.anytls_pub = pubPort(f.anytls_pub, patch.anytls_port, n.anytls_pub, n.anytls_port);
      patch.vless_pub = pubPort(f.vless_pub, patch.vless_port, n.vless_pub, n.vless_port);
      for (const k of ['anytls_port', 'vless_port', 'anytls_pub', 'vless_pub']) if (patch[k] === null) return drawerError('端口要填数字');
    }
    try {
      await api('PATCH', `/api/nodes/${n.id}`, patch);
      if (n.role === 'exit') {
        for (const e of S.data.exits.filter(x => x.node_id === n.id)) {
          const quota = quotaBytes(f[`x${e.id}_quota`] || '');
          const port = int(f[`x${e.id}_port`]), reset = int(f[`x${e.id}_reset`]), pub = pubPort(f[`x${e.id}_pub`], port, e.pub_port, e.port);
          if (quota === null || port === null || reset === null || pub === null) return drawerError('端口、额度、重置日要填数字');
          await api('PATCH', `/api/exits/${e.id}`, { name: f[`x${e.id}_name`], port, pub_port: pub, quota_bytes: quota, reset_day: reset, udp_over_tcp: f[`x${e.id}_uot`] === '1' });
        }
      }
      flash(`${patch.name || nm(n)} 已保存并热更新。`);
      closeDrawer(); await refresh({ draw: false }); render();
    } catch (e) { drawerError(e.message); }
  },
  async 'node-del'(el) {
    const n = node(+el.dataset.id);
    if (!confirm(`删除 ${nm(n)}？节点会断开，10 分钟后停止服务（服务器上的程序要自己卸载），用它的线路改回直连。`)) return;
    closeDrawer();
    act(() => api('DELETE', `/api/nodes/${n.id}`), `已删除 ${nm(n)}。`);
  },
  async 'exit-add'(el) {
    try { await api('POST', '/api/exits', { node_id: +el.dataset.id }); await refresh(); S.drawerErr = ''; renderDrawer(); }
    catch (e) { drawerError(e.message); }
  },
  async 'exit-del'(el) {
    const e = exit(+el.dataset.exit);
    if (!confirm(`删除出口「${e.name}」？走它的入口和分流会改回默认或直连。`)) return;
    if (isExternal(e)) closeDrawer();
    try { await api('DELETE', `/api/exits/${e.id}`); await refresh({ draw: false }); renderDrawer(); render(); }
    catch (err) { drawerError(err.message); }
  },
  'ext-import'() { openDrawer({ kind: 'ext-import' }); },
  ext(el) { openDrawer({ kind: 'ext', id: +el.dataset.exit }); },
  async 'ext-create'() {
    const f = form();
    if (!f.link.trim()) return drawerError('先粘贴链接');
    try {
      const r = await api('POST', '/api/exits', { link: f.link, name: f.name });
      closeDrawer(); await refresh();
      const n = r.ids.length;
      flash(n > 1 ? `导入了 ${n} 个外部出口，可以在入口的默认、分流或备用里选它们。` : `导入了「${exit(r.id) ? exit(r.id).name : '外部出口'}」，可以在入口的默认、分流或备用里选它。`);
      render();
    } catch (e) { Object.assign(S.drawer, { link: f.link, name: f.name }); drawerError(e.message); }
  },
  async 'ext-save'(el) {
    const e = exit(+el.dataset.exit), f = form();
    try {
      await api('PATCH', `/api/exits/${e.id}`, { name: f.name, link: f.link });
      flash(`「${f.name || e.name}」已保存并热更新。`);
      closeDrawer(); await refresh({ draw: false }); render();
    } catch (err) { drawerError(err.message); }
  },
  user(el) { openDrawer({ kind: 'user', id: +el.dataset.id }); },
  'new-user'() { openDrawer({ kind: 'user', id: 0 }); },
  'user-entry'(el) {
    keepUserDraft();
    const id = +el.dataset.id, list = S.draft.entries;
    S.draft.entries = list.includes(id) ? list.filter(x => x !== id) : list.concat([id]);
    renderDrawer();
  },
  async 'save-user'(el) {
    keepUserDraft();
    const f = S.draft, id = +el.dataset.id || 0;
    const quota = quotaBytes(f.quota), reset = int(f.reset);
    if (quota === null) return drawerError('额度要填数字，留空为不限');
    if (reset === null || reset < 1 || reset > 31) return drawerError('重置日填 1–31');
    const body = { name: f.name, plan: f.plan, quota_bytes: quota, expire_date: f.expire || '', reset_day: reset, entries: f.entries };
    try {
      if (id) await api('PATCH', `/api/users/${id}`, body); else await api('POST', '/api/users', body);
      flash(id ? `${f.name} 已保存。` : `已添加 ${f.name}。`);
      closeDrawer(); await refresh({ draw: false }); render();
    } catch (e) { drawerError(e.message); }
  },
  async 'user-reset'(el) {
    const u = S.data.users.find(x => x.id === +el.dataset.id);
    if (!confirm(`把 ${u.name} 本期流量清零？`)) return;
    try { await api('POST', `/api/users/${u.id}/reset`); flash(`${u.name} 的流量已清零。`); await refresh({ draw: false }); renderDrawer(); render(); }
    catch (e) { drawerError(e.message); }
  },
  async 'user-toggle'(el) {
    const u = S.data.users.find(x => x.id === +el.dataset.id);
    try { await api('PATCH', `/api/users/${u.id}`, { enabled: !u.enabled }); flash(`${u.name} 已${u.enabled ? '停用' : '启用'}。`); await refresh({ draw: false }); renderDrawer(); render(); }
    catch (e) { drawerError(e.message); }
  },
  async 'user-del'(el) {
    const u = S.data.users.find(x => x.id === +el.dataset.id);
    if (!confirm(`删除 ${u.name}？他正在用的连接会立即断开。`)) return;
    closeDrawer();
    act(() => api('DELETE', `/api/users/${u.id}`), `已删除 ${u.name}。`);
  },
  async 'users-per-entry'() {
    const old = S.data.users.filter(u => !u.per_entry).length;
    if (!confirm(`让 ${old} 个老用户在每个入口用不同的密码和 UUID？一个入口泄露的配置就开不了别的入口。切换后这些用户要刷新订阅（客户端一般 12 小时内自动刷新），刷新前连不上。继续？`)) return;
    act(() => api('POST', '/api/users/per-entry'), '已切换，让用户刷新一下订阅。');
  },
  async 'sub-rotate'(el) {
    if (!confirm('重置后旧订阅链接和代理密码都立即失效，要把新链接重新发给这个用户，他的客户端要重新导入。继续？')) return;
    try { await api('POST', `/api/users/${el.dataset.id}/sub`); flash('订阅已重置，点复制订阅拿新链接。'); await refresh(); keepUserDraft(); renderDrawer(); }
    catch (e) { drawerError(e.message); }
  },
  async 'save-settings'() {
    const f = form(), st = S.data.settings;
    const body = {
      tz_offset: int(f.tz_offset),
      probe_targets: st.probe_targets.map(t => ({ name: t.name, label: t.label, host: (f['probe_' + t.name] || '').trim() }))
    };
    body.acme_email = (f.acme_email || '').trim();
    body.panel_url = (f.panel_url || '').trim();
    body.public_page = f.public_page === '1';
    if (st.panel_acme_available) body.panel_acme = f.panel_acme === '1';
    if (f.cf_token) body.cf_token = f.cf_token.trim();
    body.username = f.username.trim(); body.current_password = f.current_password;
    if (f.password) body.password = f.password;
    try { await api('PATCH', '/api/settings', body); flash('设置已保存。'); closeDrawer(); await refresh({ draw: false }); render(); }
    catch (e) { drawerError(e.message); }
  },
  async 'cf-clear'() {
    if (!confirm('清除 Cloudflare Token？之后改用 HTTP / TLS 验证。')) return;
    try { await api('PATCH', '/api/settings', { cf_token: '-' }); flash('Token 已清除。'); await refresh(); renderDrawer(); }
    catch (e) { drawerError(e.message); }
  },
  async logout() {
    try { await api('POST', '/api/logout'); } catch (e) { /* ignore */ }
    S.loggedIn = false; S.data = null; closeDrawer(); render();
  },
  copy(el) {
    const text = el.dataset.text || (document.getElementById(el.dataset.target) || {}).textContent || '';
    copyText(text).then(ok => { el.textContent = ok ? '已复制' : '请手动复制'; setTimeout(() => { el.textContent = el.dataset.text ? '复制订阅' : '复制'; }, 1600); });
  }
};

async function copyText(text) {
  try { await navigator.clipboard.writeText(text); return true; } catch (e) { /* not a secure context */ }
  const ta = document.createElement('textarea');
  ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
  document.body.appendChild(ta); ta.select();
  let ok = false;
  try { ok = document.execCommand('copy'); } catch (e) { /* ignore */ }
  ta.remove();
  return ok;
}

function setRules(n, rules, msg) {
  const body = rules.map(r => ({ ruleset: r.ruleset, exit_id: r.exit_id, fallback: (r.fallback || []).filter(id => id !== r.exit_id) }));
  act(() => api('PUT', `/api/nodes/${n.id}/rules`, { rules: body }), msg + '已热更新。');
}

// rule '' is the default exit's fallback list, otherwise that rule's.
function changeFallback(n, rule, fn, msg) {
  if (!rule) {
    act(() => api('PATCH', `/api/nodes/${n.id}`, { default_fallback: fn(n.default_fallback || []) }), msg + '已热更新。');
  } else {
    setRules(n, n.rules.map(r => r.ruleset === rule ? Object.assign({}, r, { fallback: fn(r.fallback || []) }) : r), msg);
  }
}

document.addEventListener('click', e => {
  const el = e.target.closest('[data-act]');
  if (!el) return;
  const fn = actions[el.dataset.act];
  if (!fn) return;
  e.preventDefault();
  fn(el);
});

document.addEventListener('keydown', e => {
  if (e.key === 'Escape' && S.drawer) closeDrawer();
  else if (e.key === 'Escape' && S.picker) { S.picker = null; render(); }
});

document.addEventListener('submit', async e => {
  e.preventDefault();
  if (e.target.dataset.form === 'login') {
    const pw = e.target.password.value, user = e.target.username.value;
    try {
      await api('POST', '/api/login', { username: user, password: pw });
      S.loggedIn = true; await refresh({ draw: false }); render();
    } catch (err) {
      const box = document.getElementById('login-err');
      if (box) box.textContent = err.message;
    }
  }
  // Enter inside a drawer field does nothing; saving is an explicit button.
});

(async function start() {
  if (ADMIN) {
    try {
      const s = await api('GET', '/api/session');
      S.loggedIn = s.logged_in;
    } catch (e) { S.loggedIn = false; }
  }
  if (S.loggedIn || !ADMIN) await refresh({ draw: false });
  render();
  // No polling while the tab is in the background. The next poll waits at
  // least twice as long as the last answer took, so a slow master is asked
  // less often instead of piling requests up.
  const every = ADMIN ? 2000 : 3000;
  const poll = async () => {
    const start = Date.now();
    if ((S.loggedIn || !ADMIN) && !document.hidden) await refresh({ poll: true });
    setTimeout(poll, Math.max(every, 2 * (Date.now() - start)));
  };
  setTimeout(poll, every);
  document.addEventListener('visibilitychange', () => { if (!document.hidden && (S.loggedIn || !ADMIN)) refresh({ poll: true }); });
})();
