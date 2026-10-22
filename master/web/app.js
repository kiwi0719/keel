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
const PLANS = [{ label: '轻量', gb: 100 }, { label: '标准', gb: 300 }, { label: '自用', gb: 1000 }, { label: '自定义', gb: null }];
const GB = 1024 ** 3;

const S = {
  tab: load('tab') || 'probe',
  data: null,
  loggedIn: null,
  openProbe: null,
  editing: null,      // entry node id being renamed inline
  toast: '',
  drawer: null,       // { kind, id, ... }
  draft: null         // drawer form state
};

function load(k) { try { return localStorage.getItem('keel.' + k); } catch (e) { return null; } }
function save(k, v) { try { localStorage.setItem('keel.' + k, v); } catch (e) { /* private mode */ } }

// ---------- helpers ----------

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

function node(id) { return S.data.nodes.find(n => n.id === id); }
function exit(id) { return S.data.exits.find(e => e.id === id); }
function exitStyle(id) {
  const i = S.data.exits.findIndex(e => e.id === id);
  return i < 0 ? { color: C.faint, shape: 'circle' } : EXIT_STYLE[i % EXIT_STYLE.length];
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
    headers: body ? { 'content-type': 'application/json' } : {},
    body: body ? JSON.stringify(body) : undefined
  });
  let json = {};
  try { json = await res.json(); } catch (e) { /* empty */ }
  if (res.status === 401 && path !== '/api/login') { S.loggedIn = false; render(); throw new Error(json.error || '请先登录'); }
  if (!res.ok) throw new Error(json.error || ('出错了（' + res.status + '）'));
  return json;
}

async function refresh() {
  try {
    S.data = await api('GET', '/api/state');
    S.loggedIn = true;
    if (!busy()) render();
  } catch (e) { /* shown via login or kept stale */ }
}

// True while the user is typing or choosing in the main area: re-rendering
// would steal focus or close an open select.
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
    await refresh();
    render();
    return true;
  } catch (e) {
    flash(e.message);
    render();
    return false;
  }
}

// ---------- pages ----------

function render() {
  const root = document.getElementById('app');
  if (S.loggedIn === false) { root.innerHTML = loginPage(); S.drawer = null; renderDrawer(); return; }
  if (!S.data) { root.innerHTML = ''; return; }
  const t = S.tab;
  const tab = (id, label, mark) => `<button class="tab" data-act="tab" data-tab="${id}" aria-current="${t === id ? 'page' : 'false'}">${t === id ? mark : '<span class="mark"></span>'}${label}</button>`;
  root.innerHTML = `
    <header class="top">
      <nav aria-label="主导航">
        ${tab('probe', '探针', shape({ color: C.blue, shape: 'circle' }, 10))}
        ${tab('lines', '线路', shape({ color: C.red, shape: 'square' }, 10))}
        ${tab('users', '用户', shape({ color: C.yellow, shape: 'tri' }, 10))}
      </nav>
      <button class="icon-btn" data-act="settings" aria-label="设置" title="设置"><svg width="20" height="20" viewBox="0 0 20 20" aria-hidden="true"><circle cx="10" cy="10" r="3" fill="none" stroke="currentColor" stroke-width="1.4"/><path d="M10 1.5v3M10 15.5v3M1.5 10h3M15.5 10h3M4 4l2.1 2.1M13.9 13.9L16 16M4 16l2.1-2.1M13.9 6.1L16 4" stroke="currentColor" stroke-width="1.4"/></svg></button>
    </header>
    <main>${t === 'probe' ? probePage() : t === 'lines' ? linesPage() : usersPage()}</main>`;
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
  const max = Math.max(1, ...totals) * 1.1, min = Math.min(...totals, max) * 0.8;
  const spark = totals.length > 1 ? totals.map((v, i) => `${(i * 300 / (totals.length - 1)).toFixed(1)},${(52 - (v - min) / ((max - min) || 1) * 48).toFixed(1)}`).join(' ') : '';
  const hero = `
    <section class="hero">
      <div class="sun" aria-hidden="true"></div>
      <div class="main">
        <div class="label">实时总速率</div>
        <div style="display:flex;align-items:baseline;gap:10px"><span class="big">${mbps(last[0] + last[1])}</span><span style="font-size:20px">MB/s</span></div>
        <div class="muted" style="font-size:14px">入 ${mbps(last[0])} MB/s · 出 ${mbps(last[1])} MB/s</div>
        <svg class="spark" height="56" viewBox="0 0 300 56" preserveAspectRatio="none" role="img" aria-label="近 3 分钟总速率走势"><polyline points="${spark}" fill="none" stroke="${C.ink}" stroke-width="1.5" vector-effect="non-scaling-stroke"></polyline></svg>
      </div>
      <div class="tiles">
        <div><div class="small muted">在线</div><div class="v">${d.summary.online}/${nodes.length}</div></div>
        <div><div class="small muted">本月</div><div class="v">${bytes(d.summary.month)}</div></div>
        <div><div class="small muted">用户</div><div class="v">${d.users.length}</div></div>
      </div>
    </section>`;
  if (!nodes.length) {
    return hero + `<div class="empty">还没有节点。去「线路」页点「添加节点」，在服务器上运行给出的那一行命令。</div>`;
  }
  return hero + `<div class="grid probe">${nodes.map(probeCard).join('')}</div>`;
}

function probeCard(n) {
  const st = nodeStatus(n), off = st.kind === 'off', s = n.system || {};
  const open = S.openProbe === n.id && !off;
  const meter = (label, p, text) => `<div><div class="small muted">${label}</div><div style="font-size:14px">${off ? '—' : text}</div><div class="meter"><i style="width:${off ? 0 : p.toFixed(0)}%;background:${p >= 80 ? C.red : C.ink}"></i></div></div>`;
  const mem = s.mem_total ? `${Math.round(s.mem_used / 1048576)}/${Math.round(s.mem_total / 1048576)}` : '—';
  const disk = s.disk_total ? `${(s.disk_used / GB).toFixed(1)}/${(s.disk_total / GB).toFixed(0)}` : '—';
  const probes = n.probes || [];
  const hint = off ? '失联中，没有三网数据' : probes.length ? (open ? '点一下收起' : '点一下看三网延迟') : '没有三网数据（在设置里填测速目标）';
  return `<div class="card ${open ? 'wide' : ''} ${off ? 'off' : ''}">
    <button class="probe-btn" data-act="probe" data-id="${n.id}" aria-expanded="${open}">
      <div class="row">
        <span class="code">${esc(n.code)}</span>
        <span style="font-size:14px;flex:1 1 auto;min-width:0">${esc(n.name)} <span class="muted">· ${n.role === 'entry' ? '入口' : '出口'}</span></span>
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
      <span class="small muted">${hint}</span>
    </button>
    ${open && probes.length ? ispBlock(n, probes) : ''}
  </div>`;
}

function ispBlock(n, probes) {
  const s = n.system || {};
  const items = probes.map(p => {
    const col = ISP_COLOR[p.name] || [C.ink, C.ink];
    const pts = polyline(p.points, 300, 44, 4);
    const lossColor = p.loss >= 2 ? C.danger : C.ink;
    const range = p.max > 0 ? `${Math.round(p.min)}–${Math.round(p.max)} ms` : '';
    const lat = p.latency > 0 ? Math.round(p.latency) : '—';
    return `<div class="isp-item">
      <div style="display:flex;align-items:center;gap:8px;font-size:15px;font-weight:500">${shape({ color: col[0], shape: 'circle' }, 8)}${esc(p.label || p.name)}</div>
      <div class="three" style="gap:8px;margin-top:6px">
        <div><div class="small muted">延迟</div><div class="isp-num">${lat}<small> ms</small></div></div>
        <div><div class="small muted">波动</div><div class="isp-num">±${Math.round(p.jitter)}<small> ms</small></div></div>
        <div><div class="small muted" title="超时或 SYN 重传（≥1 秒）的连接占比">重传</div><div class="isp-num" style="color:${lossColor}">${p.loss.toFixed(p.loss >= 10 ? 0 : 1)}<small> %</small></div></div>
      </div>
      <svg width="100%" height="44" viewBox="0 0 300 44" preserveAspectRatio="none" style="display:block;margin-top:8px" role="img" aria-label="${esc(p.label)} 近 1 小时延迟走势"><polyline points="${pts}" fill="none" stroke="${col[1]}" stroke-width="1.5" vector-effect="non-scaling-stroke"></polyline></svg>
      <div style="display:flex;justify-content:space-between;font-size:11px" class="muted"><span>${p.since ? ago(p.since) : ''}</span><span>${range}</span><span>现在</span></div>
    </div>`;
  }).join('');
  const retrans = s.tcp_retrans_pct != null ? ` · 整机 TCP 重传 ${(+s.tcp_retrans_pct).toFixed(1)}%` : '';
  return `<div class="isp">
    <div class="isp-head"><span>到国内三网 · 近 1 小时</span><span>TCPing，每轮 10 次${retrans}</span></div>
    <div class="isp-grid">${items}</div>
  </div>`;
}

function linesPage() {
  const es = entries(), xs = exitNodes();
  const toast = S.toast ? `${shape({ color: C.blue, shape: 'circle' }, 8)}<span>${esc(S.toast)}</span>` : '';
  let html = `
    <div class="section-head">
      <h2>入口 <span class="muted">用户连这里，选它走哪个出口</span></h2>
      <button class="btn" data-act="new-node">添加节点</button>
    </div>
    <div class="toast" role="status">${toast}</div>`;
  html += es.length ? `<div class="grid entries">${es.map(entryCard).join('')}</div>`
    : `<div class="empty" style="margin-bottom:48px">还没有入口节点。</div>`;
  html += `<h2 style="margin:0 0 16px">出口 <span class="muted">统一 SS-2022</span></h2>`;
  const cards = [];
  for (const x of xs) {
    const ports = S.data.exits.filter(e => e.node_id === x.id);
    if (!ports.length) cards.push(exitNodeCard(x));
    ports.forEach(e => cards.push(exitCard(e, x)));
  }
  html += cards.length ? `<div class="grid exits">${cards.join('')}</div>` : `<div class="empty">还没有出口节点。</div>`;
  return html;
}

function entryCard(n) {
  const st = nodeStatus(n);
  const editing = S.editing === n.id;
  const protos = [n.anytls_on && 'AnyTLS', n.vless_on && 'VLESS', n.ss_on && 'SS'].filter(Boolean).join(' · ') || '没开协议';
  const head = editing
    ? `<span class="code" style="font-size:28px">${esc(n.code)}</span>
       <input class="rename-input" id="rename-input" value="${esc(n.name)}" aria-label="给 ${esc(n.code)} 改名" data-key="rename" data-id="${n.id}">
       <button class="btn small solid" data-act="rename-done" data-id="${n.id}">完成</button>`
    : `<button class="name-btn" data-act="node" data-id="${n.id}"><span class="code">${esc(n.code)}</span><span>${esc(n.name)}</span></button>
       <button class="icon-btn" data-act="rename" data-id="${n.id}" aria-label="给 ${esc(n.code)} 改名" title="改名" style="width:40px;margin-left:-6px"><svg width="14" height="14" viewBox="0 0 14 14" aria-hidden="true"><path d="M1.5 12.5L1.5 10L10 1.5L12.5 4L4 12.5Z" fill="none" stroke="currentColor" stroke-width="1.3"></path></svg></button>
       <span style="flex:1 1 auto" class="small muted">${protos}</span>`;
  const chip = (id, label, style, ghost) => {
    const on = n.default_exit === id;
    const mark = ghost ? shape({ color: on ? C.paper : C.faint, shape: 'circle' }, 8) : shape(style, 8);
    return `<button class="chip ${ghost ? 'ghost' : ''}" aria-pressed="${on}" data-act="default-exit" data-id="${n.id}" data-exit="${id}">${mark}${esc(label)}</button>`;
  };
  const chips = S.data.exits.map(e => chip(e.id, e.name, exitStyle(e.id), false)).join('') + chip(0, '直连', null, true);
  const options = sel => S.data.exits.map(e => `<option value="${e.id}" ${sel === e.id ? 'selected' : ''}>${esc(e.name)}</option>`).join('')
    + `<option value="0" ${sel === 0 ? 'selected' : ''}>直连</option>`;
  const used = n.rules.map(r => r.ruleset);
  const rows = n.rules.map(r => {
    const set = S.data.rulesets.find(s => s.id === r.ruleset) || { label: r.ruleset, description: '' };
    return `<div class="rule">
      <span class="what"><span style="font-size:15px;font-weight:500">${esc(set.label)}</span> <span class="small muted">${esc(set.description)}</span></span>
      <span class="muted" style="font-size:13px">走</span>
      <select class="line-select" data-change="rule" data-id="${n.id}" data-rule="${esc(r.ruleset)}" aria-label="${esc(n.code)} ${esc(set.label)} 走哪个出口">${options(r.exit_id)}</select>
      <button class="icon-btn" data-act="rule-del" data-id="${n.id}" data-rule="${esc(r.ruleset)}" aria-label="删除 ${esc(set.label)} 分流"><svg width="12" height="12" viewBox="0 0 12 12" aria-hidden="true"><path d="M1 1L11 11M11 1L1 11" stroke="currentColor" stroke-width="1.5"></path></svg></button>
    </div>`;
  }).join('');
  const free = S.data.rulesets.filter(s => !used.includes(s.id));
  const add = free.length ? `<select class="add-select" data-change="rule-add" data-id="${n.id}" aria-label="${esc(n.code)} 添加分流">
      <option value="">＋ 添加分流</option>${free.map(s => `<option value="${esc(s.id)}">${esc(s.label)}${s.description ? '（' + esc(s.description) + '）' : ''}</option>`).join('')}
    </select>` : '';
  return `<div class="card entry ${st.kind === 'off' ? 'off' : ''}">
    <div class="row">${head}<span style="font-size:13px;color:${st.kind === 'off' ? C.danger : C.muted}">${esc(st.text)}</span></div>
    <div><div class="sublabel">默认出口</div><div class="chips" role="group" aria-label="${esc(n.code)} 默认出口">${chips}</div></div>
    <div><div class="sublabel" style="margin-bottom:4px">分流</div>${rows}${add}</div>
  </div>`;
}

function exitCard(e, x) {
  const st = exitStyle(e.id);
  const parts = [`${esc(x.code)} :${e.port}`];
  if (e.quota_bytes) parts.push(`${gib(e.used)} / ${gib(e.quota_bytes)} G`, `${e.reset_day} 号重置`);
  else parts.push(`本期 ${bytes(e.used)}`);
  if (e.udp_over_tcp) parts.push('UDP 走 TCP');
  if (!x.address) parts.push('还不知道地址');
  const defaults = entries().filter(n => n.default_exit === e.id).map(n => n.code);
  const split = [];
  for (const n of entries()) {
    const hit = n.rules.filter(r => r.exit_id === e.id).map(r => (S.data.rulesets.find(s => s.id === r.ruleset) || {}).label || r.ruleset);
    if (hit.length) split.push(n.code + ' ' + hit.join('/'));
  }
  const usedBy = [];
  if (defaults.length) usedBy.push('默认：' + defaults.join(' · '));
  if (split.length) usedBy.push('分流：' + split.join('，'));
  const bar = e.quota_bytes ? `<span style="display:block;height:3px;background:#D6D1C6"><span style="display:block;height:100%;width:${pct(e.used, e.quota_bytes).toFixed(0)}%;background:${e.used >= e.quota_bytes ? C.red : C.ink}"></span></span>` : '';
  const off = !x.online ? ` <span style="font-size:13px;font-weight:400;color:${C.danger}">失联</span>` : '';
  return `<button class="exit-card" data-act="node" data-id="${x.id}">
    <span class="title">${shape(st)}${esc(e.name)}${off}</span>
    <span class="muted" style="font-size:13px">${parts.join(' · ')}</span>
    ${bar}
    <span style="font-size:14px">${esc(usedBy.length ? usedBy.join('；') : '没有入口在用')}</span>
  </button>`;
}

function exitNodeCard(x) {
  return `<button class="exit-card" data-act="node" data-id="${x.id}">
    <span class="title">${shape({ color: C.faint, shape: 'circle' })}${esc(x.code)} ${esc(x.name)}</span>
    <span class="muted" style="font-size:13px">还没有 SS 端口，点开添加</span>
  </button>`;
}

const USTATUS = { ok: '正常', warn: '将满', over: '超额停用', expired: '已过期', disabled: '已停用' };

function usersPage() {
  const all = entries().map(n => n.id);
  const list = S.data.users.map(u => {
    const p = pct(u.used, u.quota_bytes), bad = ['over', 'expired', 'disabled'].includes(u.status);
    const barColor = p >= 100 ? C.red : p >= 90 ? C.amber : C.ink;
    const nodesText = !u.entries.length ? '没有入口' : (all.length && all.every(id => u.entries.includes(id))) ? '全部入口'
      : u.entries.map(id => (node(id) || {}).code).filter(Boolean).join(' · ');
    const online = u.conns ? ` · ${u.conns} 个连接` : '';
    return `<button class="user" data-act="user" data-id="${u.id}">
      <span class="n">${esc(u.name)} <span style="font-size:13px;font-weight:400" class="muted">${esc(u.plan)}</span></span>
      <span class="bar">
        <span style="display:flex;justify-content:space-between;font-size:14px"><span>${gib(u.used)} / ${u.quota_bytes ? gib(u.quota_bytes) + ' GB' : '不限'}</span><span style="color:${bad ? C.danger : C.muted}">${USTATUS[u.status]}${online}</span></span>
        <span style="display:block;height:3px;background:#D6D1C6;margin-top:6px"><span style="display:block;height:100%;width:${u.quota_bytes ? p.toFixed(0) : 0}%;background:${barColor}"></span></span>
      </span>
      <span class="meta">到期 ${u.expire_date || '不限'} · ${u.reset_day} 号重置 · ${esc(nodesText)}</span>
    </button>`;
  }).join('');
  return `
    <div class="section-head" style="margin-bottom:20px">
      <h2>用户</h2>
      <button class="btn solid" data-act="new-user">添加用户</button>
    </div>
    ${S.toast ? `<div class="toast" role="status">${shape({ color: C.blue, shape: 'circle' }, 8)}<span>${esc(S.toast)}</span></div>` : ''}
    <div class="users">${list || '<div class="empty">还没有用户。</div>'}</div>
    <p class="muted" style="font-size:13px;margin:20px 0 0">额度在节点本地执行，主控断线也照样生效。到期或用完自动停用，到重置日自动清零。</p>`;
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
  return `<label class="field ${opts.full ? 'full' : ''}">${label}<input name="${name}" value="${esc(value)}" ${opts.type ? `type="${opts.type}"` : ''} ${opts.placeholder ? `placeholder="${esc(opts.placeholder)}"` : ''} ${opts.inputmode ? `inputmode="${opts.inputmode}"` : ''}></label>`;
}
function sw(name, on, label) {
  return `<button type="button" class="switch" data-act="switch" data-name="${name}" aria-pressed="${!!on}" aria-label="${esc(label)}"><i></i></button><input type="hidden" name="${name}" value="${on ? 1 : 0}">`;
}

function nodeDrawer(d) {
  const n = node(d.id);
  if (!n) return null;
  const st = nodeStatus(n);
  const isEntry = n.role === 'entry';
  let body = `<section class="sec"><div class="fields two">
      ${field('代号', 'code', n.code)}
      ${field('名称', 'name', n.name)}
      ${field('地址（域名或 IP）', 'host', n.host, { full: true, placeholder: n.last_ip ? '留空用 ' + n.last_ip : '节点连上后自动填' })}
    </div></section>`;
  if (isEntry) {
    const proto = (key, name, extra, portName, port) => `<div class="proto">
        ${sw(key, n[key], '启用 ' + name)}
        <div class="info"><div style="font-size:16px;font-weight:500">${name}</div><div class="small muted">${extra}</div></div>
        <input class="port" name="${portName}" value="${port}" inputmode="numeric" aria-label="${name} 端口">
      </div>`;
    const built = n.protocols && n.protocols.length ? n.protocols : null;
    const missing = ['anytls', 'vless', 'ss2022'].filter(p => built && !built.includes(p) && n[{ anytls: 'anytls_on', vless: 'vless_on', ss2022: 'ss_on' }[p]]);
    body += `<section class="sec" style="gap:0">
        <h3 style="margin-bottom:4px">协议</h3>
        ${proto('anytls_on', 'AnyTLS', '自签证书，客户端跳过校验', 'anytls_port', n.anytls_port)}
        ${proto('vless_on', 'VLESS Reality', 'Vision · 伪装 ' + esc(n.reality_sni), 'vless_port', n.vless_port)}
        <div class="fields two" style="padding:10px 0;border-bottom:1px solid #D6D1C6">
          ${field('Reality 伪装站点', 'reality_sni', n.reality_sni, { full: true })}
        </div>
        ${proto('ss_on', 'SS-2022', '每人独立密钥', 'ss_port', n.ss_port)}
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
          ${field('端口', `x${e.id}_port`, e.port, { inputmode: 'numeric' })}
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
    title: `${n.code} ${n.name}`,
    mark: shape({ color: isEntry ? C.red : C.blue, shape: isEntry ? 'square' : 'circle' }, 16),
    body,
    foot: `<button class="btn solid" data-act="save-node" data-id="${n.id}">保存并热更新</button>
      <button class="btn danger" data-act="node-del" data-id="${n.id}">删除</button>`
  };
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
        <p class="small muted" style="margin:0">${role === 'entry' ? '入口：用户连它（AnyTLS / VLESS Reality / SS-2022），再按规则把流量交给出口。' : '出口：只开 SS-2022，接各个入口转来的流量，比如家宽落地。'}</p>
        <div class="fields two">
          ${field('代号', 'code', d.code || '', { placeholder: role === 'entry' ? 'JP' : 'UK' })}
          ${field('名称', 'name', d.name || '', { placeholder: role === 'entry' ? '日本' : '英国' })}
        </div>
      </section>`,
    foot: `<button class="btn solid" data-act="create-node">创建并生成安装命令</button>`
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
    title: n ? `${n.code} 安装命令` : '安装命令', mark: shape({ color: C.red, shape: 'square' }, 16),
    body: installBody(d.install) + (d.rotated ? '<p class="err">令牌已换，旧令牌立即失效，节点要用新命令重装一次。</p>' : ''),
    foot: `<button class="btn solid" data-act="close">完成</button>`
  };
}

function userDraft(u) {
  return {
    name: u ? u.name : '', plan: u ? u.plan : '标准',
    quota: u ? quotaGB(u.quota_bytes) : 300,
    expire: u ? u.expire_date : '', reset: u ? u.reset_day : new Date().getDate(),
    entries: u ? u.entries.slice() : entries().map(n => n.id), enabled: u ? u.enabled : true
  };
}

function userDrawer(d) {
  const u = d.id ? S.data.users.find(x => x.id === d.id) : null;
  if (d.id && !u) return null;
  const f = S.draft || (S.draft = userDraft(u));
  const plans = PLANS.map(p => `<button type="button" data-act="plan" data-plan="${p.label}" aria-pressed="${f.plan === p.label}"><b>${p.label}</b><span>${p.gb ? p.gb + ' G' : '手填'}</span></button>`).join('');
  const chips = entries().map(n => `<button type="button" class="chip" style="min-width:60px;justify-content:center;font-size:15px;font-weight:500" data-act="user-entry" data-id="${n.id}" aria-pressed="${f.entries.includes(n.id)}">${esc(n.code)}</button>`).join('');
  let body = `<section class="sec">
      <label class="field">名称<input name="name" value="${esc(f.name)}" placeholder="用户名" data-draft="name"></label>
      <div class="plans" role="group" aria-label="套餐">${plans}</div>
      <div class="fields three">
        ${field('额度 GB', 'quota', f.quota, { inputmode: 'numeric', placeholder: '不限' })}
        ${field('到期', 'expire', f.expire, { type: 'date' })}
        ${field('重置日', 'reset', f.reset, { inputmode: 'numeric' })}
      </div>
    </section>
    <section class="sec"><h3>可用入口</h3><div class="chips">${chips || '<span class="muted">还没有入口节点</span>'}</div></section>`;
  if (u) {
    body += `<section class="sec">
      <div style="display:flex;align-items:center;gap:12px">
        <span class="mono" id="sub-url" style="flex:1 1 auto;min-width:0;font-size:13px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(u.sub_url)}</span>
        <button type="button" class="btn small" data-act="copy" data-text="${esc(u.sub_url)}">复制订阅</button>
      </div>
      <p class="small muted" style="margin:0">Stash / Clash 自动拿到 Clash 配置，其他客户端拿到通用链接。链接泄露了就点 <button type="button" class="btn small" style="min-height:32px" data-act="sub-rotate" data-id="${u.id}">换订阅链接</button></p>
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
  const tzOpts = [];
  for (let h = -12; h <= 14; h++) tzOpts.push(`<option value="${h * 60}" ${h === tz ? 'selected' : ''}>UTC${h >= 0 ? '+' : ''}${h}</option>`);
  const targets = st.probe_targets.map(t => field(`${esc(t.label)}（IP:端口）`, `probe_${t.name}`, t.host, { full: true, placeholder: 'sh-' + t.name + '-v4.ip.zstaticcdn.com:80' })).join('');
  return {
    title: '设置', mark: shape({ color: C.ink, shape: 'circle' }, 16),
    body: `<section class="sec"><div class="fields two">
        ${field('面板地址（订阅和节点安装用）', 'panel_url', st.panel_url, { full: true, placeholder: st.base_url })}
        <label class="field">时区（重置日按它算）<select name="tz_offset">${tzOpts.join('')}</select></label>
      </div></section>
      <section class="sec"><h3>三网测速目标</h3><div class="fields">${targets}</div>
        <p class="small muted" style="margin:0">默认是上海三网（Zstatic 公开的 TCPing 节点，地址由对方自动更新）。换省份就把 sh 改成对应代号。节点每 30 秒对每个目标 TCP 连 10 次，算延迟、波动和重传。留空就不测。</p></section>
      ${st.fingerprint ? `<section class="sec"><h3>主控证书指纹</h3><div class="mono small" style="word-break:break-all">${esc(st.fingerprint)}</div></section>` : ''}
      <section class="sec"><h3>登录</h3><div class="fields two">
        ${field('用户名', 'username', st.username, { full: true })}
        ${field('当前密码', 'current_password', '', { type: 'password' })}
        ${field('新密码（不改就留空）', 'password', '', { type: 'password' })}
      </div><p class="small muted" style="margin:0">改用户名或密码都要填当前密码。</p></section>`,
    foot: `<button class="btn solid" data-act="save-settings">保存</button>
      <button class="btn" data-act="logout">退出登录</button>`
  };
}

function form() {
  const f = document.getElementById('drawer-form');
  const out = {};
  if (!f) return out;
  for (const el of f.elements) if (el.name) out[el.name] = el.value;
  return out;
}
function drawerError(msg) { S.drawerErr = msg; renderDrawer(); }
function int(v) { const s = String(v).trim(); return /^\d+$/.test(s) ? parseInt(s, 10) : null; }
// GB as typed in a quota field; '' is unlimited (0). Decimals are allowed.
function quotaBytes(v) {
  const s = String(v).trim();
  if (s === '') return 0;
  return /^\d+(\.\d+)?$/.test(s) ? Math.round(parseFloat(s) * GB) : null;
}
function quotaGB(b) { return b ? String(+(b / GB).toFixed(2)) : ''; }

// Keeps typed values when the drawer re-renders for a button press.
function keepUserDraft() {
  if (!S.draft) return;
  const f = form();
  S.draft.name = f.name; S.draft.quota = f.quota; S.draft.expire = f.expire; S.draft.reset = f.reset;
}

// ---------- actions ----------

const actions = {
  tab(el) { S.tab = el.dataset.tab; save('tab', S.tab); S.toast = ''; render(); window.scrollTo(0, 0); },
  settings() { openDrawer({ kind: 'settings' }); },
  close() { closeDrawer(); },
  probe(el) { const id = +el.dataset.id; S.openProbe = S.openProbe === id ? null : id; render(); },
  rename(el) {
    S.editing = +el.dataset.id; render();
    const i = document.getElementById('rename-input'); if (i) { i.focus(); i.select(); }
  },
  'rename-done'(el) { commitRename(+el.dataset.id); },
  'default-exit'(el) {
    const n = node(+el.dataset.id), x = +el.dataset.exit;
    const label = x ? exit(x).name : '直连';
    act(() => api('PATCH', `/api/nodes/${n.id}`, { default_exit: x }), `${n.code} 默认改走 ${label}。已热更新，现有连接不断。`);
  },
  'rule-del'(el) {
    const n = node(+el.dataset.id), rid = el.dataset.rule;
    const set = S.data.rulesets.find(s => s.id === rid);
    setRules(n, n.rules.filter(r => r.ruleset !== rid), `${n.code} 的 ${set ? set.label : rid} 改回走默认出口。`);
  },
  node(el) { openDrawer({ kind: 'node', id: +el.dataset.id }); },
  'new-node'() { openDrawer({ kind: 'new-node', role: 'entry' }); },
  role(el) { const f = form(); Object.assign(S.drawer, { role: el.dataset.role, code: f.code, name: f.name }); renderDrawer(); },
  async 'create-node'() {
    const f = form();
    try {
      const r = await api('POST', '/api/nodes', { role: S.drawer.role || 'entry', code: f.code, name: f.name });
      S.drawer.install = r.install; S.drawerErr = '';
      await refresh(); renderDrawer();
    } catch (e) { drawerError(e.message); }
  },
  async install(el) {
    try { const r = await api('GET', `/api/nodes/${el.dataset.id}/install`); openDrawer({ kind: 'install', id: +el.dataset.id, install: r.install }); }
    catch (e) { drawerError(e.message); }
  },
  async token(el) {
    if (!confirm('换令牌后旧令牌立即失效，节点会断开，要用新命令重装一次。继续？')) return;
    try { const r = await api('POST', `/api/nodes/${el.dataset.id}/token`); await refresh(); openDrawer({ kind: 'install', id: +el.dataset.id, install: r.install, rotated: true }); }
    catch (e) { drawerError(e.message); }
  },
  switch(el) {
    const on = el.getAttribute('aria-pressed') !== 'true';
    el.setAttribute('aria-pressed', on);
    const input = el.parentElement.querySelector(`input[name="${el.dataset.name}"]`);
    if (input) input.value = on ? 1 : 0;
  },
  async 'save-node'(el) {
    const n = node(+el.dataset.id), f = form();
    const patch = { code: f.code, name: f.name, host: f.host, ipv4_only: f.ipv4_only === '1' };
    if (n.role === 'entry') {
      Object.assign(patch, {
        anytls_on: f.anytls_on === '1', vless_on: f.vless_on === '1', ss_on: f.ss_on === '1',
        anytls_port: int(f.anytls_port), vless_port: int(f.vless_port), ss_port: int(f.ss_port),
        direct_list: f.direct_list, reality_sni: f.reality_sni.trim()
      });
      if (patch.reality_sni && patch.reality_sni !== n.reality_sni) patch.reality_dest = patch.reality_sni + ':443';
      for (const k of ['anytls_port', 'vless_port', 'ss_port']) if (patch[k] === null) return drawerError('端口要填数字');
    }
    try {
      await api('PATCH', `/api/nodes/${n.id}`, patch);
      if (n.role === 'exit') {
        for (const e of S.data.exits.filter(x => x.node_id === n.id)) {
          const quota = quotaBytes(f[`x${e.id}_quota`] || '');
          const port = int(f[`x${e.id}_port`]), reset = int(f[`x${e.id}_reset`]);
          if (quota === null || port === null || reset === null) return drawerError('端口、额度、重置日要填数字');
          await api('PATCH', `/api/exits/${e.id}`, { name: f[`x${e.id}_name`], port, quota_bytes: quota, reset_day: reset, udp_over_tcp: f[`x${e.id}_uot`] === '1' });
        }
      }
      flash(`${patch.code || n.code} 已保存并热更新。`);
      closeDrawer(); await refresh(); render();
    } catch (e) { drawerError(e.message); }
  },
  async 'node-del'(el) {
    const n = node(+el.dataset.id);
    if (!confirm(`删除 ${n.code} ${n.name}？节点会断开，用它的线路改回直连。`)) return;
    closeDrawer();
    act(() => api('DELETE', `/api/nodes/${n.id}`), `已删除 ${n.code}。`);
  },
  async 'exit-add'(el) {
    try { await api('POST', '/api/exits', { node_id: +el.dataset.id }); await refresh(); S.drawerErr = ''; renderDrawer(); }
    catch (e) { drawerError(e.message); }
  },
  async 'exit-del'(el) {
    const e = exit(+el.dataset.exit);
    if (!confirm(`删除出口「${e.name}」？走它的入口和分流会改回默认或直连。`)) return;
    try { await api('DELETE', `/api/exits/${e.id}`); await refresh(); renderDrawer(); render(); }
    catch (err) { drawerError(err.message); }
  },
  user(el) { openDrawer({ kind: 'user', id: +el.dataset.id }); },
  'new-user'() { openDrawer({ kind: 'user', id: 0 }); },
  plan(el) {
    keepUserDraft();
    const p = PLANS.find(x => x.label === el.dataset.plan);
    S.draft.plan = p.label;
    if (p.gb) S.draft.quota = p.gb;
    renderDrawer();
  },
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
      closeDrawer(); await refresh(); render();
    } catch (e) { drawerError(e.message); }
  },
  async 'user-reset'(el) {
    const u = S.data.users.find(x => x.id === +el.dataset.id);
    if (!confirm(`把 ${u.name} 本期流量清零？`)) return;
    try { await api('POST', `/api/users/${u.id}/reset`); flash(`${u.name} 的流量已清零。`); await refresh(); renderDrawer(); render(); }
    catch (e) { drawerError(e.message); }
  },
  async 'user-toggle'(el) {
    const u = S.data.users.find(x => x.id === +el.dataset.id);
    try { await api('PATCH', `/api/users/${u.id}`, { enabled: !u.enabled }); flash(`${u.name} 已${u.enabled ? '停用' : '启用'}。`); await refresh(); renderDrawer(); render(); }
    catch (e) { drawerError(e.message); }
  },
  async 'user-del'(el) {
    const u = S.data.users.find(x => x.id === +el.dataset.id);
    if (!confirm(`删除 ${u.name}？他正在用的连接会立即断开。`)) return;
    closeDrawer();
    act(() => api('DELETE', `/api/users/${u.id}`), `已删除 ${u.name}。`);
  },
  async 'sub-rotate'(el) {
    if (!confirm('换订阅链接后旧链接立即失效，要把新链接重新发给这个用户。继续？')) return;
    try { await api('POST', `/api/users/${el.dataset.id}/sub`); await refresh(); keepUserDraft(); renderDrawer(); }
    catch (e) { drawerError(e.message); }
  },
  async 'save-settings'() {
    const f = form(), st = S.data.settings;
    const body = {
      panel_url: f.panel_url, tz_offset: int(f.tz_offset),
      probe_targets: st.probe_targets.map(t => ({ name: t.name, label: t.label, host: (f['probe_' + t.name] || '').trim() }))
    };
    body.username = f.username.trim(); body.current_password = f.current_password;
    if (f.password) body.password = f.password;
    try { await api('PATCH', '/api/settings', body); flash('设置已保存。'); closeDrawer(); await refresh(); render(); }
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
  act(() => api('PUT', `/api/nodes/${n.id}/rules`, { rules: rules.map(r => ({ ruleset: r.ruleset, exit_id: r.exit_id })) }), msg + '已热更新。');
}

function commitRename(id) {
  const n = node(id), input = document.getElementById('rename-input');
  const name = input ? input.value.trim() : '';
  S.editing = null;
  if (!name || name === n.name) { render(); return; }
  act(() => api('PATCH', `/api/nodes/${id}`, { name }), `已改名为「${name}」。`);
}

document.addEventListener('click', e => {
  const el = e.target.closest('[data-act]');
  if (!el) return;
  const fn = actions[el.dataset.act];
  if (!fn) return;
  e.preventDefault();
  fn(el);
});

document.addEventListener('change', e => {
  const el = e.target;
  if (el.dataset.change === 'rule') {
    const n = node(+el.dataset.id), x = +el.value, rid = el.dataset.rule;
    const set = S.data.rulesets.find(s => s.id === rid);
    el.blur();
    setRules(n, n.rules.map(r => r.ruleset === rid ? { ruleset: rid, exit_id: x } : r), `${n.code} 的 ${set.label} 走 ${x ? exit(x).name : '直连'}。`);
  } else if (el.dataset.change === 'rule-add') {
    const n = node(+el.dataset.id), rid = el.value;
    if (!rid) return;
    const set = S.data.rulesets.find(s => s.id === rid);
    // A new split starts on the first exit that is not the default.
    const first = S.data.exits.find(x => x.id !== n.default_exit);
    const target = first ? first.id : 0;
    el.blur();
    setRules(n, n.rules.concat([{ ruleset: rid, exit_id: target }]), `${n.code} 的 ${set.label} 走 ${target ? exit(target).name : '直连'}。`);
  }
});

document.addEventListener('keydown', e => {
  if (e.target.id === 'rename-input') {
    if (e.key === 'Enter') { e.preventDefault(); commitRename(+e.target.dataset.id); }
    if (e.key === 'Escape') { S.editing = null; render(); }
    return;
  }
  if (e.key === 'Escape' && S.drawer) closeDrawer();
});

document.addEventListener('submit', async e => {
  e.preventDefault();
  if (e.target.dataset.form === 'login') {
    const pw = e.target.password.value, user = e.target.username.value;
    try {
      await api('POST', '/api/login', { username: user, password: pw });
      S.loggedIn = true; await refresh(); render();
    } catch (err) {
      const box = document.getElementById('login-err');
      if (box) box.textContent = err.message;
    }
  }
  // Enter inside a drawer field does nothing; saving is an explicit button.
});

(async function start() {
  try {
    const s = await api('GET', '/api/session');
    S.loggedIn = s.logged_in;
  } catch (e) { S.loggedIn = false; }
  if (S.loggedIn) await refresh();
  render();
  setInterval(() => { if (S.loggedIn) refresh(); }, 2000);
})();
