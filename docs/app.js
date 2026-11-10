// ============================================================================
// tcptui — Interactive Browser TUI State Machine & Telemetry Engine
// ============================================================================

const PKG_COMMANDS = {
  scoop: 'scoop install https://github.com/sametcn99/tcptui/releases/download/v1.3.0/scoop-tcptui.json',
  cargo: 'cargo install --git https://github.com/sametcn99/tcptui.git --all-features',
  pwsh: 'iwr https://github.com/sametcn99/tcptui/releases/download/v1.3.0/tcptui-v1.3.0-windows-x86_64.zip -OutFile tcptui.zip; Expand-Archive tcptui.zip',
  source: 'git clone https://github.com/sametcn99/tcptui.git && cd tcptui && cargo build --release --all-features'
};

// Initial live socket dataset
const INITIAL_SOCKETS = [
  { id: 1, marked: true, process: 'chrome.exe', path: 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe', user: 'WORKSTATION\\samet', signed: 'Valid (Google LLC)', sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', asn: 'AS15169 Google LLC', netname: 'GOOGLE (142.250.0.0/15)', pid: 39496, proto: 'TCP', laddr: '192.168.1.111', lport: 54720, raddr: '142.250.187.206', rport: 443, state: 'ESTABLISHED', service: '', tx: 1468006, rx: 9332326, age: 14, change: 'unchanged', loopback: false, connected: true, country: '🇺🇸 US' },
  { id: 2, marked: false, process: 'chrome.exe', path: 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe', user: 'WORKSTATION\\samet', signed: 'Valid (Google LLC)', sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', asn: 'AS13335 Cloudflare, Inc.', netname: 'CLOUDFLARENET (104.16.0.0/12)', pid: 39496, proto: 'TCP', laddr: '192.168.1.111', lport: 54788, raddr: '104.18.32.47', rport: 443, state: 'ESTABLISHED', service: '', tx: 48110, rx: 365632, age: 2, change: 'new', loopback: false, connected: true, country: '🇺🇸 US' },
  { id: 3, marked: false, process: 'Code.exe', path: 'C:\\Users\\samet\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe', user: 'WORKSTATION\\samet', signed: 'Valid (Microsoft Corporation)', sha256: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08', asn: 'LOOPBACK-LOCAL', netname: 'IANA-LOOPBACK (127.0.0.0/8)', pid: 35668, proto: 'TCP', laddr: '127.0.0.1', lport: 6907, raddr: '0.0.0.0', rport: 0, state: 'LISTEN', service: '', tx: 0, rx: 0, age: 10800, change: 'unchanged', loopback: true, connected: false, country: '—' },
  { id: 4, marked: true, process: 'Code.exe', path: 'C:\\Users\\samet\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe', user: 'WORKSTATION\\samet', signed: 'Valid (Microsoft Corporation)', sha256: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08', asn: 'AS36459 GitHub, Inc.', netname: 'GITHUB-NET4 (140.82.112.0/20)', pid: 35668, proto: 'TCP', laddr: '192.168.1.111', lport: 51892, raddr: '140.82.121.4', rport: 443, state: 'ESTABLISHED', service: '', tx: 911360, rx: 2202009, age: 2640, change: 'unchanged', loopback: false, connected: true, country: '🇺🇸 US' },
  { id: 5, marked: false, process: 'cargo.exe', path: 'C:\\Users\\samet\\.cargo\\bin\\cargo.exe', user: 'WORKSTATION\\samet', signed: 'Valid (Rust Foundation)', sha256: '4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a', asn: 'AS54113 Fastly, Inc.', netname: 'FASTLY-CDN (151.101.0.0/16)', pid: 41204, proto: 'TCP', laddr: '192.168.1.111', lport: 55012, raddr: '151.101.1.69', rport: 443, state: 'ESTABLISHED', service: '', tx: 131072, rx: 14889779, age: 8, change: 'new', loopback: false, connected: true, country: '🇳🇱 NL' },
  { id: 6, marked: false, process: 'discord.exe', path: 'C:\\Users\\samet\\AppData\\Local\\Discord\\app-1.0.9162\\Discord.exe', user: 'WORKSTATION\\samet', signed: 'Valid (Discord Inc.)', sha256: 'ef2d127de37b942baad06145e54b0c619a1f22327b2ebbcfbec78f5564afe39d', asn: 'AS13335 Cloudflare, Inc.', netname: 'DISCORD-EDGE (162.159.128.0/18)', pid: 22816, proto: 'TCP', laddr: '192.168.1.111', lport: 50144, raddr: '162.159.135.232', rport: 443, state: 'TIME_WAIT', service: '', tx: 3250585, rx: 9856614, age: 1680, change: 'changed', loopback: false, connected: false, country: '🇺🇸 US' },
  { id: 7, marked: false, process: 'postgres.exe', path: 'C:\\Program Files\\PostgreSQL\\16\\bin\\postgres.exe', user: 'NT AUTHORITY\\NETWORK SERVICE', signed: 'Valid (PostgreSQL Global Dev)', sha256: '7902699be42c8a8e46fbbb4501726517e86b22c56a189f7625a6da49081b2451', asn: 'LOOPBACK-LOCAL', netname: 'IANA-LOOPBACK (127.0.0.0/8)', pid: 8840, proto: 'TCP', laddr: '127.0.0.1', lport: 5432, raddr: '127.0.0.1', rport: 53110, state: 'ESTABLISHED', service: 'postgresql-x64-16', tx: 6710886, rx: 1992294, age: 14400, change: 'unchanged', loopback: true, connected: true, country: '—' },
  { id: 8, marked: false, process: 'postgres.exe', path: 'C:\\Program Files\\PostgreSQL\\16\\bin\\postgres.exe', user: 'NT AUTHORITY\\NETWORK SERVICE', signed: 'Valid (PostgreSQL Global Dev)', sha256: '7902699be42c8a8e46fbbb4501726517e86b22c56a189f7625a6da49081b2451', asn: 'LOOPBACK-LOCAL', netname: 'IANA-LOOPBACK (127.0.0.0/8)', pid: 8840, proto: 'TCP', laddr: '127.0.0.1', lport: 5432, raddr: '0.0.0.0', rport: 0, state: 'LISTEN', service: 'postgresql-x64-16', tx: 0, rx: 0, age: 14400, change: 'unchanged', loopback: true, connected: false, country: '—' },
  { id: 9, marked: false, process: 'spotify.exe', path: 'C:\\Users\\samet\\AppData\\Roaming\\Spotify\\Spotify.exe', user: 'WORKSTATION\\samet', signed: 'Valid (Spotify AB)', sha256: '2c624232cdd221771294dfbb310aca000a0df6ac8b66b696d90ef06fdefb64a3', asn: 'AS15169 Google Cloud', netname: 'GOOGLE-CLOUD-EU (35.184.0.0/13)', pid: 18400, proto: 'TCP', laddr: '192.168.1.111', lport: 52901, raddr: '35.186.224.25', rport: 443, state: 'ESTABLISHED', service: '', tx: 524288, rx: 25794969, age: 3600, change: 'unchanged', loopback: false, connected: true, country: '🇩🇪 DE' },
  { id: 10, marked: false, process: 'svchost.exe', path: 'C:\\Windows\\System32\\svchost.exe', user: 'NT AUTHORITY\\NETWORK SERVICE', signed: 'Valid (Microsoft Windows)', sha256: '19581e27de7ced00ff1ce50b2047e7a567c76b1cbaebabe5ef03f7c3017bb5b7', asn: 'MULTICAST-MDNS', netname: 'LOCAL-MDNS-UDP', pid: 1420, proto: 'UDP', laddr: '0.0.0.0', lport: 5353, raddr: '*', rport: 0, state: '', service: 'Dnscache', tx: 14540, rx: 39936, age: 86400, change: 'unchanged', loopback: false, connected: false, country: '—' },
  { id: 11, marked: false, process: 'svchost.exe', path: 'C:\\Windows\\System32\\svchost.exe', user: 'NT AUTHORITY\\LOCAL SERVICE', signed: 'Valid (Microsoft Windows)', sha256: '19581e27de7ced00ff1ce50b2047e7a567c76b1cbaebabe5ef03f7c3017bb5b7', asn: 'AS8075 Microsoft Corp', netname: 'MSFT-AZURE-NORTH-EU (20.192.0.0/10)', pid: 2188, proto: 'TCP', laddr: '192.168.1.111', lport: 54119, raddr: '20.199.120.85', rport: 443, state: 'ESTABLISHED', service: 'WinHttpAutoProxySvc', tx: 94208, rx: 419840, age: 1140, change: 'unchanged', loopback: false, connected: true, country: '🇮🇪 IE' },
  { id: 12, marked: false, process: 'lsass.exe', path: 'C:\\Windows\\System32\\lsass.exe', user: 'NT AUTHORITY\\SYSTEM', signed: 'Valid (Microsoft Windows)', sha256: '4a44dc15364204a80fe80e9039455cc1608281820fe2b24f1e5233ade6af1dd5', asn: 'LOCAL-RPC', netname: 'WINDOWS-LSASS-RPC', pid: 912, proto: 'TCP', laddr: '0.0.0.0', lport: 49664, raddr: '0.0.0.0', rport: 0, state: 'LISTEN', service: 'SamSs', tx: 0, rx: 0, age: 86400, change: 'unchanged', loopback: false, connected: false, country: '—' },
  { id: 13, marked: false, process: 'curl.exe', path: 'C:\\Windows\\System32\\curl.exe', user: 'WORKSTATION\\samet', signed: 'Valid (Microsoft Windows)', sha256: '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b', asn: 'AS15133 Edgecast Inc.', netname: 'EDGECAST-NETBLK (93.184.216.0/24)', pid: 44910, proto: 'TCP', laddr: '192.168.1.111', lport: 55104, raddr: '93.184.216.34', rport: 443, state: 'CLOSE_WAIT', service: '', tx: 1843, rx: 65536, age: 3, change: 'deleted', loopback: false, connected: false, country: '🇺🇸 US' },
  { id: 14, marked: false, process: 'wezterm-gui.exe', path: 'C:\\Program Files\\WezTerm\\wezterm-gui.exe', user: 'WORKSTATION\\samet', signed: 'Valid (Wez Furlong)', sha256: 'd4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35', asn: 'LOOPBACK-LOCAL', netname: 'IANA-LOOPBACK (127.0.0.0/8)', pid: 11024, proto: 'TCP', laddr: '127.0.0.1', lport: 48120, raddr: '127.0.0.1', rport: 48121, state: 'ESTABLISHED', service: '', tx: 430080, rx: 430080, age: 18000, change: 'unchanged', loopback: true, connected: true, country: '—' },
  { id: 15, marked: false, process: 'WireGuard.exe', path: 'C:\\Program Files\\WireGuard\\wireguard.exe', user: 'NT AUTHORITY\\SYSTEM', signed: 'Valid (WireGuard LLC)', sha256: '4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce', asn: 'UDP-TUNNEL', netname: 'WIREGUARD-INTERFACE-WG0', pid: 6104, proto: 'UDP', laddr: '0.0.0.0', lport: 51820, raddr: '*', rport: 0, state: '', service: 'WireGuardTunnel$wg0', tx: 92694118, rx: 327155712, age: 86400, change: 'unchanged', loopback: false, connected: false, country: '—' },
  { id: 16, marked: false, process: 'node.exe', path: 'C:\\Program Files\\nodejs\\node.exe', user: 'WORKSTATION\\samet', signed: 'Valid (OpenJS Foundation)', sha256: '4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a', asn: 'LOOPBACK-LOCAL', netname: 'IANA-LOOPBACK (127.0.0.0/8)', pid: 29800, proto: 'TCP', laddr: '127.0.0.1', lport: 3000, raddr: '0.0.0.0', rport: 0, state: 'LISTEN', service: '', tx: 0, rx: 0, age: 45, change: 'new', loopback: true, connected: false, country: '—' }
];

let liveSockets = INITIAL_SOCKETS.map(s => ({ ...s }));
let selectedSocketId = 1;
let sortCol = 'process';
let sortDesc = false;
let tuiFilterText = '';
let tuiPaused = false;
let currentTuiMode = 'table';

let txHistory = [18, 24, 42, 65, 50, 31, 22, 19, 38, 74, 88, 61, 40, 29, 35, 54, 71, 63, 44, 30, 25, 48, 82, 95, 70, 52, 39, 41, 60, 78, 66, 49, 33, 27, 45, 68, 72, 55, 38, 42];
let rxHistory = [32, 48, 75, 92, 81, 54, 40, 35, 62, 89, 98, 84, 60, 44, 51, 77, 90, 82, 64, 48, 42, 70, 94, 99, 86, 68, 55, 61, 80, 91, 79, 62, 49, 43, 67, 85, 88, 73, 58, 64];

// ============================================================================
// Formatting & Filter Engine (Matches src/filter.rs)
// ============================================================================
function fmtBytes(b) {
  if (!b || b <= 0) return '0 B';
  if (b >= 1024 * 1024) return (b / (1024 * 1024)).toFixed(1) + ' MiB';
  if (b >= 1024) return (b / 1024).toFixed(1) + ' KiB';
  return b + ' B';
}

function fmtAge(sec) {
  if (sec < 60) return sec + 's';
  if (sec < 3600) return Math.floor(sec / 60) + 'm';
  if (sec < 86400) return Math.floor(sec / 3600) + 'h';
  return Math.floor(sec / 86400) + 'd';
}

function parseByteSize(valStr) {
  const m = String(valStr).trim().match(/^(\d+(?:\.\d+)?)\s*(b|kb|kib|mb|mib|gb|gib)?$/i);
  if (!m) return null;
  const n = parseFloat(m[1]);
  const unit = (m[2] || 'b').toLowerCase();
  const mult = { b: 1, kb: 1024, kib: 1024, mb: 1048576, mib: 1048576, gb: 1073741824, gib: 1073741824 }[unit] || 1;
  return Math.round(n * mult);
}

function wildcardToRegExp(pattern) {
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.');
  return new RegExp('^' + escaped + '$', 'i');
}

function evalClause(clause, row) {
  const trimmed = clause.trim();
  if (!trimmed) return true;
  const opMatch = trimmed.match(/^([a-zA-Z_]+)\s*(==|=~|!~|!=|>=|<=|=|>|<|:)\s*(.*)$/);
  if (!opMatch) {
    const hay = `${row.process} ${row.path} ${row.pid} ${row.proto} ${row.laddr}:${row.lport} ${row.raddr}:${row.rport} ${row.state} ${row.service}`.toLowerCase();
    return hay.includes(trimmed.replace(/^["']|["']$/g, '').toLowerCase());
  }

  const rawField = opMatch[1].toLowerCase();
  const op = opMatch[2];
  const rawVal = opMatch[3].trim().replace(/^["']|["']$/g, '');

  const fieldMap = {
    process: 'process', proc: 'process', name: 'process',
    path: 'path', exe: 'path', pid: 'pid',
    proto: 'proto', protocol: 'proto', state: 'state',
    laddr: 'laddr', local_addr: 'laddr', raddr: 'raddr', remote_addr: 'raddr',
    addr: 'addr', address: 'addr', lport: 'lport', local_port: 'lport',
    rport: 'rport', remote_port: 'rport', port: 'port',
    service: 'service', svc: 'service', tx: 'tx', sent: 'tx',
    rx: 'rx', received: 'rx', change: 'change',
    loopback: 'loopback', connected: 'connected'
  };

  const field = fieldMap[rawField];
  if (!field) throw new Error(`unknown field '${rawField}'`);

  if (field === 'addr') {
    return evalSingleVal(row.laddr, op, rawVal, false) || evalSingleVal(row.raddr, op, rawVal, false);
  }
  if (field === 'port') {
    return evalSingleVal(row.lport, op, rawVal, true) || evalSingleVal(row.rport, op, rawVal, true);
  }

  const isNumeric = ['pid', 'lport', 'rport', 'tx', 'rx'].includes(field);
  const isBool = ['loopback', 'connected'].includes(field);

  if (isBool) {
    const bVal = ['true', '1', 'yes', 'on'].includes(rawVal.toLowerCase());
    if (op === '=' || op === '==') return row[field] === bVal;
    if (op === '!=') return row[field] !== bVal;
    throw new Error(`boolean field '${field}' only supports = or !=`);
  }

  if (field === 'state' && (op === '=' || op === '==')) {
    return row.state.toLowerCase().startsWith(rawVal.toLowerCase());
  }

  return evalSingleVal(row[field], op, rawVal, isNumeric);
}

function evalSingleVal(rowVal, op, rawVal, isNumeric) {
  if (op === '=~') return new RegExp(rawVal, 'i').test(String(rowVal));
  if (op === '!~') return !new RegExp(rawVal, 'i').test(String(rowVal));
  if (op === ':') return String(rowVal).toLowerCase().includes(rawVal.toLowerCase());

  if (isNumeric) {
    const target = parseByteSize(rawVal);
    if (target === null) throw new Error(`invalid number '${rawVal}'`);
    const actual = Number(rowVal) || 0;
    if (op === '=' || op === '==') return actual === target;
    if (op === '!=') return actual !== target;
    if (op === '>') return actual > target;
    if (op === '>=') return actual >= target;
    if (op === '<') return actual < target;
    if (op === '<=') return actual <= target;
  }

  const sActual = String(rowVal).toLowerCase();
  const sTarget = rawVal.toLowerCase();
  if (op === '=' || op === '==') {
    if (sTarget.includes('*') || sTarget.includes('?')) return wildcardToRegExp(sTarget).test(sActual);
    return sActual === sTarget;
  }
  if (op === '!=') {
    if (sTarget.includes('*') || sTarget.includes('?')) return !wildcardToRegExp(sTarget).test(sActual);
    return sActual !== sTarget;
  }
  return sActual.includes(sTarget);
}

function tokenizeFilter(input) {
  const tokens = [];
  let i = 0;
  while (i < input.length) {
    if (/\s/.test(input[i])) { i++; continue; }
    if (input[i] === '(' || input[i] === ')') {
      tokens.push({ type: 'PAREN', val: input[i] });
      i++; continue;
    }
    if (input.slice(i, i + 2) === '&&') { tokens.push({ type: 'AND', val: 'AND' }); i += 2; continue; }
    if (input.slice(i, i + 2) === '||') { tokens.push({ type: 'OR', val: 'OR' }); i += 2; continue; }
    if (input[i] === '!' && input[i + 1] !== '=' && input[i + 1] !== '~') {
      tokens.push({ type: 'NOT', val: 'NOT' }); i++; continue;
    }
    let term = '';
    while (i < input.length && !/\s/.test(input[i]) && input[i] !== '(' && input[i] !== ')') {
      if (input[i] === '"' || input[i] === "'") {
        const q = input[i++]; term += q;
        while (i < input.length && input[i] !== q) term += input[i++];
        if (i < input.length) term += input[i++];
      } else {
        term += input[i++];
      }
    }
    const lower = term.toLowerCase();
    if (lower === 'and') tokens.push({ type: 'AND', val: 'AND' });
    else if (lower === 'or') tokens.push({ type: 'OR', val: 'OR' });
    else if (lower === 'not') tokens.push({ type: 'NOT', val: 'NOT' });
    else tokens.push({ type: 'TERM', val: term });
  }
  return tokens;
}

function evaluateQuery(query, row) {
  const q = query.trim();
  if (!q) return true;
  if (q.startsWith('re:')) {
    const re = new RegExp(q.slice(3), 'i');
    return re.test(`${row.process} ${row.path} ${row.pid} ${row.proto} ${row.laddr}:${row.lport} ${row.raddr}:${row.rport} ${row.state} ${row.service}`);
  }
  const tokens = tokenizeFilter(q);
  let pos = 0;

  function parseOr() {
    let left = parseAnd();
    while (pos < tokens.length && tokens[pos].type === 'OR') {
      pos++;
      const right = parseAnd();
      left = left || right;
    }
    return left;
  }
  function parseAnd() {
    let left = parseNot();
    while (pos < tokens.length && (tokens[pos].type === 'AND' || (tokens[pos].type !== 'OR' && tokens[pos].val !== ')'))) {
      if (tokens[pos].type === 'AND') pos++;
      if (pos >= tokens.length || tokens[pos].val === ')') break;
      const right = parseNot();
      left = left && right;
    }
    return left;
  }
  function parseNot() {
    if (pos < tokens.length && tokens[pos].type === 'NOT') {
      pos++;
      return !parseNot();
    }
    return parsePrimary();
  }
  function parsePrimary() {
    if (pos >= tokens.length) throw new Error('incomplete expression');
    const tok = tokens[pos];
    if (tok.type === 'PAREN' && tok.val === '(') {
      pos++;
      const val = parseOr();
      if (pos >= tokens.length || tokens[pos].val !== ')') throw new Error('unclosed "("');
      pos++;
      return val;
    }
    if (tok.type === 'TERM') {
      pos++;
      return evalClause(tok.val, row);
    }
    throw new Error('unexpected token');
  }
  const res = parseOr();
  if (pos < tokens.length) throw new Error('unexpected trailing token');
  return res;
}

// ============================================================================
// 1. Live Interactive TUI Workstation Renderer + Context Menu
// ============================================================================
function getFilteredAndSortedSockets() {
  let list = liveSockets.filter(row => {
    try {
      return evaluateQuery(tuiFilterText, row);
    } catch {
      return true;
    }
  });

  const numericCols = ['pid', 'lport', 'rport', 'tx', 'rx', 'age'];
  list.sort((a, b) => {
    let cmp = 0;
    if (sortCol === 'mark') {
      cmp = (b.marked ? 1 : 0) - (a.marked ? 1 : 0);
    } else if (numericCols.includes(sortCol)) {
      cmp = (Number(a[sortCol]) || 0) - (Number(b[sortCol]) || 0);
    } else {
      cmp = String(a[sortCol] || '').localeCompare(String(b[sortCol] || ''));
    }
    return sortDesc ? -cmp : cmp;
  });

  return list;
}

function hideContextMenu() {
  document.getElementById('tui-ctx-menu')?.classList.remove('open');
}

function renderTuiWorkstation() {
  const tbody = document.getElementById('tui-live-tbody');
  const sortInd = document.getElementById('tui-sort-indicator');
  const statsLine = document.getElementById('tui-stats-line');
  if (!tbody) return;

  const visible = getFilteredAndSortedSockets();
  sortInd.textContent = `sort:${sortCol}${sortDesc ? '↓' : '↑'}`;

  document.querySelectorAll('.tui-grid-table th').forEach(th => {
    const col = th.dataset.sort;
    const base = th.textContent.replace(/ [▲▼]$/, '');
    th.textContent = col === sortCol ? `${base} ${sortDesc ? '▼' : '▲'}` : base;
  });

  tbody.innerHTML = visible.map(r => {
    const isSel = r.id === selectedSocketId;
    const rowClasses = [
      isSel ? 'row-selected' : '',
      !isSel && r.marked ? 'row-marked' : '',
      !isSel && r.change === 'new' ? 'row-new' : '',
      !isSel && r.change === 'changed' ? 'row-changed' : '',
      !isSel && r.change === 'deleted' ? 'row-deleted' : ''
    ].filter(Boolean).join(' ');

    const gutter = r.marked ? '*' : r.change === 'new' ? '+' : r.change === 'changed' ? '~' : r.change === 'deleted' ? '-' : ' ';

    return `<tr class="${rowClasses}" data-row-id="${r.id}">
      <td>${gutter}</td>
      <td>${r.process}</td>
      <td>${r.pid}</td>
      <td>${r.proto}</td>
      <td>${r.laddr}</td>
      <td>${r.lport}</td>
      <td>${r.raddr}</td>
      <td>${r.rport || '*'}</td>
      <td>${r.state || '—'}</td>
      <td>${r.service || '—'}</td>
      <td>${fmtBytes(r.tx)}</td>
      <td>${fmtBytes(r.rx)}</td>
      <td>${fmtAge(r.age)}</td>
      <td>${r.country}</td>
    </tr>`;
  }).join('');

  tbody.querySelectorAll('tr').forEach(tr => {
    tr.addEventListener('click', () => {
      hideContextMenu();
      selectedSocketId = Number(tr.dataset.rowId);
      renderTuiWorkstation();
    });
    tr.addEventListener('dblclick', () => {
      hideContextMenu();
      selectedSocketId = Number(tr.dataset.rowId);
      openTuiModal('detail');
    });
    tr.addEventListener('contextmenu', (e) => {
      e.preventDefault();
      selectedSocketId = Number(tr.dataset.rowId);
      renderTuiWorkstation();
      const sel = liveSockets.find(s => s.id === selectedSocketId);
      const menu = document.getElementById('tui-ctx-menu');
      const title = document.getElementById('tui-ctx-title');
      const container = document.getElementById('tui-body-container');
      if (menu && container && sel) {
        const rect = container.getBoundingClientRect();
        const menuW = Math.min(255, Math.max(200, container.clientWidth - 16));
        const menuH = 225;
        const maxLeft = container.scrollLeft + Math.max(8, container.clientWidth - menuW - 8);
        const rawLeft = e.clientX - rect.left + container.scrollLeft;
        const x = Math.max(container.scrollLeft + 8, Math.min(rawLeft, maxLeft));

        const maxTop = container.scrollTop + Math.max(8, container.clientHeight - menuH - 8);
        const rawTop = e.clientY - rect.top + container.scrollTop;
        const y = Math.max(container.scrollTop + 8, Math.min(rawTop, maxTop));

        title.textContent = `┌ ${sel.process} (${sel.pid}) ──┐`;
        menu.style.left = `${x}px`;
        menu.style.top = `${y}px`;
        menu.classList.add('open');
      }
    });
  });

  const tcpCount = liveSockets.filter(s => s.proto === 'TCP').length;
  const udpCount = liveSockets.filter(s => s.proto === 'UDP').length;
  const estCount = liveSockets.filter(s => s.state === 'ESTABLISHED').length;
  const lsnCount = liveSockets.filter(s => s.state === 'LISTEN').length;
  const twCount = liveSockets.filter(s => s.state === 'TIME_WAIT').length;
  const cwCount = liveSockets.filter(s => s.state === 'CLOSE_WAIT').length;

  statsLine.textContent = `total ${liveSockets.length} · tcp ${tcpCount} (est ${estCount} lsn ${lsnCount} tw ${twCount} cw ${cwCount}) · udp ${udpCount} · shown ${visible.length}`;

  if (currentTuiMode !== 'table') {
    renderModalContent(currentTuiMode);
  }
}

function showStatusBanner(msg) {
  const el = document.getElementById('tui-status-msg');
  if (!el) return;
  el.textContent = ` ${msg}`;
  el.style.display = 'block';
  clearTimeout(showStatusBanner._timer);
  showStatusBanner._timer = setTimeout(() => { el.style.display = 'none'; }, 3500);
}

let hudTimer = null;
function flashKeystrokeHud(label) {
  const hud = document.getElementById('keystroke-hud');
  if (!hud) return;
  hud.textContent = label;
  hud.classList.add('show');
  clearTimeout(hudTimer);
  hudTimer = setTimeout(() => hud.classList.remove('show'), 1400);
}

// ============================================================================
// Modal Views inside the Interactive Terminal
// ============================================================================
function openTuiModal(mode) {
  hideContextMenu();
  currentTuiMode = mode;
  const modal = document.getElementById('tui-modal');
  document.querySelectorAll('[data-tui-mode]').forEach(btn => {
    if (btn.classList.contains('mode-btn')) {
      btn.classList.toggle('active', btn.dataset.tuiMode === mode);
    }
  });

  if (mode === 'table') {
    modal.classList.remove('open');
    return;
  }
  modal.classList.add('open');
  renderModalContent(mode);
}

function barsFromSeries(arr) {
  const blocks = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
  return arr.map(v => blocks[Math.min(7, Math.floor((v / 100) * 8))]).join('');
}

function renderModalContent(mode) {
  const titleEl = document.getElementById('tui-modal-title');
  const contentEl = document.getElementById('tui-modal-content');
  const footEl = document.getElementById('tui-modal-foot');
  const sel = liveSockets.find(s => s.id === selectedSocketId) || liveSockets[0];

  if (mode === 'chart') {
    titleEl.textContent = `┌ Bandwidth Chart (B) — Total System EStats · 60s Rolling Delta ──┐`;
    const txBars = barsFromSeries(txHistory);
    const rxBars = barsFromSeries(rxHistory);
    const curTx = (txHistory[txHistory.length - 1] * 14.2).toFixed(1);
    const curRx = (rxHistory[rxHistory.length - 1] * 48.6).toFixed(1);
    contentEl.innerHTML = `<pre style="font-family: var(--font-mono); line-height: 1.5; white-space: pre-wrap;">
<span style="color: var(--t-header); font-weight: 700;">▲ Tx (Sent)</span>      current: <strong>${curTx} KiB/s</strong>   peak: <strong>1.42 MiB/s</strong>   session total: <strong>108.4 MiB</strong>
  <span style="color: var(--t-header); font-size: clamp(0.68rem, 2.2vw, 1.15rem); letter-spacing: 1px;">${txBars}</span>

<span style="color: var(--t-new); font-weight: 700;">▼ Rx (Received)</span>  current: <strong>${curRx} KiB/s</strong>   peak: <strong>6.84 MiB/s</strong>   session total: <strong>491.2 MiB</strong>
  <span style="color: var(--t-new); font-size: clamp(0.68rem, 2.2vw, 1.15rem); letter-spacing: 1px;">${rxBars}</span>

Selected Endpoint Focus [Tab]: <strong>${sel.process}</strong> (${sel.laddr}:${sel.lport} → ${sel.raddr}:${sel.rport})
Endpoint Cumulative Counters : Tx <strong>${fmtBytes(sel.tx)}</strong> · Rx <strong>${fmtBytes(sel.rx)}</strong></pre>`;
    footEl.textContent = 'Live EStats delta stream active · Press Esc or click Endpoints to return';
  } else if (mode === 'grouped') {
    titleEl.textContent = `┌ Grouped Process Tree (G) — Hierarchical Process Aggregation ──┐`;
    const groups = {};
    liveSockets.forEach(s => {
      if (!groups[s.process]) groups[s.process] = { pid: s.pid, rows: [], tx: 0, rx: 0 };
      groups[s.process].rows.push(s);
      groups[s.process].tx += s.tx;
      groups[s.process].rx += s.rx;
    });
    const html = Object.entries(groups).map(([proc, info]) => {
      const children = info.rows.map(r =>
        `    ├─ ${r.proto.padEnd(4)} ${(r.laddr + ':' + r.lport).padEnd(22)} → ${(r.raddr + ':' + (r.rport || '*')).padEnd(22)} ${r.state || 'UDP'}`
      ).join('\n');
      return `<span style="color: var(--t-header); font-weight: 700;">▼ ${proc}</span> (PID ${info.pid} · ${info.rows.length} endpoint(s) · Tx ${fmtBytes(info.tx)} · Rx ${fmtBytes(info.rx)})\n${children}`;
    }).join('\n\n');
    contentEl.innerHTML = `<pre style="font-family: var(--font-mono); font-size: 0.76rem; line-height: 1.45;">${html}</pre>`;
    footEl.textContent = 'Enter: expand/collapse group · K: kill entire process group · w: whois · Esc: close';
  } else if (mode === 'palette') {
    titleEl.textContent = `┌ Command Palette (Ctrl+P) — 22 Fuzzy-Searchable Actions ──┐`;
    const cmds = [
      { label: 'pause/resume live updates', key: 'p', act: () => togglePause() },
      { label: 'bandwidth chart', key: 'B', act: () => openTuiModal('chart') },
      { label: 'rules: alerts and colors', key: 'A', act: () => openTuiModal('rules') },
      { label: 'toggle grouped view', key: 'G', act: () => openTuiModal('grouped') },
      { label: 'inspect process & authenticode', key: 'Enter', act: () => openTuiModal('detail') },
      { label: 'whois remote address (RFC 3912)', key: 'w', act: () => openTuiModal('whois') },
      { label: 'virustotal reputation lookup', key: 'V', act: () => openTuiModal('vt') },
      { label: 'close selected TCP connection (SetTcpEntry)', key: 'c', act: () => { closeSelectedConnection(); openTuiModal('table'); } }
    ];
    contentEl.innerHTML = `<div style="display:flex; flex-direction:column; gap:5px; margin-top:4px;">
      ${cmds.map((c, idx) => `<button class="tui-mini-btn palette-exec-btn" data-cmd-idx="${idx}" style="display:flex; justify-content:space-between; padding:6px 12px; text-align:left; font-size:0.76rem;">
        <span>▸ ${c.label}</span>
        <kbd style="color:var(--t-header);">[${c.key}]</kbd>
      </button>`).join('')}
    </div>`;
    contentEl.querySelectorAll('.palette-exec-btn').forEach((btn, idx) => {
      btn.addEventListener('click', () => cmds[idx].act());
    });
    footEl.textContent = 'Click any command above to execute immediately in the workstation';
  } else if (mode === 'rules') {
    titleEl.textContent = `┌ Rules Studio (A) — Alert Triggers & Wireshark Row Coloring ──┐`;
    contentEl.innerHTML = `<pre style="font-family: var(--font-mono); font-size: 0.77rem; line-height: 1.55;">
<span style="color: var(--t-header); font-weight: 700;">[ALERT RULES — Fire ⚠ banner, event log &amp; terminal bell on newly opened endpoints]</span>
  <span style="color: var(--t-new);">[x] rport=4444 or rport=1337 or rport=31337</span>              (Suspicious C2 / reverse shell port)
  <span style="color: var(--t-new);">[x] proto=tcp and state=listen and laddr=0.0.0.0</span>         (New wildcard listener opened)
  <span>[ ] process~=^(powershell|cmd|mshta) and connected=true</span>  (Shell outbound connection)

<span style="color: var(--t-header); font-weight: 700;">[WIRESHARK-STYLE COLORING RULES — Evaluated top-to-bottom per row]</span>
  <span style="color: var(--t-header);">1. [x] state=listen</span>                         → fg: cyan     bold: true
  <span style="color: var(--t-changed);">2. [x] tx&gt;5MB or rx&gt;5MB</span>                    → fg: yellow   bold: true
  <span style="color: var(--t-marked);">3. [x] proto=udp and loopback=false</span>           → fg: magenta  bold: false
  <span style="color: var(--t-deleted);">4. [x] state=close_wait or state=time_wait</span>  → fg: red      bold: false</pre>`;
    footEl.textContent = 'Configured rules persist in %APPDATA%\\tcptui\\config.toml under [[alerts]] and [[colors]]';
  } else if (mode === 'detail') {
    titleEl.textContent = `┌ Process & Authenticode Inspection (Enter) — PID ${sel.pid} (${sel.process}) ──┐`;
    contentEl.innerHTML = `<pre style="font-family: var(--font-mono); font-size: 0.78rem; line-height: 1.55;">
  Process Name   : <strong style="color: var(--t-header);">${sel.process}</strong> (PID ${sel.pid})
  Executable     : ${sel.path}
  Token User SID : <strong>${sel.user}</strong>
  Authenticode   : <span style="color: var(--t-new); font-weight: 700;">✔ ${sel.signed} [WinVerifyTrust]</span>
  Hosted Service : ${sel.service || '— (Standalone Executable)'}
  Socket Tuple   : ${sel.proto} ${sel.laddr}:${sel.lport} → ${sel.raddr}:${sel.rport || '*'} (${sel.state || 'STATELESS'})
  GeoIP Location : ${sel.country} · First-Seen Age: ${fmtAge(sel.age)}
  Traffic (2min) : <span style="color: var(--t-header);">▁▂▃▄▆█▇▅▃▂▄▆█▇▄▃▂▁▂▄▆▇█▆▄▃▂▃▅▆▄▃▂▁▂▃▅▇█▆</span> (Tx ${fmtBytes(sel.tx)} / Rx ${fmtBytes(sel.rx)})</pre>`;
    footEl.textContent = 'Double-click any row in the table to inspect its Authenticode signature & traffic sparkline';
  } else if (mode === 'whois') {
    titleEl.textContent = `┌ RFC 3912 Whois Lookup (w) — ${sel.raddr} ──┐`;
    contentEl.innerHTML = `<pre style="font-family: var(--font-mono); font-size: 0.77rem; line-height: 1.55;">
<span style="color: var(--t-dim);"># Querying whois.iana.org:43 -> referral to RIR authority...</span>
  Remote IP      : <strong style="color: var(--t-header);">${sel.raddr}</strong> (Port ${sel.rport || '*'})
  Origin ASN     : <strong style="color: var(--t-new);">${sel.asn}</strong>
  Network Range  : ${sel.netname}
  Country / Geo  : ${sel.country}
  Owning Process : ${sel.process} (PID ${sel.pid})
  Registry Status: ALLOCATED PA · Direct RIR Referral Verified</pre>`;
    footEl.textContent = 'src/actions.rs performs non-blocking TCP port 43 referral resolution starting from whois.iana.org';
  } else if (mode === 'vt') {
    titleEl.textContent = `┌ VirusTotal v3 Intelligence (V) — ${sel.process} & ${sel.raddr} ──┐`;
    contentEl.innerHTML = `<pre style="font-family: var(--font-mono); font-size: 0.77rem; line-height: 1.55;">
<span style="color: var(--t-header); font-weight: 700;">[FILE HASH REPORT — SHA-256 OF ${sel.path}]</span>
  SHA-256 Digest : ${sel.sha256}
  Detections     : <span style="color: var(--t-new); font-weight: 700;">0 / 74 security vendors flagged this binary (CLEAN)</span>
  Signer         : ${sel.signed}

<span style="color: var(--t-header); font-weight: 700;">[REMOTE IP REPUTATION — ${sel.raddr}]</span>
  ASN / Owner    : ${sel.asn} (${sel.country})
  Detections     : <span style="color: var(--t-new); font-weight: 700;">0 / 94 security vendors flagged this IP address</span></pre>`;
    footEl.textContent = 'Enabled via cargo build --release --features virustotal · Uses [virustotal] api_key in config.toml';
  }
}

function togglePause() {
  tuiPaused = !tuiPaused;
  const pausePill = document.getElementById('tui-pause-pill');
  const pauseBtn = document.getElementById('tui-btn-pause');
  if (pausePill) pausePill.style.display = tuiPaused ? 'inline-block' : 'none';
  if (pauseBtn) pauseBtn.textContent = tuiPaused ? '▶ RESUME [p]' : '⏸ PAUSE [p]';
  showStatusBanner(tuiPaused ? 'Live updates paused — snapshots frozen for inspection' : 'Live updates resumed');
}

function closeSelectedConnection() {
  const sel = liveSockets.find(s => s.id === selectedSocketId);
  if (!sel) return;
  if (sel.proto !== 'TCP' || sel.state !== 'ESTABLISHED') {
    showStatusBanner(`SetTcpEntry: can only close ESTABLISHED IPv4 TCP sockets (selected is ${sel.proto} ${sel.state || 'UDP'})`);
    return;
  }
  sel.state = 'CLOSED';
  sel.change = 'deleted';
  sel.connected = false;
  showStatusBanner(`SetTcpEntry(DELETE_TCB): closed ${sel.process} (${sel.laddr}:${sel.lport} -> ${sel.raddr}:${sel.rport})`);
  renderTuiWorkstation();
}

// ============================================================================
// 2. 60fps Live EStats Oscilloscope Canvas in Hero
// ============================================================================
function initOscilloscope() {
  const canvas = document.getElementById('estats-canvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  let phase = 0;

  function resizeCanvas() {
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    const rect = canvas.getBoundingClientRect();
    const cssW = Math.max(240, Math.round(rect.width || canvas.offsetWidth || 520));
    const cssH = Math.max(54, Math.round(rect.height || 68));
    const targetW = Math.round(cssW * dpr);
    const targetH = Math.round(cssH * dpr);
    if (canvas.width !== targetW || canvas.height !== targetH) {
      canvas.width = targetW;
      canvas.height = targetH;
    }
  }
  resizeCanvas();
  window.addEventListener('resize', resizeCanvas);

  function drawWave() {
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    const w = canvas.width / dpr;
    const h = canvas.height / dpr;
    ctx.save();
    ctx.scale(dpr, dpr);
    ctx.clearRect(0, 0, w, h);

    // Subtle oscilloscope grid
    ctx.strokeStyle = 'rgba(35, 50, 77, 0.45)';
    ctx.lineWidth = 1;
    for (let x = 0; x < w; x += 32) {
      ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, h); ctx.stroke();
    }
    ctx.beginPath(); ctx.moveTo(0, h / 2); ctx.lineTo(w, h / 2); ctx.stroke();

    // Rx Waveform (Green)
    ctx.beginPath();
    ctx.strokeStyle = '#00e676';
    ctx.lineWidth = 1.8;
    for (let x = 0; x < w; x++) {
      const y = h * 0.58 + Math.sin((x * 0.032) + phase) * 14 + Math.cos((x * 0.08) - phase * 1.4) * 7;
      if (x === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
    }
    ctx.stroke();

    // Tx Waveform (Cyan)
    ctx.beginPath();
    ctx.strokeStyle = '#00f0ff';
    ctx.lineWidth = 2;
    for (let x = 0; x < w; x++) {
      const y = h * 0.42 + Math.cos((x * 0.025) - phase * 1.2) * 13 + Math.sin((x * 0.065) + phase * 0.9) * 6;
      if (x === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
    }
    ctx.stroke();
    ctx.restore();

    if (!tuiPaused) phase += 0.055;
    requestAnimationFrame(drawWave);
  }
  requestAnimationFrame(drawWave);
}

// ============================================================================
// 3. Architecture Inspector & Tactile Keydeck Definitions
// ============================================================================
const ARCH_DETAILS = {
  net: `<strong style="color: var(--cyan);">[STAGE 01 // src/net.rs · src/proc.rs · src/services.rs]</strong><br/>Calls <code>netstat2::get_sockets_info(AF_INET | AF_INET6, TCP | UDP)</code>, queries Win32 <code>GetPerTcpConnectionEStats</code> / <code>GetPerTcp6ConnectionEStats</code> for raw <code>DataBytesOut</code> and <code>DataBytesIn</code> counters, enriches PIDs via <code>sysinfo</code>, and maps Windows Service Control Manager (SCM) services with <code>EnumServicesStatusExW</code>.`,
  etw: `<strong style="color: var(--cyan);">[STAGE 02 // src/etw.rs · src/dns.rs · src/geoip.rs]</strong><br/>Subscribes to the <code>Microsoft-Windows-Kernel-Network</code> ETW provider (<code>StartTraceW</code> / <code>ProcessTrace</code>) for real kernel connect/disconnect events. Reverse DNS runs on isolated non-blocking lookup threads (<code>getnameinfo</code>), and remote IPs are resolved against MaxMind <code>GeoLite2-Country.mmdb</code>.`,
  model: `<strong style="color: var(--cyan);">[STAGE 03 // src/model.rs · src/filter.rs · src/app.rs]</strong><br/><code>merge_snapshots()</code> diffs the incoming socket table against the previous tick, tagging each 5-tuple as <code>New</code> (+), <code>Changed</code> (~), <code>Deleted</code> (-), or <code>Unchanged</code> while preserving <code>first_seen</code> timestamps. Then evaluates the 17-field recursive-descent filter AST, alert rules, and Wireshark coloring rules.`,
  ui: `<strong style="color: var(--cyan);">[STAGE 04 // src/events.rs · src/ui/table.rs · src/actions.rs]</strong><br/>Pure <code>event → state → render</code> architecture on Ratatui + Crossterm. Supports horizontal wheel scroll, header drag-resize, fuzzy command palette, headless <code>--dump-frame</code> rendering, <code>WinVerifyTrust</code> Authenticode checks, and <code>SetTcpEntry</code> connection termination.`
};

const KEYDECK_INFO = {
  'Esc': { title: 'Close Popup / Clear Prompt (Esc)', desc: 'Closes any active popup (Help, Chart, Rules, Profiles, Settings, Whois, Command Palette) or cancels the current filter/search input.', mode: 'table' },
  '1': { title: 'Preset 1 — TCP Only (proto=tcp)', desc: 'Applies quick filter preset #1 to display only IPv4 and IPv6 TCP endpoints.', preset: 'proto=tcp' },
  '2': { title: 'Preset 2 — UDP Only (proto=udp)', desc: 'Applies quick filter preset #2 to display only stateless UDP endpoints.', preset: 'proto=udp' },
  '3': { title: 'Preset 3 — ESTABLISHED Only', desc: 'Filters the table to active ESTABLISHED TCP connections (`state=established`).', preset: 'state=established' },
  '4': { title: 'Preset 4 — LISTEN Only', desc: 'Shows only local listening server sockets (`state=listen`).', preset: 'state=listen' },
  '5': { title: 'Preset 5 — Loopback Only', desc: 'Restricts the view to 127.0.0.1 and ::1 loopback traffic (`loopback=true`).', preset: 'loopback=true' },
  '6': { title: 'Preset 6 — External (Non-Loopback)', desc: 'Hides local IPC loopback sockets to focus on external network traffic (`loopback=false`).', preset: 'loopback=false' },
  '7': { title: 'Preset 7 — Newly Opened Endpoints', desc: 'Shows only endpoints that appeared on the most recent snapshot diff (`change=new`).', preset: 'change=new' },
  '8': { title: 'Preset 8 — Clear Filter', desc: 'Clears the active filter expression and restores all endpoints.', preset: '' },
  'F5': { title: 'Manual Snapshot Refresh (F5)', desc: 'Immediately wakes the background collector thread to capture and diff a fresh socket snapshot.' },
  'F6': { title: 'Watch Selected Process PID (F6)', desc: 'Locks the table to the currently selected process PID (`WATCH <PID>` indicator in the title bar).' },
  'Tab': { title: 'Switch Series / Popup Tab (Tab)', desc: 'Switches between Total System and Selected Endpoint in the Bandwidth Chart (B), or toggles between Alerts and Colors in the Rules popup (A).' },
  'q': { title: 'Quit Application / Close Modal (q)', desc: 'Closes the active popup or exits tcptui cleanly, persisting column widths and settings to config.toml.', mode: 'table' },
  'w': { title: 'RFC 3912 Whois Lookup (w)', desc: 'Queries IANA/RIR whois servers on port 43 (following referrals automatically) for the selected remote IP address.', mode: 'whois' },
  'e': { title: 'Export Table (e)', desc: 'Exports all currently visible endpoints to a timestamped CSV, TSV, JSON, or plain-text file.' },
  'r': { title: 'Toggle Reverse DNS Resolution (r)', desc: 'Enables or disables background asynchronous PTR hostname lookups for local and remote IP addresses.' },
  't': { title: 'Toggle TCP Visibility (t)', desc: 'Shows or hides TCP endpoints without altering your structured filter expression.' },
  'u': { title: 'Toggle UDP Visibility (u)', desc: 'Shows or hides UDP endpoints (Shift+U toggles unconnected/listening endpoints).' },
  'i': { title: 'System Statistics Popup (i)', desc: 'Opens the system summary popup with protocol state counts and top processes ranked by socket count and transferred bytes.', mode: 'detail' },
  'o': { title: 'Multi-Key Sort Order Editor (o)', desc: 'Opens the interactive sort chain editor where you can reorder, toggle ascending/descending, or enable multi-column sort keys.' },
  'p': { title: 'Pause / Resume Live Updates (p)', desc: 'Freezes incoming snapshots so the table, colors, and chart hold still for inspection while ETW timestamps continue buffering.', act: 'pause' },
  'A': { title: 'Alert & Coloring Rules Studio (Shift+A)', desc: 'Opens the Rules editor to configure alert expressions (with ⚠ indicator and bell) and Wireshark-style row coloring rules.', mode: 'rules' },
  's': { title: 'Cycle Sort Column (s / Shift+S)', desc: 'Cycles the primary sort column forward (`s`) or reverses the current sort order (`Shift+S`).' },
  'Ctrl+F': { title: 'Incremental Cell Search (Ctrl+F)', desc: 'Highlights matching text directly inside table cells and jumps between matches with `n` and `N`.' },
  'G': { title: 'Grouped Process Tree View (Shift+G)', desc: 'Aggregates endpoints into collapsible per-process tree nodes with total Tx/Rx byte summaries.', mode: 'grouped' },
  '?': { title: 'Two-Column Scrollable Help (? / H)', desc: 'Opens the balanced two-column keyboard and mouse shortcut reference.' },
  'j/k': { title: 'Vim-Style Row Navigation (j / k)', desc: 'Moves selection down (`j` / `Down`) or up (`k` / `Up`) across the endpoint table or active popup.' },
  'K': { title: 'Terminate Process (Shift+K)', desc: 'Prompts for confirmation and terminates the owning process (or all marked processes) via Win32 TerminateProcess.' },
  'L': { title: 'Toggle Loopback Visibility (Shift+L)', desc: 'Quickly hides or reveals loopback (`127.0.0.1` / `::1`) endpoints.' },
  'Enter': { title: 'Process & Authenticode Details (Enter)', desc: 'Opens the process inspection popup showing executable path, user account, WinVerifyTrust signature status, and 2-minute traffic sparkline.', mode: 'detail' },
  'Ctrl+P': { title: 'Fuzzy Command Palette (Ctrl+P)', desc: 'Opens the interactive Command Palette with subsequence matching across all 22 actions.', mode: 'palette' },
  'x': { title: 'Clear Marks, Alerts & Filter (x)', desc: 'Resets row marks, dismisses pending alert banners, and clears any active filter in one keystroke.', preset: '' },
  'c': { title: 'Close TCP Connection (c)', desc: 'Immediately tears down the selected (or all marked) ESTABLISHED IPv4 TCP connection(s) using Win32 SetTcpEntry(DELETE_TCB).', act: 'close' },
  'V': { title: 'VirusTotal Reputation Lookup (Shift+V)', desc: 'Hashes the owning process executable (SHA-256) or queries the remote IP against the VirusTotal v3 API.', mode: 'vt' },
  'B': { title: 'Live EStats Bandwidth Chart (Shift+B)', desc: 'Opens the rolling per-interval Tx/Rx throughput bar chart powered by Windows EStats counters.', mode: 'chart' },
  'n': { title: 'Next / Previous Search Match (n / N)', desc: 'Jumps the cursor to the next (`n`) or previous (`Shift+N`) row matching the active Ctrl+F search.' },
  'M': { title: 'In-App Settings Screen (Shift+M)', desc: 'Opens the interactive settings modal to edit refresh rate, theme, EStats, ETW, GeoIP path, and bell notifications.' },
  '/': { title: 'Structured Filter Prompt (/)', desc: 'Focuses the filter bar with live match counts, inline syntax diagnostics, and Up/Down command history.' },
  'Space': { title: 'Mark / Unmark Row for Batch Actions (Space)', desc: 'Toggles the `*` mark on the selected row (or use Shift+Up/Down for range marking) for batch Close, Kill, or TSV Copy.' }
};

const CLI_SAMPLES = {
  json: `PS> tcpvcon.exe -a -j -n --filter "proto=tcp and state=established and loopback=false"
[
  {
    "Process": "chrome.exe",
    "PID": "39496",
    "Protocol": "TCP",
    "Local Address": "192.168.1.111",
    "Local Port": "54720",
    "Remote Address": "142.250.187.206",
    "Remote Port": "443",
    "State": "ESTABLISHED"
  },
  {
    "Process": "cargo.exe",
    "PID": "41204",
    "Protocol": "TCP",
    "Local Address": "192.168.1.111",
    "Local Port": "55012",
    "Remote Address": "151.101.1.69",
    "Remote Port": "443",
    "State": "ESTABLISHED"
  }
]`,
  csv: `PS> tcpvcon.exe -a -c -n chrome
Process,PID,Protocol,Local Address,Local Port,Remote Address,Remote Port,State
chrome.exe,39496,TCP,192.168.1.111,54720,142.250.187.206,443,ESTABLISHED
chrome.exe,39496,TCP,192.168.1.111,54788,104.18.32.47,443,ESTABLISHED`,
  table: `PS> tcpvcon.exe -a -n
Process            PID    Proto Local Address                  L-Port Remote Address                 R-Port State
------------------ ------ ----- ------------------------------ ------ ------------------------------ ------ -------------
Code.exe           35668  TCP   127.0.0.1                      6907   0.0.0.0                        0      LISTEN
Code.exe           35668  TCP   192.168.1.111                  51892  140.82.121.4                   443    ESTABLISHED
WireGuard.exe      6104   UDP   0.0.0.0                        51820                                        
cargo.exe          41204  TCP   192.168.1.111                  55012  151.101.1.69                   443    ESTABLISHED
chrome.exe         39496  TCP   192.168.1.111                  54720  142.250.187.206                443    ESTABLISHED`,
  dump: `PS> tcptui.exe --dump-frame snapshot-120x30.txt --frame-size 120x30 --filter "state=established"
 tcptui  FILTER:state=established sort:Process↑ resolve:off                                            1000ms ADMIN
┌ 9 endpoint(s) ───────────────────────────────────────────────────────────────────────────────────────────────────────┐
│M Process          PID    Proto Local Address          L-Port Remote Address         R-Port State         Age         │
│  Code.exe         35668  TCP   192.168.1.111            51892 140.82.121.4              443 ESTABLISHED   44m         │
│  cargo.exe        41204  TCP   192.168.1.111            55012 151.101.1.69              443 ESTABLISHED   8s          │
│  chrome.exe       39496  TCP   192.168.1.111            54720 142.250.187.206           443 ESTABLISHED   14s         │
└──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘`
};

// ============================================================================
// 4. Initialization & Event Listeners
// ============================================================================
document.addEventListener('DOMContentLoaded', () => {
  initOscilloscope();

  // --- Mobile Navigation Drawer ---
  const mobileMenuBtn = document.getElementById('mobile-menu-toggle');
  const mobileNavDrawer = document.getElementById('mobile-nav-drawer');

  function setMobileDrawer(open) {
    if (!mobileMenuBtn || !mobileNavDrawer) return;
    mobileNavDrawer.classList.toggle('open', open);
    mobileMenuBtn.setAttribute('aria-expanded', open ? 'true' : 'false');
    mobileMenuBtn.textContent = open ? '✕' : '☰';
  }

  mobileMenuBtn?.addEventListener('click', (e) => {
    e.stopPropagation();
    const isOpen = mobileNavDrawer?.classList.contains('open');
    setMobileDrawer(!isOpen);
  });

  mobileNavDrawer?.querySelectorAll('a').forEach(link => {
    link.addEventListener('click', () => setMobileDrawer(false));
  });

  document.addEventListener('click', (e) => {
    if (!e.target.closest('.navbar')) setMobileDrawer(false);
    if (!e.target.closest('#tui-ctx-menu')) hideContextMenu();
  });

  window.addEventListener('resize', () => {
    hideContextMenu();
    if (window.innerWidth > 1024) setMobileDrawer(false);
  });

  // Context menu item execution
  document.querySelectorAll('.tui-ctx-item').forEach(item => {
    item.addEventListener('click', () => {
      const act = item.dataset.ctx;
      hideContextMenu();
      const sel = liveSockets.find(s => s.id === selectedSocketId);
      if (!sel) return;
      if (act === 'detail') openTuiModal('detail');
      if (act === 'whois') openTuiModal('whois');
      if (act === 'vt') openTuiModal('vt');
      if (act === 'close') closeSelectedConnection();
      if (act === 'kill') {
        liveSockets.forEach(s => { if (s.pid === sel.pid) s.change = 'deleted'; });
        showStatusBanner(`TerminateProcess: ended ${sel.process} (PID ${sel.pid})`);
        renderTuiWorkstation();
      }
      if (act === 'mark') {
        sel.marked = !sel.marked;
        renderTuiWorkstation();
      }
      if (act === 'json') {
        navigator.clipboard?.writeText(JSON.stringify(sel, null, 2));
        showStatusBanner(`Copied ${sel.process} (${sel.laddr}:${sel.lport}) row as JSON to clipboard`);
      }
    });
  });

  // Global physical keyboard handler for the workstation
  document.addEventListener('keydown', (e) => {
    if (e.target.tagName === 'INPUT' || e.target.tagName === 'SELECT' || e.target.tagName === 'TEXTAREA') {
      if (e.key === 'Escape') e.target.blur();
      return;
    }
    const k = e.key;
    if (k === 'p') { e.preventDefault(); togglePause(); flashKeystrokeHud('KEY_EVENT // [p] Pause/Resume'); }
    else if (k === 'B' || k === 'b') { e.preventDefault(); openTuiModal(currentTuiMode === 'chart' ? 'table' : 'chart'); flashKeystrokeHud('KEY_EVENT // [B] Bandwidth Chart'); }
    else if (k === 'G') { e.preventDefault(); openTuiModal(currentTuiMode === 'grouped' ? 'table' : 'grouped'); flashKeystrokeHud('KEY_EVENT // [G] Grouped Process Tree'); }
    else if (k === 'A' || k === 'a') { e.preventDefault(); openTuiModal(currentTuiMode === 'rules' ? 'table' : 'rules'); flashKeystrokeHud('KEY_EVENT // [A] Alert & Color Rules'); }
    else if (k === 'w') { e.preventDefault(); openTuiModal(currentTuiMode === 'whois' ? 'table' : 'whois'); flashKeystrokeHud('KEY_EVENT // [w] Whois Lookup'); }
    else if (k === 'V' || k === 'v') { e.preventDefault(); openTuiModal(currentTuiMode === 'vt' ? 'table' : 'vt'); flashKeystrokeHud('KEY_EVENT // [V] VirusTotal Scan'); }
    else if (k === 'Enter') { e.preventDefault(); openTuiModal(currentTuiMode === 'detail' ? 'table' : 'detail'); flashKeystrokeHud('KEY_EVENT // [Enter] Process Authenticode'); }
    else if (k === 'Escape' || k === 'q') { openTuiModal('table'); hideContextMenu(); flashKeystrokeHud('KEY_EVENT // [Esc] Normal Table View'); }
    else if (k === 'c') { closeSelectedConnection(); flashKeystrokeHud('KEY_EVENT // [c] SetTcpEntry Close'); }
    else if (k === ' ') {
      e.preventDefault();
      const sel = liveSockets.find(s => s.id === selectedSocketId);
      if (sel) { sel.marked = !sel.marked; renderTuiWorkstation(); flashKeystrokeHud('KEY_EVENT // [Space] Toggle Row Mark'); }
    } else if (k === 'j' || k === 'ArrowDown') {
      e.preventDefault();
      const vis = getFilteredAndSortedSockets();
      const idx = vis.findIndex(s => s.id === selectedSocketId);
      if (idx >= 0 && idx + 1 < vis.length) {
        selectedSocketId = vis[idx + 1].id;
        renderTuiWorkstation();
      }
    } else if (k === 'k' || k === 'ArrowUp') {
      e.preventDefault();
      const vis = getFilteredAndSortedSockets();
      const idx = vis.findIndex(s => s.id === selectedSocketId);
      if (idx > 0) {
        selectedSocketId = vis[idx - 1].id;
        renderTuiWorkstation();
      }
    } else if (['1', '2', '3', '4', '5', '6', '7', '8'].includes(k)) {
      const info = KEYDECK_INFO[k];
      if (info && info.preset !== undefined) {
        tuiFilterText = info.preset;
        const inp = document.getElementById('tui-live-filter');
        if (inp) inp.value = tuiFilterText;
        openTuiModal('table');
        renderTuiWorkstation();
        flashKeystrokeHud(`KEY_EVENT // [${k}] Preset '${info.preset || 'ALL'}'`);
      }
    }
  });

  // --- Package Manager Deck ---
  let currentPkg = 'scoop';
  const pkgDisplay = document.getElementById('pkg-cmd-display');
  const pkgTabs = document.querySelectorAll('.deck-tab');
  const copyPkgBtn = document.getElementById('copy-pkg-btn');

  pkgTabs.forEach(tab => {
    tab.addEventListener('click', () => {
      pkgTabs.forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      currentPkg = tab.dataset.pkg;
      pkgDisplay.textContent = PKG_COMMANDS[currentPkg];
    });
  });

  copyPkgBtn?.addEventListener('click', () => {
    navigator.clipboard.writeText(PKG_COMMANDS[currentPkg]);
    copyPkgBtn.textContent = 'COPIED ✓';
    setTimeout(() => { copyPkgBtn.textContent = 'COPY'; }, 1500);
  });

  // --- Workstation Column Sorting ---
  document.querySelectorAll('.tui-grid-table th').forEach(th => {
    th.addEventListener('click', () => {
      const col = th.dataset.sort;
      if (sortCol === col) sortDesc = !sortDesc;
      else { sortCol = col; sortDesc = false; }
      renderTuiWorkstation();
    });
  });

  // --- Workstation Presets & Live Filter Input ---
  const tuiFilterInput = document.getElementById('tui-live-filter');
  const presetBtns = document.querySelectorAll('[data-preset]');

  presetBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      presetBtns.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      tuiFilterText = btn.dataset.preset;
      if (tuiFilterInput) tuiFilterInput.value = tuiFilterText;
      openTuiModal('table');
      renderTuiWorkstation();
    });
  });

  tuiFilterInput?.addEventListener('input', () => {
    tuiFilterText = tuiFilterInput.value;
    openTuiModal('table');
    renderTuiWorkstation();
  });

  // --- Workstation Mode Switcher & Modal Close ---
  document.querySelectorAll('[data-tui-mode]').forEach(el => {
    el.addEventListener('click', () => openTuiModal(el.dataset.tuiMode));
  });

  document.getElementById('tui-modal-close')?.addEventListener('click', () => openTuiModal('table'));

  document.getElementById('tui-btn-pause')?.addEventListener('click', togglePause);
  document.getElementById('tui-btn-close-conn')?.addEventListener('click', closeSelectedConnection);
  document.getElementById('hint-close')?.addEventListener('click', closeSelectedConnection);
  document.getElementById('hint-mark')?.addEventListener('click', () => {
    const sel = liveSockets.find(s => s.id === selectedSocketId);
    if (sel) { sel.marked = !sel.marked; renderTuiWorkstation(); }
  });
  document.getElementById('hint-kill')?.addEventListener('click', () => {
    const sel = liveSockets.find(s => s.id === selectedSocketId);
    if (sel) {
      liveSockets.forEach(s => { if (s.pid === sel.pid) s.change = 'deleted'; });
      showStatusBanner(`TerminateProcess: ended ${sel.process} (PID ${sel.pid})`);
      renderTuiWorkstation();
    }
  });

  const crtBtn = document.getElementById('tui-btn-crt');
  const viewport = document.getElementById('tui-viewport');
  crtBtn?.addEventListener('click', () => {
    viewport.classList.toggle('crt-on');
    crtBtn.textContent = viewport.classList.contains('crt-on') ? 'CRT: ON' : 'CRT: OFF';
  });

  document.getElementById('tui-theme-picker')?.addEventListener('change', (e) => {
    viewport.setAttribute('data-theme', e.target.value);
  });

  // --- Live 1200ms Telemetry Simulation Loop ---
  const topThroughput = document.getElementById('top-live-throughput');
  setInterval(() => {
    if (tuiPaused) return;
    liveSockets.forEach(s => {
      s.age += 1;
      if (s.connected) {
        s.tx += Math.floor(Math.random() * 18400);
        s.rx += Math.floor(Math.random() * 64200);
      }
    });
    txHistory.shift();
    txHistory.push(Math.max(12, Math.min(98, txHistory[txHistory.length - 1] + Math.floor(Math.random() * 34 - 16))));
    rxHistory.shift();
    rxHistory.push(Math.max(18, Math.min(99, rxHistory[rxHistory.length - 1] + Math.floor(Math.random() * 36 - 17))));
    if (topThroughput) {
      const txK = (txHistory[txHistory.length - 1] * 8.4).toFixed(1);
      const rxM = (rxHistory[rxHistory.length - 1] * 0.038).toFixed(2);
      topThroughput.textContent = `TX: ${txK} KiB/s · RX: ${rxM} MiB/s`;
    }
    renderTuiWorkstation();
  }, 1200);

  renderTuiWorkstation();

  // --- Bento Architecture Inspector ---
  const archNodes = document.querySelectorAll('.arch-node');
  const archBox = document.getElementById('arch-inspector-box');
  archNodes.forEach(node => {
    node.addEventListener('click', () => {
      archNodes.forEach(n => n.classList.remove('active'));
      node.classList.add('active');
      archBox.innerHTML = ARCH_DETAILS[node.dataset.arch];
    });
  });

  // --- Bento Snapshot Diff Burst Injector ---
  const diffBtn = document.getElementById('btn-trigger-diff');
  const diffBox = document.getElementById('diff-sim-box');
  diffBtn?.addEventListener('click', () => {
    const randPort = 55200 + Math.floor(Math.random() * 700);
    const procs = ['chrome.exe', 'cargo.exe', 'pwsh.exe', 'git-remote-https.exe'];
    const p = procs[Math.floor(Math.random() * procs.length)];
    diffBox.innerHTML = `
      <div class="diff-line d-new"><span>+ TCP 192.168.1.111:${randPort} → 140.82.121.4:443 (${p})</span><span>RowChange::New (age: 0s)</span></div>
      <div class="diff-line d-chg"><span>~ TCP 192.168.1.111:54720 → 142.250.187.206:443</span><span>Tx +64.2 KiB / Rx +312 KiB</span></div>
      <div class="diff-line d-del"><span>- TCP 192.168.1.111:${randPort - 18} → 104.18.32.47:443</span><span>RowChange::Deleted (FIN_WAIT2)</span></div>
    `;
  });

  // --- Section 03: AST Filter Compiler & Live Table ---
  const astInput = document.getElementById('ast-query-input');
  const astBadge = document.getElementById('ast-status-badge');
  const astRibbon = document.getElementById('ast-token-ribbon');
  const astTbody = document.getElementById('ast-table-body');

  function updateAstCompiler() {
    if (!astInput) return;
    const q = astInput.value;
    let matched = [];
    try {
      matched = INITIAL_SOCKETS.filter(r => evaluateQuery(q, r));
      astBadge.className = 'query-badge ok';
      astBadge.textContent = `${matched.length} / ${INITIAL_SOCKETS.length} MATCHED`;
    } catch (err) {
      astBadge.className = 'query-badge err';
      astBadge.textContent = `PARSE ERR: ${err.message}`;
      return;
    }

    const tokens = tokenizeFilter(q);
    if (tokens.length === 0) {
      astRibbon.innerHTML = `<span style="color: var(--text-muted);">AST_STREAM // EMPTY (MATCHING ALL ENDPOINTS)</span>`;
    } else {
      astRibbon.innerHTML = `<span style="color: var(--text-muted);">AST_TOKENS:</span>` + tokens.map(t => {
        if (t.type === 'AND' || t.type === 'OR' || t.type === 'NOT' || t.type === 'PAREN') {
          return `<span class="ast-op">${t.val}</span>`;
        }
        return `<span class="ast-token">${t.val}</span>`;
      }).join('');
    }

    astTbody.innerHTML = matched.map(r => {
      const diffColor = r.change === 'new' ? 'color: var(--green);'
        : r.change === 'changed' ? 'color: var(--amber);'
        : r.change === 'deleted' ? 'color: var(--crimson); text-decoration: line-through;' : '';
      return `<tr style="${diffColor}">
        <td><strong>${r.process}</strong></td>
        <td>${r.pid}</td>
        <td>${r.proto}</td>
        <td>${r.laddr}:${r.lport}</td>
        <td>${r.raddr}:${r.rport || '*'}</td>
        <td>${r.state || 'UDP'}</td>
        <td>${r.service || '—'}</td>
        <td>${fmtBytes(r.tx)}</td>
        <td>${fmtBytes(r.rx)}</td>
        <td>${r.change.toUpperCase()}</td>
        <td>${r.country}</td>
      </tr>`;
    }).join('');
  }

  astInput?.addEventListener('input', updateAstCompiler);
  document.querySelectorAll('[data-ast-query]').forEach(btn => {
    btn.addEventListener('click', () => {
      astInput.value = btn.dataset.astQuery;
      updateAstCompiler();
    });
  });
  updateAstCompiler();

  // --- Section 04: Interactive Physical Keyboard Deck ---
  const kbKeys = document.querySelectorAll('.kb-key[data-key]');
  const kbCap = document.getElementById('kb-display-cap');
  const kbTitle = document.getElementById('kb-display-title');
  const kbDesc = document.getElementById('kb-display-desc');

  kbKeys.forEach(btn => {
    btn.addEventListener('click', () => {
      kbKeys.forEach(k => k.classList.remove('active'));
      btn.classList.add('active');
      const k = btn.dataset.key;
      const info = KEYDECK_INFO[k];
      if (!info) return;
      kbCap.textContent = k;
      kbTitle.textContent = info.title;
      kbDesc.textContent = info.desc;

      if (info.mode) openTuiModal(info.mode);
      if (info.preset !== undefined) {
        tuiFilterText = info.preset;
        if (tuiFilterInput) tuiFilterInput.value = tuiFilterText;
        openTuiModal('table');
        renderTuiWorkstation();
      }
      if (info.act === 'pause') togglePause();
      if (info.act === 'close') closeSelectedConnection();
    });
  });

  // --- Section 05A: CLI & tcpvcon Output Switcher ---
  const cliBox = document.getElementById('cli-preview-box');
  const cliTabs = document.querySelectorAll('[data-cli-tab]');
  cliTabs.forEach(tab => {
    tab.addEventListener('click', () => {
      cliTabs.forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      cliBox.textContent = CLI_SAMPLES[tab.dataset.cliTab];
    });
  });
  if (cliBox) cliBox.textContent = CLI_SAMPLES.json;

  // --- Section 05B: Live config.toml Synthesizer ---
  const tomlBox = document.getElementById('toml-preview-box');
  const cfgInputs = document.querySelectorAll('.cfg-input');
  const copyTomlBtn = document.getElementById('btn-copy-toml');

  function updateToml() {
    if (!tomlBox) return;
    const interval = document.getElementById('c-interval').value || 1000;
    const theme = document.getElementById('c-theme').value || 'dark';
    const resolve = document.getElementById('c-resolve').checked;
    const estats = document.getElementById('c-estats').checked;
    const etw = document.getElementById('c-etw').checked;
    const bell = document.getElementById('c-bell').checked;

    tomlBox.textContent = `# %APPDATA%\\tcptui\\config.toml
[view]
refresh_interval_ms = ${interval}
resolve_addresses = ${resolve}
show_tcp = true
show_udp = true
show_unconnected = true
show_loopback = true
theme = "${theme}"

[estats]
enabled = ${estats}

[etw]
enabled = ${etw}

[geoip]
enabled = true
path = "GeoLite2-Country.mmdb"

[notifications]
bell = ${bell}

[[alerts]]
expression = "rport=4444 or rport=1337"
enabled = true

[[colors]]
expression = "state=listen"
enabled = true
fg = "cyan"
bold = true`;
  }

  cfgInputs.forEach(el => {
    el.addEventListener('input', updateToml);
    el.addEventListener('change', updateToml);
  });
  updateToml();

  copyTomlBtn?.addEventListener('click', () => {
    navigator.clipboard.writeText(tomlBox.textContent);
    copyTomlBtn.textContent = 'COPIED ✓';
    setTimeout(() => { copyTomlBtn.textContent = 'COPY TOML'; }, 1500);
  });

  // --- Language Switcher (EN / TR) ---
  let lang = 'en';
  const langDict = {
    en: {
      nav_workstation: '01 // LIVE WORKSTATION',
      nav_arch: '02 // ARCHITECTURE',
      nav_filter: '03 // FILTER AST',
      nav_kb: '04 // KEYDECK',
      nav_cli: '05 // CLI & CONFIG',
      hero_coord: 'SYSINTERNALS TCPVIEW // TERMINAL RE-ENGINEERING',
      hero_h1_a: 'Total Socket Visibility.',
      hero_h1_b: 'Zero GUI Overhead.',
      hero_lead: 'Native Rust terminal UI for Windows that enumerates every IPv4 & IPv6 TCP/UDP endpoint in real time. Equipped with extended TCP byte counters (EStats), kernel ETW connection tracing, a 17-field boolean query compiler, Wireshark-style row coloring, Authenticode verification, and instant SetTcpEntry socket termination.',
      bento_title: 'Engineered for Sub-Millisecond Terminal Rendering.',
      bento_sub: 'No Electron. No Tokio async bloat. Classic std::thread + mpsc channels bridge low-level Windows IP Helper & ETW kernel APIs to a deterministic Ratatui frame buffer.',
      filter_title: 'Test the 17-Field Query Compiler Live.',
      kb_title: 'Interactive Keyboard Deck'
    },
    tr: {
      nav_workstation: '01 // CANLI TUI İSTASYONU',
      nav_arch: '02 // SİSTEM MİMARİSİ',
      nav_filter: '03 // FİLTRE MOTORU',
      nav_kb: '04 // KLAVYE KONSOLU',
      nav_cli: '05 // CLI & CONFIG',
      hero_coord: 'SYSINTERNALS TCPVIEW // TERMİNAL YENİDEN MÜHENDİSLİĞİ',
      hero_h1_a: 'Tam Soket Görünürlüğü.',
      hero_h1_b: 'Sıfır GUI Yükü.',
      hero_lead: 'Windows üzerindeki tüm IPv4 ve IPv6 TCP/UDP uç noktalarını gerçek zamanlı izleyen yerel Rust terminal arayüzü. Genişletilmiş TCP bayt sayaçları (EStats), çekirdek düzeyi ETW bağlantı izleme, 17 alanlı boolean sorgu derleyicisi, Wireshark tarzı satır renklendirme, Authenticode imza doğrulaması ve SetTcpEntry ile anında soket sonlandırma.',
      bento_title: 'Milisaniye Altı Terminal Çizimi İçin Tasarlandı.',
      bento_sub: 'Electron yok. Gereksiz async çalışma zamanı yükü yok. Klasik std::thread + mpsc kanalları, düşük seviyeli Windows IP Helper ve ETW çekirdek API’lerini doğrudan Ratatui tamponuna bağlar.',
      filter_title: '17 Alanlı Sorgu Derleyicisini Canlı Test Edin.',
      kb_title: 'Etkileşimli Fiziksel Klavye Konsolu'
    }
  };

  document.getElementById('lang-switch')?.addEventListener('click', () => {
    lang = lang === 'en' ? 'tr' : 'en';
    const d = langDict[lang];
    document.querySelectorAll('[data-i18n]').forEach(el => {
      const k = el.getAttribute('data-i18n');
      if (d[k]) el.textContent = d[k];
    });
  });
});
