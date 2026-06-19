import * as d3 from 'd3';

const API = {
  upload: '/api/upload',
  uploads: '/api/uploads',
  timeRange: '/api/time-range',
  trafficWindow: '/api/traffic/time-window',
  protoDist: '/api/protocol/distribution',
  ipRanking: '/api/ip-pairs/ranking',
  sessionsAt: '/api/sessions/at-time',
  sessionPackets: '/api/sessions',
};

const state = {
  currentUploadId: null,
  minTs: 0,
  maxTs: 0,
  windowSec: 1.0,
  metric: 'bytes',
  rangeStart: 0,
  rangeEnd: 100,
  currentData: null,
  drillTs: null,
};

const PROTOCOL_COLORS = d3.scaleOrdinal(d3.schemeTableau10);

const $ = (id) => document.getElementById(id);

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(2)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(2)} MB`;
  return `${(bytes / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

function formatNumber(n) {
  return n.toLocaleString('en-US');
}

function formatDuration(sec) {
  if (sec < 60) return `${sec.toFixed(2)}s`;
  const m = Math.floor(sec / 60);
  const s = sec - m * 60;
  return `${m}m ${s.toFixed(1)}s`;
}

function getAbsoluteTsRange() {
  const total = state.maxTs - state.minTs;
  const start = state.minTs + (state.rangeStart / 100) * total;
  const end = state.minTs + (state.rangeEnd / 100) * total;
  return { start, end };
}

function updateRangeLabel() {
  const { start, end } = getAbsoluteTsRange();
  const relStart = start - state.minTs;
  const relEnd = end - state.minTs;
  $('rangeLabel').textContent = `${relStart.toFixed(2)}s ~ ${relEnd.toFixed(2)}s`;
}

async function loadUploads() {
  try {
    const res = await fetch(API.uploads);
    const data = await res.json();
    const sel = $('uploadSelect');
    sel.innerHTML = '<option value="">-- 选择数据集 --</option>';
    data.forEach((u) => {
      const opt = document.createElement('option');
      opt.value = u.id;
      opt.textContent = `${u.filename} (${u.packet_count} 包, ${u.status})`;
      sel.appendChild(opt);
    });
    if (state.currentUploadId) {
      sel.value = state.currentUploadId;
    }
  } catch (e) {
    console.error(e);
  }
}

function setStatus(text, progress = null) {
  $('uploadStatus').hidden = false;
  $('statusText').textContent = text;
  if (progress !== null) {
    $('progressBar .progress-fill').style.width = `${progress}%`;
  }
}

function hideStatus() {
  $('uploadStatus').hidden = true;
  $('progressBar .progress-fill').style.width = '0%';
}

async function handleUpload(file) {
  if (!file) return;
  setStatus(`正在上传并解析: ${file.name} ...`, 20);

  const fd = new FormData();
  fd.append('file', file);

  try {
    const res = await fetch(API.upload, { method: 'POST', body: fd });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || '上传失败');
    }
    const data = await res.json();
    setStatus(`✅ 解析完成！共 ${data.packet_count} 个包`, 100);
    setTimeout(() => {
      hideStatus();
      selectUpload(data.upload_id, data.min_timestamp, data.max_timestamp, data.packet_count);
    }, 800);
    loadUploads();
  } catch (e) {
    setStatus(`❌ 错误: ${e.message}`, 0);
  }
}

async function selectUpload(id, minTs, maxTs, pktCount) {
  state.currentUploadId = id;
  $('uploadSelect').value = id;
  $('emptyState').style.display = 'none';
  $('mainContent').hidden = false;

  if (minTs === undefined || maxTs === undefined) {
    try {
      const tr = await fetch(
        `${API.timeRange}?upload_id=${id}`
      ).then((r) => r.json());
      state.minTs = tr.min_timestamp;
      state.maxTs = tr.max_timestamp;
      pktCount = tr.count;
    } catch (e) {
      console.error(e);
    }
  } else {
    state.minTs = minTs;
    state.maxTs = maxTs;
  }

  state.rangeStart = 0;
  state.rangeEnd = 100;
  $('rangeStart').value = 0;
  $('rangeEnd').value = 100;

  $('statPackets').textContent = formatNumber(pktCount);
  $('statDuration').textContent = formatDuration(state.maxTs - state.minTs);

  updateRangeLabel();
  refreshAllCharts();
}

async function refreshAllCharts() {
  const { start, end } = getAbsoluteTsRange();
  setStatus('加载数据中...', 50);

  try {
    const [trafficRes, protoRes, ipRes] = await Promise.all([
      fetch(`${API.trafficWindow}?upload_id=${state.currentUploadId}&start_ts=${start}&end_ts=${end}&window_sec=${state.windowSec}`).then((r) => r.json()),
      fetch(`${API.protoDist}?upload_id=${state.currentUploadId}&start_ts=${start}&end_ts=${end}`).then((r) => r.json()),
      fetch(`${API.ipRanking}?upload_id=${state.currentUploadId}&start_ts=${start}&end_ts=${end}&top_n=15`).then((r) => r.json()),
    ]);

    state.currentData = trafficRes;
    drawStreamgraph(trafficRes);
    drawProtoChart(protoRes);
    drawIpRanking(ipRes);

    $('statProtos').textContent = protoRes.distribution.length;
    $('statBytes').textContent = formatBytes(protoRes.total_bytes);

    hideStatus();
  } catch (e) {
    setStatus(`❌ 加载失败: ${e.message}`, 0);
    console.error(e);
  }
}

function buildStackData(traffic) {
  const { protocols = [], buckets = [] } = traffic;
  const metric = state.metric;
  const suffix = metric === 'bytes' ? '_bytes' : '_packets';

  const keys = protocols.slice();
  const data = buckets.map((b) => {
    const o = { timestamp: b.timestamp, _raw: b };
    keys.forEach((k) => {
      o[k] = b[k + suffix] || 0;
    });
    return o;
  });

  const stack = d3.stack()
    .keys(keys)
    .offset(d3.stackOffsetWiggle)
    .order(d3.stackOrderInsideOut);

  return { layers: stack(data), data, keys };
}

function drawStreamgraph(traffic) {
  const svg = d3.select('#streamgraph');
  svg.selectAll('*').remove();

  const container = svg.node().parentElement;
  const width = container.clientWidth - 4;
  const height = 400;
  const margin = { top: 20, right: 30, bottom: 50, left: 30 };
  const innerW = width - margin.left - margin.right;
  const innerH = height - margin.top - margin.bottom;

  svg.attr('viewBox', `0 0 ${width} ${height}`);

  if (!traffic.buckets || traffic.buckets.length === 0) {
    svg.append('text')
      .attr('x', width / 2)
      .attr('y', height / 2)
      .attr('text-anchor', 'middle')
      .attr('fill', '#94a3b8')
      .text('当前时间范围内无数据');
    return;
  }

  const { layers, data, keys } = buildStackData(traffic);

  const xMin = d3.min(data, (d) => d.timestamp);
  const xMax = d3.max(data, (d) => d.timestamp);
  const x = d3.scaleLinear()
    .domain([xMin, xMax])
    .range([0, innerW]);

  const yMin = d3.min(layers, (l) => d3.min(l, (d) => d[0]));
  const yMax = d3.max(layers, (l) => d3.max(l, (d) => d[1]));
  const y = d3.scaleLinear()
    .domain([yMin, yMax])
    .range([innerH, 0])
    .nice();

  const g = svg.append('g')
    .attr('transform', `translate(${margin.left},${margin.top})`);

  const area = d3.area()
    .x((d) => x(d.data.timestamp))
    .y0((d) => y(d[0]))
    .y1((d) => y(d[1]))
    .curve(d3.curveCatmullRom.alpha(0.5));

  const tooltip = $('tooltip');

  const pathG = g.append('g');

  pathG.selectAll('path')
    .data(layers)
    .join('path')
    .attr('d', area)
    .attr('fill', (d) => PROTOCOL_COLORS(d.key))
    .attr('opacity', 0.85)
    .attr('stroke', '#0f172a')
    .attr('stroke-width', 0.3)
    .style('cursor', 'crosshair')
    .on('mousemove', function (event) {
      const [mx] = d3.pointer(event);
      const ts = x.invert(mx);
      const idx = d3.bisector((d) => d.timestamp).center(data, ts);
      const d = data[idx];
      if (!d) return;

      const proto = d3.select(this).datum().key;
      const val = d[proto] || 0;
      const relT = d.timestamp - state.minTs;

      const protoTotal = state.metric === 'bytes'
        ? formatBytes(val)
        : formatNumber(val);

      const layerIdx = keys.indexOf(proto);
      const layer = layers[layerIdx];
      const yVal = layer[idx];
      const [by] = d3.pointer(event, svg.node());

      let html = `<strong>${proto}</strong><br/>`;
      html += `⏱ 时刻: ${relT.toFixed(3)}s<br/>`;
      html += `📊 ${state.metric === 'bytes' ? '字节数' : '包数'}: <strong>${protoTotal}</strong><br/>`;
      html += `<hr style="border:none;border-top:1px solid #334155;margin:6px 0"/>`;
      html += `<em style="font-size:11px;color:#94a3b8">💡 点击查看该时刻活跃的TCP会话</em>`;

      tooltip.innerHTML = html;
      tooltip.hidden = false;
      const rect = svg.node().getBoundingClientRect();
      const tw = tooltip.offsetWidth;
      const th = tooltip.offsetHeight;
      let lx = event.clientX - rect.left + 15;
      let ly = by - th - 10;
      if (lx + tw > rect.width) lx = event.clientX - rect.left - tw - 15;
      if (ly < 0) ly = by + 15;
      tooltip.style.left = `${lx}px`;
      tooltip.style.top = `${ly}px`;

      d3.select(this).attr('opacity', 1);
    })
    .on('mouseleave', function () {
      tooltip.hidden = true;
      d3.select(this).attr('opacity', 0.85);
    })
    .on('click', function (event) {
      const [mx] = d3.pointer(event);
      const ts = x.invert(mx);
      const idx = d3.bisector((d) => d.timestamp).center(data, ts);
      const clickTs = data[idx] ? data[idx].timestamp : ts;
      openDrill(clickTs);
    });

  const xAxis = d3.axisBottom(x)
    .ticks(8)
    .tickFormat((d) => `${(d - state.minTs).toFixed(1)}s`);
  g.append('g')
    .attr('transform', `translate(0,${innerH})`)
    .call(xAxis)
    .attr('color', '#94a3b8')
    .selectAll('text')
    .attr('fill', '#94a3b8');

  g.append('text')
    .attr('x', innerW / 2)
    .attr('y', innerH + 42)
    .attr('text-anchor', 'middle')
    .attr('fill', '#94a3b8')
    .attr('font-size', '12px')
    .text('相对时间 (s)');

  const legend = g.append('g')
    .attr('transform', `translate(0, -6)`);

  const legendItems = keys.slice(0, 8);
  const itemW = 110;
  legendItems.forEach((k, i) => {
    const lg = legend.append('g')
      .attr('transform', `translate(${i * itemW}, 0)`);
    lg.append('rect')
      .attr('width', 12)
      .attr('height', 12)
      .attr('rx', 2)
      .attr('fill', PROTOCOL_COLORS(k));
    lg.append('text')
      .attr('x', 18)
      .attr('y', 10)
      .attr('fill', '#e2e8f0')
      .attr('font-size', '12px')
      .attr('font-weight', 600)
      .text(k);
  });

  const peakLine = g.append('g').style('pointer-events', 'none');
  g.on('mousemove', function (event) {
    const [mx] = d3.pointer(event, g.node());
    if (mx < 0 || mx > innerW) {
      peakLine.selectAll('*').remove();
      return;
    }
    const ts = x.invert(mx);
    const idx = d3.bisector((d) => d.timestamp).center(data, ts);
    if (!data[idx]) return;
    const lineX = x(data[idx].timestamp);
    peakLine.selectAll('*').remove();
    peakLine.append('line')
      .attr('x1', lineX)
      .attr('y1', 0)
      .attr('x2', lineX)
      .attr('y2', innerH)
      .attr('stroke', '#60a5fa')
      .attr('stroke-width', 1)
      .attr('stroke-dasharray', '4 3')
      .attr('opacity', 0.6);
    peakLine.append('circle')
      .attr('cx', lineX)
      .attr('cy', innerH)
      .attr('r', 4)
      .attr('fill', '#60a5fa');
  }).on('mouseleave', () => peakLine.selectAll('*').remove());
}

function drawProtoChart(proto) {
  const svg = d3.select('#protoChart');
  svg.selectAll('*').remove();
  const width = svg.node().parentElement.clientWidth - 4;
  const height = 320;
  const radius = Math.min(width, height) / 2 - 30;

  svg.attr('viewBox', `0 0 ${width} ${height}`);

  const data = proto.distribution || [];
  if (data.length === 0) {
    svg.append('text')
      .attr('x', width / 2)
      .attr('y', height / 2)
      .attr('text-anchor', 'middle')
      .attr('fill', '#94a3b8')
      .text('无数据');
    return;
  }

  const topData = data.slice(0, 8);
  const otherData = data.slice(8);
  if (otherData.length > 0) {
    topData.push({
      protocol: '其他',
      packet_count: d3.sum(otherData, (d) => d.packet_count),
      total_bytes: d3.sum(otherData, (d) => d.total_bytes),
      packet_percent: d3.sum(otherData, (d) => d.packet_percent),
      bytes_percent: d3.sum(otherData, (d) => d.bytes_percent),
    });
  }

  const g = svg.append('g').attr('transform', `translate(${width / 2},${height / 2})`);

  const pie = d3.pie()
    .sort(null)
    .value((d) => state.metric === 'bytes' ? (d.total_bytes || 0) : d.packet_count);

  const arc = d3.arc()
    .innerRadius(radius * 0.55)
    .outerRadius(radius)
    .padAngle(0.015)
    .cornerRadius(3);

  const arcHover = d3.arc()
    .innerRadius(radius * 0.5)
    .outerRadius(radius + 6)
    .padAngle(0.015)
    .cornerRadius(3);

  const tooltip = $('tooltip');

  const arcs = g.selectAll('path')
    .data(pie(topData))
    .join('path')
    .attr('d', arc)
    .attr('fill', (d) => PROTOCOL_COLORS(d.data.protocol))
    .attr('stroke', '#1e293b')
    .attr('stroke-width', 2)
    .style('cursor', 'pointer')
    .on('mousemove', function (event, d) {
      d3.select(this).transition().duration(120).attr('d', arcHover);
      const by = d.data.total_bytes || 0;
      const pk = d.data.packet_count || 0;
      tooltip.innerHTML = `<strong>${d.data.protocol}</strong><br/>
        📦 包数: ${formatNumber(pk)} (${d.data.packet_percent}%)<br/>
        💾 字节: ${formatBytes(by)} (${d.data.bytes_percent}%)`;
      tooltip.hidden = false;
      const rect = svg.node().getBoundingClientRect();
      let lx = event.clientX - rect.left + 15;
      let ly = event.clientY - rect.top - 10;
      if (lx + tooltip.offsetWidth > rect.width) lx = event.clientX - rect.left - tooltip.offsetWidth - 15;
      tooltip.style.left = `${lx}px`;
      tooltip.style.top = `${ly}px`;
    })
    .on('mouseleave', function () {
      d3.select(this).transition().duration(120).attr('d', arc);
      tooltip.hidden = true;
    });

  const totalPkts = d3.sum(topData, (d) => d.packet_count);
  const totalBytes = d3.sum(topData, (d) => d.total_bytes || 0);
  g.append('text')
    .attr('text-anchor', 'middle')
    .attr('y', -6)
    .attr('fill', '#e2e8f0')
    .attr('font-size', '22px')
    .attr('font-weight', 700)
    .text(formatNumber(totalPkts));
  g.append('text')
    .attr('text-anchor', 'middle')
    .attr('y', 16)
    .attr('fill', '#94a3b8')
    .attr('font-size', '12px')
    .text('包数');
  g.append('text')
    .attr('text-anchor', 'middle')
    .attr('y', 36)
    .attr('fill', '#60a5fa')
    .attr('font-size', '11px')
    .text(formatBytes(totalBytes));

  const legend = svg.append('g').attr('transform', `translate(10, 10)`);
  topData.forEach((d, i) => {
    const row = legend.append('g').attr('transform', `translate(0, ${i * 22})`);
    row.append('rect').attr('width', 12).attr('height', 12).attr('rx', 2).attr('fill', PROTOCOL_COLORS(d.protocol));
    row.append('text')
      .attr('x', 18).attr('y', 10)
      .attr('fill', '#e2e8f0').attr('font-size', '11px')
      .text(`${d.protocol} (${state.metric === 'bytes' ? d.bytes_percent : d.packet_percent}%)`);
  });
}

function drawIpRanking(ip) {
  const list = $('ipRankList');
  list.innerHTML = '';
  const data = ip.ranking || [];
  if (data.length === 0) {
    list.innerHTML = '<div style="color:#94a3b8;text-align:center;padding:20px">无数据</div>';
    return;
  }

  const maxBytes = d3.max(data, (d) => d.total_bytes) || 1;

  data.forEach((d, i) => {
    const item = document.createElement('div');
    item.className = 'rank-item';
    const percent = (d.total_bytes / maxBytes * 100).toFixed(1);
    item.innerHTML = `
      <div class="rank-num">${i + 1}</div>
      <div class="rank-ips">
        <div>${d.src_ip}<span class="arrow">→</span>${d.dst_ip}
          <span class="proto-tag">${d.protocol || '?'}</span>
        </div>
        <div style="margin-top:4px;height:4px;background:#0f172a;border-radius:2px;overflow:hidden">
          <div style="width:${percent}%;height:100%;background:linear-gradient(90deg,#3b82f6,#8b5cf6)"></div>
        </div>
      </div>
      <div class="rank-bytes">
        ${formatBytes(d.total_bytes || 0)}
        <div style="font-size:11px;color:#94a3b8;font-weight:400">${formatNumber(d.packet_count)} 包</div>
      </div>
    `;
    list.appendChild(item);
  });
}

async function openDrill(timestamp) {
  state.drillTs = timestamp;
  $('sessionDrill').hidden = false;
  const relT = timestamp - state.minTs;
  $('drillTimeLabel').textContent = `${relT.toFixed(3)}s`;
  loadDrillSessions();
  $('sessionDrill').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

async function loadDrillSessions() {
  const proto = $('drillProtoFilter').value;
  const tol = parseFloat($('drillTolerance').value) || 1;
  const url = `${API.sessionsAt}?upload_id=${state.currentUploadId}&timestamp=${state.drillTs}&tolerance_sec=${tol}${proto ? `&protocol=${proto}` : ''}`;
  const tbody = $('sessionTableBody');
  tbody.innerHTML = '<tr><td colspan="9" style="text-align:center;padding:20px;color:#94a3b8">加载中...</td></tr>';
  try {
    const res = await fetch(url);
    const data = await res.json();
    renderSessions(data.sessions || []);
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="9" style="text-align:center;padding:20px;color:#ef4444">加载失败: ${e.message}</td></tr>`;
  }
}

function protoTag(proto) {
  const p = (proto || '').toUpperCase();
  if (p === 'TCP') return `<span class="tag-tcp">TCP</span>`;
  if (p === 'UDP') return `<span class="tag-udp">UDP</span>`;
  return `<span class="tag-other">${p || '-'}</span>`;
}

function renderSessions(sessions) {
  const tbody = $('sessionTableBody');
  if (sessions.length === 0) {
    tbody.innerHTML = '<tr><td colspan="9" style="text-align:center;padding:20px;color:#94a3b8">无匹配会话</td></tr>';
    return;
  }
  tbody.innerHTML = sessions.map((s) => {
    const dur = (s.end_time || 0) - (s.start_time || 0);
    return `
      <tr>
        <td class="mono">${s.src_ip || '-'}</td>
        <td class="mono">${s.src_port ?? '-'}</td>
        <td class="mono">${s.dst_ip || '-'}</td>
        <td class="mono">${s.dst_port ?? '-'}</td>
        <td>${protoTag(s.protocol)}</td>
        <td>${formatNumber(s.packet_count)}</td>
        <td>${formatBytes(s.total_bytes || 0)}</td>
        <td class="mono">${dur > 0 ? formatDuration(dur) : '-'}</td>
        <td><button class="detail-btn" data-sid="${encodeURIComponent(s.id)}">详情</button></td>
      </tr>
    `;
  }).join('');

  tbody.querySelectorAll('.detail-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      const sid = decodeURIComponent(btn.dataset.sid);
      openSessionPackets(sid);
    });
  });
}

async function openSessionPackets(sessionId) {
  $('packetDetail').hidden = false;
  $('sessionIdLabel').textContent = sessionId;
  const tbody = $('packetTableBody');
  tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;padding:14px;color:#94a3b8">加载中...</td></tr>';
  try {
    const url = `${API.sessionPackets}/${encodeURIComponent(sessionId)}/packets?upload_id=${state.currentUploadId}&limit=500`;
    const res = await fetch(url);
    const data = await res.json();
    renderPackets(data.packets || [], sessionId);
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;padding:14px;color:#ef4444">加载失败: ${e.message}</td></tr>`;
  }
  $('packetDetail').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function formatFlags(flags) {
  if (!flags) return '-';
  const parts = flags.split(',').filter(Boolean);
  return parts.map((f) => {
    const cls = f === 'SYN' ? 'flags-syn'
      : f === 'ACK' ? 'flags-ack'
      : f === 'FIN' ? 'flags-fin'
      : f === 'RST' ? 'flags-rst'
      : f === 'PSH' ? 'flags-psh' : '';
    return `<span class="${cls}">${f}</span>`;
  }).join(' ');
}

function renderPackets(packets, sessionId) {
  const tbody = $('packetTableBody');
  if (packets.length === 0) {
    tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;padding:14px;color:#94a3b8">无包数据</td></tr>';
    return;
  }
  const baseTs = packets[0]?.timestamp || state.minTs;
  tbody.innerHTML = packets.map((p, i) => {
    const relTs = (p.timestamp - baseTs).toFixed(6);
    return `
      <tr>
        <td class="mono">#${i + 1}</td>
        <td class="mono">+${relTs}s</td>
        <td>${protoTag(p.protocol)}</td>
        <td class="mono">${p.length ?? '-'}</td>
        <td class="mono">${p.payload_size ?? '-'}</td>
        <td>${formatFlags(p.tcp_flags)}</td>
      </tr>
    `;
  }).join('');
}

function bindEvents() {
  $('fileInput').addEventListener('change', (e) => {
    const f = e.target.files?.[0];
    if (f) handleUpload(f);
    e.target.value = '';
  });

  $('uploadSelect').addEventListener('change', (e) => {
    if (e.target.value) {
      selectUpload(parseInt(e.target.value, 10));
    }
  });

  $('windowSelect').addEventListener('change', (e) => {
    state.windowSec = parseFloat(e.target.value);
    refreshAllCharts();
  });

  $('metricSelect').addEventListener('change', (e) => {
    state.metric = e.target.value;
    refreshAllCharts();
  });

  const rangeStart = $('rangeStart');
  const rangeEnd = $('rangeEnd');
  let rangeTimer = null;

  function onRangeChange() {
    let s = parseFloat(rangeStart.value);
    let e = parseFloat(rangeEnd.value);
    if (s > e) [s, e] = [e, s];
    state.rangeStart = s;
    state.rangeEnd = e;
    updateRangeLabel();
    clearTimeout(rangeTimer);
    rangeTimer = setTimeout(() => {
      if (state.currentUploadId) refreshAllCharts();
    }, 120);
  }

  rangeStart.addEventListener('input', onRangeChange);
  rangeEnd.addEventListener('input', onRangeChange);

  $('closeDrill').addEventListener('click', () => {
    $('sessionDrill').hidden = true;
    state.drillTs = null;
    $('packetDetail').hidden = true;
  });

  $('drillProtoFilter').addEventListener('change', loadDrillSessions);
  $('drillTolerance').addEventListener('change', loadDrillSessions);

  $('closePacketDetail').addEventListener('click', () => {
    $('packetDetail').hidden = true;
  });

  window.addEventListener('resize', () => {
    if (state.currentData) drawStreamgraph(state.currentData);
  });
}

document.addEventListener('DOMContentLoaded', async () => {
  bindEvents();
  await loadUploads();
});
