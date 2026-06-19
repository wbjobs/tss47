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
  taskStatus: (id) => `/api/tasks/${id}/status`,
  taskCancel: (id) => `/api/tasks/${id}/cancel`,
  health: '/api/health',
  anomalyIps: '/api/anomaly/ips',
  ipSessions: '/api/ip/sessions',
  filterSchema: '/api/filters/schema',
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
  pollingTaskId: null,
  pollingTimer: null,
  parserInfo: null,
  sigma: 3.0,
  anomalyData: null,
  filters: [],
  filterSchema: null,
  filterCollapsed: false,
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

function encodeFilters(filters) {
  if (!filters || filters.length === 0) return '';
  try {
    return '&filters=' + encodeURIComponent(JSON.stringify(filters));
  } catch (e) {
    return '';
  }
}

function activeFiltersCount() {
  return (state.filters || []).filter(f => f && f.field && f.op && (f.value !== undefined && f.value !== '' && f.value !== null)).length;
}

function updateFilterBadge() {
  const n = activeFiltersCount();
  const badge = $('filterActiveBadge');
  if (badge) {
    if (n > 0) {
      badge.style.display = 'inline-block';
      badge.textContent = `${n} 个条件`;
    } else {
      badge.style.display = 'none';
    }
  }
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

function setStatus(text, progress = null, options = {}) {
  $('uploadStatus').hidden = false;
  const canCancel = options.cancelable;
  const taskId = options.taskId;
  let cancelHtml = '';
  if (canCancel && taskId) {
    cancelHtml = `<button id="cancelParseBtn" class="close-btn" style="margin-left:12px;background:#f59e0b">⏹ 取消解析</button>`;
  }
  $('statusText').innerHTML = text + cancelHtml;
  if (progress !== null) {
    $('progressBar .progress-fill').style.width = `${progress}%`;
    $('progressBar .progress-fill').style.background =
      progress >= 100 ? 'linear-gradient(90deg,#10b981,#34d399)'
      : progress >= 0 ? 'linear-gradient(90deg,#3b82f6,#8b5cf6)'
      : 'linear-gradient(90deg,#ef4444,#dc2626)';
  }
  const btn = $('cancelParseBtn');
  if (btn && taskId) {
    btn.addEventListener('click', () => cancelParseTask(taskId));
  }
}

function hideStatus() {
  stopPolling();
  $('uploadStatus').hidden = true;
  $('progressBar .progress-fill').style.width = '0%';
}

function stopPolling() {
  if (state.pollingTimer) {
    clearTimeout(state.pollingTimer);
    state.pollingTimer = null;
  }
  state.pollingTaskId = null;
}

async function cancelParseTask(taskId) {
  try {
    await fetch(API.taskCancel(taskId), { method: 'POST' });
    stopPolling();
    setStatus('⏹ 解析任务已取消', -1);
    setTimeout(hideStatus, 2000);
  } catch (e) {
    console.error(e);
  }
}

async function pollTaskStatus(taskId) {
  state.pollingTaskId = taskId;
  const POLL_INTERVAL = 800;
  const MAX_POLL_TIME = 3600 * 1000;
  const started = Date.now();

  const loop = async () => {
    if (state.pollingTaskId !== taskId) return;
    if (Date.now() - started > MAX_POLL_TIME) {
      setStatus('⏱ 解析超时', -1);
      return;
    }
    try {
      const res = await fetch(API.taskStatus(taskId));
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const s = await res.json();
      const pct = Math.max(0, Math.min(100, s.progress || 0));
      const msg = s.message || '处理中...';

      if (s.status === 'completed' || pct >= 100) {
        const result = s.result || {};
        const pkt = result.packet_count ?? 0;
        setStatus(`✅ 解析完成！共 ${formatNumber(pkt)} 个包。 ${msg}`, 100);
        stopPolling();
        loadUploads();
        setTimeout(() => {
          hideStatus();
          selectUpload(
            s.upload_id ?? result.upload_id,
            result.min_timestamp,
            result.max_timestamp,
            pkt
          );
        }, 1000);
        return;
      }

      if (s.status === 'failed') {
        stopPolling();
        const errMsg = s.error ? s.error.split('\n')[0] : (msg || '解析失败');
        setStatus(`❌ 解析失败：${errMsg}`, -1);
        return;
      }

      setStatus(`⏳ ${msg}`, pct, { cancelable: true, taskId });
    } catch (e) {
      console.warn('poll error:', e);
    }
    state.pollingTimer = setTimeout(loop, POLL_INTERVAL);
  };
  loop();
}

async function handleUpload(file) {
  if (!file) return;
  stopPolling();

  const fsize = file.size;
  let sizeHint = '';
  if (fsize > 50 * 1024 * 1024) {
    sizeHint = `（${formatBytes(fsize)}，大文件将使用 tshark 流式解析）`;
  }
  setStatus(`📤 正在上传文件: ${file.name} ${sizeHint} ...`, 3);

  const fd = new FormData();
  fd.append('file', file);

  try {
    const res = await fetch(API.upload, { method: 'POST', body: fd });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || '上传失败');
    }
    const data = await res.json();
    const taskId = data.task_id;
    const note = data.note ? `（${data.note}）` : '';
    setStatus(`📥 文件已接收，任务已提交${note}`, 5, { cancelable: true, taskId });
    loadUploads();
    pollTaskStatus(taskId);
  } catch (e) {
    setStatus(`❌ 错误: ${e.message}`, -1);
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

  $('filterPanel').hidden = false;
  initFilterPanel();

  $('statPackets').textContent = formatNumber(pktCount);
  $('statDuration').textContent = formatDuration(state.maxTs - state.minTs);

  updateRangeLabel();
  refreshAllCharts();
}

async function refreshAllCharts() {
  const { start, end } = getAbsoluteTsRange();
  setStatus('加载数据中...', 50);
  const fs = encodeFilters(state.filters);
  const anomalyWin = Math.max(state.windowSec * 5, 2.0);

  try {
    const urls = [
      `${API.trafficWindow}?upload_id=${state.currentUploadId}&start_ts=${start}&end_ts=${end}&window_sec=${state.windowSec}${fs}`,
      `${API.protoDist}?upload_id=${state.currentUploadId}&start_ts=${start}&end_ts=${end}${fs}`,
      `${API.ipRanking}?upload_id=${state.currentUploadId}&start_ts=${start}&end_ts=${end}&top_n=15${fs}`,
      `${API.anomalyIps}?upload_id=${state.currentUploadId}&start_ts=${start}&end_ts=${end}&window_sec=${anomalyWin}&sigma=${state.sigma}${fs}`,
    ];
    const [trafficRes, protoRes, ipRes, anomalyRes] = await Promise.all(urls.map(u => fetch(u).then(r => r.json())));

    state.currentData = trafficRes;
    state.anomalyData = anomalyRes;

    drawStreamgraph(trafficRes, anomalyRes);
    drawProtoChart(protoRes);
    drawIpRanking(ipRes);

    const cnt = (anomalyRes.anomalies || []).length;
    $('anomalyCount').textContent = cnt;
    $('anomalyBadge').style.display = cnt > 0 ? 'inline-block' : 'none';

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

function drawStreamgraph(traffic, anomalyData = null) {
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

  // ===== 异常点红点层 =====
  if (anomalyData && anomalyData.anomalies && anomalyData.anomalies.length > 0) {
    const anomG = g.append('g').attr('class', 'anomaly-layer');
    const anoms = anomalyData.anomalies;
    const maxSigma = d3.max(anoms, d => d.sigma_over) || 3;
    const sizeScale = d3.scaleSqrt().domain([3, maxSigma]).range([5, 14]).clamp(true);

    const tooltip = $('tooltip');

    anomG.selectAll('.anomaly-dot')
      .data(anoms)
      .join('circle')
      .attr('class', (_, i) => `anomaly-dot ${i % 3 === 0 ? 'pulse' : ''}`)
      .attr('cx', d => {
        const cx = x(d.window_mid);
        return Math.max(4, Math.min(innerW - 4, cx));
      })
      .attr('cy', innerH / 2 + Math.sin(anoms.indexOf(d)) * 30)
      .attr('r', d => sizeScale(d.sigma_over))
      .attr('fill', d => {
        if (d.direction === 'uplink') return '#f97316';
        return '#ef4444';
      })
      .attr('stroke', '#fef2f2')
      .attr('stroke-width', 1.5)
      .attr('opacity', 0.9)
      .on('mousemove', function (event, d) {
        const relT = d.window_mid - state.minTs;
        const html = `
          <strong style="color:#fca5a5">🚨 IP 流量异常突增</strong><br/>
          <span style="font-size:11px;color:#94a3b8">${d.direction === 'uplink' ? '上行' : '下行'} · ${d.sigma_over.toFixed(1)}σ 超阈值</span>
          <hr style="border:none;border-top:1px solid #334155;margin:6px 0"/>
          <strong style="font-family:monospace">${d.ip}</strong><br/>
          ⏱ 窗口: ${relT.toFixed(2)}s ±${(anomalyData.window_sec / 2).toFixed(1)}s<br/>
          📈 实际: <strong>${formatBytes(d.bytes)}</strong><br/>
          基线 μ: ${formatBytes(Math.round(d.mean))}<br/>
          阈值 μ+${anomalyData.sigma}σ: ${formatBytes(Math.round(d.threshold))}<br/>
          超过均值: <strong style="color:#fbbf24">${d.ratio_vs_mean ? d.ratio_vs_mean.toFixed(1) + '×' : '-'}</strong>
          <hr style="border:none;border-top:1px solid #334155;margin:6px 0"/>
          <em style="font-size:11px;color:#94a3b8">💡 点击查看该IP的会话详情</em>
        `;
        tooltip.innerHTML = html;
        tooltip.hidden = false;
        const rect = svg.node().getBoundingClientRect();
        const [_, by] = d3.pointer(event, svg.node());
        let lx = event.clientX - rect.left + 15;
        let ly = by - 10;
        if (lx + tooltip.offsetWidth > rect.width) lx = event.clientX - rect.left - tooltip.offsetWidth - 15;
        if (ly < 0) ly = by + 15;
        tooltip.style.left = `${lx}px`;
        tooltip.style.top = `${ly}px`;
        d3.select(this).attr('opacity', 1).attr('stroke-width', 3);
      })
      .on('mouseleave', function () {
        tooltip.hidden = true;
        d3.select(this).attr('opacity', 0.9).attr('stroke-width', 1.5);
      })
      .on('click', function (event, d) {
        event.stopPropagation();
        openIpAnomalyDrill(d, anomalyData.sigma);
      });
  }
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
  const fs = encodeFilters(state.filters);
  const url = `${API.sessionsAt}?upload_id=${state.currentUploadId}&timestamp=${state.drillTs}&tolerance_sec=${tol}${proto ? `&protocol=${proto}` : ''}${fs}`;
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

// ============================================================
//  过滤面板
// ============================================================

async function loadFilterSchema() {
  if (state.filterSchema) return state.filterSchema;
  try {
    const res = await fetch(API.filterSchema);
    if (!res.ok) return null;
    state.filterSchema = await res.json();
    return state.filterSchema;
  } catch (e) {
    console.warn('加载过滤schema失败', e);
    return null;
  }
}

async function initFilterPanel() {
  updateFilterBadge();
  if (state.filterSchema) {
    renderFilterRows();
    return;
  }
  const schema = await loadFilterSchema();
  if (!schema) return;
  renderFilterRows();
}

function renderFilterRows() {
  const rowsContainer = $('filterRows');
  const template = $('filterRowTemplate');
  const schema = state.filterSchema;
  if (!schema || !rowsContainer || !template) return;

  if (state.filters.length === 0) {
    // 空的，加一个默认行
    state.filters.push({ field: 'protocol', op: '==', value: '' });
  }

  rowsContainer.innerHTML = '';
  state.filters.forEach((filter, index) => {
    const rowEl = template.content.firstElementChild.cloneNode(true);

    const fieldSel = rowEl.querySelector('.f-field');
    const opSel = rowEl.querySelector('.f-op');
    const valueInput = rowEl.querySelector('.f-value');
    const removeBtn = rowEl.querySelector('.f-remove');

    schema.packet_fields.forEach(f => {
      const opt = document.createElement('option');
      opt.value = f.field;
      opt.textContent = `${f.label} (${f.type})`;
      opt.dataset.type = f.type;
      fieldSel.appendChild(opt);
    });

    const refreshOps = () => {
      const selectedField = fieldSel.value;
      const fieldDef = schema.packet_fields.find(f => f.field === selectedField);
      const fieldType = fieldDef?.type || 'string';
      opSel.innerHTML = '';
      schema.ops.forEach(op => {
        if (!op.types.includes(fieldType)) return;
        const opt = document.createElement('option');
        opt.value = op.op;
        opt.textContent = op.label;
        opSel.appendChild(opt);
      });
      if (state.filters[index]) state.filters[index].field = selectedField;
      if (!opSel.querySelector(`[value="${state.filters[index]?.op}"]`)) {
        state.filters[index].op = opSel.value;
      } else {
        opSel.value = state.filters[index].op;
      }
    };

    fieldSel.value = filter.field || 'protocol';
    refreshOps();
    opSel.value = filter.op || '==';
    valueInput.value = filter.value || '';

    fieldSel.addEventListener('change', refreshOps);
    fieldSel.addEventListener('change', () => {
      state.filters[index] = state.filters[index] || {};
      state.filters[index].field = fieldSel.value;
      state.filters[index].op = opSel.value;
    });
    opSel.addEventListener('change', () => {
      state.filters[index] = state.filters[index] || {};
      state.filters[index].op = opSel.value;
    });
    valueInput.addEventListener('input', () => {
      state.filters[index] = state.filters[index] || {};
      state.filters[index].value = valueInput.value;
    });

    removeBtn.addEventListener('click', () => {
      state.filters.splice(index, 1);
      renderFilterRows();
      updateFilterBadge();
    });

    rowsContainer.appendChild(rowEl);
  });
  updateFilterBadge();
}

function addFilterRow() {
  state.filters.push({ field: 'protocol', op: '==', value: '' });
  renderFilterRows();
  updateFilterBadge();
}

function clearFilters() {
  state.filters = [];
  renderFilterRows();
  updateFilterBadge();
}

function applyFilters() {
  // 只保留有效条件
  state.filters = state.filters.filter(f =>
    f && f.field && f.op && (f.value !== undefined && f.value !== '' && f.value !== null)
  );
  renderFilterRows();
  updateFilterBadge();
  if (state.currentUploadId) refreshAllCharts();
}

function toggleFilterPanel() {
  state.filterCollapsed = !state.filterCollapsed;
  const panel = $('filterPanel');
  const btn = $('toggleFilterPanel');
  if (state.filterCollapsed) {
    panel.classList.add('collapsed');
    if (btn) btn.textContent = '展开';
  } else {
    panel.classList.remove('collapsed');
    if (btn) btn.textContent = '折叠';
  }
}

// ============================================================
//  IP 异常点下钻
// ============================================================

async function openIpAnomalyDrill(anomaly, sigma) {
  const drill = $('ipAnomalyDrill');
  drill.hidden = false;

  $('anomIp').textContent = anomaly.ip;
  $('anomDir').textContent = anomaly.direction === 'uplink' ? '⬆ 上行（该IP发出）' : '⬇ 下行（该IP接收）';
  const summary = $('anomSummary');
  summary.innerHTML = '';
  const cards = [
    { cls: 'danger', label: '异常窗口实际流量', value: formatBytes(anomaly.bytes), sub: `${anomaly.sigma_over.toFixed(1)}σ 超阈值` },
    { cls: 'info', label: `基线均值 μ (N=${anomaly.n_windows || '-'})`, value: formatBytes(Math.round(anomaly.mean)), sub: `σ=${formatBytes(Math.round(anomaly.std || 0))}` },
    { cls: 'warn', label: `触发阈值 μ+${sigma}σ`, value: formatBytes(Math.round(anomaly.threshold)), sub: `超过均值 ${anomaly.ratio_vs_mean ? anomaly.ratio_vs_mean.toFixed(1) + '×' : '-'}` },
    { cls: 'success', label: '发生时刻', value: `${(anomaly.window_mid - state.minTs).toFixed(2)}s`, sub: `窗口 ${formatDuration(anomaly.window_end - anomaly.window_start)}` },
  ];
  cards.forEach(c => {
    const d = document.createElement('div');
    d.className = `anom-stats ${c.cls}`;
    d.innerHTML = `
      <div class="as-label">${c.label}</div>
      <div class="as-value">${c.value}</div>
      <div class="as-sub">${c.sub}</div>
    `;
    summary.appendChild(d);
  });

  // 获取该方向的会话
  const fs = encodeFilters(state.filters);
  const direction = anomaly.direction === 'uplink' ? 'as_src' : 'as_dst';
  const url = `${API.ipSessions}?upload_id=${state.currentUploadId}&ip=${encodeURIComponent(anomaly.ip)}&direction=${direction}&start_ts=${anomaly.window_start}&end_ts=${anomaly.window_end}&limit=100${fs}`;

  const tbody = $('ipSessionBody');
  tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;padding:20px;color:#94a3b8">加载会话中...</td></tr>';

  try {
    const res = await fetch(url);
    const data = await res.json();
    renderIpSessions(anomaly, data);
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="8" style="text-align:center;padding:20px;color:#ef4444">加载失败: ${e.message}</td></tr>`;
  }

  drill.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function renderIpSessions(anomaly, data) {
  const tbody = $('ipSessionBody');
  const sessions = data.sessions || [];
  const ip = anomaly.ip;
  if (sessions.length === 0) {
    tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;padding:20px;color:#94a3b8">在此时间窗口内未找到匹配会话（已被过滤器排除？）</td></tr>';
    return;
  }
  tbody.innerHTML = sessions.map(s => {
    const isSentByIp = s.src_ip === ip;
    const peerIp = isSentByIp ? s.dst_ip : s.src_ip;
    const peerPort = isSentByIp ? s.dst_port : s.src_port;
    const dirCls = isSentByIp ? 'dir-up' : 'dir-down';
    const dirSymbol = isSentByIp ? '⬆ 上行' : '⬇ 下行';
    const sb = s.sent_bytes !== undefined ? s.sent_bytes : (s.src_ip === ip ? s.total_bytes : 0);
    const rb = s.recv_bytes !== undefined ? s.recv_bytes : (s.dst_ip === ip ? s.total_bytes : 0);
    return `
      <tr>
        <td><span class="${dirCls}">${dirSymbol}</span></td>
        <td class="mono">${peerIp || '-'}</td>
        <td class="mono">${peerPort ?? '-'}</td>
        <td>${protoTag(s.protocol)}</td>
        <td class="mono" style="color:#f59e0b">${formatBytes(sb || 0)}</td>
        <td class="mono" style="color:#3b82f6">${formatBytes(rb || 0)}</td>
        <td>${formatNumber(s.packet_count)}</td>
        <td><button class="detail-btn" data-sid="${encodeURIComponent(s.id)}">详情</button></td>
      </tr>
    `;
  }).join('');
  tbody.querySelectorAll('.detail-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const sid = decodeURIComponent(btn.dataset.sid);
      openSessionPackets(sid);
      $('packetDetail').hidden = false;
    });
  });
}

// ============================================================
//  Sigma 阈值切换
// ============================================================

function onSigmaChange() {
  state.sigma = parseFloat($('sigmaSelect').value) || 3;
  if (state.currentUploadId) refreshAllCharts();
}

// ============================================================

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
    if (state.currentData) drawStreamgraph(state.currentData, state.anomalyData);
  });

  window.addEventListener('beforeunload', stopPolling);
  document.addEventListener('visibilitychange', () => {
    if (document.hidden && state.pollingTimer) {
      clearTimeout(state.pollingTimer);
      state.pollingTimer = null;
    } else if (!document.hidden && state.pollingTaskId) {
      pollTaskStatus(state.pollingTaskId);
    }
  });

  // sigma 阈值
  $('sigmaSelect').addEventListener('change', onSigmaChange);

  // 过滤面板
  $('addFilterBtn').addEventListener('click', addFilterRow);
  $('clearFilterBtn').addEventListener('click', clearFilters);
  $('applyFilterBtn').addEventListener('click', applyFilters);
  $('toggleFilterPanel').addEventListener('click', toggleFilterPanel);

  // IP 下钻关闭
  $('closeIpDrill').addEventListener('click', () => {
    $('ipAnomalyDrill').hidden = true;
  });
}

async function showParserInfo() {
  try {
    const res = await fetch(API.health);
    if (!res.ok) return;
    const info = await res.json();
    state.parserInfo = info;
    const p = info.parsers || {};
    const q = info.queue || {};
    const badges = [];
    badges.push(`<span style="padding:2px 8px;border-radius:4px;background:${p.tshark?.available ? '#10b98133;color:#34d399' : '#ef444433;color:#f87171'};font-size:11px">tshark ${p.tshark?.available ? '✓' : '✗'}</span>`);
    badges.push(`<span style="padding:2px 8px;border-radius:4px;background:${p.scapy?.available ? '#10b98133;color:#34d399' : '#ef444433;color:#f87171'};font-size:11px">scapy ${p.scapy?.available ? '✓' : '✗'}</span>`);
    badges.push(`<span style="padding:2px 8px;border-radius:4px;background:${p.pandas?.available ? '#10b98133;color:#34d399' : '#f59e0b33;color:#fbbf24'};font-size:11px">pandas ${p.pandas?.available ? '✓' : '✗'}</span>`);
    badges.push(`<span style="padding:2px 8px;border-radius:4px;background:${q.rq_available ? '#10b98133;color:#34d399' : '#f59e0b33;color:#fbbf24'};font-size:11px">RQ队列 ${q.rq_available ? '✓' : '回退线程'}</span>`);
    const header = document.querySelector('.app-header h1');
    if (header) {
      const wrap = document.createElement('div');
      wrap.style.cssText = 'display:flex;gap:6px;align-items:center;margin-top:6px';
      wrap.innerHTML = badges.join('');
      header.parentNode.style.flexDirection = 'column';
      header.parentNode.style.alignItems = 'flex-start';
      header.parentNode.insertBefore(wrap, header.nextSibling);
    }
  } catch (e) {
    // ignore
  }
}

document.addEventListener('DOMContentLoaded', async () => {
  bindEvents();
  await Promise.all([loadUploads(), showParserInfo()]);
});
