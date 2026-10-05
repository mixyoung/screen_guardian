function debug(msg) {
  console.log('[SG]', msg);
}

window.onerror = function(msg, url, line, col, error) {
  debug('JS 错误: ' + msg + ' 位置: ' + url + ':' + line + ':' + col);
  if (error) debug('  堆栈: ' + error.stack);
};

// Tauri v2 IPC
async function invoke(cmd, args) {
  if (!window.__TAURI_INTERNALS__ || typeof window.__TAURI_INTERNALS__.invoke !== 'function') {
    throw new Error('Tauri IPC 不可用');
  }
  return window.__TAURI_INTERNALS__.invoke(cmd, args || {});
}

// --- Navigation ---
const navItems = document.querySelectorAll('.nav-item');
const pages = document.querySelectorAll('.page');

navItems.forEach(item => {
  item.addEventListener('click', () => {
    const page = item.dataset.page;
    navItems.forEach(n => n.classList.remove('active'));
    pages.forEach(p => p.classList.remove('active'));
    item.classList.add('active');
    document.getElementById('page-' + page).classList.add('active');

    if (page === 'windows') loadWindows();
    if (page === 'rules') loadRules();
    if (page === 'audit') loadAuditPage();
    if (page === 'threats') loadThreatsPage();
    if (page === 'logs') loadLogs();
    if (page === 'settings') loadConfig();
    if (page === 'license') loadLicensePage();
  });
});

// --- Toast ---
function showToast(msg, type) {
  type = type || '';
  var toast = document.getElementById('toast');
  toast.textContent = msg;
  toast.className = 'toast ' + type;
  setTimeout(function() { toast.className = 'toast hidden'; }, 3000);
}

// --- Windows Page ---
async function loadWindows() {
  try {
    var windows = await invoke('list_windows');
    var tbody = document.getElementById('windows-body');
    var search = document.getElementById('window-search').value.toLowerCase();

    var filtered = windows.filter(function(w) {
      return !search ||
        w.app_name.toLowerCase().indexOf(search) !== -1 ||
        w.title.toLowerCase().indexOf(search) !== -1;
    });

    var auditedMap = getAuditedMap();
    var html = '';
    for (var i = 0; i < filtered.length; i++) {
      var w = filtered[i];
      var appName = w.app_name;
      var isSelf = appName.toLowerCase().indexOf('screen-guardian') !== -1 ||
                   appName.toLowerCase().indexOf('screen_guardian') !== -1;
      var nameHtml = escapeHtml(appName);
      if (isSelf) {
        nameHtml += ' <span title="本程序进程，受自身保护" style="cursor:help;color:#D97706"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg></span>';
      }
      var key = appName + ':' + w.pid;
      var audited = auditedMap[key] !== false;
      var wType = w.window_type || '桌面应用';
      var typeClass = '';
      if (wType === '系统进程' || wType === '系统窗口' || wType === '系统组件') {
        typeClass = 'type-system';
      } else if (wType === 'UWP应用') {
        typeClass = 'type-uwp';
      } else {
        typeClass = 'type-desktop';
      }
      html += '<tr>' +
        '<td>' + w.index + '</td>' +
        '<td>' + nameHtml + '</td>' +
        '<td>' + w.pid + '</td>' +
        '<td>' + escapeHtml(w.title) + '</td>' +
        '<td><span class="type-badge ' + typeClass + '">' + escapeHtml(wType) + '</span></td>' +
        '<td><label class="toggle-sm" title="' + (audited ? '审计中，点击停止' : '已停止审计，点击恢复') + '">' +
        '<input type="checkbox" ' + (audited ? 'checked' : '') + ' ' +
        'onchange="toggleAudit(\'' + escapeAttr(appName) + '\', ' + w.pid + ', this.checked)">' +
        '<span class="toggle-slider-sm"></span></label></td>' +
        '<td><span class="badge ' + (w.is_protected ? 'badge-protected' : 'badge-unprotected') + '" ' +
        'style="cursor:pointer" ' +
        'onclick="toggleProtection(' + w.hwnd + ', ' + w.pid + ', ' + (w.is_protected ? 'true' : 'false') + ', this)">' +
        (w.is_protected ? '不显示' : '显示') +
        '</span></td></tr>';
    }
    tbody.innerHTML = html;
  } catch (e) {
    showToast('加载窗口列表失败: ' + String(e), 'error');
  }
}

async function toggleProtection(hwnd, pid, currentlyProtected, el) {
  // 确保 currentlyProtected 是布尔值
  currentlyProtected = currentlyProtected === true || currentlyProtected === 'true';
  
  var row = el ? el.closest('tr') : null;
  var appName = row ? row.cells[1].textContent.trim() : '未知';
  var title = row ? row.cells[3].textContent.trim() : '';

  try {
    // Optimistic UI update
    if (el) {
      el.className = 'badge ' + (!currentlyProtected ? 'badge-protected' : 'badge-unprotected');
      el.textContent = !currentlyProtected ? '不显示' : '显示';
    }
    await invoke('set_protection', { hwnd: hwnd, pid: pid, protect: !currentlyProtected });
    showToast(currentlyProtected ? '已移除保护' : '已启用保护', 'success');

    // Record history
    addHistoryEntry({
      time: new Date().toLocaleString('zh-CN'),
      app_name: appName,
      pid: pid,
      title: title,
      change: currentlyProtected ? '保护→未保护' : '未保护→保护',
      source: '手动'
    });

    loadWindows();
  } catch (e) {
    var msg = String(e);
    // Revert optimistic update
    if (el) {
      el.className = 'badge ' + (currentlyProtected ? 'badge-protected' : 'badge-unprotected');
      el.textContent = currentlyProtected ? '不显示' : '显示';
    }
    if (msg.indexOf('Win32 error 8') !== -1 || msg.indexOf('error 8') !== -1) {
      showToast('此窗口不支持截屏保护（系统/UWP进程或特殊窗口类型不支持此API）', 'error');
    } else if (msg.indexOf('Access Denied') !== -1 || msg.indexOf('error 5') !== -1) {
      showToast('权限不足，无法保护此窗口（需要管理员权限）', 'error');
    } else if (msg.indexOf('error 6') !== -1) {
      showToast('无效的窗口句柄，窗口可能已关闭', 'error');
    } else if (msg.indexOf('error 1400') !== -1) {
      showToast('无效的窗口句柄', 'error');
    } else {
      showToast('操作失败: ' + msg, 'error');
    }
  }
}

document.getElementById('btn-refresh-windows').addEventListener('click', loadWindows);
document.getElementById('window-search').addEventListener('input', loadWindows);

// --- Auto Refresh ---
var autoRefreshTimer = null;

function startAutoRefresh() {
  stopAutoRefresh();
  var interval = parseInt(document.getElementById('auto-refresh-interval').value) || 5000;
  autoRefreshTimer = setInterval(function() {
    var activePage = document.querySelector('.page.active');
    if (activePage && activePage.id === 'page-windows') {
      loadWindows();
    }
  }, interval);
  debug('自动刷新已启动，间隔: ' + interval + 'ms');
}

function stopAutoRefresh() {
  if (autoRefreshTimer) {
    clearInterval(autoRefreshTimer);
    autoRefreshTimer = null;
    debug('自动刷新已停止');
  }
}

document.getElementById('auto-refresh-toggle').addEventListener('change', function(e) {
  if (e.target.checked) {
    startAutoRefresh();
    localStorage.setItem('sg_auto_refresh', '1');
  } else {
    stopAutoRefresh();
    localStorage.setItem('sg_auto_refresh', '0');
  }
});

document.getElementById('auto-refresh-interval').addEventListener('change', function() {
  localStorage.setItem('sg_auto_refresh_interval', this.value);
  if (document.getElementById('auto-refresh-toggle').checked) {
    startAutoRefresh();
  }
});

// Restore auto refresh state
(function() {
  var enabled = localStorage.getItem('sg_auto_refresh') === '1';
  var interval = localStorage.getItem('sg_auto_refresh_interval') || '5000';
  document.getElementById('auto-refresh-toggle').checked = enabled;
  document.getElementById('auto-refresh-interval').value = interval;
  if (enabled) startAutoRefresh();
})();

// --- Rules Page ---
var selectedGroupId = null;

async function loadRules() {
  try {
    // Load groups
    var groups = await invoke('list_groups');
    var groupsList = document.getElementById('groups-list');

    if (groups.length === 0) {
      groupsList.innerHTML = '<li class="groups-empty">暂无规则组，请点击"新建规则组"</li>';
      document.getElementById('rules-body').innerHTML = '<tr><td colspan="7" style="text-align:center;color:var(--color-text-muted);padding:32px">请先创建规则组</td></tr>';
      return;
    }

    // If no group selected, select the first one
    if (!selectedGroupId || !groups.find(function(g) { return g.id === selectedGroupId; })) {
      selectedGroupId = groups[0].id;
    }

    // Render groups list
    var html = '';
    for (var i = 0; i < groups.length; i++) {
      var g = groups[i];
      var isActive = g.id === selectedGroupId;
      html += '<li class="group-item' + (isActive ? ' active' : '') + '" onclick="selectGroup(\'' + g.id + '\')">' +
        '<div class="group-item-info">' +
        '<span class="group-item-name">' + escapeHtml(g.name) + '</span>' +
        '<span class="group-item-desc">' + escapeHtml(g.description || '无描述') + '</span>' +
        '</div>' +
        '<div class="group-item-actions">' +
        '<button class="btn-icon" onclick="event.stopPropagation(); toggleGroup(\'' + g.id + '\', ' + !g.enabled + ')" title="' + (g.enabled ? '禁用组' : '启用组') + '">' +
        '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">' +
        (g.enabled
          ? '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>'
          : '<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/>'
        ) +
        '</svg></button>' +
        '<button class="btn-icon danger" onclick="event.stopPropagation(); removeGroup(\'' + g.id + '\')" title="删除组">' +
        '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">' +
        '<polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>' +
        '</svg></button>' +
        '</div>' +
        '</li>';
    }
    groupsList.innerHTML = html;

    // Load rules for selected group
    await loadRulesForGroup(selectedGroupId);
  } catch (e) {
    showToast('加载规则失败: ' + String(e), 'error');
  }
}

async function loadRulesForGroup(groupId) {
  try {
    var rules = await invoke('list_rules_by_group', { groupId: groupId });
    var tbody = document.getElementById('rules-body');

    // Update header
    var groups = await invoke('list_groups');
    var group = groups.find(function(g) { return g.id === groupId; });
    document.getElementById('selected-group-name').textContent = group ? group.name : '未知组';
    document.getElementById('selected-group-count').textContent = rules.length + ' 条规则';

    if (rules.length === 0) {
      tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:var(--color-text-muted);padding:32px">此规则组暂无规则，点击"添加规则"创建</td></tr>';
      return;
    }

    var html = '';
    for (var i = 0; i < rules.length; i++) {
      var r = rules[i];
      html += '<tr>' +
        '<td>' + (i + 1) + '</td>' +
        '<td>' + escapeHtml(r.name) + '</td>' +
        '<td><code>' + escapeHtml(r.process_pattern) + '</code></td>' +
        '<td>' + (r.protect ? '<span class="badge badge-protected">是</span>' : '<span class="badge badge-unprotected">否</span>') + '</td>' +
        '<td>' + (r.enabled ? '<span class="badge badge-enabled">开启</span>' : '<span class="badge badge-disabled">关闭</span>') + '</td>' +
        '<td>' + r.priority + '</td>' +
        '<td>' +
        '<button class="btn-icon" onclick="toggleRule(\'' + r.id + '\', ' + !r.enabled + ')" title="' + (r.enabled ? '禁用' : '启用') + '">' +
        '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">' +
        (r.enabled
          ? '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>'
          : '<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/>'
        ) +
        '</svg></button>' +
        '<button class="btn-icon danger" onclick="removeRule(\'' + r.id + '\')" title="删除">' +
        '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">' +
        '<polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>' +
        '</svg></button>' +
        '</td></tr>';
    }
    tbody.innerHTML = html;
  } catch (e) {
    showToast('加载规则失败: ' + String(e), 'error');
  }
}

function selectGroup(groupId) {
  selectedGroupId = groupId;
  loadRules();
}

async function toggleGroup(id, enabled) {
  try {
    await invoke('toggle_group', { id: id, enabled: enabled });
    showToast(enabled ? '规则组已启用' : '规则组已禁用', 'success');
    loadRules();
  } catch (e) {
    showToast('操作失败: ' + String(e), 'error');
  }
}

async function removeGroup(id) {
  if (!confirm('确定要删除此规则组吗？组内所有规则将被删除。')) return;
  try {
    await invoke('remove_group', { id: id });
    showToast('规则组已删除', 'success');
    selectedGroupId = null;
    loadRules();
  } catch (e) {
    showToast('删除失败: ' + String(e), 'error');
  }
}

async function toggleRule(id, enabled) {
  try {
    await invoke('toggle_rule', { id: id, enabled: enabled });
    showToast(enabled ? '规则已启用' : '规则已禁用', 'success');
    loadRulesForGroup(selectedGroupId);
  } catch (e) {
    showToast('操作失败: ' + String(e), 'error');
  }
}

async function removeRule(id) {
  if (!confirm('确定要删除此规则吗？')) return;
  try {
    await invoke('remove_rule', { id: id });
    showToast('规则已删除', 'success');
    loadRulesForGroup(selectedGroupId);
  } catch (e) {
    showToast('删除失败: ' + String(e), 'error');
  }
}

// Add Group Modal
var groupModal = document.getElementById('group-modal');

document.getElementById('btn-add-group').addEventListener('click', function() {
  groupModal.classList.remove('hidden');
});

document.getElementById('btn-cancel-group').addEventListener('click', function() {
  groupModal.classList.add('hidden');
});

document.getElementById('btn-save-group').addEventListener('click', async function() {
  var name = document.getElementById('group-name').value.trim();
  var desc = document.getElementById('group-desc').value.trim();

  if (!name) {
    showToast('组名称不能为空', 'error');
    return;
  }

  try {
    var id = Date.now().toString(16);
    await invoke('add_group', { group: { id: id, name: name, description: desc, enabled: true } });
    groupModal.classList.add('hidden');
    document.getElementById('group-name').value = '';
    document.getElementById('group-desc').value = '';
    showToast('规则组已创建', 'success');
    selectedGroupId = id;
    loadRules();
  } catch (e) {
    showToast('创建失败: ' + String(e), 'error');
  }
});

// Add Rule Modal
var ruleModal = document.getElementById('rule-modal');

document.getElementById('btn-add-rule').addEventListener('click', function() {
  if (!selectedGroupId) {
    showToast('请先选择或创建一个规则组', 'error');
    return;
  }
  ruleModal.classList.remove('hidden');
});

document.getElementById('btn-cancel-rule').addEventListener('click', function() {
  ruleModal.classList.add('hidden');
});

document.getElementById('btn-save-rule').addEventListener('click', async function() {
  var name = document.getElementById('rule-name').value.trim();
  var pattern = document.getElementById('rule-pattern').value.trim();
  var protect = document.getElementById('rule-protect').value === 'true';
  var priority = parseInt(document.getElementById('rule-priority').value) || 100;

  if (!name || !pattern) {
    showToast('名称和匹配模式不能为空', 'error');
    return;
  }

  if (!selectedGroupId) {
    showToast('请先选择一个规则组', 'error');
    return;
  }

  try {
    var id = Date.now().toString(16);
    await invoke('add_rule', { rule: { id: id, group_id: selectedGroupId, name: name, process_pattern: pattern, protect: protect, enabled: true, priority: priority } });
    ruleModal.classList.add('hidden');
    showToast('规则已添加', 'success');
    loadRulesForGroup(selectedGroupId);
  } catch (e) {
    showToast('添加失败: ' + String(e), 'error');
  }
});

// --- Audit History (localStorage) ---
function getHistory() {
  try {
    return JSON.parse(localStorage.getItem('sg_history') || '[]');
  } catch (e) { return []; }
}

function addHistoryEntry(entry) {
  var history = getHistory();
  history.unshift(entry);
  // Keep last 500 entries
  if (history.length > 500) history = history.slice(0, 500);
  localStorage.setItem('sg_history', JSON.stringify(history));
}

function clearHistory() {
  localStorage.setItem('sg_history', '[]');
}

// --- Audit Page ---
async function loadAuditPage() {
  try {
    var status = await invoke('get_daemon_status');
    var badge = document.getElementById('monitor-status-badge');
    badge.textContent = status.running ? '运行中' : '已停止';
    badge.className = 'badge ' + (status.running ? 'badge-enabled' : 'badge-unprotected');
    document.getElementById('protected-count').textContent = status.protected_count;
    document.getElementById('rule-count').textContent = status.rule_count;

    var history = getHistory();
    document.getElementById('total-changes').textContent = history.length;

    var monitorBtn = document.getElementById('monitor-btn-text');
    monitorBtn.textContent = status.running ? '停止监控' : '启动监控';

    renderHistory(history);
  } catch (e) {
    showToast('加载审计数据失败: ' + String(e), 'error');
  }
}

function renderHistory(history) {
  var tbody = document.getElementById('history-body');
  if (history.length === 0) {
    tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--color-text-muted);padding:32px">暂无变更记录</td></tr>';
    return;
  }
  var html = '';
  var count = Math.min(history.length, 100);
  for (var i = 0; i < count; i++) {
    var h = history[i];
    var changeClass = h.change.indexOf('未保护') > h.change.indexOf('保护') ? 'badge-unprotected' : 'badge-protected';
    html += '<tr>' +
      '<td>' + escapeHtml(h.time) + '</td>' +
      '<td>' + escapeHtml(h.app_name) + '</td>' +
      '<td>' + h.pid + '</td>' +
      '<td>' + escapeHtml(h.title) + '</td>' +
      '<td><span class="badge ' + changeClass + '">' + escapeHtml(h.change) + '</span></td>' +
      '<td>' + escapeHtml(h.source) + '</td></tr>';
  }
  tbody.innerHTML = html;
}

document.getElementById('btn-scan').addEventListener('click', async function() {
  try {
    var count = await invoke('run_scan');
    showToast('扫描完成，' + count + ' 个窗口已保护。', 'success');
    loadAuditPage();
  } catch (e) {
    showToast('扫描失败: ' + String(e), 'error');
  }
});

document.getElementById('btn-toggle-monitor').addEventListener('click', async function() {
  try {
    var status = await invoke('get_daemon_status');
    if (status.running) {
      await invoke('stop_monitor');
      showToast('监控已停止', 'success');
    } else {
      await invoke('start_monitor');
      showToast('监控已启动，正在持续保护窗口', 'success');
    }
    setTimeout(loadAuditPage, 500);
  } catch (e) {
    showToast('操作失败: ' + String(e), 'error');
  }
});

document.getElementById('btn-clear-history').addEventListener('click', function() {
  if (!confirm('确定要清空所有变更记录吗？')) return;
  clearHistory();
  loadAuditPage();
  showToast('记录已清空', 'success');
});

// --- Threats Page ---
async function loadThreatsPage() {
  try {
    var snapshot = await invoke('scan_threats');
    renderThreatSnapshot(snapshot);
    await loadGpuProtectionStatus();
  } catch (e) {
    showToast('威胁扫描失败: ' + String(e), 'error');
  }
}

async function loadGpuProtectionStatus() {
  try {
    var status = await invoke('get_gpu_protection_status');
    document.getElementById('gpu-status').textContent = status.enabled ? '已启用' : '未启用';
    document.getElementById('gpu-status').style.color = status.enabled ? 'var(--color-success)' : 'var(--color-text-muted)';
    document.getElementById('gpu-level').textContent = status.level;
    document.getElementById('gpu-wgc').textContent = status.wgc_enabled ? '可用' : '不可用';
    document.getElementById('gpu-wgc').style.color = status.wgc_enabled ? 'var(--color-success)' : 'var(--color-text-muted)';
    document.getElementById('gpu-protected').textContent = status.protected_windows;
    document.getElementById('gpu-methods-list').textContent = status.active_methods.length > 0 ? status.active_methods.join(', ') : '无';
  } catch (e) {
    debug('加载 GPU 防护状态失败: ' + String(e));
  }
}

function renderThreatSnapshot(snapshot) {
  document.getElementById('threat-total').textContent = snapshot.total_count;
  document.getElementById('threat-high').textContent = snapshot.detected.filter(function(d) { return d.threat_label === '系统截图工具'; }).length;
  document.getElementById('threat-high2').textContent = snapshot.detected.filter(function(d) { return d.threat_label === '第三方截录屏'; }).length;
  document.getElementById('threat-medium').textContent = snapshot.detected.filter(function(d) { return d.threat_label === '远程/会议共享'; }).length;
  document.getElementById('threat-scan-time').textContent = '扫描耗时: ' + snapshot.scan_time_ms + 'ms';

  var tbody = document.getElementById('threats-body');
  if (snapshot.detected.length === 0) {
    tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:var(--color-text-muted);padding:32px">未检测到截屏/录屏软件运行</td></tr>';
    return;
  }

  var html = '';
  for (var i = 0; i < snapshot.detected.length; i++) {
    var d = snapshot.detected[i];
    var levelClass = 'badge-protected';
    var levelStyle = '';
    if (d.threat_label === '系统截图工具') {
      levelStyle = 'background:#FEE2E2;color:#991B1B';
    } else if (d.threat_label === '第三方截录屏') {
      levelStyle = 'background:#FEF3C7;color:#92400E';
    } else if (d.threat_label === '远程/会议共享') {
      levelStyle = 'background:#DBEAFE;color:#1E40AF';
    }

    html += '<tr>' +
      '<td>' + (i + 1) + '</td>' +
      '<td>' + escapeHtml(d.display_name) + '</td>' +
      '<td><code>' + escapeHtml(d.process_name) + '</code></td>' +
      '<td>' + d.pid + '</td>' +
      '<td><span class="badge" style="' + levelStyle + '">' + escapeHtml(d.threat_label) + '</span></td>' +
      '<td style="font-size:12px;color:var(--color-text-secondary)">' + escapeHtml(d.description) + '</td>' +
      '<td><button class="btn btn-secondary btn-sm" onclick="protectAllFromThreat(\'' + escapeAttr(d.process_name) + '\')">全部保护</button></td>' +
      '</tr>';
  }
  tbody.innerHTML = html;
}

async function protectAllFromThreat(threatProcess) {
  try {
    var windows = await invoke('list_windows');
    var count = 0;
    for (var i = 0; i < windows.length; i++) {
      var w = windows[i];
      if (!w.is_protected) {
        try {
          await invoke('set_protection', { hwnd: w.hwnd, pid: w.pid, protect: true });
          count++;
          addHistoryEntry({
            time: new Date().toLocaleString('zh-CN'),
            app_name: w.app_name,
            pid: w.pid,
            title: w.title,
            change: '未保护→保护',
            source: '威胁检测'
          });
        } catch (e) {
          // Skip windows that can't be protected
        }
      }
    }
    showToast('已保护 ' + count + ' 个窗口', 'success');
    loadThreatsPage();
  } catch (e) {
    showToast('操作失败: ' + String(e), 'error');
  }
}

document.getElementById('btn-scan-threats').addEventListener('click', loadThreatsPage);

document.getElementById('threat-monitor-toggle').addEventListener('change', function(e) {
  if (e.target.checked) {
    invoke('start_threat_monitor').then(function() {
      showToast('自动威胁检测已启动', 'success');
    }).catch(function(err) {
      showToast('启动失败: ' + String(err), 'error');
      e.target.checked = false;
    });
  } else {
    invoke('stop_threat_monitor').then(function() {
      showToast('自动威胁检测已停止', 'success');
    });
  }
});

// --- Logs Page ---
async function loadLogs() {
  try {
    var logData = await invoke('read_log');
    var filter = document.getElementById('log-filter').value;
    var lines = logData.split('\n');

    if (filter !== 'all') {
      lines = lines.filter(function(line) {
        return line.indexOf('[' + filter + ']') !== -1;
      });
    }

    var content = lines.join('\n');
    var pre = document.getElementById('log-content');
    pre.textContent = content || '暂无日志';
    pre.scrollTop = pre.scrollHeight;
  } catch (e) {
    document.getElementById('log-content').textContent = '读取日志失败: ' + String(e);
  }
}

document.getElementById('btn-refresh-logs').addEventListener('click', loadLogs);

document.getElementById('log-filter').addEventListener('change', loadLogs);

document.getElementById('btn-clear-logs').addEventListener('click', async function() {
  if (!confirm('确定要清空日志文件吗？')) return;
  try {
    await invoke('clear_log');
    loadLogs();
    showToast('日志已清空', 'success');
  } catch (e) {
    showToast('清空日志失败: ' + String(e), 'error');
  }
});

// --- Settings Page ---
async function loadConfig() {
  try {
    var cfg = await invoke('get_config');
    document.getElementById('cfg-interval').value = cfg.poll_interval_ms;
    document.getElementById('cfg-auto-start').checked = cfg.auto_start_monitoring;
    document.getElementById('cfg-boot-start').checked = cfg.boot_auto_start;
    document.getElementById('cfg-close-to-tray').checked = cfg.close_to_tray;
    document.getElementById('cfg-helper').value = cfg.helper_path;
    document.getElementById('cfg-rules').value = cfg.rules_path;
    document.getElementById('cfg-policy').value = cfg.policy_path;
  } catch (e) {
    showToast('加载配置失败: ' + String(e), 'error');
  }
}

document.getElementById('btn-save-config').addEventListener('click', async function() {
  var cfg = {
    poll_interval_ms: parseInt(document.getElementById('cfg-interval').value) || 3000,
    auto_start_monitoring: document.getElementById('cfg-auto-start').checked,
    boot_auto_start: document.getElementById('cfg-boot-start').checked,
    close_to_tray: document.getElementById('cfg-close-to-tray').checked,
    helper_path: document.getElementById('cfg-helper').value,
    rules_path: document.getElementById('cfg-rules').value,
    policy_path: document.getElementById('cfg-policy').value
  };
  try {
    await invoke('update_config', { newConfig: cfg });
    showToast('配置已保存', 'success');
  } catch (e) {
    showToast('保存失败: ' + String(e), 'error');
  }
});

document.getElementById('btn-reset-config').addEventListener('click', function() {
  loadConfig();
  showToast('配置已重置为保存值', 'success');
});

// --- Audit State (localStorage) ---
function getAuditedMap() {
  try {
    return JSON.parse(localStorage.getItem('sg_audited') || '{}');
  } catch (e) { return {}; }
}

function toggleAudit(appName, pid, audited) {
  var map = getAuditedMap();
  var key = appName + ':' + pid;
  if (audited) {
    delete map[key];
  } else {
    map[key] = false;
  }
  localStorage.setItem('sg_audited', JSON.stringify(map));
  showToast(audited ? '已开启审计' : '已停止审计', 'success');
  loadWindows();
}

// --- Utilities ---
function escapeHtml(str) {
  var div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

function escapeAttr(str) {
  return str.replace(/'/g, "\\'").replace(/"/g, '&quot;');
}

// --- License Page ---
async function loadLicensePage() {
  try {
    var status = await invoke('get_license_status');

    // Update license status cards
    document.getElementById('license-type').textContent = status.license_type;
    document.getElementById('license-status').textContent = status.license_valid ? '有效' : '已过期';
    document.getElementById('license-max-rules').textContent = status.max_rules === 2147483647 ? '无限' : status.max_rules + ' 条';

    // Update grace days
    var graceDaysEl = document.getElementById('license-grace-days');
    if (status.grace_days_remaining !== null && status.grace_days_remaining !== undefined) {
      graceDaysEl.textContent = status.grace_days_remaining + ' 天';
      if (status.grace_days_remaining <= 7) {
        graceDaysEl.style.color = 'var(--color-warning)';
      } else if (status.grace_days_remaining <= 0) {
        graceDaysEl.style.color = 'var(--color-danger)';
      } else {
        graceDaysEl.style.color = 'var(--color-success)';
      }
    } else {
      graceDaysEl.textContent = '-';
    }

    // Update license type badge style
    var typeEl = document.getElementById('license-type');
    typeEl.className = 'card-value';
    if (status.license_type === '免费版') {
      typeEl.classList.add('badge-free');
    } else if (status.license_type === '专业版') {
      typeEl.classList.add('badge-pro');
    } else if (status.license_type === '企业版') {
      typeEl.classList.add('badge-enterprise');
    }

    // Update status badge style
    var statusEl = document.getElementById('license-status');
    statusEl.style.color = status.license_valid ? 'var(--color-success)' : 'var(--color-danger)';

    // Update offline banner
    var offlineBanner = document.getElementById('offline-banner');
    if (status.is_offline) {
      offlineBanner.style.display = 'flex';
      var bannerMessage = document.getElementById('offline-banner-message');
      if (status.grace_days_remaining !== null && status.grace_days_remaining > 0) {
        bannerMessage.textContent = '宽限期剩余 ' + status.grace_days_remaining + ' 天，之后将降级为免费版';
        offlineBanner.className = 'offline-banner';
      } else if (status.grace_days_remaining !== null && status.grace_days_remaining <= 0) {
        bannerMessage.textContent = '宽限期已过，已降级为免费版功能';
        offlineBanner.className = 'offline-banner offline-banner-error';
      } else {
        bannerMessage.textContent = '建议连接网络进行验证';
        offlineBanner.className = 'offline-banner offline-banner-info';
      }
    } else {
      offlineBanner.style.display = 'none';
    }

    // Update expiry info
    var expirySection = document.getElementById('license-expiry-info');
    if (status.expires_at) {
      expirySection.style.display = 'flex';
      var expiryDate = new Date(status.expires_at);
      document.getElementById('license-expiry-date').textContent = expiryDate.toLocaleDateString('zh-CN');

      var daysEl = document.getElementById('license-days-remaining');
      if (status.days_remaining !== null) {
        if (status.days_remaining > 30) {
          daysEl.textContent = '剩余 ' + status.days_remaining + ' 天';
          daysEl.className = 'license-days-remaining valid';
        } else if (status.days_remaining > 0) {
          daysEl.textContent = '即将到期 (' + status.days_remaining + ' 天)';
          daysEl.className = 'license-days-remaining warning';
        } else {
          daysEl.textContent = '已过期';
          daysEl.className = 'license-days-remaining expired';
        }
      }
    } else {
      expirySection.style.display = 'none';
    }

    // Update next verify info
    var nextVerifySection = document.getElementById('license-next-verify');
    if (status.next_online_verification) {
      nextVerifySection.style.display = 'flex';
      var nextVerifyDate = new Date(status.next_online_verification);
      document.getElementById('license-next-verify-date').textContent = nextVerifyDate.toLocaleDateString('zh-CN');
    } else {
      nextVerifySection.style.display = 'none';
    }

    // Update available features
    var featuresList = document.getElementById('license-features-list');
    var allFeatures = [
      '基础窗口保护', 'GUI 界面', '系统托盘', '基础威胁检测', '基础审计日志',
      '分层保护架构', 'GPU 截图防护', '无限规则', '规则组管理', '正则表达式',
      '审计日志导出', '无限审计日志', '威胁检测详情', '自动更新',
      '集中管理', '策略分发', '审计报表', 'API 集成', 'SSO 集成'
    ];

    var featuresHtml = '';
    for (var i = 0; i < allFeatures.length; i++) {
      var feature = allFeatures[i];
      var available = status.features.indexOf(feature) !== -1;
      featuresHtml += '<div class="feature-item ' + (available ? 'available' : 'unavailable') + '">' +
        '<div class="feature-icon ' + (available ? 'available' : 'unavailable') + '">' +
        (available ? '✓' : '✗') +
        '</div>' +
        '<span>' + feature + '</span>' +
        '</div>';
    }
    featuresList.innerHTML = featuresHtml;

    // Update upgrade section visibility
    var upgradePro = document.getElementById('upgrade-pro');
    var upgradeEnterprise = document.getElementById('upgrade-enterprise');

    if (status.license_type === '免费版') {
      upgradePro.style.display = 'block';
      upgradeEnterprise.style.display = 'block';
    } else if (status.license_type === '专业版') {
      upgradePro.style.display = 'none';
      upgradeEnterprise.style.display = 'block';
    } else {
      upgradePro.style.display = 'none';
      upgradeEnterprise.style.display = 'none';
    }

    debug('许可证页面加载成功');
  } catch (e) {
    debug('许可证页面加载失败: ' + String(e));
    showToast('加载许可证信息失败: ' + String(e), 'error');
  }
}

// License activation
document.getElementById('btn-activate-license').addEventListener('click', async function() {
  var keyInput = document.getElementById('license-key-input');
  var licenseKey = keyInput.value.trim();
  var onlineVerify = document.getElementById('license-online-verify').checked;

  if (!licenseKey) {
    showToast('请输入许可证密钥', 'error');
    return;
  }

  try {
    var result = await invoke('activate_license', { licenseKey: licenseKey, online: onlineVerify });
    showToast(result, 'success');
    keyInput.value = '';
    loadLicensePage();
    updateStatusBar();
  } catch (e) {
    showToast('激活失败: ' + String(e), 'error');
  }
});

// License deactivation
document.getElementById('btn-deactivate-license').addEventListener('click', async function() {
  if (!confirm('确定要清除许可证吗？将恢复为免费版功能。')) {
    return;
  }

  try {
    await invoke('deactivate_license');
    showToast('许可证已清除，已恢复为免费版', 'success');
    loadLicensePage();
    updateStatusBar();
  } catch (e) {
    showToast('清除失败: ' + String(e), 'error');
  }
});

// Upgrade buttons
document.querySelector('#upgrade-pro .upgrade-btn').addEventListener('click', async function() {
  // 尝试调用服务器创建 Checkout Session
  try {
    var response = await fetch('https://api.screen-guardian.com/api/v1/checkout', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        license_type: 'pro',
        device_count: 1,
        success_url: 'https://screen-guardian.com/success?session_id={CHECKOUT_SESSION_ID}',
        cancel_url: 'https://screen-guardian.com/pricing',
      }),
    });
    var data = await response.json();
    if (data.session_url) {
      window.open(data.session_url, '_blank');
    } else {
      showToast('创建支付会话失败，请联系 mixyoung@88.com', 'error');
    }
  } catch (e) {
    // 离线模式 - 打开购买页面
    showToast('请访问 https://screen-guardian.com/pricing 购买，或联系 mixyoung@88.com', 'success');
  }
});

document.querySelector('#upgrade-enterprise .upgrade-btn').addEventListener('click', async function() {
  // 企业版需要联系销售
  showToast('企业版请联系销售团队: mixyoung@88.com', 'success');
});

// Offline banner close button
document.getElementById('btn-close-offline-banner').addEventListener('click', function() {
  document.getElementById('offline-banner').style.display = 'none';
});

// Offline verify button
document.getElementById('btn-offline-verify').addEventListener('click', async function() {
  try {
    await invoke('activate_license', { licenseKey: '', online: true });
    showToast('在线验证成功', 'success');
    loadLicensePage();
    updateStatusBar();
  } catch (e) {
    showToast('验证失败: ' + String(e), 'error');
  }
});

// Generate activation request file
document.getElementById('btn-generate-request').addEventListener('click', async function() {
  var keyInput = document.getElementById('license-key-input');
  var licenseKey = keyInput.value.trim();

  if (!licenseKey) {
    showToast('请先输入许可证密钥', 'error');
    return;
  }

  try {
    var result = await invoke('generate_activation_request', { licenseKey: licenseKey });
    showToast('激活请求文件已生成: ' + result, 'success');
  } catch (e) {
    showToast('生成失败: ' + String(e), 'error');
  }
});

// Import activation file
document.getElementById('btn-import-license').addEventListener('click', async function() {
  try {
    var result = await invoke('import_activation_file');
    showToast(result, 'success');
    loadLicensePage();
    updateStatusBar();
  } catch (e) {
    showToast('导入失败: ' + String(e), 'error');
  }
});

// Show device info
document.getElementById('btn-show-device-info').addEventListener('click', async function() {
  var panel = document.getElementById('device-info-panel');
  if (panel.style.display === 'none') {
    try {
      var info = await invoke('get_device_info');
      document.getElementById('device-fingerprint').textContent = info.fingerprint;

      var componentsHtml = '';
      for (var i = 0; i < info.components.length; i++) {
        var comp = info.components[i];
        componentsHtml += '<div class="device-component">' +
          '<span class="device-component-type">' + comp.component_type + ':</span>' +
          '<span class="device-component-hash">' + comp.value_hash.substring(0, 16) + '...</span>' +
          '</div>';
      }
      document.getElementById('device-components').innerHTML = componentsHtml;
      panel.style.display = 'block';
    } catch (e) {
      showToast('获取设备信息失败: ' + String(e), 'error');
    }
  } else {
    panel.style.display = 'none';
  }
});

// --- Init ---
function init() {
  if (window.__TAURI_INTERNALS__ && typeof window.__TAURI_INTERNALS__.invoke === 'function') {
    debug('Tauri IPC 就绪');
    loadWindows();
    updateStatusBar();
    // Update status bar every 5 seconds
    setInterval(updateStatusBar, 5000);
  } else {
    debug('等待 Tauri IPC...');
    setTimeout(init, 300);
  }
}

// --- Status Bar ---
async function updateStatusBar() {
  try {
    var status = await invoke('get_daemon_status');
    var indicator = document.getElementById('status-indicator');
    var dot = indicator.querySelector('.status-dot');
    var statusText = document.getElementById('status-text');
    var protectedEl = document.getElementById('status-protected');
    var lastScanEl = document.getElementById('status-last-scan');
    var rulesEl = document.getElementById('status-rules');

    if (status.running) {
      dot.className = 'status-dot status-running';
      statusText.textContent = '监控运行中';
    } else {
      dot.className = 'status-dot status-stopped';
      statusText.textContent = '监控已停止';
    }

    protectedEl.textContent = '已保护 ' + status.protected_count + ' 个窗口';
    rulesEl.textContent = '规则: ' + status.rule_count;

    if (status.last_scan_secs_ago !== undefined && status.last_scan_secs_ago < 999999) {
      if (status.last_scan_secs_ago < 60) {
        lastScanEl.textContent = '最后扫描: ' + status.last_scan_secs_ago + '秒前';
      } else {
        lastScanEl.textContent = '最后扫描: ' + Math.floor(status.last_scan_secs_ago / 60) + '分钟前';
      }
    } else {
      lastScanEl.textContent = '最后扫描: --';
    }
  } catch (e) {
    debug('状态栏更新失败: ' + String(e));
  }
}

if (document.readyState === 'loading') {
  debug('DOM 加载中，等待 DOMContentLoaded');
  document.addEventListener('DOMContentLoaded', init);
} else {
  debug('DOM 已加载，立即调用 init');
  init();
}
