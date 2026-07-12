const searchInput = document.getElementById('searchInput');
const historyBody = document.getElementById('historyBody');
const resultsSummary = document.getElementById('resultsSummary');
const historyFilters = document.getElementById('historyFilters');
const widgetMyOpen = document.getElementById('widgetMyOpen');
const widgetAssigned = document.getElementById('widgetAssigned');
const widgetActivityList = document.getElementById('widgetActivityList');
const analyticsSummary = document.getElementById('analyticsSummary');
const kpiTotalInvestigations = document.getElementById('kpiTotalInvestigations');
const kpiOpenCases = document.getElementById('kpiOpenCases');
const kpiClosedCases = document.getElementById('kpiClosedCases');
const kpiHighRiskCases = document.getElementById('kpiHighRiskCases');
const kpiMediumRiskCases = document.getElementById('kpiMediumRiskCases');
const kpiLowRiskCases = document.getElementById('kpiLowRiskCases');
const kpiCreatedToday = document.getElementById('kpiCreatedToday');
const kpiCreatedThisWeek = document.getElementById('kpiCreatedThisWeek');
const chartThreatLevels = document.getElementById('chartThreatLevels');
const chartCasesOverTime = document.getElementById('chartCasesOverTime');
const chartTopIocTypes = document.getElementById('chartTopIocTypes');
const chartTopMitreTechniques = document.getElementById('chartTopMitreTechniques');
const chartTopDomains = document.getElementById('chartTopDomains');

let selectedFilter = '';

ensureAuthenticated();
bindLogoutButton();

function badgeClass(value) {
  return String(value || 'minimal').toLowerCase().replace(/\s+/g, '-');
}

function formatDate(value) {
  if (!value) return '—';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function buildRow(item) {
  const row = document.createElement('tr');
  row.className = 'clickable-row';
  row.dataset.caseId = item.case_id;
  row.innerHTML = `
    <td><strong>${item.case_id}</strong></td>
    <td><span class="badge ${badgeClass(item.threat_level)}">${item.threat_level || 'MINIMAL'}</span></td>
    <td>${item.sender || 'Unknown'}</td>
    <td>${item.title || 'Untitled Investigation'}</td>
    <td><span class="badge ${badgeClass(item.status)}">${item.status || 'Open'}</span></td>
    <td>${formatDate(item.created_at)}</td>
  `;
  row.addEventListener('click', () => {
    window.location.href = `/investigations/${item.case_id}`;
  });
  return row;
}

async function loadInvestigations() {
  try {
    const suffix = selectedFilter ? `?filter_by=${encodeURIComponent(selectedFilter)}` : '';
    const response = await authApiFetch(`/investigations${suffix}`);
    const data = await response.json();
    renderItems(data);
  } catch (error) {
    historyBody.innerHTML = `<tr><td colspan="6" class="empty-state">Unable to load investigations right now.</td></tr>`;
    resultsSummary.textContent = 'Unable to load investigations';
  }
}

function renderDashboard(summary) {
  if (!summary) return;
  widgetMyOpen.textContent = summary.my_open_cases ?? 0;
  widgetAssigned.textContent = summary.assigned_to_me ?? 0;

  const activity = Array.isArray(summary.recent_team_activity) ? summary.recent_team_activity : [];
  widgetActivityList.innerHTML = '';
  if (!activity.length) {
    widgetActivityList.innerHTML = '<li class="empty-state">No team activity yet.</li>';
    return;
  }

  activity.slice(0, 6).forEach((item) => {
    const li = document.createElement('li');
    li.innerHTML = `<strong>${item.case_id || 'Case'}</strong> ${item.title || item.event_type || 'activity'}`;
    widgetActivityList.appendChild(li);
  });
}

function renderSimpleList(target, items, emptyText) {
  if (!target) return;
  target.innerHTML = '';
  if (!Array.isArray(items) || !items.length) {
    target.innerHTML = `<li class="empty-state">${emptyText}</li>`;
    return;
  }
  items.forEach((item) => {
    const li = document.createElement('li');
    li.innerHTML = `<strong>${item.label || 'Unknown'}</strong><span>${item.count ?? 0}</span>`;
    target.appendChild(li);
  });
}

function renderThreatBars(items) {
  if (!chartThreatLevels) return;
  chartThreatLevels.innerHTML = '';
  if (!Array.isArray(items) || !items.length) {
    chartThreatLevels.innerHTML = '<p class="empty-state">No threat data available.</p>';
    return;
  }
  const max = Math.max(...items.map((item) => Number(item.count || 0)), 1);
  items.forEach((item) => {
    const count = Number(item.count || 0);
    const row = document.createElement('div');
    row.className = 'analytics-bar-row';
    row.innerHTML = `
      <span class="analytics-bar-label">${item.label}</span>
      <div class="analytics-bar-track"><span class="analytics-bar-fill" style="width:${Math.round((count / max) * 100)}%"></span></div>
      <span class="analytics-bar-value">${count}</span>
    `;
    chartThreatLevels.appendChild(row);
  });
}

function renderCasesOverTime(items) {
  if (!chartCasesOverTime) return;
  chartCasesOverTime.innerHTML = '';
  if (!Array.isArray(items) || !items.length) {
    chartCasesOverTime.innerHTML = '<p class="empty-state">No timeline data available.</p>';
    return;
  }

  const max = Math.max(...items.map((item) => Number(item.count || 0)), 1);
  const sampled = items.length > 30 ? items.slice(items.length - 30) : items;

  sampled.forEach((item, idx) => {
    const count = Number(item.count || 0);
    const bar = document.createElement('div');
    bar.className = 'analytics-line-bar';
    bar.style.height = `${Math.max(8, Math.round((count / max) * 100))}%`;
    const tooltip = `${item.date}: ${count}`;
    bar.title = tooltip;
    bar.setAttribute('aria-label', tooltip);
    if (idx === sampled.length - 1) {
      bar.classList.add('latest');
    }
    chartCasesOverTime.appendChild(bar);
  });
}

function renderAnalytics(payload) {
  if (!payload) return;
  const kpis = payload.kpis || {};
  const charts = payload.charts || {};

  if (kpiTotalInvestigations) kpiTotalInvestigations.textContent = kpis.total_investigations ?? 0;
  if (kpiOpenCases) kpiOpenCases.textContent = kpis.open_cases ?? 0;
  if (kpiClosedCases) kpiClosedCases.textContent = kpis.closed_cases ?? 0;
  if (kpiHighRiskCases) kpiHighRiskCases.textContent = kpis.high_risk_cases ?? 0;
  if (kpiMediumRiskCases) kpiMediumRiskCases.textContent = kpis.medium_risk_cases ?? 0;
  if (kpiLowRiskCases) kpiLowRiskCases.textContent = kpis.low_risk_cases ?? 0;
  if (kpiCreatedToday) kpiCreatedToday.textContent = kpis.created_today ?? 0;
  if (kpiCreatedThisWeek) kpiCreatedThisWeek.textContent = kpis.created_this_week ?? 0;

  renderThreatBars(charts.cases_by_threat_level || []);
  renderCasesOverTime(charts.cases_over_time || []);
  renderSimpleList(chartTopIocTypes, charts.top_ioc_types || [], 'No IOC data available.');
  renderSimpleList(chartTopMitreTechniques, charts.top_mitre_techniques || [], 'No MITRE data available.');
  renderSimpleList(chartTopDomains, charts.top_targeted_domains || [], 'No domain data available.');

  if (analyticsSummary) {
    const days = payload.meta && payload.meta.days ? payload.meta.days : 30;
    analyticsSummary.textContent = `Organization analytics refreshed for the last ${days} day${days === 1 ? '' : 's'}.`;
  }
}

async function loadAnalytics() {
  try {
    const response = await authApiFetch('/dashboard/analytics?days=30');
    const data = await response.json();
    renderAnalytics(data);
  } catch (error) {
    if (analyticsSummary) {
      analyticsSummary.textContent = 'Unable to load organization analytics right now.';
    }
  }
}

async function loadDashboard() {
  try {
    const response = await authApiFetch('/dashboard/summary');
    const data = await response.json();
    renderDashboard(data);
  } catch (error) {
    widgetActivityList.innerHTML = '<li class="empty-state">Unable to load team activity.</li>';
  }
}

function renderItems(items) {
  const query = searchInput.value.trim().toLowerCase();
  const filtered = items.filter((item) => {
    if (!query) return true;
    return [item.case_id, item.title, item.sender, item.threat_level, item.status]
      .join(' ')
      .toLowerCase()
      .includes(query);
  });

  historyBody.innerHTML = '';
  if (!filtered.length) {
    historyBody.innerHTML = '<tr><td colspan="6" class="empty-state">No investigations match your search.</td></tr>';
    resultsSummary.textContent = 'No matching investigations';
    return;
  }

  filtered.forEach((item) => historyBody.appendChild(buildRow(item)));
  resultsSummary.textContent = `${filtered.length} investigation${filtered.length === 1 ? '' : 's'} shown`;
}

searchInput.addEventListener('input', () => {
  loadInvestigations().catch(() => {});
});

if (historyFilters) {
  historyFilters.addEventListener('click', (event) => {
    const button = event.target.closest('button[data-filter]');
    if (!button) return;
    selectedFilter = button.dataset.filter || '';
    historyFilters.querySelectorAll('.filter-chip').forEach((chip) => chip.classList.remove('active'));
    button.classList.add('active');
    loadInvestigations().catch(() => {});
  });
}

loadInvestigations();
loadDashboard();
loadAnalytics();
