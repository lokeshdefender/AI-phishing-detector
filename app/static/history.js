const searchInput = document.getElementById('searchInput');
const historyBody = document.getElementById('historyBody');
const resultsSummary = document.getElementById('resultsSummary');
const historyFilters = document.getElementById('historyFilters');
const widgetMyOpen = document.getElementById('widgetMyOpen');
const widgetAssigned = document.getElementById('widgetAssigned');
const widgetActivityList = document.getElementById('widgetActivityList');

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
