const searchInput = document.getElementById('searchInput');
const historyBody = document.getElementById('historyBody');
const resultsSummary = document.getElementById('resultsSummary');

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
    const response = await authApiFetch('/investigations');
    const data = await response.json();
    renderItems(data);
  } catch (error) {
    historyBody.innerHTML = `<tr><td colspan="6" class="empty-state">Unable to load investigations right now.</td></tr>`;
    resultsSummary.textContent = 'Unable to load investigations';
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

loadInvestigations();
