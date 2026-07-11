const pathParts = window.location.pathname.split('/');
const currentCaseId = pathParts[pathParts.length - 1] || 'Unknown';

const caseTitle = document.getElementById('caseTitle');
const caseSubtitle = document.getElementById('caseSubtitle');
const caseIdValue = document.getElementById('caseIdValue');
const caseStatusValue = document.getElementById('caseStatusValue');
const caseCreatedValue = document.getElementById('caseCreatedValue');
const executiveSummary = document.getElementById('executiveSummary');
const threatAssessment = document.getElementById('threatAssessment');
const scoreValue = document.getElementById('scoreValue');
const confidenceValue = document.getElementById('confidenceValue');
const indicatorList = document.getElementById('indicatorList');
const urlList = document.getElementById('urlList');
const analystReportContent = document.getElementById('analystReportContent');
const analystNotesContent = document.getElementById('analystNotesContent');
const threatIntelStatus = document.getElementById('threatIntelStatus');
const threatIntelBody = document.getElementById('threatIntelBody');
const caseUpdateForm = document.getElementById('caseUpdateForm');
const titleInput = document.getElementById('titleInput');
const statusInput = document.getElementById('statusInput');
const threatInput = document.getElementById('threatInput');
const assignedToInput = document.getElementById('assignedToInput');
const summaryInput = document.getElementById('summaryInput');
const notesInput = document.getElementById('notesInput');
const tagsInput = document.getElementById('tagsInput');
const evidenceInput = document.getElementById('evidenceInput');
const saveStatus = document.getElementById('saveStatus');

let currentCaseData = null;

function setText(node, value) {
  node.textContent = value || '—';
}

function getNestedValue(source, ...paths) {
  let current = source;
  for (const path of paths) {
    if (!current || typeof current !== 'object') return null;
    current = current[path];
  }
  return current;
}

function parseJson(value) {
  if (!value) return null;
  if (typeof value === 'object') return value;
  try {
    return JSON.parse(value);
  } catch (error) {
    return null;
  }
}

function parseList(value) {
  if (!value) return [];
  if (Array.isArray(value)) return value;
  if (typeof value === 'string') {
    try {
      const parsed = JSON.parse(value);
      if (Array.isArray(parsed)) return parsed;
    } catch (error) {
      // fall through to split by newline/comma
    }
    return value
      .split(/\n|,/) 
      .map((entry) => entry.trim())
      .filter(Boolean);
  }
  return [String(value)];
}

function renderList(listNode, items) {
  listNode.innerHTML = '';
  if (!items || !items.length) {
    const emptyItem = document.createElement('li');
    emptyItem.textContent = 'No items recorded.';
    listNode.appendChild(emptyItem);
    return;
  }

  items.forEach((item) => {
    const entry = document.createElement('li');
    entry.textContent = item;
    listNode.appendChild(entry);
  });
}

function populateForm(data) {
  currentCaseData = data || {};
  titleInput.value = data.title || '';
  statusInput.value = data.status || 'Open';
  threatInput.value = (data.threat_level || 'MINIMAL').toUpperCase();
  assignedToInput.value = data.assigned_to || '';
  summaryInput.value = data.summary || '';
  notesInput.value = data.analyst_notes || '';
  tagsInput.value = parseList(data.tags).join(', ');
  evidenceInput.value = parseList(data.evidence).join('\n');
}

function renderThreatIntel(items) {
  if (!items || !items.length) {
    threatIntelBody.innerHTML = '<tr><td colspan="6" class="empty-state">Enrichment is still running for this investigation.</td></tr>';
    threatIntelStatus.textContent = 'Enrichment is still running for this investigation.';
    return;
  }
  // Determine if any provider returned useful data
  let anyProviderOk = false;

  threatIntelBody.innerHTML = '';
  items.forEach((item) => {
    const providers = item.provider_results || {};
    const providerNames = Object.keys(providers || {});
    // inspect providers for ok status
    providerNames.forEach((pn) => {
      const pres = providers[pn];
      if (pres && pres.status === 'ok') anyProviderOk = true;
    });

    const providersHtml = providerNames.length
      ? providerNames
          .map((pn) => {
            const pres = providers[pn] || {};
            const data = pres.data || {};
            const detectionRatio = data.detection_ratio || (data.malicious != null && data.harmless != null ? `${data.malicious}/${(data.malicious + data.suspicious + data.harmless)}` : '—');
            const malicious = data.malicious != null ? data.malicious : '—';
            const suspicious = data.suspicious != null ? data.suspicious : '—';
            const harmless = data.harmless != null ? data.harmless : '—';
            const reputation = data.reputation != null ? data.reputation : (pres.reputation != null ? pres.reputation : '—');
            const confidence = pres.confidence != null ? pres.confidence : item.confidence != null ? item.confidence : '—';
            const lastAnalysis = data.last_analysis_date || pres.last_analysis_date || '—';
            const permalink = data.permalink || pres.permalink || '';
            const details = pres.details || '';

            return `
              <div class="provider-block">
                <strong>${pn}</strong> — <em>${pres.status || 'unknown'}</em>
                <div class="provider-grid">
                  <div><strong>Detection ratio:</strong> ${detectionRatio}</div>
                  <div><strong>Malicious:</strong> ${malicious}</div>
                  <div><strong>Suspicious:</strong> ${suspicious}</div>
                  <div><strong>Harmless:</strong> ${harmless}</div>
                  <div><strong>Reputation:</strong> ${reputation}</div>
                  <div><strong>Confidence:</strong> ${confidence}</div>
                  <div><strong>Last analysis:</strong> ${lastAnalysis}</div>
                  <div><strong>Link:</strong> ${permalink ? `<a href="${permalink}" target="_blank" rel="noopener">View</a>` : '—'}</div>
                  <div class="provider-detail"><strong>Explanation:</strong> ${details}</div>
                </div>
              </div>
            `;
          })
          .join('')
      : '—';

    const row = document.createElement('tr');
    row.innerHTML = `
      <td>${item.ioc_value}</td>
      <td>${item.ioc_type}</td>
      <td><span class="badge ${item.reputation >= 70 ? 'high' : item.reputation >= 40 ? 'medium' : 'low'}">${item.reputation}</span></td>
      <td>${item.confidence}</td>
      <td>${item.risk_score}</td>
      <td>${providersHtml}</td>
    `;
    threatIntelBody.appendChild(row);
  });

  if (!anyProviderOk) {
    threatIntelStatus.textContent = 'Threat intelligence unavailable. Investigation completed using heuristic analysis only.';
  } else {
    threatIntelStatus.textContent = `${items.length} IOC${items.length === 1 ? '' : 's'} enriched.`;
  }
}

async function loadThreatIntel() {
  try {
    const response = await fetch(`/investigations/${currentCaseId}/intel`, {
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      throw new Error('Intel endpoint unavailable');
    }
    const data = await response.json();
    renderThreatIntel(data);
  } catch (error) {
    threatIntelBody.innerHTML = '<tr><td colspan="6" class="empty-state">Threat intelligence is not available yet.</td></tr>';
  }
}

function renderCase(data) {
  caseTitle.textContent = data.title || `Investigation ${data.case_id || currentCaseId}`;
  caseSubtitle.textContent = data.sender ? `Submitted by ${data.sender}` : 'Investigation details from the saved record.';
  setText(caseIdValue, data.case_id);
  setText(caseStatusValue, data.status);
  setText(caseCreatedValue, data.created_at || '—');

  const report = parseJson(data.analyst_report);
  const summary = data.summary || getNestedValue(report, 'summary') || getNestedValue(report, 'executive_summary') || getNestedValue(report, 'finding') || 'No executive summary available.';
  const threatLevel = (data.threat_level || 'minimal').toString().toLowerCase();
  const score = data.phishing_score ?? '—';
  const confidence = data.confidence ?? '—';

  executiveSummary.textContent = summary;
  threatAssessment.className = `threat-level ${threatLevel}`;
  threatAssessment.textContent = `${(data.threat_level || 'MINIMAL').toUpperCase()} threat`;
  scoreValue.textContent = score;
  confidenceValue.textContent = confidence;

  const parsedUrls = parseJson(data.urls);
  const urlItems = Array.isArray(parsedUrls) ? parsedUrls : [data.urls].filter(Boolean);
  renderList(urlList, urlItems);

  const indicatorItems = [];
  if (report && typeof report === 'object') {
    const indicators = report.indicators || report.key_indicators || [];
    if (Array.isArray(indicators)) {
      indicatorItems.push(...indicators);
    } else if (typeof indicators === 'string') {
      indicatorItems.push(indicators);
    }
  }
  renderList(indicatorList, indicatorItems.length ? indicatorItems : ['No indicators recorded.']);

  analystReportContent.textContent = data.analyst_report || 'No analyst report recorded.';
  analystNotesContent.textContent = data.analyst_notes || 'No analyst notes recorded.';
  populateForm(data);
}

caseUpdateForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  saveStatus.textContent = 'Saving…';

  const payload = {
    title: titleInput.value.trim() || undefined,
    status: statusInput.value || undefined,
    threat_level: threatInput.value || undefined,
    summary: summaryInput.value.trim() || undefined,
    analyst_notes: notesInput.value.trim() || undefined,
    assigned_to: assignedToInput.value.trim() || undefined,
    tags: tagsInput.value
      .split(',')
      .map((entry) => entry.trim())
      .filter(Boolean),
    evidence: evidenceInput.value
      .split('\n')
      .map((entry) => entry.trim())
      .filter(Boolean),
  };

  try {
    const response = await fetch(`/investigations/${currentCaseId}`, {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      throw new Error('Unable to save changes');
    }

    const data = await response.json();
    renderCase(data);
    saveStatus.textContent = 'Saved.';
  } catch (error) {
    saveStatus.textContent = 'Unable to save changes right now.';
  }
});

async function loadInvestigation() {
  try {
    const response = await fetch(`/investigations/${currentCaseId}`, {
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      throw new Error('Case not found');
    }
    const data = await response.json();
    renderCase(data);
  } catch (error) {
    caseTitle.textContent = 'Unable to load case';
    caseSubtitle.textContent = 'The case details could not be retrieved.';
    executiveSummary.textContent = 'The investigation record was not found or could not be loaded.';
  }
}

loadInvestigation();
loadThreatIntel();
setInterval(() => {
  loadThreatIntel();
}, 5000);
