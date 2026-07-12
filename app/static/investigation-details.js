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
const graphStatus = document.getElementById('graphStatus');
const graphNodeHint = document.getElementById('graphNodeHint');
const graphNodeDetails = document.getElementById('graphNodeDetails');
const relationshipGraph = document.getElementById('relationshipGraph');
const mitreStatus = document.getElementById('mitreStatus');
const mitreBody = document.getElementById('mitreBody');
const copilotStatus = document.getElementById('copilotStatus');
const copilotHistory = document.getElementById('copilotHistory');
const copilotForm = document.getElementById('copilotForm');
const copilotInput = document.getElementById('copilotInput');
const clearCopilotBtn = document.getElementById('clearCopilotBtn');
const copyLastResponseBtn = document.getElementById('copyLastResponseBtn');
const copilotQuickActions = document.getElementById('copilotQuickActions');

let currentCaseData = null;
const timelineContainer = document.getElementById('timelineContainer');
let graphInstance = null;
let lastAssistantMessage = '';
let copilotMessagesCache = [];

ensureAuthenticated();
bindLogoutButton();

const graphNodeStyles = {
  'Investigation': { color: '#4f46e5', shape: 'round-rectangle', icon: 'CASE' },
  'Sender': { color: '#0891b2', shape: 'round-rectangle', icon: 'SND' },
  'Recipient': { color: '#0284c7', shape: 'round-rectangle', icon: 'RCP' },
  'Email Address': { color: '#0ea5e9', shape: 'ellipse', icon: 'EML' },
  'URL': { color: '#f59e0b', shape: 'diamond', icon: 'URL' },
  'Domain': { color: '#22c55e', shape: 'hexagon', icon: 'DOM' },
  'IP Address': { color: '#14b8a6', shape: 'triangle', icon: 'IP' },
  'File Hash': { color: '#f97316', shape: 'rectangle', icon: 'HASH' },
  'VirusTotal Result': { color: '#ef4444', shape: 'tag', icon: 'VT' },
  'Threat Intelligence Provider': { color: '#8b5cf6', shape: 'vee', icon: 'TIP' },
};

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

function renderTimeline(items) {
  if (!timelineContainer) return;
  if (!items || !items.length) {
    timelineContainer.textContent = 'No timeline events recorded for this case.';
    return;
  }

  timelineContainer.innerHTML = '';
  items.forEach((ev) => {
    const card = document.createElement('div');
    card.className = 'timeline-event';
    const time = ev.timestamp ? new Date(ev.timestamp).toLocaleString() : 'Unknown time';
    const icon = ev.event_type ? ev.event_type.split('_')[0] : 'event';
    card.innerHTML = `
      <div class="event-icon">${icon.charAt(0).toUpperCase()}</div>
      <div class="event-body">
        <div class="event-meta"><strong>${ev.title || ev.event_type}</strong> — <span class="muted">${time}</span></div>
        <div class="event-desc">${ev.description || ''}</div>
      </div>
    `;
    timelineContainer.appendChild(card);
  });
}

function formatGraphNodeDetails(node) {
  if (!node) return 'No node selected.';
  const payload = {
    id: node.data('id'),
    type: node.data('type'),
    label: node.data('label'),
    metadata: node.data('metadata') || {},
  };
  return JSON.stringify(payload, null, 2);
}

function toGraphElements(graph) {
  const safeNodes = Array.isArray(graph.nodes) ? graph.nodes : [];
  const safeEdges = Array.isArray(graph.edges) ? graph.edges : [];

  const elements = [];
  safeNodes.forEach((node) => {
    const style = graphNodeStyles[node.type] || { color: '#64748b', shape: 'ellipse', icon: 'IOC' };
    elements.push({
      data: {
        id: node.id,
        type: node.type,
        label: node.label,
        metadata: node.metadata || {},
        iconLabel: style.icon,
        nodeColor: style.color,
        nodeShape: style.shape,
      },
    });
  });

  safeEdges.forEach((edge, index) => {
    elements.push({
      data: {
        id: `${edge.source}->${edge.target}:${edge.relationship || 'related_to'}:${index}`,
        source: edge.source,
        target: edge.target,
        relationship: edge.relationship || 'related_to',
      },
    });
  });

  return elements;
}

function initializeGraph(elements) {
  if (!relationshipGraph || typeof cytoscape !== 'function') return;

  graphInstance = cytoscape({
    container: relationshipGraph,
    elements,
    style: [
      {
        selector: 'node',
        style: {
          'background-color': 'data(nodeColor)',
          'shape': 'data(nodeShape)',
          'label': 'data(iconLabel)',
          'color': '#e2e8f0',
          'font-size': 9,
          'font-weight': 700,
          'text-valign': 'center',
          'text-halign': 'center',
          'width': 54,
          'height': 54,
          'border-width': 2,
          'border-color': '#0f172a',
        },
      },
      {
        selector: 'node:selected',
        style: {
          'border-color': '#f8fafc',
          'border-width': 3,
        },
      },
      {
        selector: 'edge',
        style: {
          'curve-style': 'bezier',
          'width': 2,
          'line-color': '#475569',
          'target-arrow-color': '#475569',
          'target-arrow-shape': 'triangle',
          'arrow-scale': 0.8,
          'label': 'data(relationship)',
          'font-size': 8,
          'text-background-color': '#0b1220',
          'text-background-opacity': 0.8,
          'text-background-padding': 2,
          'color': '#94a3b8',
        },
      },
    ],
    layout: {
      name: 'cose',
      animate: true,
      animationDuration: 450,
      padding: 24,
      fit: true,
    },
  });

  graphInstance.on('tap', 'node', (event) => {
    const node = event.target;
    graphNodeHint.textContent = `${node.data('type')} selected.`;
    graphNodeDetails.textContent = formatGraphNodeDetails(node);
  });
}

function renderGraph(graph) {
  const nodeCount = Array.isArray(graph.nodes) ? graph.nodes.length : 0;
  const edgeCount = Array.isArray(graph.edges) ? graph.edges.length : 0;

  if (!nodeCount) {
    graphStatus.textContent = 'No graph data is available for this investigation yet.';
    if (graphNodeDetails) graphNodeDetails.textContent = 'No node selected.';
    return;
  }

  graphStatus.textContent = `Graph loaded with ${nodeCount} node${nodeCount === 1 ? '' : 's'} and ${edgeCount} edge${edgeCount === 1 ? '' : 's'}.`;

  const elements = toGraphElements(graph);
  if (!graphInstance) {
    initializeGraph(elements);
  } else {
    graphInstance.elements().remove();
    graphInstance.add(elements);
    graphInstance.layout({ name: 'cose', animate: true, animationDuration: 350, padding: 24, fit: true }).run();
  }
}

function renderMitreMappings(payload) {
  if (!mitreBody || !mitreStatus) return;

  const mappings = Array.isArray(payload && payload.mappings) ? payload.mappings : [];
  if (!mappings.length) {
    mitreBody.innerHTML = '<tr><td colspan="6" class="empty-state">No ATT&CK mappings were produced from current evidence.</td></tr>';
    mitreStatus.textContent = 'No ATT&CK mappings available. Evidence is currently insufficient for confident mapping.';
    return;
  }

  mitreBody.innerHTML = '';
  mappings.forEach((item) => {
    const evidence = Array.isArray(item.evidence) && item.evidence.length
      ? item.evidence.map((entry) => `<div class="mitre-evidence-item">${entry}</div>`).join('')
      : '<span class="muted">No evidence listed</span>';
    const row = document.createElement('tr');
    row.innerHTML = `
      <td><strong>${item.attack_id || '—'}</strong></td>
      <td>${item.technique || '—'}</td>
      <td>${item.tactic || '—'}</td>
      <td><span class="badge ${item.confidence >= 75 ? 'high' : item.confidence >= 50 ? 'medium' : 'low'}">${item.confidence ?? '—'}</span></td>
      <td>${evidence}</td>
      <td>${item.explanation || 'No explanation provided.'}</td>
    `;
    mitreBody.appendChild(row);
  });

  mitreStatus.textContent = `Loaded ${mappings.length} ATT&CK mapping${mappings.length === 1 ? '' : 's'} for this case.`;
}

function scrollCopilotToBottom() {
  if (!copilotHistory) return;
  copilotHistory.scrollTop = copilotHistory.scrollHeight;
}

function renderCopilotMessages(messages) {
  if (!copilotHistory) return;
  copilotHistory.innerHTML = '';

  if (!messages || !messages.length) {
    copilotMessagesCache = [];
    copilotHistory.innerHTML = '<p class="subtitle">No conversation yet. Use quick actions or ask a case question.</p>';
    return;
  }

  copilotMessagesCache = messages;

  messages.forEach((entry) => {
    const role = entry.role === 'assistant' ? 'assistant' : 'user';
    const bubble = document.createElement('div');
    bubble.className = `copilot-message ${role}`;
    const ts = entry.timestamp ? new Date(entry.timestamp).toLocaleString() : 'Unknown time';
    bubble.innerHTML = `
      <div class="copilot-meta"><strong>${role === 'assistant' ? 'Copilot' : 'You'}</strong> <span class="muted">${ts}</span></div>
      <pre>${entry.message || ''}</pre>
    `;
    copilotHistory.appendChild(bubble);
    if (role === 'assistant' && entry.message) {
      lastAssistantMessage = entry.message;
    }
  });

  scrollCopilotToBottom();
}

async function loadCopilotHistory() {
  if (!copilotHistory) return;
  try {
    const response = await authApiFetch(`/investigations/${currentCaseId}/chat?order=asc&limit=500`, {
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) throw new Error('Chat endpoint unavailable');
    const data = await response.json();
    renderCopilotMessages(data.messages || []);
    copilotStatus.textContent = 'Conversation history loaded for this case.';
  } catch (error) {
    copilotStatus.textContent = 'Unable to load copilot history.';
  }
}

async function sendCopilotMessage({ message, quickAction }) {
  if (!copilotForm) return;

  const payload = {
    message: message || '',
    quick_action: quickAction || undefined,
  };

  copilotStatus.textContent = 'Copilot is analyzing this investigation...';

  try {
    const response = await authApiFetch(`/investigations/${currentCaseId}/chat`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify(payload),
    });

    if (!response.ok) throw new Error('Unable to send chat message');

    const data = await response.json();
    renderCopilotMessages((data.messages && data.messages.length)
      ? [...copilotMessagesCache, ...data.messages]
      : copilotMessagesCache);

    // Reload authoritative persisted history to avoid drift.
    await loadCopilotHistory();
    copilotStatus.textContent = 'Grounded response generated from this investigation.';
  } catch (error) {
    copilotStatus.textContent = 'Copilot could not process this request right now.';
  }
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
    const response = await authApiFetch(`/investigations/${currentCaseId}/intel`, {
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

async function loadTimeline() {
  if (!timelineContainer) return;
  try {
    const response = await authApiFetch(`/investigations/${currentCaseId}/timeline?order=desc&limit=100`, { headers: { Accept: 'application/json' } });
    if (!response.ok) throw new Error('Timeline endpoint unavailable');
    const data = await response.json();
    renderTimeline(data);
  } catch (err) {
    timelineContainer.textContent = 'Unable to load timeline.';
  }
}

async function loadRelationshipGraph() {
  if (!relationshipGraph) return;
  try {
    const response = await authApiFetch(`/investigations/${currentCaseId}/graph`, {
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) throw new Error('Graph endpoint unavailable');
    const data = await response.json();
    renderGraph(data);
  } catch (error) {
    graphStatus.textContent = 'Unable to load relationship graph.';
  }
}

async function loadMitreMappings() {
  if (!mitreBody || !mitreStatus) return;
  try {
    const response = await authApiFetch(`/investigations/${currentCaseId}/mitre`, {
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) throw new Error('MITRE endpoint unavailable');
    const data = await response.json();
    renderMitreMappings(data);
  } catch (error) {
    mitreStatus.textContent = 'Unable to load ATT&CK mappings right now.';
    mitreBody.innerHTML = '<tr><td colspan="6" class="empty-state">ATT&CK mappings are unavailable.</td></tr>';
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
    const response = await authApiFetch(`/investigations/${currentCaseId}`, {
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
    const response = await authApiFetch(`/investigations/${currentCaseId}`, {
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

if (copilotForm) {
  copilotForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    const text = (copilotInput.value || '').trim();
    if (!text) {
      copilotStatus.textContent = 'Enter a question or use a quick action.';
      return;
    }
    copilotInput.value = '';
    await sendCopilotMessage({ message: text });
  });
}

if (copilotQuickActions) {
  copilotQuickActions.addEventListener('click', async (event) => {
    const button = event.target.closest('button[data-action]');
    if (!button) return;
    const action = button.dataset.action;
    if (!action) return;
    await sendCopilotMessage({ message: '', quickAction: action });
  });
}

if (clearCopilotBtn) {
  clearCopilotBtn.addEventListener('click', async () => {
    try {
      const response = await authApiFetch(`/investigations/${currentCaseId}/chat`, {
        method: 'DELETE',
        headers: { Accept: 'application/json' },
      });
      if (!response.ok) throw new Error('Unable to clear chat');
      lastAssistantMessage = '';
      await loadCopilotHistory();
      copilotStatus.textContent = 'Conversation cleared for this case.';
    } catch (error) {
      copilotStatus.textContent = 'Unable to clear conversation right now.';
    }
  });
}

if (copyLastResponseBtn) {
  copyLastResponseBtn.addEventListener('click', async () => {
    if (!lastAssistantMessage) {
      copilotStatus.textContent = 'No assistant response available to copy.';
      return;
    }
    try {
      await navigator.clipboard.writeText(lastAssistantMessage);
      copilotStatus.textContent = 'Last copilot response copied.';
    } catch (error) {
      copilotStatus.textContent = 'Clipboard copy failed.';
    }
  });
}

loadInvestigation();
loadThreatIntel();
setInterval(() => {
  loadThreatIntel();
}, 5000);
loadTimeline();
setInterval(() => {
  loadTimeline();
}, 5000);
loadRelationshipGraph();
setInterval(() => {
  loadRelationshipGraph();
}, 7000);
loadMitreMappings();
setInterval(() => {
  loadMitreMappings();
}, 7000);
loadCopilotHistory();
