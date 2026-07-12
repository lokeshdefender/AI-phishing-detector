const el = (id) => document.getElementById(id);
const analyzeBtn = el('analyzeBtn');
const analyzeFileBtn = el('analyzeFileBtn');
const fileInput = el('fileInput');
const dropZone = el('dropZone');
let selectedFile = null;

ensureAuthenticated();
bindLogoutButton();

// Tab switching
document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    const tabId = btn.getAttribute('data-tab');
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
    btn.classList.add('active');
    el(tabId).classList.add('active');
  });
});

function verdictFromScore(score){
  if(score >= 70) return {label: 'High Risk', cls: 'high'};
  if(score >= 35) return {label: 'Medium Risk', cls: 'medium'};
  return {label: 'Low Risk', cls: 'low'};
}

function displayResult(data) {
  el('scoreVal').textContent = data.score;
  el('confidenceVal').textContent = data.confidence ?? 0;
  el('senderVal').textContent = data.sender || 'unknown';

  const caseBanner = el('caseIdBanner');
  const caseValue = el('caseIdValue');
  if (data.case_id) {
    caseValue.textContent = data.case_id;
    caseBanner.classList.remove('hidden');
  } else {
    caseBanner.classList.add('hidden');
  }
  const v = verdictFromScore(data.score);
  const verdictEl = el('verdict');
  verdictEl.textContent = v.label;
  verdictEl.className = 'verdict ' + v.cls;

  // Display analyst report if present
  if(data.analyst_report){
    const report = data.analyst_report;
    
    // Threat level
    const threatLvl = el('threatLevel');
    threatLvl.textContent = `Threat Level: ${report.threat_level} (${report.confidence_percentage}%)`;
    threatLvl.className = `threat-level ${report.threat_level.toLowerCase()}`;
    
    // Executive summary
    el('execSummary').textContent = report.executive_summary;
    
    // Threat assessment
    el('threatAssessment').textContent = report.threat_assessment;
    
    // Key indicators
    const keyIndDiv = el('keyIndicators'); keyIndDiv.innerHTML = '';
    report.key_indicators.forEach(ind => {
      const item = document.createElement('div');
      item.className = 'indicator-item';
      item.innerHTML = `<strong>[${ind.severity}]</strong> ${ind.indicator.replace(/_/g, ' ')}<br/>
        <em>Finding:</em> ${ind.finding}<br/>
        <em>Analysis:</em> ${ind.analyst_comment}`;
      keyIndDiv.appendChild(item);
    });
    
    // Detection rationale
    el('detectionRationale').textContent = report.detection_rationale;
    
    // Remediation recommendations
    const remList = el('remediationList'); remList.innerHTML = '';
    report.remediation_recommendations.forEach(rec => {
      const li = document.createElement('li');
      li.textContent = rec;
      remList.appendChild(li);
    });
    
    el('analystSection').classList.remove('hidden');
  }

  // indicators
  const indList = el('indList'); indList.innerHTML = '';
  data.indicators.forEach(i=>{
    const li = document.createElement('li');
    li.textContent = `${i.reason} (weight=${i.weight})`;
    indList.appendChild(li);
  });

  el('explainText').textContent = data.explanation || '';

  // urls
  const urlList = el('urlList'); urlList.innerHTML = '';
  (data.urls||[]).forEach(u=>{
    const li = document.createElement('li');
    const a = document.createElement('a'); a.href = u; a.textContent = u; a.target = '_blank';
    li.appendChild(a); urlList.appendChild(li);
  });

  // metadata if present
  if(data.metadata){
    el('metaSender').textContent = data.metadata.sender || 'N/A';
    el('metaSubject').textContent = data.metadata.subject || 'N/A';
    el('metaBody').textContent = data.metadata.body_preview || 'N/A';
    el('metadata').classList.remove('hidden');
  } else {
    el('metadata').classList.add('hidden');
  }

  el('result').classList.remove('hidden');
}

// Text analysis
analyzeBtn.addEventListener('click', async () =>{
  const text = el('emailText').value.trim();
  if(!text) return alert('Paste email text first');
  analyzeBtn.disabled = true;
  analyzeBtn.textContent = 'Analyzing...';
  try{
    const res = await authApiFetch('/analyze', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({email_text: text})
    });
    const data = await res.json();
    displayResult(data);
  }catch(e){
    alert('Analysis failed: '+e.message);
  }finally{
    analyzeBtn.disabled = false;
    analyzeBtn.textContent = 'Analyze';
  }
});

// File upload handling
dropZone.addEventListener('click', () => fileInput.click());
fileInput.addEventListener('change', (e) => {
  const f = e.target.files[0];
  if(f && f.name.endsWith('.eml')){
    selectedFile = f;
    dropZone.textContent = '✓ ' + f.name + ' selected';
  } else {
    alert('Please select a valid .eml file');
  }
});

// Drag and drop
dropZone.addEventListener('dragover', (e) => {
  e.preventDefault();
  dropZone.classList.add('dragover');
});
dropZone.addEventListener('dragleave', () => {
  dropZone.classList.remove('dragover');
});
dropZone.addEventListener('drop', (e) => {
  e.preventDefault();
  dropZone.classList.remove('dragover');
  const files = e.dataTransfer.files;
  if(files[0] && files[0].name.endsWith('.eml')){
    selectedFile = files[0];
    dropZone.textContent = '✓ ' + files[0].name + ' selected';
  } else {
    alert('Please drop a valid .eml file');
  }
});

// Analyze uploaded file
analyzeFileBtn.addEventListener('click', async () => {
  if(!selectedFile){
    alert('Please select an .eml file first');
    return;
  }
  analyzeFileBtn.disabled = true;
  analyzeFileBtn.textContent = 'Analyzing...';
  try{
    const formData = new FormData();
    formData.append('file', selectedFile);
    const res = await authApiFetch('/analyze-eml', {
      method: 'POST',
      body: formData
    });
    const data = await res.json();
    if(data.error){
      alert('Error: ' + data.error);
    } else {
      displayResult(data);
    }
  }catch(e){
    alert('Analysis failed: '+e.message);
  }finally{
    analyzeFileBtn.disabled = false;
    analyzeFileBtn.textContent = 'Analyze Uploaded File';
  }
});
