const form = document.getElementById('iocForm');
const iocInput = document.getElementById('iocInput');
const status = document.getElementById('iocStatus');
const resultSection = document.getElementById('iocResult');
const iocTypeValue = document.getElementById('iocTypeValue');
const reputationBadge = document.getElementById('reputationBadge');
const reputationValue = document.getElementById('reputationValue');
const normalizedOutput = document.getElementById('normalizedOutput');
const summaryOutput = document.getElementById('summaryOutput');
const enrichmentOutput = document.getElementById('enrichmentOutput');
const iocCaseId = document.getElementById('iocCaseId');
const caseIdBanner = document.getElementById('caseIdBanner');

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  const value = iocInput.value.trim();
  if (!value) {
    status.textContent = 'Enter an IOC value to analyze.';
    return;
  }

  status.textContent = 'Analyzing IOC…';
  try {
    const response = await fetch('/ioc-analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ioc_value: value }),
    });

    if (!response.ok) {
      throw new Error('Unable to analyze IOC');
    }

    const data = await response.json();
    iocTypeValue.textContent = data.ioc_type || 'Unknown';
    reputationValue.textContent = data.reputation_score ?? 0;
    reputationBadge.className = `verdict ${data.reputation_score >= 80 ? 'high' : data.reputation_score >= 60 ? 'medium' : 'low'}`;
    reputationBadge.textContent = data.reputation_score >= 80 ? 'High Risk' : data.reputation_score >= 60 ? 'Moderate Risk' : 'Low Risk';
    normalizedOutput.textContent = JSON.stringify(data.normalized, null, 2);
    summaryOutput.textContent = data.summary || 'No summary available.';
    enrichmentOutput.textContent = JSON.stringify(data.enrichment, null, 2);

    if (data.case_id) {
      iocCaseId.textContent = data.case_id;
      caseIdBanner.classList.remove('hidden');
    } else {
      caseIdBanner.classList.add('hidden');
    }

    resultSection.classList.remove('hidden');
    status.textContent = 'IOC analysis saved to the investigation case history.';
  } catch (error) {
    status.textContent = 'IOC analysis failed. Please try again.';
  }
});
