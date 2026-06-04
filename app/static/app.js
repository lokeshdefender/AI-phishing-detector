const el = (id) => document.getElementById(id);
const analyzeBtn = el('analyzeBtn');

function verdictFromScore(score){
  if(score >= 70) return {label: 'High Risk', cls: 'high'};
  if(score >= 35) return {label: 'Medium Risk', cls: 'medium'};
  return {label: 'Low Risk', cls: 'low'};
}

analyzeBtn.addEventListener('click', async () =>{
  const text = el('emailText').value.trim();
  if(!text) return alert('Paste email text first');
  analyzeBtn.disabled = true;
  analyzeBtn.textContent = 'Analyzing...';
  try{
    const res = await fetch('/analyze', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({email_text: text})
    });
    const data = await res.json();
    el('scoreVal').textContent = data.score;
    el('confidenceVal').textContent = data.confidence ?? 0;
    el('senderVal').textContent = data.sender || 'unknown';
    const v = verdictFromScore(data.score);
    const verdictEl = el('verdict');
    verdictEl.textContent = v.label;
    verdictEl.className = 'verdict ' + v.cls;

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

    el('result').classList.remove('hidden');
  }catch(e){
    alert('Analysis failed: '+e.message);
  }finally{
    analyzeBtn.disabled = false;
    analyzeBtn.textContent = 'Analyze';
  }
});
