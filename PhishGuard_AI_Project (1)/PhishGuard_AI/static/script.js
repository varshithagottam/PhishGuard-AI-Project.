const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => document.querySelectorAll(selector);

function toast(message) {
  const box = $("#toast");
  box.textContent = message;
  box.classList.add("show");
  setTimeout(() => box.classList.remove("show"), 2800);
}

function showPage(pageName) {
  $$(".page").forEach(page => page.classList.toggle("active", page.id === pageName));
  $$(".nav-link").forEach(link => link.classList.toggle("active", link.dataset.page === pageName));
  const titles = {overview:"Security Overview",scanner:"AI Message Scanner",history:"Detection History",analytics:"Analytics",awareness:"Cyber Awareness"};
  $("#page-title").textContent = titles[pageName] || "PhishGuard AI";
  if (pageName === "history") loadHistory();
  if (pageName === "analytics" || pageName === "overview") loadStats();
}

$$(".nav-link").forEach(button => button.addEventListener("click", () => showPage(button.dataset.page)));
$$("[data-go]").forEach(button => button.addEventListener("click", () => showPage(button.dataset.go)));

$$(".tab").forEach(tab => tab.addEventListener("click", () => {
  $$(".tab").forEach(item => item.classList.toggle("active", item === tab));
  $("#text-mode").classList.toggle("hidden", tab.dataset.mode !== "text");
  $("#upload-mode").classList.toggle("hidden", tab.dataset.mode !== "upload");
}));

$("#message-input").addEventListener("input", () => {
  $("#char-count").textContent = `${$("#message-input").value.length} / 10000`;
});
$("#file-input").addEventListener("change", () => {
  $("#file-name").textContent = $("#file-input").files[0]?.name || "No file selected";
});

async function analyze(formData) {
  const button = $("#analyze-btn");
  button.disabled = true;
  button.textContent = "Analyzing message...";
  try {
    const response = await fetch("/api/detect", {method:"POST", body:formData});
    const data = await response.json();
    if (!response.ok || !data.success) throw new Error(data.error || "Analysis failed.");
    displayResult(data);
    await loadStats();
    toast("Message analysis completed.");
  } catch (error) {
    toast(error.message);
  } finally {
    button.disabled = false;
    button.innerHTML = 'Analyze with AI <span>→</span>';
  }
}

$("#analyze-btn").addEventListener("click", () => {
  const activeMode = $(".tab.active").dataset.mode;
  const formData = new FormData();
  if (activeMode === "text") {
    const message = $("#message-input").value.trim();
    if (!message) return toast("Please paste a message first.");
    formData.append("message", message);
  } else {
    const file = $("#file-input").files[0];
    if (!file) return toast("Please choose a TXT or CSV file.");
    formData.append("file", file);
  }
  analyze(formData);
});

$("#quick-scan").addEventListener("click", () => {
  const message = $("#quick-message").value.trim();
  if (!message) return toast("Paste a message first.");
  $("#message-input").value = message;
  $("#char-count").textContent = `${message.length} / 10000`;
  showPage("scanner");
  const formData = new FormData();
  formData.append("message", message);
  analyze(formData);
});

function displayResult(data) {
  const result = data.result;
  const phishing = result.prediction === "Phishing";
  $("#result-panel").classList.remove("hidden");
  $("#result-badge").textContent = phishing ? "⚠ PHISHING DETECTED" : "✓ LEGITIMATE PREDICTION";
  $("#result-badge").classList.toggle("safe", !phishing);
  $("#result-title").textContent = phishing ? "Potential phishing message" : "No phishing detected";
  $("#result-advice").textContent = result.advice;
  $("#risk-value").textContent = `${result.risk_score}%`;
  $("#risk-ring").style.background = `conic-gradient(${phishing ? "#ff7184" : "#43d6a0"} ${result.risk_score * 3.6}deg, #27374e 0deg)`;
  $("#confidence-value").textContent = `${result.confidence}%`;
  $("#analyzed-message").textContent = data.message;
  $("#indicator-list").replaceChildren();
  result.indicators.forEach(indicator => {
    const li = document.createElement("li");
    li.textContent = indicator;
    $("#indicator-list").appendChild(li);
  });
  $("#result-panel").scrollIntoView({behavior:"smooth", block:"start"});
}

async function loadStats() {
  try {
    const response = await fetch("/api/stats");
    const stats = await response.json();
    $("#total-stat").textContent = stats.total;
    $("#phishing-stat").textContent = stats.phishing;
    $("#legitimate-stat").textContent = stats.legitimate;
    $("#risk-stat").textContent = `${stats.average_risk}%`;
    $("#a-total").textContent = stats.total;
    $("#a-phishing").textContent = stats.phishing;
    $("#a-legitimate").textContent = stats.legitimate;
    const phishingPct = stats.total ? Math.round(stats.phishing / stats.total * 100) : 0;
    const legitimatePct = stats.total ? 100 - phishingPct : 0;
    $("#phishing-percent").textContent = `${phishingPct}%`;
    $("#legitimate-percent").textContent = `${legitimatePct}%`;
    $("#phishing-bar").style.width = `${phishingPct}%`;
    $("#legitimate-bar").style.width = `${legitimatePct}%`;
  } catch (error) { console.error(error); }
}

async function loadHistory() {
  try {
    const response = await fetch("/api/history");
    const rows = await response.json();
    const body = $("#history-body");
    body.replaceChildren();
    if (!rows.length) {
      const tr = document.createElement("tr");
      const td = document.createElement("td");
      td.colSpan = 4; td.className = "empty-cell";
      td.textContent = "No scans yet. Analyze a message to get started.";
      tr.appendChild(td); body.appendChild(tr); return;
    }
    rows.forEach(row => {
      const tr = document.createElement("tr");
      const message = document.createElement("td");
      message.className = "message-cell"; message.textContent = row.message;
      const result = document.createElement("td");
      const chip = document.createElement("span");
      chip.className = `status-chip ${row.prediction === "Phishing" ? "bad" : "good"}`;
      chip.textContent = row.prediction; result.appendChild(chip);
      const risk = document.createElement("td"); risk.textContent = `${row.risk_score}%`;
      const date = document.createElement("td"); date.textContent = row.created_at;
      [message,result,risk,date].forEach(cell => tr.appendChild(cell));
      body.appendChild(tr);
    });
  } catch (error) { toast("Could not load history."); }
}
$("#refresh-history").addEventListener("click", loadHistory);
$("#refresh-analytics").addEventListener("click", loadStats);
loadStats();
