document.getElementById("scanBtn").addEventListener("click", async () => {
  let [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  let url = tab.url;

  let res = await fetch("http://127.0.0.1:5000/analyze", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ url: url })
  });

  let data = await res.json();

  let resultBox = document.getElementById("resultBox");
  let verdict = document.getElementById("verdict");
  let confidence = document.getElementById("confidence");
  let riskList = document.getElementById("riskList");

  resultBox.classList.remove("hidden");
  riskList.innerHTML = "";

  let analysis = data.analysis;

// Ensure this part in your popup.js matches the new classes
if (analysis.verdict === "Phishing") {
    verdict.innerText = "🚨 PHISHING DETECTED";
    verdict.className = "danger";
} else if (analysis.verdict === "Legitimate") {
    verdict.innerText = "🛡️ SECURE SITE";
    verdict.className = "safe";
} else {
    verdict.innerText = "❓ UNCERTAIN";
    verdict.className = "warning";
}
  confidence.innerText = "Confidence: " + (analysis.confidence * 100).toFixed(1) + "%";

  // ⚠️ Risk Factors
  if (analysis.risk_factors.length === 0) {
    let li = document.createElement("li");
    li.innerText = "No major risks detected";
    riskList.appendChild(li);
  } else {
    analysis.risk_factors.forEach(factor => {
      let li = document.createElement("li");
      li.innerText = factor;
      riskList.appendChild(li);
    });
  }
});