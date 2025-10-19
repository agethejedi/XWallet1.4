// =========================================
// X-Wallet v1.3 — SafeSend Modal + Animated Meter
// =========================================
import { ethers } from "https://esm.sh/ethers@6.13.2";

document.addEventListener("DOMContentLoaded", () => {

const RPCS = { sep: "https://eth-sepolia.g.alchemy.com/v2/kxHg5y9yBXWAb9cOcJsf0" };
const SAFE_SEND_URL = "https://xwalletv1dot2.agedotcom.workers.dev/check";

const $  = (q) => document.querySelector(q);
const $$ = (q) => [...document.querySelectorAll(q)];

const state = {
  unlocked: false,
  provider: null,
  decryptedPhrase: null,
  accounts: [],
  signerIndex: 0,
};

function lock() {
  state.unlocked = false;
  state.provider = null;
  state.decryptedPhrase = null;
  state.accounts = [];
  const ls = $("#lockState"); if (ls) ls.textContent = "Locked";
}

/* ===============================
   SafeSend Fetch + Modal
================================ */
async function fetchSafeSend(address) {
  try {
    const u = new URL(SAFE_SEND_URL);
    u.searchParams.set("address", address);
    u.searchParams.set("chain", "sepolia");
    const r = await fetch(u.toString());
    if (!r.ok) throw new Error("SafeSend backend error");
    return await r.json();
  } catch (e) {
    console.warn("SafeSend fetch failed", e);
    return { score: 40, findings: [{ label: "Service", detail: "SafeSend unavailable", level: "medium" }] };
  }
}

// Animate the meter
function animateMeter(score) {
  const bar = $("#riskMeterBar");
  const text = $("#riskScoreText");
  let current = 0;
  const step = () => {
    current += (score - current) * 0.2;
    bar.style.width = `${current}%`;
    bar.style.background = `linear-gradient(90deg, green, yellow ${50 - current/2}%, red ${current}%)`;
    text.textContent = `Risk score: ${Math.round(current)}`;
    if (Math.abs(current - score) > 0.5) requestAnimationFrame(step);
  };
  step();
}

function showRiskModal(result) {
  const modal = $("#riskModal");
  const factors = $("#riskFactors");
  const warning = $("#riskWarning");
  const agree = $("#riskAgree");
  const proceed = $("#riskProceed");
  const cancel = $("#riskCancel");

  // populate
  factors.innerHTML = result.findings.map(f =>
    `<div class="factor factor--${f.level}">
       <span class="factor__badge">${f.level}</span> ${f.detail}
     </div>`).join("");

  warning.style.display = result.score >= 60 ? "block" : "none";
  proceed.disabled = result.score >= 60;

  animateMeter(result.score);
  modal.classList.add("active");

  agree?.addEventListener("change", () => {
    proceed.disabled = result.score >= 60 && !agree.checked;
  });

  cancel.onclick = () => modal.classList.remove("active");
  $("#riskClose").onclick = () => modal.classList.remove("active");
}

async function sendEthFlow() {
  const to = $("#sendTo").value.trim();
  const amt = $("#sendAmt").value.trim();
  if (!ethers.isAddress(to)) return alert("Invalid recipient");

  const n = Number(amt);
  if (isNaN(n) || n <= 0) return alert("Invalid amount");

  const acct = state.accounts[state.signerIndex];
  if (!acct || !state.provider) return alert("Unlock first");

  $("#sendOut").textContent = "Checking SafeSend…";
  const check = await fetchSafeSend(to);
  $("#sendOut").textContent = `SafeSend score ${check.score}`;
  showRiskModal(check);
}

// Event binding
$("#doSend")?.addEventListener("click", sendEthFlow);

});
