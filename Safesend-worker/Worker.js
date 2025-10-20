// worker.js — SafeSend risk service (Alchemy-only)

// ---------------- CORS ----------------
function corsHeaders(origin) {
  // Echo the caller origin if present, otherwise allow GitHub Pages (your app)
  const allow = origin || "https://agethejedi.github.io";
  return {
    "Access-Control-Allow-Origin": allow,
    "Access-Control-Allow-Methods": "GET,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Max-Age": "86400",
    "Content-Type": "application/json; charset=utf-8",
    "Vary": "Origin",
  };
}

// ---------------- utils ----------------
const isHexAddr = (s) => /^0x[a-fA-F0-9]{40}$/.test(s);
function clamp(n, lo, hi){ return Math.max(lo, Math.min(hi, n)); }
function nowMs(){ return Date.now(); }
function parseCSVSecret(v){
  if (!v) return [];
  return String(v)
    .split(/[,\s]+/)
    .map(x => x.trim().toLowerCase())
    .filter(Boolean);
}
function severityWeight(sev){
  switch(sev){
    case "critical": return 60;
    case "high":     return 35;
    case "med":      return 15;
    default:         return 5;   // low
  }
}
function scoreFromFactors(factors){
  const s = factors.reduce((sum,f)=> sum + severityWeight(f.severity||"low"), 0);
  return clamp(s, 0, 100);
}
function decisionFromScore(score){
  if (score >= 80) return "block";
  if (score >= 60) return "review";
  return "allow";
}

// ---------------- Alchemy RPC ----------------
function chainToAlchemyUrl(env, chain){
  const c = (chain || "sepolia").toLowerCase();
  if (c === "sepolia") return env.ALCHEMY_SEPOLIA_URL;
  if (c === "mainnet") return env.ALCHEMY_MAINNET_URL;
  if (c === "polygon") return env.ALCHEMY_POLYGON_URL;
  // Default to Sepolia if unknown
  return env.ALCHEMY_SEPOLIA_URL;
}

async function rpc(url, method, params = [], timeoutMs = 8000) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!res.ok) throw new Error(`rpc_http_${res.status}`);
  const j = await res.json();
  if (j.error) throw new Error(`rpc_${method}_${j.error.code}:${j.error.message}`);
  return j.result;
}

async function getCode(url, address) {
  // eth_getCode returns "0x" for EOAs, bytecode hex for contracts
  return rpc(url, "eth_getCode", [address, "latest"]);
}

async function getTransfers(url, address, { limit = 25 } = {}) {
  const base = {
    fromBlock: "0x0",
    toBlock: "latest",
    category: ["external"], // ETH transfers only (no ERC20/721); expand if you want
    withMetadata: true,
    excludeZeroValue: false,
    maxCount: "0x" + Math.max(1, Math.min(limit, 100)).toString(16),
    order: "desc",
  };

  const [outRes, inRes] = await Promise.all([
    rpc(url, "alchemy_getAssetTransfers", [{ ...base, fromAddress: address }]).catch(() => ({ transfers: [] })),
    rpc(url, "alchemy_getAssetTransfers", [{ ...base, toAddress: address }]).catch(() => ({ transfers: [] })),
  ]);

  const out = outRes?.transfers || [];
  const inn = inRes?.transfers || [];

  // Normalize: timestamp (ms), value (ETH number), from/to/hash
  const all = [...out, ...inn].map(t => ({
    hash: t.hash,
    from: (t.from || "").toLowerCase(),
    to: (t.to || "").toLowerCase(),
    valueEth: typeof t.value === "number" ? t.value : (t.value ? Number(t.value) : 0),
    tsMs: t.metadata?.blockTimestamp ? Date.parse(t.metadata.blockTimestamp) : 0,
  }));

  // Sort desc by time and cap
  all.sort((a, b) => b.tsMs - a.tsMs);
  return all.slice(0, limit);
}

// ---------------- Heuristics ----------------
async function runHeuristics({ address, ens, chain, amountEth, env }) {
  const alchemyUrl = chainToAlchemyUrl(env, chain);
  const lower = address.toLowerCase();
  const factors = [];

  if (!alchemyUrl) {
    factors.push({ label: "Config", severity: "high", reason: "Missing Alchemy URL for selected chain" });
    return { factors };
  }

  // 1) Static lists
  const badlist = parseCSVSecret(env.BADLIST);
  const badEns  = parseCSVSecret(env.BAD_ENS);

  if (badlist.includes(lower)) {
    factors.push({ label: "Badlist", severity: "critical", reason: "Address appears on internal blocklist" });
  }
  if (ens && badEns.includes(String(ens).toLowerCase())) {
    factors.push({ label: "ENS", severity: "high", reason: `ENS name flagged (${ens})` });
  }

  // 2) Contract code check (eth_getCode via Alchemy)
  try {
    const code = await getCode(alchemyUrl, address);
    if (typeof code === "string" && code !== "0x") {
      factors.push({ label: "Contract", severity: "med", reason: "Address is a contract (eth_getCode != 0x)" });
    }
  } catch (e) {
    factors.push({ label: "RPC", severity: "low", reason: `eth_getCode failed: ${e.message || e}` });
  }

  // 3) Transfers analysis (alchemy_getAssetTransfers)
  let transfers = [];
  try {
    transfers = await getTransfers(alchemyUrl, address, { limit: 50 });
  } catch (e) {
    factors.push({ label: "RPC", severity: "low", reason: `Transfers fetch failed: ${e.message || e}` });
  }

  if (transfers.length === 0) {
    factors.push({ label: "Activity", severity: "med", reason: "No on-chain transfer history" });
  } else {
    // Recency
    const latest = transfers[0];
    const ageMin = (nowMs() - (latest.tsMs || 0)) / 60000;
    if (ageMin < 60) {
      factors.push({ label: "Fresh activity", severity: "low", reason: "Recent transfer in the last hour" });
    }

    // Burst in the last hour
    const in1h = transfers.filter(t => nowMs() - t.tsMs <= 60 * 60 * 1000);
    if (in1h.length >= 10) {
      factors.push({ label: "Bursting", severity: "med", reason: `High activity: ${in1h.length} transfers in last hour` });
    }

    // Dust pattern: many tiny outgoing txs
    const dust = isFinite(Number(env.DUST_THRESHOLD)) ? Number(env.DUST_THRESHOLD) : 0.001; // ETH
    const tinyOut = transfers.filter(t => t.from === lower && t.valueEth > 0 && t.valueEth <= dust).length;
    if (tinyOut >= 5) {
      factors.push({ label: "Dust spam", severity: "med", reason: `Multiple tiny outgoing transfers (${tinyOut})` });
    }

    // If the user is sending a tiny amount and the address tends to do dust, nudge
    if (amountEth && amountEth <= dust) {
      factors.push({ label: "Amount", severity: "low", reason: `Send amount <= dust threshold (${dust} ETH)` });
    }
  }

  return { factors };
}

// ---------------- Worker entry ----------------
export default {
  async fetch(req, env) {
    const origin = req.headers.get("Origin") || "*";

    // Preflight
    if (req.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders(origin) });
    }

    const url = new URL(req.url);

    // Health
    if (url.pathname === "/health") {
      return new Response(JSON.stringify({ ok: true, build: "safesend-alchemy-v1" }), {
        headers: corsHeaders(origin),
      });
    }

    // Main: /check
    if (url.pathname === "/check") {
      const address = (url.searchParams.get("address") || "").trim();
      const chain   = (url.searchParams.get("chain") || "sepolia").toLowerCase();
      const amount  = Number(url.searchParams.get("amount") || "0");
      const ens     = (url.searchParams.get("ens") || "").trim();

      if (!isHexAddr(address)) {
        return new Response(JSON.stringify({
          score: 0,
          decision: "allow",
          factors: [{ label: "Input", severity: "low", reason: "Invalid 0x address" }],
        }), { headers: corsHeaders(origin) });
      }

      let factors = [];
      try {
        const res = await runHeuristics({ address, ens, chain, amountEth: amount, env });
        factors = res.factors || [];
      } catch (e) {
        factors.push({ label: "Engine", severity: "low", reason: `Heuristics failed: ${e.message || e}` });
      }

      const score = scoreFromFactors(factors);
      const decision = decisionFromScore(score);

      return new Response(JSON.stringify({ score, decision, factors }), {
        headers: corsHeaders(origin),
      });
    }

    // 404
    return new Response(JSON.stringify({ error: "Not found" }), {
      status: 404,
      headers: corsHeaders(origin),
    });
  },
};