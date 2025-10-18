import express from "express";
import cors from "cors";
import fetch from "node-fetch";
import dotenv from "dotenv";

dotenv.config();
const app = express();
app.use(cors());

const PORT = process.env.PORT || 3001;
const ETHERSCAN_API_KEY = process.env.ETHERSCAN_API_KEY;

// ---- Explorers ----
const HOST = {
  sepolia: "api-sepolia.etherscan.io",
  mainnet: "api.etherscan.io",
  polygon: "api.polygonscan.com",
};

// ---- Lists ----
const blocklist = new Set(["0x000000000000000000000000000000000000dead"]);
const allowlist = new Set([]);

// ---- Helper ----
async function scan(host, query) {
  const url = `https://${host}/api${query}&apikey=${ETHERSCAN_API_KEY}`;
  const r = await fetch(url);
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}

// ===== SafeSend route =====
app.get("/check", async (req, res) => {
  try {
    const address = (req.query.address || "").toLowerCase();
    const chain = (req.query.chain || "sepolia").toLowerCase();
    const host = HOST[chain] || HOST.sepolia;

    if (!address.startsWith("0x")) {
      return res.status(400).json({ error: "address required" });
    }
    if (blocklist.has(address))
      return res.json({ score: 95, findings: ["Blocklist match: known scam"] });
    if (allowlist.has(address))
      return res.json({ score: 5, findings: ["Allowlist: low risk"] });

    let score = 20;
    const findings = [];

    // 1) contract check
    const code = await scan(host, `?module=proxy&action=eth_getCode&address=${address}&tag=latest`);
    if (code?.result && code.result !== "0x") {
      score += 30;
      findings.push("Address is a contract");
    }

    // 2) tx history / age
    const txs = await scan(
      host,
      `?module=account&action=txlist&address=${address}&startblock=0&endblock=99999999&sort=asc`
    );
    if (txs.status === "1") {
      const list = txs.result || [];
      if (list.length === 0) {
        score += 30; findings.push("No transactions (new address)");
      } else {
        const first = list[0];
        const ageSec = Date.now() / 1000 - Number(first.timeStamp || 0);
        if (ageSec < 2 * 24 * 3600) {
          score += 20; findings.push("Very new address (<2 days)");
        } else {
          findings.push("Has transaction history");
        }
      }
    } else {
      findings.push("Explorer returned no tx data");
    }

    score = Math.max(0, Math.min(100, score));
    res.json({ score, findings });
  } catch (e) {
    console.error("SafeSend error:", e);
    res.status(500).json({ score: 50, findings: ["SafeSend backend error", String(e.message || e)] });
  }
});

// ===== CoinGecko proxy (60s cache) =====
const CG_CACHE = new Map();
function cgCacheGet(key) {
  const hit = CG_CACHE.get(key);
  if (!hit) return null;
  if (Date.now() - hit.ts > 60_000) return null; // 60s TTL
  return hit.data;
}
function cgCacheSet(key, data) {
  CG_CACHE.set(key, { ts: Date.now(), data });
}

// GET /market/chart?id=ethereum&days=1&interval=minute
app.get("/market/chart", async (req, res) => {
  try {
    const id = (req.query.id || "ethereum").toString();
    const days = (req.query.days || "1").toString();
    const interval = (req.query.interval || "minute").toString();

    const cacheKey = `${id}|${days}|${interval}`;
    const cached = cgCacheGet(cacheKey);
    if (cached) return res.json(cached);

    const url = `https://api.coingecko.com/api/v3/coins/${encodeURIComponent(id)}/market_chart?vs_currency=usd&days=${encodeURIComponent(days)}&interval=${encodeURIComponent(interval)}`;

    const headers = {};
    if (process.env.COINGECKO_API_KEY) {
      headers["x-cg-pro-api-key"] = process.env.COINGECKO_API_KEY;
    }

    const r = await fetch(url, { headers });
    if (!r.ok) throw new Error(`CoinGecko ${r.status}`);
    const data = await r.json();

    cgCacheSet(cacheKey, data);
    res.json(data);
  } catch (e) {
    console.error("CoinGecko proxy error:", e);
    res.status(500).json({ error: "coingecko_failed", message: String(e.message || e) });
  }
});

// Health that reports whether /market/chart is registered
app.get("/health", (req, res) => {
  const hasCG = !!app._router.stack.find(l => l.route?.path === "/market/chart");
  res.json({
    ok: true,
    build: "safesend-etherscan-v1.1",
    hasKey: !!process.env.ETHERSCAN_API_KEY,
    hasCG
  });
});
// Debug: list registered routes at startup
console.log(
  "Routes:",
  app._router.stack
    .filter(l => l.route)
    .map(l => `${Object.keys(l.route.methods).join(',').toUpperCase()} ${l.route.path}`)
);

app.listen(PORT, () => {
  console.log(`✅ SafeSend running on http://localhost:${PORT}`);
});
