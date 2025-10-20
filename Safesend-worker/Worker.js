// worker.js — SafeSend Worker + CoinGecko proxy (demo/pro-safe)
export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const origin = req.headers.get("Origin") || "";

    // CORS preflight
    if (req.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders(origin) });
    }

    if (url.pathname === "/health") {
      return json({ ok: true, build: "safesend-cloudflare-v1.2" }, 200, origin);
    }

    if (url.pathname === "/check") {
      return handleCheck(url, env, origin);
    }

    if (url.pathname === "/market/price") {
      return handleMarketPrice(url, env, origin);
    }

    return new Response("Not Found", { status: 404, headers: corsHeaders(origin) });
  },
};

// ---------- CORS / JSON ----------
function corsHeaders(origin) {
  // allow your app origins
  const ALLOW = new Set([
    "https://agethejedi.github.io",
    "http://localhost:8080",
    "http://127.0.0.1:8080",
  ]);
  const allowed = origin && ALLOW.has(origin);
  return {
    "Access-Control-Allow-Origin": allowed ? origin : "https://agethejedi.github.io",
    "Vary": "Origin",
    "Access-Control-Allow-Methods": "GET,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Max-Age": "86400",
  };
}
function json(data, status = 200, origin = "") {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json", ...corsHeaders(origin) },
  });
}

// ---------- /market/price (CoinGecko Simple Price proxy) ----------
async function handleMarketPrice(url, env, origin) {
  // sanitize params
  const idsRaw = (url.searchParams.get("ids") || "").trim();
  const vs = (url.searchParams.get("vs") || "usd").trim().toLowerCase();

  if (!idsRaw) return json({ error: "missing_ids" }, 400, origin);

  // ensure comma-separated without spaces
  const ids = idsRaw.split(",").map(s => s.trim()).filter(Boolean).join(",");

  const cgURL = new URL("https://api.coingecko.com/api/v3/simple/price");
  cgURL.searchParams.set("ids", ids);
  cgURL.searchParams.set("vs_currencies", vs);
  cgURL.searchParams.set("include_24hr_change", "true");

  const headers = {};
  // IMPORTANT: send both headers so demo OR pro keys work
  if (env.COINGECKO_API_KEY) {
    headers["x-cg-pro-api-key"] = env.COINGECKO_API_KEY;
    headers["x-cg-demo-api-key"] = env.COINGECKO_API_KEY;
  }

  try {
    const res = await fetch(cgURL.toString(), {
      headers,
      // cache at the edge to prevent 429s and smooth load
      cf: { cacheTtl: 60, cacheEverything: true },
    });

    // pass through CG error details for easier debugging
    if (!res.ok) {
      const text = await res.text().catch(() => "");
      return json({ error: "coingecko_failed", status: res.status, body: text }, res.status, origin);
    }

    const data = await res.json();
    return new Response(JSON.stringify(data), {
      status: 200,
      headers: {
        "content-type": "application/json",
        ...corsHeaders(origin),
        "Cache-Control": "public, max-age=60",
      },
    });
  } catch (e) {
    return json({ error: "coingecko_request_error", message: String(e) }, 500, origin);
  }
}

// ---------- /check (SafeSend) ----------
async function handleCheck(url, env, origin) {
  const address = (url.searchParams.get("address") || "").toLowerCase();
  const chain = (url.searchParams.get("chain") || "sepolia").toLowerCase();
  if (!address.startsWith("0x")) return json({ error: "address required" }, 400, origin);

  const HOSTS = {
    sepolia: "api-sepolia.etherscan.io",
    mainnet: "api.etherscan.io",
    polygon: "api.polygonscan.com",
  };
  const host = HOSTS[chain] || HOSTS.sepolia;

  const blocklist = new Set(["0x000000000000000000000000000000000000dead"]);
  const allowlist = new Set();

  if (blocklist.has(address)) return json({ score: 95, findings: ["Blocklist match"] }, 200, origin);
  if (allowlist.has(address)) return json({ score: 5, findings: ["Allowlist"] }, 200, origin);

  let score = 20;
  const findings = [];

  try {
    const codeUrl = `https://${host}/api?module=proxy&action=eth_getCode&address=${address}&tag=latest&apikey=${env.ETHERSCAN_API_KEY||""}`;
    const codeRes = await fetch(codeUrl);
    const code = await codeRes.json();
    if (code?.result && code.result !== "0x") { score += 30; findings.push("Address is a contract"); }
  } catch { findings.push("Etherscan code check failed"); }

  try {
    const txUrl = `https://${host}/api?module=account&action=txlist&address=${address}&startblock=0&endblock=99999999&sort=asc&apikey=${env.ETHERSCAN_API_KEY||""}`;
    const txRes = await fetch(txUrl);
    const txs = await txRes.json();
    if (txs.status === "1") {
      const list = txs.result || [];
      if (list.length === 0) { score += 30; findings.push("No history"); }
      else {
        const first = list[0];
        const ageSec = Date.now()/1000 - Number(first.timeStamp || 0);
        if (ageSec < 48*3600) { score += 20; findings.push("Very new address"); }
        else findings.push("Has history");
      }
    } else findings.push("Explorer returned no tx data");
  } catch { findings.push("Etherscan tx fetch failed"); }

  score = Math.max(0, Math.min(100, score));
  return json({ score, findings }, 200, origin);
}
// ---- /account/txs ----
if (url.pathname === "/account/txs") {
  return handleAccountTxs(url, env, origin);
}

async function handleAccountTxs(url, env, origin) {
  const address = url.searchParams.get("address") || "";
  const chain = (url.searchParams.get("chain") || "sepolia").toLowerCase();
  if (!address.startsWith("0x"))
    return json({ error: "address required" }, 400, origin);

  const HOSTS = {
    sepolia: "api-sepolia.etherscan.io",
    mainnet: "api.etherscan.io",
    polygon: "api.polygonscan.com",
  };
  const host = HOSTS[chain] || HOSTS.sepolia;

  const api = `https://${host}/api?module=account&action=txlist&address=${encodeURIComponent(
    address
  )}&startblock=0&endblock=99999999&sort=desc&apikey=${env.ETHERSCAN_API_KEY}`;

  try {
    const r = await fetch(api, { cf: { cacheTtl: 60, cacheEverything: true } });
    const j = await r.json();
    if (j.status !== "1" || !Array.isArray(j.result)) {
      return json({ error: "etherscan_failed", j }, 502, origin);
    }
    const top10 = j.result.slice(0, 10);
    return new Response(JSON.stringify({ txs: top10 }), {
      status: 200,
      headers: {
        "content-type": "application/json",
        ...corsHeaders(origin),
        "Cache-Control": "public, max-age=60",
      },
    });
  } catch (e) {
    return json({ error: "tx_fetch_failed", message: e.message }, 500, origin);
  }
}