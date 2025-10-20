// SafeSend Worker – Alchemy-only heuristics
// Endpoints:
//   GET /health -> { ok: true }
//   GET /check?address=0x...&chain=sepolia -> { score, decision, factors: [{severity,label,reason}] }

export default {
  async fetch(request, env, ctx) {
    if (request.method === 'OPTIONS') return cors();
    const url = new URL(request.url);
    if (url.pathname === '/health') return cors(json({ ok: true }));

    if (url.pathname === '/check') {
      const address = (url.searchParams.get('address') || '').trim();
      const chain = (url.searchParams.get('chain') || 'sepolia').toLowerCase();

      if (!/^0x[a-fA-F0-9]{40}$/.test(address))
        return cors(jsonError(400, 'invalid_address'));

      if (chain !== 'sepolia')
        return cors(jsonError(400, 'unsupported_chain'));

      try {
        const res = await runRiskEval(address, env);
        return cors(json(res));
      } catch (e) {
        console.error('check_failed', e);
        return cors(jsonError(500, 'server_error', String(e?.message || e)));
      }
    }

    return cors(jsonError(404, 'not_found'));
  }
};

/* ----------------------------- Config / helpers ---------------------------- */

const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8' }
  });

const jsonError = (status, code, detail) =>
  json({ error: code, status, detail }, status);

const cors = (res = new Response(null, { status: 204 })) => {
  res.headers.set('access-control-allow-origin', '*');
  res.headers.set('access-control-allow-methods', 'GET,OPTIONS');
  res.headers.set('access-control-allow-headers', 'content-type');
  res.headers.set('cache-control', 'no-store');
  return res;
};

const nowMs = () => Date.now();

/* ------------------------------ RPC primitives ----------------------------- */

async function rpc(url, method, params = []) {
  const body = {
    jsonrpc: '2.0',
    id: Math.floor(Math.random() * 1e9),
    method,
    params
  };
  const r = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body)
  });
  if (!r.ok) throw new Error(`rpc_http_${r.status}`);
  const j = await r.json();
  if (j.error) throw new Error(`rpc_${method}_error_${j.error?.code || ''}`);
  return j.result;
}

/* ----------------------------- Risk evaluation ----------------------------- */

async function runRiskEval(address, env) {
  const ALCHEMY = env.ALCHEMY_SEPOLIA_URL;
  if (!ALCHEMY) throw new Error('missing_ALCHEMY_SEPOLIA_URL');

  const BADLIST = parseCsvList(env.BADLIST);
  const DUST_WATCH = parseCsvList(env.DUST_WATCHLIST);

  // Parallel baseline lookups
  const [code, nonce, outTxs, inTxs] = await Promise.all([
    rpc(ALCHEMY, 'eth_getCode', [address, 'latest']),
    rpc(ALCHEMY, 'eth_getTransactionCount', [address, 'latest']),
    // recent outbound transfers
    rpc(ALCHEMY, 'alchemy_getAssetTransfers', [{
      fromBlock: '0x0',
      toBlock: 'latest',
      category: ['external'],
      withMetadata: true,
      excludeZeroValue: false,
      maxCount: '0x64', // 100
      order: 'desc',
      fromAddress: address
    }]).catch(() => ({ transfers: [] })),
    // recent inbound transfers
    rpc(ALCHEMY, 'alchemy_getAssetTransfers', [{
      fromBlock: '0x0',
      toBlock: 'latest',
      category: ['external'],
      withMetadata: true,
      excludeZeroValue: false,
      maxCount: '0x64',
      order: 'desc',
      toAddress: address
    }]).catch(() => ({ transfers: [] }))
  ]);

  const out = (outTxs?.transfers || []).map(t => normalizeTransfer(t));
  const inn = (inTxs?.transfers || []).map(t => normalizeTransfer(t));

  const factors = [];

  // Heuristic: known-bad address list
  if (BADLIST.has(address.toLowerCase())) {
    factors.push(factor('high', 'On blocklist', 'Recipient is present in a locally configured blocklist.'));
  }

  // Heuristic: contract address receiving funds (often phishing)
  const isContract = (code && code !== '0x');
  if (isContract) {
    factors.push(factor('medium', 'Contract address', 'Recipient is a contract (non-EOA).'));
  }

  // Heuristic: brand-new or dormant address
  const txCount = hexToInt(nonce);
  if (txCount === 0) {
    factors.push(factor('medium', 'New address', 'Recipient has no prior transactions (nonce 0).'));
  } else if (txCount < 3) {
    factors.push(factor('low', 'Very low activity', 'Recipient has very limited on-chain activity.'));
  }

  // Heuristic: bursty outbounds (many out tx in last 24h)
  const burst24 = countWithin(out, 24 * 60 * 60 * 1000);
  if (burst24 >= 10) {
    factors.push(factor('high', 'High-frequency outbounds', `~${burst24} outgoing transfers in last 24h.`));
  } else if (burst24 >= 5) {
    factors.push(factor('medium', 'Frequent outbounds', `~${burst24} outgoing transfers in last 24h.`));
  }

  // Heuristic: dust pattern (many tiny inbound amounts)
  const tiny = inn.filter(t => (t.valueEth ?? 0) > 0 && t.valueEth < 0.0005);
  if (tiny.length >= 6) {
    factors.push(factor('medium', 'Dusting pattern', `${tiny.length} tiny inbound transfers observed.`));
  } else if (tiny.length >= 3) {
    factors.push(factor('low', 'Possible dusting', `${tiny.length} tiny inbound transfers observed.`));
  }

  // Heuristic: repeated equal outbound amounts (bot/airdrop pattern)
  const repeatOut = repeatedAmounts(out);
  if (repeatOut.maxRepeats >= 8) {
    factors.push(factor('medium', 'Repeated equal amounts', `Outbound transfers show repeated amount ${repeatOut.amountStr} ETH.`));
  }

  // Heuristic: fresh funds then quick out (within 10 minutes)
  const quickOut = freshInThenOut(inn, out, 10 * 60 * 1000);
  if (quickOut) {
    factors.push(factor('high', 'Fresh funds → fast outflow', 'Outbound occurred shortly after inbound (≤10m).'));
  }

  // Heuristic: counterparties on dust watchlist
  const touchedWatch = inn.some(t => DUST_WATCH.has((t.from || '').toLowerCase())) ||
                       out.some(t => DUST_WATCH.has((t.to || '').toLowerCase()));
  if (touchedWatch) {
    factors.push(factor('low', 'Dust watchlist touch', 'History includes interaction with a watched address.'));
  }

  // Aggregate into score (0–100)
  let score = 10; // base
  for (const f of factors) {
    if (f.severity === 'high') score += 25;
    if (f.severity === 'medium') score += 12;
    if (f.severity === 'low') score += 6;
  }
  if (BADLIST.has(address.toLowerCase())) score = Math.max(score, 95);
  score = Math.max(0, Math.min(100, Math.round(score)));

  const decision = score >= 60 ? 'block' : 'allow';

  return { score, decision, factors };
}

/* --------------------------------- Utils ---------------------------------- */

function normalizeTransfer(t) {
  // Alchemy returns { hash, value (ETH string or null), metadata.blockTimestamp, from, to }
  const ts = t?.metadata?.blockTimestamp ? Date.parse(t.metadata.blockTimestamp) : 0;
  const valueEth = t?.value != null ? Number(t.value) : null;
  return {
    hash: t?.hash || '',
    from: (t?.from || '').toLowerCase(),
    to: (t?.to || '').toLowerCase(),
    valueEth,
    timestamp: Number.isFinite(ts) ? ts : 0
  };
}

function hexToInt(h) {
  try { return parseInt(h, 16) || 0; } catch { return 0; }
}

function countWithin(list, windowMs) {
  const cutoff = nowMs() - windowMs;
  return list.filter(t => (t.timestamp || 0) >= cutoff).length;
}

function repeatedAmounts(list) {
  const counts = new Map();
  for (const t of list) {
    if (t.valueEth == null) continue;
    // Round to 6 decimals to collapse tiny fee differences
    const key = t.valueEth.toFixed(6);
    counts.set(key, (counts.get(key) || 0) + 1);
  }
  let maxRepeats = 0, amountStr = '';
  for (const [k, v] of counts) {
    if (v > maxRepeats) { maxRepeats = v; amountStr = k; }
  }
  return { maxRepeats, amountStr };
}

function freshInThenOut(inbound, outbound, windowMs) {
  if (!inbound.length || !outbound.length) return false;
  const latestIn = inbound[0]; // lists are desc
  const firstOutAfter = outbound.find(o => o.timestamp >= latestIn.timestamp);
  if (!firstOutAfter) return false;
  return (firstOutAfter.timestamp - latestIn.timestamp) <= windowMs;
}

function factor(severity, label, reason) {
  return { severity, label, reason };
}

function parseCsvList(str) {
  const out = new Set();
  if (!str) return out;
  for (const part of String(str).split(',')) {
    const a = part.trim().toLowerCase();
    if (/^0x[a-f0-9]{40}$/.test(a)) out.add(a);
  }
  return out;
}