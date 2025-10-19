export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);
      if (url.pathname !== "/check") return json({ error: "not_found" }, 404);

      const addr = (url.searchParams.get("address") || "").trim();
      const chain = (url.searchParams.get("chain") || "sepolia").toLowerCase();
      if (!/^0x[a-fA-F0-9]{40}$/.test(addr)) return json({ error: "bad_address" }, 400);
      if (chain !== "sepolia") return json({ error: "unsupported_chain" }, 400);

      const ALCHEMY_SEPOLIA_RPC = env.ALCHEMY_SEPOLIA_RPC;
      if (!ALCHEMY_SEPOLIA_RPC)
        return json({ error: "missing_ALCHEMY_SEPOLIA_RPC" }, 500);

      const BADLIST_ADDRESSES = (env.BADLIST_ADDRESSES || "")
        .toLowerCase()
        .split(",")
        .map(s => s.trim())
        .filter(Boolean);
      const BAD_ENS_NAMES = (env.BAD_ENS_NAMES || "")
        .toLowerCase()
        .split(",")
        .map(s => s.trim())
        .filter(Boolean);
      let BAD_ENS_ADDRS = {};
      try {
        BAD_ENS_ADDRS = JSON.parse(env.BAD_ENS_ADDRS || "{}");
      } catch {}
      const DUST_THRESHOLD_ETH = Number(env.DUST_THRESHOLD_ETH || "0.00002");

      const rpc = (method, params = []) =>
        fetch(ALCHEMY_SEPOLIA_RPC, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            jsonrpc: "2.0",
            id: 1,
            method,
            params
          })
        }).then(async r => {
          if (!r.ok) throw new Error("rpc_http_" + r.status);
          const j = await r.json();
          if (j.error) throw new Error(j.error.message || "rpc_error");
          return j.result;
        });

      let score = 0;
      const findings = [];
      const addFinding = (label, detail, level, delta) => {
        findings.push({ label, detail, level });
        score += delta;
      };

      // --- Blocklists / negative reputation ---
      if (BADLIST_ADDRESSES.includes(addr.toLowerCase()))
        addFinding("Blocklisted", "Address appears on internal blocklist.", "high", 90);
      if (BAD_ENS_ADDRS[addr.toLowerCase()])
        addFinding(
          "Negative ENS link",
          `Associated with ${BAD_ENS_ADDRS[addr.toLowerCase()]}`,
          "high",
          25
        );

      // --- Contract / bytecode ---
      let isContract = false;
      let bytecode = "0x";
      try {
        bytecode = await rpc("eth_getCode", [addr, "latest"]);
        isContract = !!bytecode && bytecode !== "0x";
        if (isContract) {
          addFinding("Contract", "Recipient is a contract address.", "medium", 10);
          if (/363d3d/i.test(bytecode.slice(2)))
            addFinding("Proxy pattern", "EIP-1167 minimal proxy detected.", "medium", 6);
          if (bytecode.length < 200)
            addFinding("Tiny bytecode", "Contract runtime is unusually short.", "medium", 6);
        } else {
          addFinding("EOA", "Recipient is an externally owned address.", "low", 0);
        }
      } catch {
        addFinding("Unknown type", "Could not verify contract/EOA.", "low", 0);
      }

      // --- Transfers / activity ---
      const base = {
        fromBlock: "0x0",
        toBlock: "latest",
        category: ["external"],
        withMetadata: true,
        excludeZeroValue: false,
        maxCount: "0x64",
        order: "desc"
      };
      const [outRes, inRes] = await Promise.all([
        rpc("alchemy_getAssetTransfers", [{ ...base, fromAddress: addr }]).catch(() => ({ transfers: [] })),
        rpc("alchemy_getAssetTransfers", [{ ...base, toAddress: addr }]).catch(() => ({ transfers: [] }))
      ]);
      const outs = outRes?.transfers || [];
      const ins = inRes?.transfers || [];
      const all = [...outs, ...ins];

      const recentMs = t => (t?.metadata?.blockTimestamp ? Date.parse(t.metadata.blockTimestamp) : 0);
      const latestTs = all.length ? Math.max(...all.map(recentMs)) : 0;
      const firstTs = all.length ? Math.min(...all.map(recentMs)) : 0;
      const daysSinceFirst = firstTs ? (Date.now() - firstTs) / 86400000 : null;
      const daysSinceLatest = latestTs ? (Date.now() - latestTs) / 86400000 : null;

      if (all.length === 0) {
        addFinding("No history", "No transactions found on Sepolia.", "medium", 22);
      } else {
        if (daysSinceFirst < 1)
          addFinding("New address", "First seen < 24h.", "high", 28);
        else if (daysSinceFirst < 7)
          addFinding("Newish address", "First seen < 7d.", "medium", 18);
        else if (daysSinceFirst < 30)
          addFinding("Recent address", "First seen < 30d.", "low", 8);

        if (all.length < 5)
          addFinding("Low activity", "Fewer than 5 total transfers.", "medium", 10);
        if (outs.length === 0)
          addFinding("Inbound only", "No outbound history.", "low", 6);

        const uniqueRecipients = new Set(
          outs.map(t => (t.to || "").toLowerCase()).filter(Boolean)
        );
        if (uniqueRecipients.size >= 10)
          addFinding("Fan-out", `${uniqueRecipients.size} distinct recent recipients.`, "high", 18);

        const senders = ins.map(t => (t.from || "").toLowerCase()).filter(Boolean);
        const uniqueSenders = new Set(senders);
        if (ins.length >= 5 && uniqueSenders.size >= 5 && outs.length === 0)
          addFinding(
            "Inbound burst",
            "Many unique inbound senders, no outbound history.",
            "medium",
            10
          );

        const parseEth = v => (typeof v === "number" ? v : v ? Number(v) : 0);
        const incomingValues = ins.map(t => parseEth(t.value)).filter(Number.isFinite);
        if (incomingValues.length >= 3) {
          incomingValues.sort((a, b) => a - b);
          const mid = Math.floor(incomingValues.length / 2);
          const median =
            incomingValues.length % 2
              ? incomingValues[mid]
              : (incomingValues[mid - 1] + incomingValues[mid]) / 2;
          if (median > 0 && median < DUST_THRESHOLD_ETH)
            addFinding(
              "Dusting",
              `Median inbound < ${DUST_THRESHOLD_ETH} ETH.`,
              "medium",
              12
            );
        }

        if (daysSinceLatest > 180)
          addFinding("Dormant", "Last activity > 180 days ago. Slightly safer.", "low", -5);
      }

      // --- ENS negatives (if passed as ?ens=) ---
      const ens = url.searchParams.get("ens") || "";
      if (ens && BAD_ENS_NAMES.includes(ens.toLowerCase()))
        addFinding("ENS flagged", `${ens} has negative reputation.`, "high", 20);

      // --- clamp / output ---
      score = Math.max(0, Math.min(100, score));
      return json({ score, findings });
    } catch (e) {
      return json({ error: "worker_error", message: e.message }, 500);
    }
  }
};

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" }
  });
}
