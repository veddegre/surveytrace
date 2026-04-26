<?php
/**
 * SurveyTrace — main UI entry point
 * All data is loaded from the API endpoints via fetch().
 */
?><!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SurveyTrace</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=IBM+Plex+Sans:wght@400;500&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0d0f12;--bg2:#13161b;--bg3:#1e2230;--bg4:#252c3a;
  --bd:#2e3650;--bd2:#4a5570;
  --tx:#dde4f0;--tx2:#9aa8c0;--tx3:#6b7a96;
  --green:#2ecc71;--gdim:#0d3022;--gbrd:#1a6640;
  --amber:#f39c12;--adim:#3a2400;--abrd:#7a4d00;
  --red:#e74c3c;--rdim:#3a0a08;--rbrd:#7a1a15;
  --blue:#4a9eff;--bdim2:#0d1e3a;--bbrd:#1a4a8a;
  --orange:#f97316;--odim:#2d1400;
  --acc:#00d4aa;--acc2:#009978;--adim2:#003d30;
  --mf:'IBM Plex Mono',monospace;--sf:'IBM Plex Sans',sans-serif;
}
body{background:var(--bg);color:var(--tx);font-family:var(--sf);font-size:14px;line-height:1.6;overflow:hidden;height:100vh}
.shell{display:grid;grid-template-columns:192px 1fr;grid-template-rows:46px 1fr;height:100vh}

/* Top bar */
.bar{grid-column:1/-1;display:flex;align-items:center;gap:10px;padding:0 14px;background:var(--bg2);border-bottom:1px solid var(--bd);z-index:10}
.logo{font-family:var(--mf);font-size:13px;font-weight:500;color:var(--acc);display:flex;align-items:center;gap:6px}
.logo-dot{width:7px;height:7px;background:var(--acc);border-radius:50%}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.25}}
.logo-dot.active{animation:blink 1.2s ease-in-out infinite}
.bar-meta{font-family:var(--mf);font-size:11px;color:var(--tx2)}
.sep{flex:1}
.pill{font-family:var(--mf);font-size:10px;padding:3px 9px;border-radius:2px;border:1px solid var(--gbrd);background:var(--gdim);color:var(--green);display:flex;align-items:center;gap:5px}
.pill.run{border-color:var(--abrd);background:var(--adim);color:var(--amber)}
.pill.err{border-color:var(--rbrd);background:var(--rdim);color:var(--red)}
.pdot{width:5px;height:5px;border-radius:50%;background:currentColor}
.pill.run .pdot{animation:blink .9s ease-in-out infinite}
.tbtn{font-family:var(--mf);font-size:12px;padding:3px 9px;border-radius:2px;border:1px solid var(--bd2);background:transparent;color:var(--tx2);cursor:pointer;transition:all .12s}
.tbtn:hover{border-color:var(--acc);color:var(--acc)}

/* Sidebar */
.side{background:var(--bg2);border-right:1px solid var(--bd);padding:10px 0;overflow-y:auto;display:flex;flex-direction:column;gap:1px}
.ns{font-family:var(--mf);font-size:11px;color:var(--tx3);padding:8px 14px 3px;letter-spacing:.07em;text-transform:uppercase}
.ni{display:flex;align-items:center;gap:8px;padding:7px 14px;cursor:pointer;border-left:2px solid transparent;color:var(--tx2);font-size:13px;transition:all .12s;user-select:none}
.ni:hover{background:var(--bg3);color:var(--tx)}
.ni.on{background:var(--bg3);color:var(--acc);border-left-color:var(--acc)}
.nb{margin-left:auto;font-family:var(--mf);font-size:10px;padding:1px 5px;background:var(--rdim);color:var(--red);border-radius:2px;min-width:18px;text-align:center}
.nb.warn{background:var(--adim);color:var(--amber)}
.nb.err{background:var(--rdim);color:var(--red)}
.nb.warn{background:var(--adim);color:var(--amber)}

/* Main */
.main{overflow-y:auto;background:var(--bg)}
.tab{display:none;padding:16px}
.tab.on{display:block}

/* Stat cards */
.sgrid{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-bottom:16px}
.sc{background:var(--bg2);border:1px solid var(--bd);border-radius:4px;padding:12px 14px;cursor:default}
.sl{font-family:var(--mf);font-size:11px;color:var(--tx2);letter-spacing:.05em;text-transform:uppercase;margin-bottom:5px}
.sv{font-family:var(--mf);font-size:22px;font-weight:500;line-height:1}
.ss{font-size:12px;color:var(--tx2);margin-top:3px}
.sc.r .sv{color:var(--red)}.sc.a .sv{color:var(--amber)}.sc.g .sv{color:var(--acc)}

/* Section headers */
.sth{font-family:var(--mf);font-size:11px;color:var(--tx2);letter-spacing:.05em;text-transform:uppercase;margin-bottom:8px;display:flex;align-items:center;gap:8px}
.sth::after{content:'';flex:1;height:1px;background:var(--bd)}
.sth-btn{font-family:var(--mf);font-size:10px;color:var(--tx3);background:none;border:1px solid var(--bd);border-radius:2px;padding:1px 6px;cursor:pointer}
.sth-btn:hover{border-color:var(--acc);color:var(--acc)}

/* Activity feed */
.feed{background:var(--bg2);border:1px solid var(--bd);border-radius:4px;font-family:var(--mf);font-size:12px;max-height:220px;overflow-y:auto;margin-bottom:16px}
.fr{display:flex;gap:10px;padding:5px 10px;border-bottom:1px solid var(--bd);align-items:flex-start}
.fr:last-child{border-bottom:none}
.ft{color:var(--tx3);flex-shrink:0;min-width:62px}
.ftg{padding:1px 5px;border-radius:2px;flex-shrink:0;font-size:10px}
.ftg.nw{background:var(--gdim);color:var(--green)}
.ftg.vl{background:var(--rdim);color:var(--red)}
.ftg.ch{background:var(--adim);color:var(--amber)}
.ftg.sc{background:var(--bdim2);color:var(--blue)}
.ftg.er{background:var(--rdim);color:var(--red)}
.fm{color:var(--tx2);word-break:break-all}.fm b{color:var(--tx);font-weight:400}
.empty-feed{padding:12px;color:var(--tx3);text-align:center;font-family:var(--mf);font-size:11px}

/* Tables */
.tbl-wrap{background:var(--bg2);border:1px solid var(--bd);border-radius:4px;overflow:auto}
.tbl{width:100%;border-collapse:collapse;font-size:11.5px}
.tbl th{font-family:var(--mf);font-size:11px;color:var(--tx2);text-transform:uppercase;letter-spacing:.05em;padding:8px 10px;text-align:left;border-bottom:1px solid var(--bd);background:var(--bg3);font-weight:400;white-space:nowrap;cursor:pointer;user-select:none}
.tbl th:hover{color:var(--tx)}
.tbl td{padding:8px 10px;border-bottom:1px solid var(--bd);color:var(--tx2);vertical-align:middle}
.tbl tr:last-child td{border-bottom:none}
.tbl tr:hover td{background:var(--bg3)}
.tbl tr.selected td{background:var(--bg4)}
.mono{font-family:var(--mf);color:var(--tx)}

/* Severity badges */
.sev{font-family:var(--mf);font-size:11px;padding:2px 6px;border-radius:2px;white-space:nowrap}
.sev.critical{background:var(--rdim);color:var(--red)}
.sev.high{background:var(--odim);color:var(--orange)}
.sev.medium{background:var(--adim);color:var(--amber)}
.sev.low{background:var(--bdim2);color:var(--blue)}
.sev.none{background:var(--bg4);color:var(--tx3)}
.profile-card{display:flex;align-items:center;gap:10px;padding:10px 12px;border:1px solid var(--bd);border-radius:4px;cursor:pointer;transition:border-color .15s}
.profile-card:hover{border-color:var(--acc)}
.profile-card.on{border-color:var(--acc);background:var(--adim2)}
.pc-icon{font-size:18px;flex-shrink:0}
.pc-name{font-size:12px;color:var(--tx);font-weight:500}
.pc-desc{font-size:11px;color:var(--tx2);font-family:var(--mf);margin-top:2px}
.pc-badge{font-size:9px;font-family:var(--mf);padding:2px 6px;border-radius:2px;margin-left:auto;flex-shrink:0;white-space:nowrap}
.pc-badge.safe{background:var(--gdim);color:var(--green)}
.pc-badge.warn{background:var(--adim);color:var(--amber)}

/* Category badges */
.cat{font-family:var(--mf);font-size:11px;padding:2px 6px;border-radius:2px}
.cat.srv{background:#1a1040;color:#a78bfa}
.cat.iot{background:var(--gdim);color:var(--green)}
.cat.ot{background:var(--adim);color:var(--amber)}
.cat.net{background:var(--bdim2);color:var(--blue)}
.cat.ws{background:#1a1a0d;color:#d4d48a}
.cat.voi{background:#2a0d2a;color:#d48ad4}
.cat.prn{background:#0d2a2a;color:#8ad4d4}
.cat.hv{background:#0d1a2a;color:#6ab0e8}
.cat.unk{background:var(--bg4);color:var(--tx3)}

/* Port tags */
.pts{display:flex;flex-wrap:wrap;gap:3px}
.pt{font-family:var(--mf);font-size:10px;padding:1px 4px;border:1px solid var(--bd2);border-radius:2px;color:var(--tx3)}

/* Filter bar */
.fbar{display:flex;gap:8px;margin-bottom:10px;align-items:center;flex-wrap:wrap}
.finp{background:var(--bg3);border:1px solid var(--bd);border-radius:3px;padding:5px 8px;color:var(--tx);font-family:var(--mf);font-size:13px;outline:none;transition:border-color .12s}
.finp:focus{border-color:var(--acc)}
.finp.wide{flex:1;min-width:160px}
.finp.narrow{width:120px}

/* Scan control layout */
.scgrid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.card{background:var(--bg2);border:1px solid var(--bd);border-radius:4px;padding:14px;margin-bottom:10px}
.card:last-child{margin-bottom:0}
.ct{font-family:var(--mf);font-size:11px;color:var(--tx2);text-transform:uppercase;letter-spacing:.05em;margin-bottom:12px}
.flbl{display:block;font-size:12px;color:var(--tx);margin-bottom:4px;font-family:var(--mf)}
.finput{width:100%;background:var(--bg3);border:1px solid var(--bd);border-radius:3px;padding:6px 9px;color:var(--tx);font-family:var(--mf);font-size:13px;outline:none;margin-bottom:9px;transition:border-color .12s}
.finput:focus{border-color:var(--acc)}
textarea.finput{resize:vertical;min-height:72px}

/* Toggle switches */
.tr2{display:flex;justify-content:space-between;align-items:center;padding:7px 0;border-bottom:1px solid var(--bd)}
.tr2:last-child{border-bottom:none}
.tl{font-size:13px;color:var(--tx)}.tsubl{font-size:12px;color:var(--tx2);font-family:var(--mf)}
.tog{position:relative;width:32px;height:17px;flex-shrink:0}
.tog input{opacity:0;width:0;height:0;position:absolute}
.trk{position:absolute;inset:0;background:var(--bg4);border:1px solid var(--bd2);border-radius:9px;cursor:pointer;transition:all .18s}
.tog input:checked+.trk{background:var(--acc2);border-color:var(--acc)}
.tth{position:absolute;top:2px;left:2px;width:11px;height:11px;background:var(--tx2);border-radius:50%;transition:all .18s;pointer-events:none}
.tog input:checked~.tth{left:17px;background:#fff}

/* Range sliders */
.rr{margin-bottom:10px}
.rv{display:flex;justify-content:space-between;font-family:var(--mf);font-size:10px;color:var(--tx3);margin-bottom:2px}
.rng{width:100%;accent-color:var(--acc);cursor:pointer}

/* Buttons */
.btnp{background:var(--acc);color:#081a15;font-family:var(--mf);font-size:11px;font-weight:500;padding:8px 16px;border:none;border-radius:3px;cursor:pointer;display:inline-flex;align-items:center;gap:5px;transition:background .12s}
.btnp:hover{background:var(--acc2)}
.btnp:disabled{opacity:.4;cursor:not-allowed}
.btnd{background:var(--rdim);color:var(--red);border:1px solid var(--rbrd);font-family:var(--mf);font-size:11px;padding:7px 14px;border-radius:3px;cursor:pointer;transition:all .12s}
.btnd:hover{background:var(--red);color:#fff}
.brow{display:flex;gap:8px;margin-top:4px}

/* Progress bar */
.pbar-wrap{margin-top:12px}
.pm{font-family:var(--mf);font-size:11px;color:var(--tx2);margin-bottom:4px;display:flex;justify-content:space-between}
.ptrack{height:3px;background:var(--bg4);border-radius:2px}
.pfill{height:100%;width:0%;background:var(--acc);border-radius:2px;transition:width .5s}
.pfill.done{background:var(--green)}
.pfill.failed{background:var(--red)}

/* Audit log */
.log-wrap{background:var(--bg2);border:1px solid var(--bd);border-radius:4px;font-family:var(--mf);font-size:11px;max-height:500px;overflow-y:auto}
.lr{display:flex;gap:10px;padding:4px 10px;border-bottom:1px solid var(--bd);align-items:flex-start}
.lr:last-child{border-bottom:none}
.lts{color:var(--tx3);min-width:64px;flex-shrink:0}
.llv{min-width:42px;flex-shrink:0}
.llv.INFO{color:var(--blue)}.llv.WARN{color:var(--amber)}.llv.PROBE{color:var(--acc)}.llv.ERR{color:var(--red)}
.lm{color:var(--tx2);word-break:break-all}.lm b{color:var(--tx);font-weight:400}

/* Pagination */
.pgn{display:flex;align-items:center;gap:6px;margin-top:10px;font-family:var(--mf);font-size:11px;color:var(--tx2)}
.pgn button{font-family:var(--mf);font-size:10px;padding:3px 8px;border:1px solid var(--bd2);background:transparent;color:var(--tx2);border-radius:2px;cursor:pointer}
.pgn button:hover{border-color:var(--acc);color:var(--acc)}
.pgn button:disabled{opacity:.3;cursor:not-allowed}

/* Toast notifications */
.toast-wrap{position:fixed;bottom:16px;right:16px;display:flex;flex-direction:column;gap:6px;z-index:999}
.toast{font-family:var(--mf);font-size:11px;padding:7px 12px;border-radius:3px;border:1px solid;animation:fadeIn .2s ease}
.toast.ok{background:var(--gdim);border-color:var(--gbrd);color:var(--green)}
.toast.err{background:var(--rdim);border-color:var(--rbrd);color:var(--red)}
@keyframes fadeIn{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:translateY(0)}}

/* Loading indicator */
.loading{color:var(--tx2);font-family:var(--mf);font-size:11px;padding:20px;text-align:center}
</style>
</head>
<body>
<div class="shell">

<!-- Top bar -->
<div class="bar">
  <div class="logo"><div class="logo-dot" id="logodot"></div>SurveyTrace</div>
  <div class="bar-meta" id="bar-meta">v<?= defined('ST_VERSION') ? ST_VERSION : '0.2.0' ?></div>
  <div class="sep"></div>
  <div class="pill" id="status-pill"><div class="pdot"></div><span id="status-txt">Idle</span></div>
  <button class="tbtn" onclick="goTab('scan');hiNav('nscan')">+ New scan</button>
  <button class="tbtn" onclick="goTab('settings');hiNav('nsettings')">Settings</button>
</div>

<!-- Sidebar -->
<div class="side">
  <div class="ns">Monitor</div>
  <div class="ni" id="ndash" onclick="goTab('dash');hiNav('ndash')">
    <svg width="13" height="13" viewBox="0 0 14 14" fill="currentColor"><rect x="0" y="0" width="6" height="6" rx="1"/><rect x="8" y="0" width="6" height="6" rx="1"/><rect x="0" y="8" width="6" height="6" rx="1"/><rect x="8" y="8" width="6" height="6" rx="1"/></svg>
    Dashboard
  </div>
  <div class="ni" id="nassets" onclick="goTab('assets');hiNav('nassets')">
    <svg width="13" height="13" viewBox="0 0 14 14" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="1" y="2" width="12" height="10" rx="1.5"/><path d="M1 6h12M4 2V1M10 2V1"/></svg>
    Assets
    <span class="nb warn" id="nb-assets">—</span>
  </div>
  <div class="ni" id="nvulns" onclick="goTab('vulns');hiNav('nvulns')">
    <svg width="13" height="13" viewBox="0 0 14 14" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M7 1L1 4v3.5C1 10.5 3.5 13 7 13s6-2.5 6-5.5V4z"/><path d="M7 6v3M7 5h.01"/></svg>
    Vulnerabilities
    <span class="nb" id="nb-vulns">—</span>
  </div>
  <div class="ns">Control</div>
  <div class="ni" id="nscan" onclick="goTab('scan');hiNav('nscan')">
    <svg width="13" height="13" viewBox="0 0 14 14" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="7" cy="7" r="5.5"/><path d="M7 4.5v3l2 1.2"/></svg>
    Scan control
  </div>
  <div class="ni" id="nsched" onclick="goTab('sched');hiNav('nsched')">
    <svg width="13" height="13" viewBox="0 0 14 14" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="1" y="2" width="12" height="11" rx="1.5"/><path d="M1 6h12M4 1v2M10 1v2M4 9h2M7 9h3"/></svg>
    Schedules
  </div>
  <div class="ni" id="nlogs" onclick="goTab('logs');hiNav('nlogs')">
    <svg width="13" height="13" viewBox="0 0 14 14" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M2 3h10M2 7h6M2 11h4"/></svg>
    Audit log
  </div>
  <div class="ns">System</div>
  <div class="ni" id="nenrich" onclick="goTab('enrich');hiNav('nenrich')">
    <svg width="13" height="13" viewBox="0 0 14 14" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M7 1L1 4v3.5C1 10.5 3.5 13 7 13s6-2.5 6-5.5V4z"/><path d="M4 7h6M7 4v6"/></svg>
    Enrichment
  </div>
  <div class="ni" id="nsettings" onclick="goTab('settings');hiNav('nsettings')">
    <svg width="13" height="13" viewBox="0 0 14 14" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="7" cy="7" r="2.5"/><path d="M7 1v2M7 11v2M1 7h2M11 7h2M2.9 2.9l1.4 1.4M9.7 9.7l1.4 1.4M2.9 11.1l1.4-1.4M9.7 4.3l1.4-1.4"/></svg>
    Settings
  </div>
</div>

<!-- Main content -->
<div class="main">

<!-- ================================================================ DASHBOARD -->
<div class="tab" id="t-dash">
  <div class="sgrid" id="dash-stats">
    <div class="sc g"><div class="sl">Total assets</div><div class="sv" id="d-total">—</div><div class="ss" id="d-new">loading…</div></div>
    <div class="sc a"><div class="sl">Unclassified</div><div class="sv" id="d-unk">—</div><div class="ss">needs review</div></div>
    <div class="sc r"><div class="sl">Open CVEs</div><div class="sv" id="d-cves">—</div><div class="ss" id="d-crit">— critical</div></div>
    <div class="sc"><div class="sl">Last scan</div><div class="sv" id="d-age" style="font-size:16px;color:var(--tx)">—</div><div class="ss" id="d-scan-target">—</div></div>
  </div>

  <div class="sgrid" id="dash-cats">
    <div class="sc"><div class="sl">Servers</div><div class="sv" style="font-size:18px;color:var(--tx)" id="dc-srv">—</div></div>
    <div class="sc"><div class="sl">Workstations</div><div class="sv" style="font-size:18px;color:var(--tx)" id="dc-ws">—</div></div>
    <div class="sc"><div class="sl">Network gear</div><div class="sv" style="font-size:18px;color:var(--tx)" id="dc-net">—</div></div>
    <div class="sc"><div class="sl">IoT / OT / other</div><div class="sv" style="font-size:18px;color:var(--tx)" id="dc-iot">—</div></div>
  </div>

  <div class="sth">Top vulnerable assets</div>
  <div class="tbl-wrap" style="margin-bottom:16px">
    <table class="tbl"><thead><tr><th>IP</th><th>Hostname</th><th>Type</th><th>Vendor</th><th>Top CVE</th><th>CVSS</th><th>Findings</th></tr></thead>
    <tbody id="dash-top-vuln"><tr><td colspan="7" class="loading">Loading…</td></tr></tbody></table>
  </div>

  <div class="sth">Recent activity <button class="sth-btn" onclick="loadDashboard()">&#8635; Refresh</button></div>
  <div class="feed" id="dash-feed"><div class="loading">Loading…</div></div>
</div>

<!-- ================================================================ ASSETS -->
<div class="tab" id="t-assets">
  <div class="fbar">
    <input class="finp wide" id="af-q" placeholder="Search IP, hostname, vendor, MAC…" oninput="debounceAssets()">
    <select class="finp narrow" id="af-cat" onchange="loadAssets(1)">
      <option value="">All types</option>
      <option value="srv">Server</option><option value="ws">Workstation</option>
      <option value="net">Network gear</option><option value="iot">IoT</option>
      <option value="ot">OT / ICS</option><option value="voi">VoIP</option>
      <option value="prn">Printer</option><option value="hv">Hypervisor</option>
      <option value="unk">Unknown</option>
    </select>
    <select class="finp narrow" id="af-sev" onchange="loadAssets(1)">
      <option value="">All severity</option>
      <option value="critical">Critical</option><option value="high">High</option>
      <option value="medium">Medium</option><option value="low">Low</option><option value="none">None</option>
    </select>
    <select class="finp narrow" id="af-sort" onchange="loadAssets(1)">
      <option value="ip">Sort: IP</option><option value="hostname">Hostname</option>
      <option value="category">Type</option><option value="top_cvss">CVSS</option>
      <option value="last_seen">Last seen</option><option value="open_findings">Findings</option>
    </select>
    <button class="tbtn" onclick="exportAssets('csv')" title="Export as CSV">&#8595; CSV</button>
    <button class="tbtn" onclick="exportAssets('json')" title="Export as JSON">&#8595; JSON</button>
  </div>
  <div class="tbl-wrap">
    <table class="tbl">
      <thead><tr>
        <th onclick="sortAssets('ip')">IP address</th>
        <th onclick="sortAssets('hostname')">Hostname</th>
        <th onclick="sortAssets('category')">Type</th>
        <th>Vendor / model</th>
        <th>Open ports</th>
        <th onclick="sortAssets('open_findings')">CVEs</th>
        <th onclick="sortAssets('top_cvss')">CVSS</th>
        <th onclick="sortAssets('last_seen')">Last seen</th>
        <th>Edit</th>
      </tr></thead>
      <tbody id="asset-tbody"><tr><td colspan="8" class="loading">Loading…</td></tr></tbody>
    </table>
  </div>
  <div class="pgn">
    <button id="aprev" onclick="loadAssets(assetPage-1)" disabled>&#8592; Prev</button>
    <span id="apgn-info">—</span>
    <button id="anext" onclick="loadAssets(assetPage+1)" disabled>Next &#8594;</button>
  </div>
</div>

<!-- ================================================================ VULNERABILITIES -->
<div class="tab" id="t-vulns">
  <div class="fbar">
    <input class="finp wide" id="vf-cve" placeholder="Search CVE ID or description…" oninput="debounceFindings()">
    <input class="finp narrow" id="vf-ip" placeholder="Filter by IP…" oninput="debounceFindings()" style="width:130px">
    <button class="tbtn" id="vf-clear-ip" onclick="clearIPFilter()" style="display:none;font-size:10px">✕ clear</button>
    <select class="finp narrow" id="vf-sev" onchange="loadFindings(1)">
      <option value="">All severity</option>
      <option value="critical">Critical</option><option value="high">High</option>
      <option value="medium">Medium</option><option value="low">Low</option>
    </select>
    <select class="finp narrow" id="vf-cat" onchange="loadFindings(1)">
      <option value="">All asset types</option>
      <option value="srv">Server</option><option value="ws">Workstation</option>
      <option value="net">Network</option><option value="iot">IoT</option>
      <option value="ot">OT/ICS</option><option value="voi">VoIP</option>
      <option value="prn">Printer</option><option value="hv">Hypervisor</option>
    </select>
    <select class="finp narrow" id="vf-resolved" onchange="loadFindings(1)">
      <option value="0">Open</option><option value="1">Resolved</option>
    </select>
    <select class="finp narrow" id="vf-minyear" onchange="loadFindings(1)" title="Filter out old CVEs">
      <option value="">All years</option>
      <option value="2020">2020+</option>
      <option value="2018">2018+</option>
      <option value="2015">2015+</option>
    </select>
    <button class="tbtn" onclick="exportFindings('csv')" title="Export filtered CVEs as CSV">&#8595; CSV</button>
    <button class="tbtn" onclick="exportFindings('json')" title="Export filtered CVEs as JSON">&#8595; JSON</button>
  </div>
  <div class="tbl-wrap">
    <table class="tbl">
      <thead><tr><th>CVE ID</th><th>Asset IP</th><th>Hostname</th><th>Type</th><th>Description</th><th>CVSS</th><th>Published</th><th>Action</th></tr></thead>
      <tbody id="vuln-tbody"><tr><td colspan="8" class="loading">Loading…</td></tr></tbody>
    </table>
  </div>
  <div class="pgn">
    <button id="vprev" onclick="loadFindings(vulnPage-1)" disabled>&#8592; Prev</button>
    <span id="vpgn-info">—</span>
    <button id="vnext" onclick="loadFindings(vulnPage+1)" disabled>Next &#8594;</button>
  </div>
</div>

<!-- ================================================================ SCAN CONTROL -->
<div class="tab" id="t-scan">
  <div class="scgrid">
    <div>
      <div class="card">
        <div class="ct">Target &amp; scope</div>
        <label class="flbl">CIDR target(s)</label>
        <input class="finput" id="sc-cidr" type="text" placeholder="192.168.0.0/16, 10.0.0.0/8" value="192.168.0.0/16">
        <label class="flbl">Exclusion list (IPs, CIDRs, ranges, # comments)</label>
        <textarea class="finput" id="sc-excl" placeholder="192.168.1.254&#10;10.0.0.0/24&#10;# SCADA servers&#10;192.168.10.88-95"></textarea>
        <label class="flbl">Scan label (optional)</label>
        <input class="finput" id="sc-label" type="text" placeholder="Weekly full scan">
      </div>
      <div class="card">
        <div class="ct">Rate limiting</div>
        <div class="rr">
          <label class="flbl">Max packets/sec per host</label>
          <div class="rv"><span>1</span><span id="pps-val">5 pps</span><span>50</span></div>
          <input class="rng" type="range" id="sc-pps" min="1" max="50" step="1" value="5" oninput="document.getElementById('pps-val').textContent=this.value+' pps'">
        </div>
        <div class="rr">
          <label class="flbl">Inter-host delay</label>
          <div class="rv"><span>0</span><span id="delay-val">200 ms</span><span>2000</span></div>
          <input class="rng" type="range" id="sc-delay" min="0" max="2000" step="10" value="200" oninput="document.getElementById('delay-val').textContent=this.value+' ms'">
        </div>
      </div>
    </div>
    <div>
      <div class="card">
        <div class="ct">Scan profile</div>
        <div style="display:grid;gap:8px">
          <label class="profile-card on" id="prof-standard_inventory">
            <input type="radio" name="scan_profile" value="standard_inventory" checked style="display:none">
            <div class="pc-icon">&#128203;</div>
            <div style="flex:1">
              <div class="pc-name">Standard Inventory</div>
              <div class="pc-desc">Common ports, light banner probing, CVE correlation</div>
            </div>
          </label>
          <label class="profile-card" id="prof-iot_safe">
            <input type="radio" name="scan_profile" value="iot_safe" style="display:none">
            <div class="pc-icon">&#128737;</div>
            <div style="flex:1">
              <div class="pc-name">IoT Safe</div>
              <div class="pc-desc">Passive only — ARP/ICMP, no port scanning, no banners</div>
            </div>
            <div class="pc-badge safe">Safe for IoT</div>
          </label>
          <label class="profile-card" id="prof-deep_scan">
            <input type="radio" name="scan_profile" value="deep_scan" style="display:none">
            <div class="pc-icon">&#128300;</div>
            <div style="flex:1">
              <div class="pc-name">Deep Scan</div>
              <div class="pc-desc">Full nmap -sV, SNMP, all ports — requires confirmation</div>
            </div>
            <div class="pc-badge warn">Confirmation required</div>
          </label>
          <label class="profile-card" id="prof-full_tcp">
            <input type="radio" name="scan_profile" value="full_tcp" style="display:none">
            <div class="pc-icon">&#129517;</div>
            <div style="flex:1">
              <div class="pc-name">Full TCP</div>
              <div class="pc-desc">All TCP ports (-p-) + service detect — slower, high coverage</div>
            </div>
            <div class="pc-badge warn">Confirmation required</div>
          </label>
          <label class="profile-card" id="prof-ot_careful">
            <input type="radio" name="scan_profile" value="ot_careful" style="display:none">
            <div class="pc-icon">&#9888;</div>
            <div style="flex:1">
              <div class="pc-name">OT Careful</div>
              <div class="pc-desc">Passive only, 2pps max — safe for industrial networks</div>
            </div>
            <div class="pc-badge safe">Safe for OT</div>
          </label>
        </div>
      </div>

      <div class="card">
        <div class="ct">Scan phases</div>
        <div class="tr2"><div><div class="tl">Passive discovery</div><div class="tsubl">ARP watch, mDNS/Bonjour sniff — zero packets sent</div></div><label class="tog"><input type="checkbox" id="ph-passive" checked><div class="trk"></div><div class="tth"></div></label></div>
        <div class="tr2"><div><div class="tl">ICMP sweep</div><div class="tsubl">Ping / ARP sweep all hosts in scope</div></div><label class="tog"><input type="checkbox" id="ph-icmp" checked><div class="trk"></div><div class="tth"></div></label></div>
        <div class="tr2"><div><div class="tl">Port &amp; banner probe</div><div class="tsubl">TCP connect on safe port list only</div></div><label class="tog"><input type="checkbox" id="ph-banner" checked><div class="trk"></div><div class="tth"></div></label></div>
        <div class="tr2"><div><div class="tl">Service fingerprinting</div><div class="tsubl">OUI + banner + port profile → CPE</div></div><label class="tog"><input type="checkbox" id="ph-fingerprint" checked><div class="trk"></div><div class="tth"></div></label></div>
        <div class="tr2"><div><div class="tl">SNMP GET (read-only)</div><div class="tsubl">sysDescr, sysName, ifTable — no SET</div></div><label class="tog"><input type="checkbox" id="ph-snmp"><div class="trk"></div><div class="tth"></div></label></div>
        <div class="tr2"><div><div class="tl">OT protocol probes</div><div class="tsubl" style="color:var(--amber)">&#9888; Modbus/S7 read coils only — no writes</div></div><label class="tog"><input type="checkbox" id="ph-ot"><div class="trk"></div><div class="tth"></div></label></div>
        <div class="tr2"><div><div class="tl">CVE correlation</div><div class="tsubl">Match CPE strings against local NVD db</div></div><label class="tog"><input type="checkbox" id="ph-cve" checked><div class="trk"></div><div class="tth"></div></label></div>
      </div>
      <div class="card">
        <div class="ct">Discovery mode</div>
        <div class="tr2">
          <div>
            <div class="tl">Auto</div>
            <div class="tsubl">ARP for same-subnet, ping scan for routed</div>
          </div>
          <input type="radio" name="scan_mode" id="sm-auto" value="auto" checked style="accent-color:var(--acc)">
        </div>
        <div class="tr2">
          <div>
            <div class="tl">Routed</div>
            <div class="tsubl">ICMP/TCP ping scan only — no ARP (cross-router)</div>
          </div>
          <input type="radio" name="scan_mode" id="sm-routed" value="routed" style="accent-color:var(--acc)">
        </div>
        <div class="tr2">
          <div>
            <div class="tl">Force (-Pn)</div>
            <div class="tsubl" style="color:var(--amber)">&#9888; Scan all IPs regardless of ping — use for firewalled hosts</div>
          </div>
          <input type="radio" name="scan_mode" id="sm-force" value="force" style="accent-color:var(--acc)">
        </div>
      </div>
      <div class="card">
        <div class="ct">Launch</div>
        <div class="brow">
          <button class="btnp" id="btn-start" onclick="startScan()">&#9654; Queue scan</button>
        </div>
        <div id="scan-stats" style="margin-top:8px;font-family:var(--mf);font-size:10px;color:var(--tx3);display:none">
          Hosts found: <span id="ss-found">0</span> &nbsp;·&nbsp;
          Scanned: <span id="ss-scanned">0</span> &nbsp;·&nbsp;
          Elapsed: <span id="ss-elapsed">0s</span>
        </div>
      </div>
    </div>
  </div>

  <!-- Job queue — always visible, primary status view -->
  <div class="sth" style="margin-top:4px">Job queue</div>
  <div id="job-queue-wrap">
    <div id="job-queue" style="display:none;margin-bottom:8px">
      <div class="tbl-wrap">
        <table class="tbl">
          <thead><tr><th>#</th><th>Label</th><th>Target</th><th>Profile</th><th>Status / Progress</th><th>Priority</th><th>Queued</th><th></th></tr></thead>
          <tbody id="queue-tbody"></tbody>
        </table>
      </div>
    </div>
    <div id="job-queue-empty" style="font-family:var(--mf);font-size:11px;color:var(--tx3);padding:8px 0;margin-bottom:8px">No jobs queued or running</div>
  </div>

  <!-- Scan history -->
  <div class="sth" style="margin-top:4px">Scan history</div>
  <div class="tbl-wrap">
    <table class="tbl">
      <thead><tr><th>#</th><th>Label</th><th>Target</th><th>Status</th><th>Profile</th><th>Hosts</th><th>Duration</th><th>Completed</th><th></th></tr></thead>
      <tbody id="scan-hist"><tr><td colspan="7" class="loading">Loading…</td></tr></tbody>
    </table>
  </div>
</div>

<!-- ================================================================ AUDIT LOG -->
<div class="tab" id="t-sched">
  <!-- Schedule modal -->
  <div id="sched-bg" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:100;align-items:center;justify-content:center">
    <div style="background:var(--bg2);border:1px solid var(--bd2);border-radius:6px;padding:20px;width:480px;max-height:90vh;overflow-y:auto">
      <div style="font-family:var(--mf);font-size:12px;color:var(--acc);margin-bottom:14px" id="sched-title">New schedule</div>
      <input type="hidden" id="sched-id" value="">
      <input type="hidden" id="sched-paused" value="0">

      <label class="flbl">Schedule name</label>
      <input class="finp" id="sched-name" placeholder="Weekly full scan" style="width:100%;margin-bottom:10px">

      <label class="flbl">Target CIDR</label>
      <input class="finp" id="sched-cidr" placeholder="192.168.86.0/24" style="width:100%;margin-bottom:10px">

      <label class="flbl">Cron expression</label>
      <div style="display:flex;gap:6px;margin-bottom:6px;flex-wrap:wrap" id="cron-presets">
        <button class="tbtn" onclick="setCron('@daily')">Daily</button>
        <button class="tbtn" onclick="setCron('@weekly')">Weekly</button>
        <button class="tbtn" onclick="setCron('@monthly')">Monthly</button>
        <button class="tbtn" onclick="setCron('0 2 * * 0')">Sun 2am</button>
        <button class="tbtn" onclick="setCron('0 3 * * 1-5')">Weekdays 3am</button>
        <button class="tbtn" onclick="setCron('0 */6 * * *')">Every 6h</button>
      </div>
      <input class="finp" id="sched-cron" placeholder="0 3 * * 0" style="width:100%;margin-bottom:4px">
      <div style="font-family:var(--mf);font-size:10px;color:var(--tx3);margin-bottom:10px" id="sched-cron-desc">
        Format: minute hour day-of-month month day-of-week
      </div>

      <label class="flbl">Profile</label>
      <select class="finp" id="sched-profile" style="width:100%;margin-bottom:10px">
        <option value="standard_inventory">Standard Inventory</option>
        <option value="iot_safe">IoT Safe</option>
        <option value="deep_scan">Deep Scan</option>
        <option value="full_tcp">Full TCP</option>
        <option value="ot_careful">OT Careful</option>
      </select>

      <label class="flbl">Discovery mode</label>
      <select class="finp" id="sched-mode" style="width:100%;margin-bottom:10px">
        <option value="auto">Auto</option>
        <option value="routed">Routed</option>
        <option value="force">Force (-Pn)</option>
      </select>

      <label class="flbl">Timezone</label>
      <select class="finp" id="sched-tz" style="width:100%;margin-bottom:10px">
        <option value="UTC">UTC</option>
        <option value="America/New_York">America/New_York (ET)</option>
        <option value="America/Chicago">America/Chicago (CT)</option>
        <option value="America/Denver">America/Denver (MT)</option>
        <option value="America/Los_Angeles">America/Los_Angeles (PT)</option>
        <option value="America/Anchorage">America/Anchorage (AKT)</option>
        <option value="Pacific/Honolulu">Pacific/Honolulu (HT)</option>
        <option value="Europe/London">Europe/London (GMT/BST)</option>
        <option value="Europe/Paris">Europe/Paris (CET)</option>
        <option value="Europe/Berlin">Europe/Berlin (CET)</option>
        <option value="Asia/Tokyo">Asia/Tokyo (JST)</option>
        <option value="Asia/Shanghai">Asia/Shanghai (CST)</option>
        <option value="Australia/Sydney">Australia/Sydney (AEST)</option>
      </select>
      <div style="font-family:var(--mf);font-size:10px;color:var(--tx3);margin-bottom:10px" id="sched-tz-note">
        Cron times are interpreted in this timezone
      </div>

      <label class="flbl">Exclusions (optional)</label>
      <textarea class="finp" id="sched-excl" placeholder="192.168.86.1&#10;10.0.0.0/8" style="width:100%;height:60px;margin-bottom:10px;resize:vertical"></textarea>

      <label class="flbl">Notes (optional)</label>
      <input class="finp" id="sched-notes" placeholder="Description or reason for this schedule" style="width:100%;margin-bottom:10px">

      <label class="flbl">If a run is missed (daemon down, pause, etc.)</label>
      <select class="finp" id="sched-missed-pol" style="width:100%;margin-bottom:6px">
        <option value="run_once">Run one catch-up scan, then resume cadence</option>
        <option value="skip_no_run">Skip scan — only move next run forward</option>
        <option value="run_all">Queue one job per missed slot (capped)</option>
      </select>
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px">
        <label style="font-family:var(--mf);font-size:11px;color:var(--tx2);white-space:nowrap">Max jobs per wake</label>
        <input class="finp" type="number" id="sched-missed-max" min="1" max="100" value="5" style="width:72px">
      </div>
      <div style="font-family:var(--mf);font-size:10px;color:var(--tx3);margin-bottom:12px">
        “Run all” uses this cap so a long outage cannot flood the queue.
      </div>

      <label style="display:flex;align-items:center;gap:8px;margin-bottom:14px;font-family:var(--mf);font-size:12px;color:var(--tx2)">
        <input type="checkbox" id="sched-en" checked> Cron enabled (off = schedule dormant; use Pause on the list to freeze without turning off)
      </label>

      <div style="display:flex;gap:8px">
        <button class="btnp" onclick="saveSchedule()">Save schedule</button>
        <button class="tbtn" onclick="closeSchedModal()">Cancel</button>
      </div>
    </div>
  </div>

  <div id="sched-hist-bg" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:101;align-items:center;justify-content:center">
    <div style="background:var(--bg2);border:1px solid var(--bd2);border-radius:6px;padding:20px;width:560px;max-height:85vh;overflow-y:auto">
      <div style="font-family:var(--mf);font-size:12px;color:var(--acc);margin-bottom:10px" id="sched-hist-title">Run history</div>
      <div class="tbl-wrap">
        <table class="tbl">
          <thead><tr>
            <th>#</th><th>Status</th><th>Label</th><th>Hosts</th><th>Queued</th><th>Finished</th>
          </tr></thead>
          <tbody id="sched-hist-tbody"><tr><td colspan="6" class="loading">Loading…</td></tr></tbody>
        </table>
      </div>
      <button class="tbtn" style="margin-top:12px" onclick="closeSchedHistModal()">Close</button>
    </div>
  </div>

  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px">
    <div class="sth" style="margin:0">Scan schedules</div>
    <button class="btnp" style="font-size:12px" onclick="openSchedModal()">+ New schedule</button>
  </div>

  <div class="tbl-wrap">
    <table class="tbl">
      <thead><tr>
        <th>Name</th><th>Target</th><th>Profile</th><th>Cron</th>
        <th>Missed runs</th><th>Next run</th><th>Last run</th><th>Last result</th>
        <th>On</th><th></th>
      </tr></thead>
      <tbody id="sched-tbody"><tr><td colspan="10" class="loading">Loading…</td></tr></tbody>
    </table>
  </div>
</div>

<div class="tab" id="t-logs">
  <div class="fbar">
    <input class="finp wide" id="lf-q" placeholder="Filter log output…" oninput="filterLog()">
    <select class="finp narrow" id="lf-level" onchange="filterLog()">
      <option value="">All levels</option>
      <option value="PROBE">PROBE</option><option value="INFO">INFO</option>
      <option value="WARN">WARN</option><option value="ERR">ERR</option>
    </select>
    <button class="tbtn" onclick="loadLog()">&#8635; Refresh</button>
    <button class="tbtn" id="btn-autoscroll" onclick="toggleAutoscroll()">Auto-scroll: ON</button>
  </div>
  <div class="log-wrap" id="log-wrap">
    <div class="loading">Loading…</div>
  </div>
</div>

<!-- ================================================================ ENRICHMENT -->
<div class="tab" id="t-enrich">
  <div class="scgrid">
    <div>
      <div class="card">
        <div class="ct">Active sources</div>
        <div id="enrich-list"><div class="loading">Loading…</div></div>
        <div style="margin-top:12px">
          <button class="btnp" onclick="openAddSource()">+ Add source</button>
        </div>
      </div>
    </div>
    <div>
      <div class="card">
        <div class="ct">Available source types</div>
        <div id="enrich-types"><div class="loading">Loading…</div></div>
      </div>
      <div class="card">
        <div class="ct">How enrichment works</div>
        <div style="font-size:11px;color:var(--tx2);line-height:1.8">
          Enrichment sources run as <b style="color:var(--tx)">Phase 3b</b> during each scan.<br>
          They provide MAC addresses, hostnames, and VLAN data that the scanner
          alone can't get — especially for devices across routers.<br><br>
          <b style="color:var(--tx)">UniFi / UDM</b> — queries your controller for all
          known clients. Solves MAC lookup for the entire network in one call.<br><br>
          <b style="color:var(--tx)">SNMP</b> — walks the ARP table of your router/switch.
          Universal fallback that works with any managed device.
        </div>
      </div>
    </div>
  </div>
</div>

<!-- ================================================================ SETTINGS -->
<div class="tab" id="t-settings">
  <div class="scgrid">
    <div>
      <div class="card">
        <div class="ct">NVD feed status</div>
        <div style="font-family:var(--mf);font-size:11px;color:var(--tx2);margin-bottom:10px">
          Last sync: <span id="nvd-sync-ts" style="color:var(--tx)">—</span>
        </div>
        <div style="font-size:11px;color:var(--tx2);margin-bottom:10px">
          The NVD feed maps CPE strings to CVE IDs for offline vulnerability correlation.
          Run <code style="color:var(--acc)">sync_nvd.py</code> to refresh (auto-runs weekly via cron).
        </div>
      </div>
      <div class="card">
        <div class="ct">Fingerprint feed status</div>
        <div style="font-family:var(--mf);font-size:11px;color:var(--tx2);line-height:1.8">
          OUI last sync: <span id="oui-sync-ts" style="color:var(--tx)">—</span><br>
          OUI prefixes: <span id="oui-sync-count" style="color:var(--tx)">0</span><br>
          WebFP last sync: <span id="webfp-sync-ts" style="color:var(--tx)">—</span><br>
          WebFP rules: <span id="webfp-sync-count" style="color:var(--tx)">0</span>
        </div>
        <div style="font-size:11px;color:var(--tx2);margin-top:10px">
          Source feeds: IEEE OUI CSV + Wappalyzer technologies (synced daily via cron).
          Run <code style="color:var(--acc)">sync_oui.py</code> and
          <code style="color:var(--acc)">sync_webfp.py</code> manually any time.
        </div>
        <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:12px">
          <button class="tbtn" id="btn-sync-oui" onclick="runFeedSync('oui')">Sync OUI now</button>
          <button class="tbtn" id="btn-sync-webfp" onclick="runFeedSync('webfp')">Sync WebFP now</button>
          <button class="btnp" id="btn-sync-all" onclick="runFeedSync('all')">Sync all feeds</button>
          <button class="tbtn" onclick="openFeedSyncOutput()">View last output</button>
        </div>
      </div>
      <div class="card">
        <div class="ct">About</div>
        <div style="font-family:var(--mf);font-size:11px;color:var(--tx2);line-height:1.8">
          SurveyTrace v0.2.0<br>
          PHP + SQLite + Python scanner daemon<br>
          <span style="color:var(--tx3)">Data stored in data/surveytrace.db</span>
        </div>
      </div>
    </div>
    <div>
      <div class="card">
        <div class="ct">Asset categories</div>
        <table style="width:100%;font-size:11px;font-family:var(--mf)">
          <tr><td style="padding:3px 0"><span class="cat srv">srv</span></td><td style="color:var(--tx2);padding:3px 6px">Server (Linux, Windows Server)</td></tr>
          <tr><td style="padding:3px 0"><span class="cat ws">ws</span></td><td style="color:var(--tx2);padding:3px 6px">Workstation / desktop</td></tr>
          <tr><td style="padding:3px 0"><span class="cat net">net</span></td><td style="color:var(--tx2);padding:3px 6px">Network gear (switch, router, firewall)</td></tr>
          <tr><td style="padding:3px 0"><span class="cat iot">iot</span></td><td style="color:var(--tx2);padding:3px 6px">IoT device</td></tr>
          <tr><td style="padding:3px 0"><span class="cat ot">ot</span></td><td style="color:var(--tx2);padding:3px 6px">OT / ICS (PLC, SCADA, HMI)</td></tr>
          <tr><td style="padding:3px 0"><span class="cat voi">voi</span></td><td style="color:var(--tx2);padding:3px 6px">VoIP phone / PBX</td></tr>
          <tr><td style="padding:3px 0"><span class="cat prn">prn</span></td><td style="color:var(--tx2);padding:3px 6px">Printer / MFP</td></tr>
          <tr><td style="padding:3px 0"><span class="cat hv">hv</span></td><td style="color:var(--tx2);padding:3px 6px">Hypervisor (ESXi, Proxmox, Hyper-V)</td></tr>
        </table>
      </div>
    </div>
  </div>
</div>

</div><!-- .main -->
</div><!-- .shell -->

<div class="toast-wrap" id="toasts"></div>

<!-- Host detail panel -->
<div id="host-panel" style="display:none;position:fixed;top:0;right:0;width:420px;height:100vh;background:var(--bg2);border-left:1px solid var(--bd2);z-index:200;overflow-y:auto;box-shadow:-4px 0 20px rgba(0,0,0,.3)">
  <div style="display:flex;align-items:center;justify-content:space-between;padding:14px 16px;border-bottom:1px solid var(--bd);position:sticky;top:0;background:var(--bg2);z-index:1">
    <div style="font-family:var(--mf);font-size:12px;color:var(--acc)" id="hp-title">Host detail</div>
    <button class="tbtn" onclick="closeHostPanel()" style="font-size:14px;padding:2px 8px">✕</button>
  </div>
  <div id="hp-body" style="padding:16px"></div>
</div>
<div id="host-panel-bg" onclick="closeHostPanel()" style="display:none;position:fixed;inset:0;z-index:199;background:rgba(0,0,0,.2)"></div>

<!-- Feed sync output modal -->
<div id="fsync-bg" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.65);z-index:210;align-items:center;justify-content:center">
  <div style="background:var(--bg2);border:1px solid var(--bd2);border-radius:6px;padding:16px;width:min(980px,92vw);max-height:86vh;display:flex;flex-direction:column">
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:10px">
      <div style="font-family:var(--mf);font-size:12px;color:var(--acc)" id="fsync-title">Feed sync output</div>
      <button class="tbtn" onclick="closeFeedSyncOutput()">Close</button>
    </div>
    <pre id="fsync-out" style="margin:0;white-space:pre-wrap;overflow:auto;max-height:72vh;background:var(--bg);border:1px solid var(--bd);padding:12px;font-size:11px;font-family:var(--mf);color:var(--tx2)">No sync output yet.</pre>
  </div>
</div>

<!-- Enrichment source modal -->
<div id="esrc-bg" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:100;align-items:center;justify-content:center">
  <div style="background:var(--bg2);border:1px solid var(--bd2);border-radius:6px;padding:24px;width:440px;max-height:80vh;overflow-y:auto;font-family:var(--sf)">
    <div style="font-family:var(--mf);font-size:12px;color:var(--acc);margin-bottom:14px">
      <span id="esrc-title">Add enrichment source</span>
    </div>
    <input type="hidden" id="esrc-id" value="0">
    <label class="flbl">Source type</label>
    <select class="finp" id="esrc-type" style="width:100%;margin-bottom:10px" onchange="updateSourceFields()">
      <option value="unifi">UniFi / UDM</option>
      <option value="snmp">SNMP (universal)</option>
      <option value="dhcp_leases">DHCP leases (generic)</option>
      <option value="dns_logs">DNS logs (generic)</option>
      <option value="firewall_logs">Firewall logs (generic)</option>
      <option value="ms_dns">Microsoft DNS</option>
      <option value="cisco_dna">Cisco DNA Center (stub)</option>
      <option value="meraki">Cisco Meraki (stub)</option>
      <option value="juniper_mist">Juniper Mist (stub)</option>
    </select>
    <label class="flbl">Label</label>
    <input class="finp" id="esrc-label" type="text" style="width:100%;margin-bottom:10px" placeholder="e.g. Home UDM">
    <div id="esrc-fields"></div>
    <div class="tr2" style="margin-bottom:14px">
      <div><div class="tl">Enabled</div><div class="tsubl">Run this source during scans</div></div>
      <label class="tog"><input type="checkbox" id="esrc-enabled" checked><div class="trk"></div><div class="tth"></div></label>
    </div>
    <div id="esrc-test-result" style="font-family:var(--mf);font-size:11px;margin-bottom:10px;display:none"></div>
    <div style="display:flex;gap:8px;justify-content:flex-end">
      <button class="tbtn" onclick="testSource()">Test</button>
      <button class="tbtn" onclick="closeSourceModal()">Cancel</button>
      <button class="btnp" onclick="saveSource()">Save</button>
    </div>
  </div>
</div>

<!-- Reclassify modal -->
<div id="modal-bg" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:100;align-items:center;justify-content:center">
  <div style="background:var(--bg2);border:1px solid var(--bd2);border-radius:6px;padding:24px;width:380px;font-family:var(--sf)">
    <div style="font-family:var(--mf);font-size:12px;color:var(--acc);margin-bottom:14px">Edit asset — <span id="modal-ip" style="color:var(--tx)"></span></div>
    <input type="hidden" id="modal-asset-id">
    <label style="display:block;font-size:11px;color:var(--tx2);font-family:var(--mf);margin-bottom:3px">Hostname</label>
    <input class="finp" id="modal-hostname" type="text" style="width:100%;margin-bottom:10px">
    <label style="display:block;font-size:11px;color:var(--tx2);font-family:var(--mf);margin-bottom:3px">Category</label>
    <select class="finp" id="modal-cat" style="width:100%;margin-bottom:10px">
      <option value="srv">Server</option>
      <option value="ws">Workstation</option>
      <option value="net">Network gear</option>
      <option value="iot">IoT</option>
      <option value="ot">OT / ICS</option>
      <option value="voi">VoIP</option>
      <option value="prn">Printer</option>
      <option value="hv">Hypervisor</option>
      <option value="unk">Unknown</option>
    </select>
    <label style="display:block;font-size:11px;color:var(--tx2);font-family:var(--mf);margin-bottom:3px">Vendor override</label>
    <input class="finp" id="modal-vendor" type="text" style="width:100%;margin-bottom:10px" placeholder="Leave blank to keep existing">
    <label style="display:block;font-size:11px;color:var(--tx2);font-family:var(--mf);margin-bottom:3px">Notes</label>
    <textarea class="finp" id="modal-notes" style="width:100%;min-height:56px;margin-bottom:14px" placeholder="Optional notes about this asset"></textarea>
    <div style="display:flex;gap:8px;justify-content:flex-end">
      <button class="tbtn" onclick="closeModal()">Cancel</button>
      <button class="btnp" onclick="saveReclassify()">Save</button>
    </div>
  </div>
</div>

<script>
// ==========================================================================
// State
// ==========================================================================
var currentTab   = 'dash';
var assetPage    = 1;
var assetSort    = 'ip';
var assetOrder   = 'asc';
var vulnPage     = 1;
var activeJobId  = null;
var pollTimer    = null;
var logSinceId   = 0;
var autoscroll   = true;
var allLogRows   = [];
var dashTimer    = null;
var feedSyncLastOutput = 'No sync output yet.';

// ==========================================================================
// Nav
// ==========================================================================
function goTab(name) {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('on'));
    document.getElementById('t-' + name).classList.add('on');
    currentTab = name;
    try { sessionStorage.setItem('st_tab', name); } catch(e) {}
    if (name === 'dash')     loadDashboard();
    if (name === 'assets')   loadAssets(1);
    if (name === 'vulns')    loadFindings(1);
    if (name === 'logs')     loadLog();
    if (name === 'scan')     loadScanStatus();
    if (name === 'enrich')   loadEnrichment();
    if (name === 'sched')    loadSchedules();
    if (name === 'settings') loadEnrichment(); // NVD sync status on settings tab
}

function hiNav(id) {
    document.querySelectorAll('.ni').forEach(n => n.classList.remove('on'));
    document.getElementById(id).classList.add('on');
}

// ==========================================================================
// Fetch helper
// ==========================================================================
async function api(url) {
    try {
        const r = await fetch(url, {credentials: 'same-origin'});
        if (!r.ok) throw new Error('HTTP ' + r.status);
        return await r.json();
    } catch (e) {
        console.error('API error', url, e);
        return null;
    }
}

async function apiPost(url, body) {
    try {
        const r = await fetch(url, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(body),
            credentials: 'same-origin'
        });
        return await r.json();
    } catch (e) {
        console.error('POST error', url, e);
        return null;
    }
}

// ==========================================================================
// Dashboard
// ==========================================================================
async function loadDashboard() {
    const d = await api('/api/dashboard.php');
    if (!d) return;

    document.getElementById('d-total').textContent = d.assets.total;
    document.getElementById('d-new').textContent   = '+' + (d.assets.new_24h || 0) + ' in last 24h';
    document.getElementById('d-unk').textContent   = d.assets.unclassified;
    document.getElementById('d-cves').textContent  = d.findings.open;
    document.getElementById('d-crit').textContent  = (d.findings.by_severity.critical || 0) + ' critical';

    // Update sidebar badges
    updateSidebarBadges(d.assets.total, d.findings.open, d.findings.by_severity?.critical || 0);

    // Last scan
    if (d.last_scan) {
        const age = d.last_scan.age_secs;
        document.getElementById('d-age').textContent = age < 3600
            ? Math.floor(age/60) + 'm'
            : Math.floor(age/3600) + 'h';
        document.getElementById('d-scan-target').textContent = d.last_scan.target_cidr || '—';
    }

    // Category breakdown
    const bc = d.assets.by_category || {};
    document.getElementById('dc-srv').textContent = bc.srv || 0;
    document.getElementById('dc-ws').textContent  = bc.ws  || 0;
    document.getElementById('dc-net').textContent = bc.net || 0;
    document.getElementById('dc-iot').textContent = (bc.iot||0)+(bc.ot||0)+(bc.voi||0)+(bc.prn||0)+(bc.hv||0)+(bc.unk||0);

    // NVD sync
    document.getElementById('nvd-sync-ts').textContent = d.nvd_last_sync || 'never';
    document.getElementById('oui-sync-ts').textContent = d.oui_last_sync || 'never';
    document.getElementById('webfp-sync-ts').textContent = d.webfp_last_sync || 'never';
    document.getElementById('oui-sync-count').textContent = d.oui_prefix_count || 0;
    document.getElementById('webfp-sync-count').textContent = d.webfp_rule_count || 0;

    // Top vulnerable
    const tv = d.top_vulnerable || [];
    document.getElementById('dash-top-vuln').innerHTML = tv.length
        ? tv.map(a => `<tr>
            <td class="mono" style="cursor:pointer;color:var(--acc)" onclick="openHostPanel(${a.id},'${esc(a.ip)}')" title="View host detail">${esc(a.ip)}</td>
            <td style="color:var(--tx)">${esc(a.hostname||'—')}</td>
            <td><span class="cat ${esc(a.category)}">${esc(a.category)}</span></td>
            <td style="color:var(--tx);font-size:11px">${esc(a.vendor||'—')}</td>
            <td class="mono" style="font-size:10px">${esc(a.top_cve||'—')}</td>
            <td><span class="sev ${sevClass(a.top_cvss)}">${a.top_cvss||'—'}</span></td>
            <td class="mono">${a.finding_count}</td>
          </tr>`).join('')
        : '<tr><td colspan="7" class="loading">No vulnerable assets found</td></tr>';

    // Activity feed
    const act = d.activity || [];
    document.getElementById('dash-feed').innerHTML = act.length
        ? act.map(e => feedRow(e)).join('')
        : '<div class="empty-feed">No activity yet</div>';

    // Check for active scan and update status pill
    updateStatusPill(d.last_scan);
}

function feedRow(e) {
    const tag = e.level === 'WARN' || e.level === 'ERR' ? 'ch'
              : e.message && e.message.match(/CVE|vuln/i) ? 'vl'
              : e.message && e.message.match(/first seen|new host/i) ? 'nw'
              : 'sc';
    const ts  = (e.ts || '').split(' ')[1] || e.ts || '';
    const msg = esc(e.message || '').replace(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/g, '<b>$1</b>');
    return `<div class="fr"><span class="ft">${ts}</span><span class="ftg ${tag}">${e.level||'INFO'}</span><span class="fm">${msg}</span></div>`;
}

// ==========================================================================
// Assets
// ==========================================================================
var assetDebounce = null;
function debounceAssets() {
    clearTimeout(assetDebounce);
    assetDebounce = setTimeout(() => loadAssets(1), 350);
}

function sortAssets(col) {
    if (assetSort === col) assetOrder = assetOrder === 'asc' ? 'desc' : 'asc';
    else { assetSort = col; assetOrder = 'asc'; }
    document.getElementById('af-sort').value = col;
    loadAssets(assetPage);
}

function detectServiceHitsFromAsset(asset) {
    const banners = asset.banners || {};
    const httpProbe = String(banners._http || '');
    const ports = asset.open_ports || [];
    const SERVICE_SIGS = [
        ['Uptime Kuma', /uptime.?kuma/i],
        ['Zabbix', /zabbix/i],
        ['ntfy', /\bntfy\b/i],
        ['Kasm Workspaces', /\bkasm(web|vnc)?\b|kasmtechnologies/i],
        ['Proxmox VE', /proxmox|pve\./i],
        ['Portainer', /portainer/i],
        ['Grafana', /\bgrafana\b/i],
        ['Prometheus', /prometheus/i],
        ['Docker Engine', /docker/i],
        ['Jellyfin', /jellyfin/i],
        ['Gitea', /\bgitea\b/i],
        ['Nextcloud', /nextcloud/i],
        ['Mastodon', /mastodon/i],
        ['OpenObserve', /openobserve/i],
    ];
    const hits = new Set();
    const scan = (txt) => {
        if (!txt) return;
        for (const [name, rx] of SERVICE_SIGS) if (rx.test(txt)) hits.add(name);
    };
    scan(httpProbe);
    for (const p of ports) scan(String(banners[String(p)] || ''));
    return Array.from(hits).sort();
}

async function loadAssets(page) {
    refreshBadges();
    assetPage = page;
    const q    = document.getElementById('af-q')?.value    || '';
    const cat  = document.getElementById('af-cat')?.value  || '';
    const sev  = document.getElementById('af-sev')?.value  || '';
    const sort = document.getElementById('af-sort')?.value || assetSort;

    // Show loading state immediately
    document.getElementById('asset-tbody').innerHTML =
        '<tr><td colspan="9" class="loading">Loading assets…</td></tr>';

    const url = `/api/assets.php?page=${page}&per_page=50&q=${enc(q)}&category=${enc(cat)}&severity=${enc(sev)}&sort=${sort}&order=${assetOrder}`;
    const d   = await api(url);
    if (!d) return;

    document.getElementById('asset-tbody').innerHTML = (d.assets || []).map(a => {
        const ports = (a.open_ports || []).slice(0,6).map(p => `<span class="pt">${Number(p)}</span>`).join('');
        const more  = a.open_ports && a.open_ports.length > 6 ? `<span class="pt">+${a.open_ports.length-6}</span>` : '';
        const svcHits = detectServiceHitsFromAsset(a);
        const primaryVendor = a.vendor || '—';
        let vendorCell = esc(primaryVendor) + (a.model ? '<span style="color:var(--tx2)"> ' + esc(a.model) + '</span>' : '');
        if (svcHits.length > 1) {
            const extra = svcHits.filter(s => s.toLowerCase() !== String(primaryVendor).toLowerCase());
            if (extra.length) {
                vendorCell += ` <span style="font-family:var(--mf);font-size:10px;color:var(--tx3)" title="${esc(svcHits.join(', '))}">+${extra.length} services</span>`;
            }
        }
        return `<tr>
          <td class="mono" style="cursor:pointer;color:var(--acc)" onclick="openHostPanel(${a.id},'${esc(a.ip)}')" title="View host detail">${esc(a.ip)}</td>
          <td style="color:var(--tx)">${esc(a.hostname||'—')}</td>
          <td><span class="cat ${esc(a.category||'unk')}">${esc(a.category||'unk')}</span></td>
          <td style="color:var(--tx);font-size:11px">${vendorCell}</td>
          <td><div class="pts">${ports}${more}</div></td>
          <td class="mono">${a.open_findings||0}</td>
          <td><span class="sev ${sevClass(a.top_cvss)}">${a.top_cvss?a.top_cvss:'—'}</span></td>
          <td class="mono" style="font-size:10px">${relTime(a.last_seen)}</td>
          <td><button class="tbtn" style="font-size:10px" onclick="openReclassify(${a.id},'${esc(a.ip)}','${esc(a.hostname||'')}','${esc(a.category)}','${esc(a.vendor||'')}','${esc(a.notes||'')}')">&#9998;</button></td>
        </tr>`;
    }).join('') || '<tr><td colspan="8" class="loading">No assets found</td></tr>';

    document.getElementById('apgn-info').textContent = `Page ${d.page} of ${d.pages} (${d.total} assets)`;
    document.getElementById('aprev').disabled = page <= 1;
    document.getElementById('anext').disabled = page >= d.pages;
}

// ==========================================================================
// Findings / Vulnerabilities
// ==========================================================================
var vulnDebounce = null;

async function loadFindings(page) {
    refreshBadges();
    // Show loading state immediately
    document.getElementById('vuln-tbody').innerHTML =
        '<tr><td colspan="8" class="loading">Loading vulnerabilities…</td></tr>';

    vulnPage = page;
    const cve  = document.getElementById('vf-cve').value;
    const sev  = document.getElementById('vf-sev').value;
    const cat  = document.getElementById('vf-cat').value;
    const res  = document.getElementById('vf-resolved').value;

    const ip   = document.getElementById('vf-ip')?.value || '';
    const miny = document.getElementById('vf-minyear')?.value || '';
    const url = `/api/findings.php?page=${page}&per_page=50&cve_id=${enc(cve)}&ip=${enc(ip)}&severity=${enc(sev)}&category=${enc(cat)}&resolved=${res}&min_year=${enc(miny)}&sort=cvss&order=desc`;
    const d   = await api(url);
    if (!d) return;

    document.getElementById('vuln-tbody').innerHTML = (d.findings || []).map(f => `<tr>
      <td class="mono" style="font-size:10px">${esc(f.cve_id)}</td>
      <td class="mono" style="cursor:pointer;color:var(--acc)"
          onclick="filterVulnsByIP('${esc(f.ip)}')"
          title="Filter to this host">${esc(f.ip)}</td>
      <td style="color:var(--acc);font-size:11px;cursor:pointer"
          onclick="filterVulnsByIP('${esc(f.ip)}')"
          title="Filter to this host">${esc(f.hostname||'—')}</td>
      <td><span class="cat ${esc(f.category||'unk')}">${esc(f.category||'unk')}</span></td>
      <td style="color:var(--tx2);font-size:11px;max-width:260px">${esc(f.description||'—')}</td>
      <td><span class="sev ${sevClass(f.cvss)}">${f.cvss||'—'}</span></td>
      <td class="mono" style="font-size:10px">${localDate(f.published)}</td>
      <td>${f.resolved ? '<span style="color:var(--green);font-family:var(--mf);font-size:10px">resolved</span>'
          : `<button class="tbtn" style="font-size:10px" onclick="resolveFinding(${f.id}, this)">Resolve</button>`}</td>
    </tr>`).join('') || '<tr><td colspan="8" class="loading">No findings</td></tr>';

    document.getElementById('vpgn-info').textContent = `Page ${d.page} of ${d.pages} (${d.total} findings)`;
    document.getElementById('vprev').disabled = page <= 1;
    document.getElementById('vnext').disabled = page >= d.pages;
}

async function resolveFinding(id, btn) {
    btn.disabled = true;
    const r = await apiPost('/api/findings.php?action=resolve', {action:'resolve', finding_id: id});
    if (r && r.ok) { toast('Finding marked resolved', 'ok'); loadFindings(vulnPage); }
    else { toast('Failed to resolve finding', 'err'); btn.disabled = false; }
}

// ==========================================================================
// Scan control
// ==========================================================================
async function startScan() {
    const cidr  = document.getElementById('sc-cidr').value.trim();
    if (!cidr) { toast('Enter a CIDR target', 'err'); return; }

    // Warn on large subnets — /16 is 65k hosts, /8 is 16M
    const cidrs = cidr.split(',').map(c => c.trim());
    for (const c of cidrs) {
        const prefix = parseInt((c.split('/')[1] || '32'));
        if (prefix <= 8) {
            toast('/' + prefix + ' is too broad — maximum allowed is /8', 'err');
            return;
        }
        if (prefix <= 16) {
            const hosts = Math.pow(2, 32 - prefix).toLocaleString();
            if (!confirm(`Warning: /${prefix} covers ${hosts} hosts and may take hours.\n\nAre you sure you want to scan ${c}?`)) {
                return;
            }
        }
    }

    const phases = [];
    ['passive','icmp','banner','fingerprint','snmp','ot','cve'].forEach(p => {
        if (document.getElementById('ph-'+p)?.checked) phases.push(p);
    });

    const profileEl = document.querySelector('input[name="scan_profile"]:checked');
    const profileVal  = profileEl ? profileEl.value : 'standard_inventory';

    // Confirmation required for dangerous profiles
    if (['deep_scan', 'full_tcp', 'ot_careful'].includes(profileVal)) {
        if (!confirm(`Profile "${profileVal}" generates significant network traffic and requires confirmation.\n\nProceed?`)) return;
    }

    const modeEl = document.querySelector('input[name="scan_mode"]:checked');
    const body = {
        cidr:        cidr,
        exclusions:  document.getElementById('sc-excl').value,
        phases:      phases,
        rate_pps:    parseInt(document.getElementById('sc-pps').value),
        inter_delay: parseInt(document.getElementById('sc-delay').value),
        label:       document.getElementById('sc-label').value.trim(),
        scan_mode:   modeEl ? modeEl.value : 'auto',
        profile:     profileVal,
        confirmed:   true,
    };

    document.getElementById('btn-start').disabled = true;
    const r = await apiPost('/api/scan_start.php', body);
    if (!r) { toast('API error starting scan', 'err'); document.getElementById('btn-start').disabled = false; return; }
    if (r.error) { toast(r.error, 'err'); document.getElementById('btn-start').disabled = false; return; }

    activeJobId = r.job_id;
    toast('Scan #' + activeJobId + ' queued', 'ok');
    document.getElementById('btn-start').disabled = false;
    document.getElementById('btn-start').textContent = '\u25b6 Queue scan';
    loadScanHistory();   // refresh queue panel immediately
    startPoll(activeJobId);
}

async function abortScan() {
    let jobId = activeJobId;
    if (!jobId) {
        const s = await api('/api/scan_status.php?log_limit=1');
        if (s && s.job && ['running','queued'].includes(s.job.status)) {
            jobId = s.job.id;
        }
    }
    if (!jobId) { toast('No active scan to abort', 'err'); return; }
    abortJobById(jobId);
}

function showScanRunning(jobId) {
    document.getElementById('scan-stats').style.display = '';
    setStatusPill('run', 'Scanning…');
}

function startPoll(jobId) {
    clearInterval(pollTimer);
    logSinceId = 0;
    pollTimer = setInterval(() => pollJob(jobId), 2500);
}

async function pollJob(jobId) {
    const d = await api(`/api/scan_status.php?job_id=${jobId}&since_log_id=${logSinceId}&log_limit=100`);
    if (!d || !d.job) return;

    const job = d.job;

    // Update scan stats (kept for backward compat)
    document.getElementById('ss-found').textContent   = job.hosts_found || 0;
    document.getElementById('ss-scanned').textContent = job.hosts_scanned || 0;
    const el = job.elapsed_secs || 0;
    document.getElementById('ss-elapsed').textContent = el < 60 ? el+'s' : Math.floor(el/60)+'m '+(el%60)+'s';

    // Update queue panel inline progress
    if (d.history) updateQueuePanel(d.history);

    // Update inline message for running job row
    const msgEl = document.getElementById('qmsg-' + jobId);
    if (msgEl) {
        const lastInfo = (d.log || []).slice().reverse().find(l => l.level === 'INFO');
        if (lastInfo) {
            const pct = job.progress_pct || 0;
            const hf  = job.hosts_found || 0;
            const hs  = job.hosts_scanned || 0;
            msgEl.textContent = (hf > 0 ? hs+'/'+hf+' hosts · '+pct+'% · ' : '') + lastInfo.message.slice(0,60);
        }
    }

    // Append new log lines to audit log view
    if (d.log && d.log.length) {
        logSinceId = d.log[d.log.length-1].id;
        if (currentTab === 'logs') appendLogRows(d.log);
    }

    if (job.status === 'done' || job.status === 'failed' || job.status === 'aborted') {
        clearInterval(pollTimer);
        activeJobId = null;
        setStatusPill('idle', 'Idle');
        if (job.status === 'done') { toast('Scan complete — ' + job.hosts_scanned + ' hosts catalogued', 'ok'); refreshBadges(); }
        if (job.status === 'failed') toast('Scan failed: ' + (job.error_msg || 'unknown error'), 'err');
        loadScanHistory();
        if (currentTab === 'dash') loadDashboard();
        // Check if another job is queued and auto-start polling it
        setTimeout(async () => {
            const next = await api('/api/scan_status.php?log_limit=1');
            if (next && next.job && next.job.status === 'running') {
                activeJobId = next.job.id;
                showScanRunning(activeJobId);
                startPoll(activeJobId);
            }
        }, 2000);
    } else {
        // Refresh queue panel on each poll so counts stay current
        if (d.history) updateQueuePanel(d.history);
    }
}

async function loadScanStatus() {
    const d = await api('/api/scan_status.php?log_limit=50');
    if (!d) return;
    if (d.job) {
        if (d.job.status === 'running' || d.job.status === 'queued') {
            activeJobId = d.job.id;
            showScanRunning(activeJobId);
            startPoll(activeJobId);
        }
    }
    loadScanHistory(d.history);
}

async function loadScanHistory(history) {
    if (!history) {
        const d = await api('/api/scan_status.php?log_limit=1');
        history = d ? d.history : [];
    }
    const statColors = {done:'var(--green)', failed:'var(--red)', aborted:'var(--amber)', running:'var(--acc)', queued:'var(--tx3)'};
    const statColors2 = {done:'var(--green)',failed:'var(--red)',aborted:'var(--amber)',running:'var(--acc)',queued:'var(--tx3)',retrying:'var(--amber)'};
    updateQueuePanel(history);
    document.getElementById('scan-hist').innerHTML = (history||[]).filter(j => !['queued','running','retrying'].includes(j.status)).map(j => `<tr>
      <td class="mono">#${j.id}</td>
      <td style="color:var(--tx);font-size:11px">${esc(j.label||'\u2014')}${j.retry_count > 0 ? ` <span style="font-family:var(--mf);font-size:9px;color:var(--amber)">retry ${j.retry_count}</span>` : ''}</td>
      <td class="mono" style="font-size:10px">${esc(j.target_cidr)}</td>
      <td><span style="color:${statColors2[j.status]||'var(--tx2)'};font-family:var(--mf);font-size:10px">${j.status}</span>${j.status==='failed'&&j.error_msg?`<div style="font-family:var(--mf);font-size:9px;color:var(--red);margin-top:1px" title="${esc(j.error_msg)}">${esc((j.error_msg||'').slice(0,50))}</div>`:''}</td>
      <td style="font-family:var(--mf);font-size:9px;color:var(--tx3)">${j.profile?esc(j.profile.replace(/_/g,' ')):'\u2014'}</td>
      <td class="mono">${j.hosts_found||0}</td>
      <td class="mono" style="font-size:10px">${fmtDuration(j.duration_secs)}</td>
      <td class="mono" style="font-size:10px">${localDate(j.finished_at)}</td>
      <td>${['queued','retrying'].includes(j.status)?`<button class="tbtn" style="font-size:9px;color:var(--red)" onclick="cancelJob(${j.id})">Cancel</button>`:j.status==='failed'?`<button class="tbtn" style="font-size:9px" onclick="retryJob(${j.id})">Retry</button>`:''}</td>
    </tr>`).join('') || '<tr><td colspan="9" class="loading">No previous scans</td></tr>';
}

// ==========================================================================
// Job queue panel
// ==========================================================================
function updateQueuePanel(history) {
    const queued = (history||[]).filter(j =>
        ['queued','running','retrying'].includes(j.status)
    ).sort((a,b) => (a.priority||10)-(b.priority||10) || a.id-b.id);

    const wrap  = document.getElementById('job-queue');
    const empty = document.getElementById('job-queue-empty');
    const tbody = document.getElementById('queue-tbody');

    if (!queued.length) {
        wrap.style.display  = 'none';
        empty.style.display = 'block';
        // Hide scan stats if nothing running
        document.getElementById('scan-stats').style.display = 'none';
        return;
    }

    wrap.style.display  = 'block';
    empty.style.display = 'none';

    const statusColor = {running:'var(--acc)',queued:'var(--tx3)',retrying:'var(--amber)'};
    tbody.innerHTML = queued.map(j => {
        const pct  = j.progress_pct || 0;
        const isRun = j.status === 'running';
        const msgEl = isRun ? `
            <div style="font-family:var(--mf);font-size:9px;color:var(--tx3);margin-top:3px;max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" id="qmsg-${j.id}">
              ${j.hosts_found > 0 ? j.hosts_scanned+'/'+ j.hosts_found+' hosts &nbsp;·&nbsp; '+pct+'%' : 'Starting…'}
            </div>
            <div style="height:3px;background:var(--bg4);border-radius:2px;margin-top:4px;width:200px">
              <div style="height:3px;background:var(--acc);border-radius:2px;width:${pct}%;transition:width .3s"></div>
            </div>` : '';
        return `<tr>
          <td class="mono">#${j.id}</td>
          <td style="font-size:11px;color:var(--tx)">${esc(j.label||'—')}</td>
          <td class="mono" style="font-size:10px">${esc(j.target_cidr)}</td>
          <td style="font-family:var(--mf);font-size:9px;color:var(--tx3)">${j.profile?esc(j.profile.replace(/_/g,' ')):'—'}</td>
          <td>
            <span style="font-family:var(--mf);font-size:10px;color:${statusColor[j.status]||'var(--tx2)'}">
              ${isRun ? '&#9654; running' : j.status}
            </span>
            ${msgEl}
          </td>
          <td class="mono" style="font-size:10px">${j.priority||10}</td>
          <td class="mono" style="font-size:10px">${localTime(j.created_at,{hour:'2-digit',minute:'2-digit'})}</td>
          <td>
            ${isRun
              ? `<button class="btnd" style="font-size:9px" onclick="abortJobById(${j.id})">&#9632; Abort</button>`
              : `<button class="tbtn" style="font-size:9px;color:var(--red)" onclick="cancelJob(${j.id})">Cancel</button>`}
          </td>
        </tr>`;
    }).join('');
}

// ==========================================================================
// Job queue management
// ==========================================================================
async function abortJobById(id) {
    if (!confirm('Abort job #' + id + '? The scan will stop after the current batch.')) return;
    const r = await apiPost('/api/scan_abort.php', {job_id: id});
    if (r && r.ok) {
        toast('Job #' + id + ' aborted', 'ok');
        clearInterval(pollTimer);
        activeJobId = null;
        setStatusPill('idle', 'Idle');
        loadScanHistory();
    } else {
        toast((r && r.error) || 'Abort failed', 'err');
    }
}

async function cancelJob(id) {
    if (!confirm('Cancel job #' + id + '?')) return;
    const r = await apiPost('/api/scan_abort.php', {job_id: id});
    if (r && r.ok) { toast('Job #' + id + ' cancelled', 'ok'); loadScanHistory(); }
    else toast((r && r.error) || 'Cancel failed', 'err');
}

async function retryJob(id) {
    // Clone the failed job as a new queued job
    const r = await apiPost('/api/scan_start.php', {retry_job_id: id});
    if (r && r.job_id) { toast('Job #' + r.job_id + ' queued (retry)', 'ok'); loadScanHistory(); }
    else toast((r && r.error) || 'Retry failed', 'err');
}

// ==========================================================================
// Audit log
// ==========================================================================
async function loadLog() {
    const d = await api('/api/scan_status.php?log_limit=200');
    if (!d) return;
    allLogRows = d.log || [];
    if (d.log && d.log.length) logSinceId = d.log[d.log.length-1].id;
    renderLog();
}

function appendLogRows(rows) {
    allLogRows = allLogRows.concat(rows);
    if (allLogRows.length > 2000) allLogRows = allLogRows.slice(-2000);
    renderLog();
}

function renderLog() {
    filterLog();
}

function filterLog() {
    const q   = (document.getElementById('lf-q')?.value || '').toLowerCase();
    const lvl = document.getElementById('lf-level')?.value || '';
    const filtered = allLogRows.filter(r =>
        (!lvl || r.level === lvl) &&
        (!q   || (r.message||'').toLowerCase().includes(q) || (r.ip||'').includes(q))
    );
    const wrap = document.getElementById('log-wrap');
    wrap.innerHTML = filtered.map(r => `<div class="lr">
      <span class="lts">${(r.ts||'').split(' ')[1]||r.ts||''}</span>
      <span class="llv ${r.level}">${r.level}</span>
      <span class="lm">${r.ip ? '<b>'+esc(r.ip)+'</b> ' : ''}${esc(r.message||'')}</span>
    </div>`).join('') || '<div class="loading">No log entries</div>';
    if (autoscroll) wrap.scrollTop = wrap.scrollHeight;
}

function toggleAutoscroll() {
    autoscroll = !autoscroll;
    document.getElementById('btn-autoscroll').textContent = 'Auto-scroll: ' + (autoscroll ? 'ON' : 'OFF');
}

// ==========================================================================
// Status pill
// ==========================================================================
function setStatusPill(state, text) {
    const pill = document.getElementById('status-pill');
    pill.className = 'pill' + (state === 'run' ? ' run' : state === 'err' ? ' err' : '');
    document.getElementById('status-txt').textContent = text;
    document.getElementById('logodot').classList.toggle('active', state === 'run');
}

function updateStatusPill(lastScan) {
    if (lastScan && (lastScan.status === 'running' || lastScan.status === 'queued')) {
        setStatusPill('run', 'Scanning…');
        if (!pollTimer && lastScan.id) startPoll(lastScan.id);
    } else {
        setStatusPill('idle', 'Idle');
    }
}

// ==========================================================================
// Helpers
// ==========================================================================
function esc(s) {
    if (s === null || s === undefined) return '';
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function enc(s) { return encodeURIComponent(s || ''); }

function sevClass(cvss) {
    const v = parseFloat(cvss);
    if (isNaN(v) || v === 0) return 'none';
    if (v >= 9) return 'critical';
    if (v >= 7) return 'high';
    if (v >= 4) return 'medium';
    return 'low';
}

function relTime(ts) {
    if (!ts) return '—';
    // SQLite stores UTC without 'Z' suffix — add it so JS parses correctly
    const normalized = ts.includes('T') ? ts : ts.replace(' ', 'T') + 'Z';
    const secs = Math.floor((Date.now() - new Date(normalized)) / 1000);
    if (secs < 0)      return 'just now';
    if (secs < 120)    return secs + 's ago';
    if (secs < 3600)   return Math.floor(secs/60) + 'm ago';
    if (secs < 86400)  return Math.floor(secs/3600) + 'h ago';
    return Math.floor(secs/86400) + 'd ago';
}

function localTime(ts, opts) {
    // Convert a UTC DB timestamp to the user's local time for display
    if (!ts) return '—';
    const normalized = ts.includes('T') ? ts : ts.replace(' ', 'T') + 'Z';
    const d = new Date(normalized);
    if (isNaN(d)) return ts;
    return d.toLocaleString([], opts || {
        month: 'short', day: 'numeric',
        hour: '2-digit', minute: '2-digit'
    });
}

function localDate(ts) {
    // Date only, no time
    if (!ts) return '—';
    const normalized = ts.includes('T') ? ts : ts.replace(' ', 'T') + 'Z';
    const d = new Date(normalized);
    if (isNaN(d)) return ts;
    return d.toLocaleDateString([], {year:'numeric', month:'short', day:'numeric'});
}

function fmtDuration(secs) {
    if (!secs) return '—';
    if (secs < 60)   return secs + 's';
    if (secs < 3600) return Math.floor(secs/60) + 'm ' + (secs%60) + 's';
    return Math.floor(secs/3600) + 'h ' + Math.floor((secs%3600)/60) + 'm';
}

function toast(msg, type) {
    const w = document.getElementById('toasts');
    const d = document.createElement('div');
    d.className = 'toast ' + (type || 'ok');
    d.textContent = msg;
    w.appendChild(d);
    setTimeout(() => d.remove(), 4000);
}

// ==========================================================================
// Enrichment sources
// ==========================================================================
var SOURCE_FIELDS = {
    unifi: [
        {id:'host',            label:'Controller IP/hostname', type:'text',     placeholder:'192.168.86.1', default:''},
        {id:'port',            label:'Port',                   type:'number',   placeholder:'443',          default:'443'},
        {id:'username',        label:'Local admin username',   type:'text',     placeholder:'admin',        default:'admin'},
        {id:'password',        label:'Password',               type:'password', placeholder:'',             default:''},
        {id:'site',            label:'Site name',              type:'text',     placeholder:'default',      default:'default'},
        {id:'controller_type', label:'Controller type',        type:'select',   options:['udm','legacy'],   default:'udm'},
        {id:'verify_ssl',      label:'Verify TLS cert',            type:'select', options:['false','true'], default:'false'},
        {id:'timeout',         label:'HTTP timeout seconds',   type:'number',   placeholder:'10',           default:'10'},
    ],
    snmp: [
        {id:'targets',   label:'Router/switch IPs (comma-separated)', type:'text',   placeholder:'192.168.86.1', default:''},
        {id:'community', label:'Community string',                     type:'text',   placeholder:'public',       default:'public'},
        {id:'version',   label:'SNMP version',                        type:'select', options:['2c','3'],          default:'2c'},
        {id:'port',      label:'Port',                                 type:'number', placeholder:'161',           default:'161'},
    ],
    dhcp_leases: [
        {id:'paths',           label:'Lease file paths (comma-separated)', type:'text', placeholder:'/var/lib/misc/dnsmasq.leases', default:'/var/lib/misc/dnsmasq.leases'},
        {id:'format',          label:'Lease format',                       type:'select', options:['auto','dnsmasq','isc','json'], default:'auto'},
        {id:'include_expired', label:'Include expired leases (true/false)', type:'text', placeholder:'false', default:'false'},
    ],
    dns_logs: [
        {id:'paths',            label:'DNS log paths (comma-separated)', type:'text', placeholder:'/var/log/pihole/pihole.log,/var/log/dnsmasq.log', default:'/var/log/pihole/pihole.log'},
        {id:'parser',           label:'Parser mode',                      type:'select', options:['auto','pihole','dnsmasq','bind','jsonl','json'], default:'auto'},
        {id:'allowed_suffixes', label:'Allowed suffixes (optional)',      type:'text', placeholder:'lan,home.arpa,local', default:''},
        {id:'include_reverse',  label:'Include PTR/reverse lookups (true/false)', type:'text', placeholder:'false', default:'false'},
        {id:'max_age_hours',    label:'Max age hours (0 disables)',       type:'number', placeholder:'168', default:'168'},
    ],
    firewall_logs: [
        {id:'paths',            label:'Firewall log paths (comma-separated)', type:'text', placeholder:'/var/log/filter.log,/var/log/ufw.log', default:'/var/log/filter.log'},
        {id:'parser',           label:'Parser mode',                          type:'select', options:['auto','kv','jsonl','json'], default:'auto'},
        {id:'direction',        label:'Direction filter',                      type:'select', options:['any','in','out'], default:'any'},
        {id:'include_blocked',  label:'Include blocked/denied (true/false)',  type:'text', placeholder:'true', default:'true'},
        {id:'max_age_hours',    label:'Max age hours (0 disables)',           type:'number', placeholder:'168', default:'168'},
    ],
    ms_dns: [
        {id:'dns_server', label:'DNS server IP',   type:'text', placeholder:'10.0.0.5'},
        {id:'method',     label:'Method',          type:'select', options:['ptr','zone_transfer','ldap']},
        {id:'domain',     label:'AD domain (LDAP only)', type:'text', placeholder:'corp.example.com'},
        {id:'username',   label:'AD username (LDAP only)', type:'text', placeholder:''},
        {id:'password',   label:'AD password (LDAP only)', type:'password', placeholder:''},
    ],
};

async function loadEnrichment() {
    const d = await api('/api/enrichment.php');
    if (!d) return;

    // Active sources list
    const list = d.sources || [];
    document.getElementById('enrich-list').innerHTML = list.length
        ? list.map(s => `
            <div style="display:flex;align-items:center;gap:8px;padding:8px 0;border-bottom:1px solid var(--bd)">
              <div style="flex:1">
                <div style="color:var(--tx);font-size:12px">${esc(s.label)}</div>
                <div style="font-family:var(--mf);font-size:10px;color:var(--tx3)">${esc(s.source_type)} · priority ${s.priority}</div>
                ${s.last_test_msg ? `<div style="font-family:var(--mf);font-size:10px;color:${s.last_test_ok?'var(--green)':'var(--red)'}">${esc(s.last_test_msg)}</div>` : ''}
              </div>
              <div style="font-family:var(--mf);font-size:10px;padding:2px 6px;border-radius:2px;background:${s.enabled?'var(--gdim)':'var(--bg4)'};color:${s.enabled?'var(--green)':'var(--tx3)'}">
                ${s.enabled ? 'enabled' : 'disabled'}
              </div>
              <button class="tbtn" style="font-size:10px"
                      data-id="${s.id}" data-type="${esc(s.source_type)}"
                      data-label="${esc(s.label)}" data-enabled="${s.enabled}"
                      data-priority="${s.priority}"
                      data-config="${esc(JSON.stringify(JSON.parse(s.config_json||'{}'))  )}"
                      onclick="editSourceFromBtn(this)">Edit</button>
              <button class="tbtn" style="font-size:10px;color:var(--red)" onclick="deleteSource(${s.id})">✕</button>
            </div>`).join('')
        : '<div style="color:var(--tx3);font-size:11px;font-family:var(--mf);padding:8px 0">No enrichment sources configured. Add one below.</div>';

    // Available types
    const types = d.available_types || [];
    document.getElementById('enrich-types').innerHTML = types.map(t => `
        <div style="display:flex;align-items:center;gap:8px;padding:5px 0;border-bottom:1px solid var(--bd)">
          <div style="flex:1;font-size:12px;color:var(--tx)">${esc(t.label)}</div>
          <div style="font-family:var(--mf);font-size:10px;padding:2px 6px;border-radius:2px;background:${t.status==='ready'?'var(--gdim)':t.status==='partial'?'var(--adim)':'var(--bg4)'};color:${t.status==='ready'?'var(--green)':t.status==='partial'?'var(--amber)':'var(--tx3)'}">
            ${t.status}
          </div>
          ${t.status==='ready'||t.status==='partial' ? `<button class="tbtn" style="font-size:10px" onclick="openAddSource('${t.type}')">+ Add</button>` : ''}
        </div>`).join('');
}

function updateSourceFields(existingConfig) {
    const type   = document.getElementById('esrc-type').value;
    const fields = SOURCE_FIELDS[type] || [];
    const cfg    = existingConfig || {};
    document.getElementById('esrc-fields').innerHTML = fields.map(f => {
        const val = cfg[f.id] !== undefined ? cfg[f.id] : (f.default || '');
        if (f.type === 'select') {
            return `<label class="flbl">${esc(f.label)}</label>
                    <select class="finp" id="esrc-f-${f.id}" style="width:100%;margin-bottom:10px">
                      ${f.options.map(o => `<option value="${o}"${o===val?' selected':''}>${o}</option>`).join('')}
                    </select>`;
        }
        return `<label class="flbl">${esc(f.label)}</label>
                <input class="finp" id="esrc-f-${f.id}" type="${f.type}"
                       style="width:100%;margin-bottom:10px"
                       value="${esc(String(val))}"
                       placeholder="${esc(f.placeholder||'')}">`;
    }).join('');
}

function openAddSource(type) {
    document.getElementById('esrc-id').value = '0';
    document.getElementById('esrc-title').textContent = 'Add enrichment source';
    document.getElementById('esrc-label').value = '';
    document.getElementById('esrc-enabled').checked = true;
    if (type) document.getElementById('esrc-type').value = type;
    updateSourceFields();
    document.getElementById('esrc-test-result').style.display = 'none';
    document.getElementById('esrc-bg').style.display = 'flex';
}

function editSourceFromBtn(btn) {
    const id       = parseInt(btn.dataset.id);
    const type     = btn.dataset.type;
    const label    = btn.dataset.label;
    const enabled  = parseInt(btn.dataset.enabled);
    const priority = parseInt(btn.dataset.priority);
    let configJson = {};
    try { configJson = JSON.parse(btn.dataset.config || '{}'); } catch(e) {}
    editSource(id, type, label, enabled, priority, configJson);
}

function editSource(id, type, label, enabled, priority, configJson) {
    document.getElementById('esrc-id').value    = id;
    document.getElementById('esrc-title').textContent = 'Edit enrichment source';
    document.getElementById('esrc-type').value  = type;
    document.getElementById('esrc-label').value = label;
    document.getElementById('esrc-enabled').checked = !!enabled;
    const cfg = typeof configJson === 'string' ? JSON.parse(configJson||'{}') : (configJson||{});
    updateSourceFields(cfg);
    // Populate field values from config
    // config values populated by updateSourceFields(cfg) above
    document.getElementById('esrc-test-result').style.display = 'none';
    document.getElementById('esrc-bg').style.display = 'flex';
}

function closeSourceModal() {
    document.getElementById('esrc-bg').style.display = 'none';
}

function _collectSourceConfig() {
    const type   = document.getElementById('esrc-type').value;
    const fields = SOURCE_FIELDS[type] || [];
    const config = {};
    fields.forEach(f => {
        const el = document.getElementById('esrc-f-' + f.id);
        if (el) config[f.id] = el.value;
    });
    return config;
}

async function saveSource() {
    const body = {
        id:          parseInt(document.getElementById('esrc-id').value),
        source_type: document.getElementById('esrc-type').value,
        label:       document.getElementById('esrc-label').value.trim() || document.getElementById('esrc-type').value,
        enabled:     document.getElementById('esrc-enabled').checked ? 1 : 0,
        priority:    10,
        config:      _collectSourceConfig(),
    };
    const r = await apiPost('/api/enrichment.php', body);
    if (r && r.ok) {
        toast('Enrichment source saved', 'ok');
        closeSourceModal();
        loadEnrichment();
    } else {
        toast(r?.error || 'Save failed', 'err');
    }
}

async function testSource() {
    const id = parseInt(document.getElementById('esrc-id').value);
    if (!id) { toast('Save first, then test', 'err'); return; }
    const res_el = document.getElementById('esrc-test-result');
    res_el.style.display = 'block';
    res_el.style.color   = 'var(--tx2)';
    res_el.textContent   = 'Testing…';
    const r = await apiPost('/api/enrichment.php?test=1', {id});
    if (!r) { res_el.textContent = 'Request failed'; return; }
    res_el.style.color   = r.ok ? 'var(--green)' : 'var(--red)';
    res_el.textContent   = r.message || (r.ok ? 'OK' : 'Failed');
    loadEnrichment();
}

async function deleteSource(id) {
    if (!confirm('Delete this enrichment source?')) return;
    const r = await fetch('/api/enrichment.php?id=' + id, {
        method: 'DELETE', credentials: 'same-origin'
    });
    const d = await r.json();
    if (d.ok) { toast('Source deleted', 'ok'); loadEnrichment(); }
    else toast(d.error || 'Delete failed', 'err');
}

// ==========================================================================
// Sidebar badges — update independently so they stay current on all tabs
// ==========================================================================
function updateSidebarBadges(assets, vulns, critical) {
    const na = document.getElementById('nb-assets');
    const nv = document.getElementById('nb-vulns');
    if (na && assets !== undefined) na.textContent = assets;
    if (nv && vulns  !== undefined) {
        nv.textContent = vulns;
        nv.className   = critical > 0 ? 'nb err' : (vulns > 0 ? 'nb warn' : 'nb');
    }
}

async function refreshBadges() {
    const d = await api('/api/dashboard.php');
    if (d) updateSidebarBadges(d.assets?.total, d.findings?.open, d.findings?.by_severity?.critical || 0);
}

async function runFeedSync(target) {
    const btnIds = ['btn-sync-oui', 'btn-sync-webfp', 'btn-sync-all'];
    btnIds.forEach(id => { const b = document.getElementById(id); if (b) b.disabled = true; });
    toast('Starting ' + target + ' feed sync…', 'ok');
    const r = await apiPost('/api/feeds.php?sync=1', {target});
    btnIds.forEach(id => { const b = document.getElementById(id); if (b) b.disabled = false; });

    if (!r) {
        feedSyncLastOutput = '[client] Feed sync request failed (no response)';
        toast('Feed sync request failed', 'err');
        return;
    }
    const lines = [];
    lines.push(`target=${target} ok=${!!r.ok}`);
    for (const res of (r.results || [])) {
        lines.push(`\n=== ${res.script} | ok=${!!res.ok} exit=${res.exit_code} ===`);
        lines.push((res.output || '').trim() || '(no output)');
    }
    feedSyncLastOutput = lines.join('\n');
    if (!r.ok) {
        const msg = (r.results && r.results.find(x => !x.ok)?.output) || r.error || 'Sync failed';
        toast(msg.slice(0, 120), 'err');
        openFeedSyncOutput();
        return;
    }

    const names = (r.results || []).map(x => x.script.replace('.py', '')).join(', ');
    toast('Feed sync complete: ' + names, 'ok');
    await loadDashboard(); // refresh status timestamps/counts in Settings
    openFeedSyncOutput();
}

function openFeedSyncOutput() {
    const bg = document.getElementById('fsync-bg');
    const out = document.getElementById('fsync-out');
    if (!bg || !out) return;
    out.textContent = feedSyncLastOutput || 'No sync output yet.';
    bg.style.display = 'flex';
}

function closeFeedSyncOutput() {
    const bg = document.getElementById('fsync-bg');
    if (bg) bg.style.display = 'none';
}

// ==========================================================================
// Schedules
// ==========================================================================
async function loadSchedules() {
    const d = await api('/api/schedules.php');
    if (!d) return;

    const statColor = {done:'var(--green)',failed:'var(--red)',aborted:'var(--amber)'};
    const tbody = document.getElementById('sched-tbody');
    if (!d.schedules || !d.schedules.length) {
        tbody.innerHTML = '<tr><td colspan="10" class="loading">No schedules yet — create one to get started</td></tr>';
        return;
    }

    tbody.innerHTML = d.schedules.map(s => {
        const pol = (s.missed_run_policy || 'run_once');
        const missedLbl = pol === 'skip_no_run'
            ? 'Skip'
            : pol === 'run_all'
                ? `All ≤${parseInt(s.missed_run_max, 10) || 5}`
                : 'Once';
        const isPaused = !!(parseInt(s.paused, 10) || 0);
        const isOn = !!(parseInt(s.enabled, 10) || 0);
        const pausedTag = isPaused
            ? '<span style="color:var(--amber);font-size:10px;margin-left:6px;font-family:var(--mf)">Paused</span>'
            : '';

        // next_run is stored as UTC — display as local browser time
        let nextRun = '<span style="color:var(--tx3)">pending</span>';
        if (s.next_run) {
            const nr = new Date(s.next_run + 'Z');  // append Z to treat as UTC
            const secs = s.secs_until_next;
            const timeStr = nr.toLocaleString([], {month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'});
            if (secs <= 0) {
                nextRun = '<span style="color:var(--amber)">due now</span>';
            } else if (secs < 3600) {
                nextRun = `<span title="${timeStr}">${Math.floor(secs/60)}m</span>`;
            } else if (secs < 86400) {
                nextRun = `<span title="${timeStr}">${Math.floor(secs/3600)}h</span>`;
            } else {
                nextRun = `<span title="${timeStr}">${Math.floor(secs/86400)}d · ${timeStr}</span>`;
            }
        }

        const lastRun   = s.last_run   ? relTime(s.last_run)   : '—';
        const lastStat  = s.last_job_status
            ? `<span style="color:${statColor[s.last_job_status]||'var(--tx2)'};font-family:var(--mf);font-size:10px">${s.last_job_status}</span>`
              + (s.last_hosts_found ? ` <span style="font-family:var(--mf);font-size:10px;color:var(--tx3)">${s.last_hosts_found} hosts</span>` : '')
            : '—';

        const pauseResume = isOn
            ? (isPaused
                ? `<button class="tbtn" style="font-size:9px" onclick="resumeSchedule(${s.id})" title="Resume schedule">Resume</button>`
                : `<button class="tbtn" style="font-size:9px" onclick="pauseSchedule(${s.id})" title="Pause without deleting">Pause</button>`)
            : '';

        return `<tr>
          <td style="color:var(--tx)">${esc(s.name)}${pausedTag}</td>
          <td class="mono" style="font-size:11px">${esc(s.target_cidr)}</td>
          <td style="font-family:var(--mf);font-size:11px;color:var(--tx2)">${esc((s.profile||'').replace(/_/g,' '))}</td>
          <td class="mono" style="font-size:11px">${esc(s.cron_expr)}</td>
          <td style="font-family:var(--mf);font-size:10px;color:var(--tx2)" title="Catch-up when overdue">${missedLbl}</td>
          <td style="font-family:var(--mf);font-size:11px">${nextRun}</td>
          <td style="font-family:var(--mf);font-size:11px;color:var(--tx2)">${lastRun}</td>
          <td>${lastStat}</td>
          <td>
            <button class="tbtn" style="font-size:10px;font-family:var(--mf);
              color:${isOn ? 'var(--green)' : 'var(--tx3)'};
              border-color:${isOn ? 'var(--green)' : 'var(--bd2)'};
              min-width:52px"
              onclick="toggleSchedule(${s.id})"
              title="${isOn ? 'Click to disable' : 'Click to enable'}">
              ${isOn ? '● ON' : '○ OFF'}
            </button>
          </td>
          <td style="display:flex;flex-wrap:wrap;gap:4px;padding:4px 8px;max-width:200px">
            <button class="tbtn" style="font-size:9px" onclick="openSchedHist(${s.id})" title="Run history">Hist</button>
            ${pauseResume}
            <button class="tbtn" style="font-size:10px" onclick="runSchedNow(${s.id})" title="Run now">&#9654;</button>
            <button class="tbtn" style="font-size:10px" onclick="editSchedule(${s.id})">&#9998;</button>
            <button class="tbtn" style="font-size:10px;color:var(--red)" onclick="deleteSchedule(${s.id})">&#10005;</button>
          </td>
        </tr>`;
    }).join('');
}

function openSchedModal(s) {
    document.getElementById('sched-id').value    = s ? s.id : '';
    document.getElementById('sched-title').textContent = s ? 'Edit schedule' : 'New schedule';
    document.getElementById('sched-name').value  = s ? s.name : '';
    document.getElementById('sched-cidr').value  = s ? s.target_cidr : '';
    document.getElementById('sched-cron').value  = s ? s.cron_expr : '0 3 * * 0';
    document.getElementById('sched-profile').value = s ? (s.profile||'standard_inventory') : 'standard_inventory';
    document.getElementById('sched-mode').value  = s ? (s.scan_mode||'auto') : 'auto';
    document.getElementById('sched-excl').value  = s ? (s.exclusions||'') : '';
    document.getElementById('sched-notes').value = s ? (s.notes||'') : '';
    const polEl = document.getElementById('sched-missed-pol');
    if (polEl) polEl.value = s ? (s.missed_run_policy || 'run_once') : 'run_once';
    const mxEl = document.getElementById('sched-missed-max');
    if (mxEl) mxEl.value = s ? (parseInt(s.missed_run_max, 10) || 5) : 5;
    const enCb = document.getElementById('sched-en');
    if (enCb) enCb.checked = s ? !!(parseInt(s.enabled, 10) || 0) : true;
    const pz = document.getElementById('sched-paused');
    if (pz) pz.value = s ? (parseInt(s.paused, 10) || 0) : 0;
    const tzSel = document.getElementById('sched-tz');
    if (tzSel) {
        // Try to default to browser timezone for new schedules
        const browserTz = Intl.DateTimeFormat().resolvedOptions().timeZone;
        tzSel.value = s ? (s.timezone||'UTC') : (browserTz||'UTC');
        // If browser TZ not in list, add it
        if (tzSel.value !== (s ? (s.timezone||'UTC') : (browserTz||'UTC'))) {
            const opt = document.createElement('option');
            opt.value = browserTz;
            opt.textContent = browserTz;
            tzSel.appendChild(opt);
            tzSel.value = browserTz;
        }
    }
    updateCronDesc();
    document.getElementById('sched-bg').style.display = 'flex';
}

function closeSchedModal() {
    document.getElementById('sched-bg').style.display = 'none';
}

function setCron(expr) {
    document.getElementById('sched-cron').value = expr;
    updateCronDesc();
}

function updateCronDesc() {
    const expr = document.getElementById('sched-cron').value.trim();
    const descs = {
        '@daily':'Every day at midnight','@weekly':'Every Sunday at midnight',
        '@monthly':'First of every month at midnight','@hourly':'Every hour',
        '@yearly':'Every year on Jan 1st','@annually':'Every year on Jan 1st',
        '@midnight':'Every day at midnight',
    };
    const el = document.getElementById('sched-cron-desc');
    if (descs[expr]) { el.textContent = descs[expr]; el.style.color='var(--green)'; return; }
    const parts = expr.split(/\s+/);
    if (parts.length === 5) {
        el.textContent = 'Custom: ' + expr;
        el.style.color = 'var(--tx2)';
    } else {
        el.textContent = 'Format: minute hour day-of-month month day-of-week';
        el.style.color = 'var(--tx3)';
    }
}

document.getElementById('sched-cron')?.addEventListener('input', updateCronDesc);

async function editSchedule(id) {
    const d = await api('/api/schedules.php');
    if (!d) return;
    const s = d.schedules.find(s => s.id === id);
    if (s) openSchedModal(s);
}

async function saveSchedule() {
    const id      = document.getElementById('sched-id').value;
    let mx = parseInt(document.getElementById('sched-missed-max')?.value || '5', 10);
    if (mx < 1) mx = 1;
    if (mx > 100) mx = 100;
    const payload = {
        id:          id ? parseInt(id) : 0,
        name:        document.getElementById('sched-name').value.trim(),
        target_cidr: document.getElementById('sched-cidr').value.trim(),
        cron_expr:   document.getElementById('sched-cron').value.trim(),
        profile:     document.getElementById('sched-profile').value,
        scan_mode:   document.getElementById('sched-mode').value,
        exclusions:  document.getElementById('sched-excl').value.trim(),
        notes:       document.getElementById('sched-notes').value.trim(),
        timezone:    document.getElementById('sched-tz')?.value || 'UTC',
        enabled:     document.getElementById('sched-en')?.checked ? 1 : 0,
        paused:      parseInt(document.getElementById('sched-paused')?.value || '0', 10) || 0,
        missed_run_policy: document.getElementById('sched-missed-pol')?.value || 'run_once',
        missed_run_max: mx,
    };
    if (!payload.name)        { toast('Name is required', 'err'); return; }
    if (!payload.target_cidr) { toast('Target CIDR is required', 'err'); return; }
    if (!payload.cron_expr)   { toast('Cron expression is required', 'err'); return; }

    const r = await apiPost('/api/schedules.php', payload);
    if (r && r.ok) {
        toast(id ? 'Schedule updated' : 'Schedule created', 'ok');
        closeSchedModal();
        loadSchedules();
    } else {
        toast((r && r.error) || 'Save failed', 'err');
    }
}

async function toggleSchedule(id) {
    const r = await apiPost('/api/schedules.php?toggle=1', {id});
    if (r && r.ok) loadSchedules();
    else toast('Toggle failed', 'err');
}

async function runSchedNow(id) {
    const r = await apiPost('/api/schedules.php?run_now=1', {id});
    if (r && r.ok) {
        toast('Job #' + r.job_id + ' queued', 'ok');
        loadSchedules();
        loadScanStatus();
    } else {
        toast((r && r.error) || 'Failed to queue job', 'err');
    }
}

async function deleteSchedule(id) {
    if (!confirm('Delete this schedule? This cannot be undone.')) return;
    const r = await fetch(`/api/schedules.php?id=${id}`, {
        method: 'DELETE', credentials: 'same-origin'
    });
    if (r.ok) { toast('Schedule deleted', 'ok'); loadSchedules(); }
    else toast('Delete failed', 'err');
}

function closeSchedHistModal() {
    const el = document.getElementById('sched-hist-bg');
    if (el) el.style.display = 'none';
}

function openJobFromHist(jobId) {
    closeSchedHistModal();
    goTab('scan');
    hiNav('nscan');
    activeJobId = jobId;
    showScanRunning(jobId);
    startPoll(jobId);
    pollJob(jobId);
    loadScanHistory();
}

async function openSchedHist(id) {
    const bg = document.getElementById('sched-hist-bg');
    const tb = document.getElementById('sched-hist-tbody');
    const title = document.getElementById('sched-hist-title');
    if (!bg || !tb) return;
    let name = 'Schedule #' + id;
    const list = await api('/api/schedules.php');
    if (list && list.schedules) {
        const row = list.schedules.find(x => x.id === id);
        if (row) name = row.name;
    }
    title.textContent = 'Run history — ' + name;
    tb.innerHTML = '<tr><td colspan="6" class="loading">Loading…</td></tr>';
    bg.style.display = 'flex';
    const d = await api('/api/schedules.php?history=1&id=' + encodeURIComponent(id) + '&limit=25');
    if (!d || !d.runs) {
        tb.innerHTML = '<tr><td colspan="6" class="loading">Could not load history</td></tr>';
        return;
    }
    if (!d.runs.length) {
        tb.innerHTML = '<tr><td colspan="6" class="loading">No jobs linked to this schedule yet</td></tr>';
        return;
    }
    const toLoc = (ts) => {
        if (!ts) return '—';
        const iso = String(ts).replace(' ', 'T');
        const dt = new Date(/Z|[+-]\d{2}:?\d{2}$/.test(iso) ? iso : iso + 'Z');
        return isNaN(dt.getTime()) ? esc(ts) : dt.toLocaleString([], {month:'short', day:'numeric', hour:'2-digit', minute:'2-digit'});
    };
    tb.innerHTML = d.runs.map(r => {
        const hosts = (r.hosts_found != null && r.hosts_found !== '')
            ? `${parseInt(r.hosts_scanned, 10) || 0}/${parseInt(r.hosts_found, 10) || 0}`
            : '—';
        return `<tr>
          <td class="mono" style="font-size:11px"><a href="#" onclick="openJobFromHist(${r.id});return false">${r.id}</a></td>
          <td style="font-family:var(--mf);font-size:10px">${esc(r.status || '')}</td>
          <td style="font-size:11px;color:var(--tx2)">${esc(r.label || '')}</td>
          <td style="font-family:var(--mf);font-size:10px">${hosts}</td>
          <td style="font-family:var(--mf);font-size:10px;color:var(--tx2)">${toLoc(r.created_at)}</td>
          <td style="font-family:var(--mf);font-size:10px;color:var(--tx2)">${toLoc(r.finished_at)}</td>
        </tr>`;
    }).join('');
}

async function pauseSchedule(id) {
    const r = await apiPost('/api/schedules.php?pause=1', {id});
    if (r && r.ok) { toast('Schedule paused', 'ok'); loadSchedules(); }
    else toast((r && r.error) || 'Pause failed', 'err');
}

async function resumeSchedule(id) {
    const r = await apiPost('/api/schedules.php?resume=1', {id});
    if (r && r.ok) { toast('Schedule resumed', 'ok'); loadSchedules(); }
    else toast((r && r.error) || 'Resume failed', 'err');
}

// ==========================================================================
// Export findings (CVEs) with current filters
// ==========================================================================
function exportFindings(format) {
    const cve   = document.getElementById('vf-cve')?.value   || '';
    const ip    = document.getElementById('vf-ip')?.value    || '';
    const sev   = document.getElementById('vf-sev')?.value   || '';
    const cat   = document.getElementById('vf-cat')?.value   || '';
    const res   = document.getElementById('vf-resolved')?.value || '0';
    const miny  = document.getElementById('vf-minyear')?.value || '';

    const params = new URLSearchParams({
        format,
        cve_id:    cve,
        ip:        ip,
        severity:  sev,
        category:  cat,
        resolved:  res,
        min_year:  miny,
        per_page:  9999,
    });

    const a = document.createElement('a');
    a.href     = `/api/findings_export.php?${params}`;
    a.download = `surveytrace_cves_${new Date().toISOString().slice(0,10)}.${format}`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    toast(`Exporting CVEs as ${format.toUpperCase()}…`, 'ok');
}

// ==========================================================================
// Reclassify modal
// ==========================================================================
function openReclassify(id, ip, hostname, category, vendor, notes) {
    document.getElementById('modal-asset-id').value  = id;
    document.getElementById('modal-ip').textContent  = ip;
    document.getElementById('modal-hostname').value  = hostname;
    document.getElementById('modal-vendor').value    = vendor;
    document.getElementById('modal-notes').value     = notes;
    const sel = document.getElementById('modal-cat');
    for (let i = 0; i < sel.options.length; i++) {
        sel.options[i].selected = (sel.options[i].value === category);
    }
    const bg = document.getElementById('modal-bg');
    bg.style.display = 'flex';
    document.getElementById('modal-hostname').focus();
}

function closeModal() {
    document.getElementById('modal-bg').style.display = 'none';
}

async function saveReclassify() {
    const id       = document.getElementById('modal-asset-id').value;
    const hostname = document.getElementById('modal-hostname').value.trim();
    const category = document.getElementById('modal-cat').value;
    const vendor   = document.getElementById('modal-vendor').value.trim();
    const notes    = document.getElementById('modal-notes').value.trim();

    const body = {category};
    if (hostname) body.hostname = hostname;
    if (vendor)   body.vendor   = vendor;
    if (notes !== undefined) body.notes = notes;

    const r = await fetch(`/api/assets.php?id=${id}`, {
        method: 'PUT',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(body),
        credentials: 'same-origin'
    });
    const data = await r.json();
    if (data.ok) {
        toast('Asset updated', 'ok');
        closeModal();
        loadAssets(assetPage);
        if (currentTab === 'dash') loadDashboard();
    } else {
        toast(data.error || 'Save failed', 'err');
    }
}

// Close modal on background click
document.getElementById('modal-bg')?.addEventListener('click', function(e) {
    if (e.target === this) closeModal();
});

// ==========================================================================
// View vulns for a specific asset IP
// ==========================================================================
function viewAssetVulns(ip) {
    goTab('vulns');
    hiNav('nvulns');
    document.getElementById('vf-ip').value = ip;
    loadFindings(1);
}

function filterVulnsByIP(ip) {
    goTab('vulns');
    hiNav('nvulns');
    document.getElementById('vf-ip').value = ip;
    document.getElementById('vf-cve').value = '';
    const clr = document.getElementById('vf-clear-ip');
    if (clr) {
        clr.style.display = ip ? '' : 'none';
        clr.textContent = '\u2715 ' + ip;
    }
    loadFindings(1);
}

// Profile card selection
document.querySelectorAll('.profile-card').forEach(card => {
    card.addEventListener('click', () => {
        document.querySelectorAll('.profile-card').forEach(c => c.classList.remove('on'));
        card.classList.add('on');
        // Also update phases visibility based on profile
        const profile = card.querySelector('input').value;
        const bannerPhases = ['ph-banner','ph-fingerprint','ph-cve'];
        const allowBanner  = !['iot_safe','ot_careful'].includes(profile);
        bannerPhases.forEach(id => {
            const el = document.getElementById(id);
            if (el) {
                el.checked = allowBanner;
                el.closest('.tr2').style.opacity = allowBanner ? '1' : '0.4';
            }
        });
    });
});

function clearIPFilter() {
    document.getElementById('vf-ip').value = '';
    document.getElementById('vf-clear-ip').style.display = 'none';
    loadFindings(1);
}

function debounceFindings() {
    const ip = document.getElementById('vf-ip')?.value || '';
    const clr = document.getElementById('vf-clear-ip');
    if (clr) {
        clr.style.display = ip ? '' : 'none';
        clr.textContent = '✕ ' + ip;
    }
    clearTimeout(vulnDebounce);
    vulnDebounce = setTimeout(() => loadFindings(1), 350);
}

// ==========================================================================
// Host detail panel
// ==========================================================================
async function openHostPanel(id, ip) {
    document.getElementById('host-panel').style.display = 'block';
    document.getElementById('host-panel-bg').style.display = 'block';
    document.getElementById('hp-title').textContent = ip;
    document.getElementById('hp-body').innerHTML = '<div class="loading">Loading…</div>';

    const [assetData, findingsData] = await Promise.all([
        api('/api/assets.php?id=' + id),
        api('/api/findings.php?asset_id=' + id + '&per_page=50&sort=cvss&order=desc')
    ]);

    if (!assetData || !assetData.asset) {
        document.getElementById('hp-body').innerHTML = '<div class="loading">Failed to load</div>';
        return;
    }

    const a = assetData.asset;
    const findings = findingsData ? findingsData.findings : [];
    const ports = a.open_ports || [];
    const banners = a.banners || {};
    const httpProbe = String(banners._http || '');

    const sevColor = {critical:'var(--red)',high:'#f97316',medium:'var(--amber)',low:'var(--blue)',none:'var(--tx3)'};

    // IANA port names that are commonly wrong in practice
    const MISLEADING_PORTS = {
        3000:'Grafana / Homarr / dev server', 3001:'Uptime Kuma / Gitea / dev server',
        3030:'Homepage dashboard', 5080:'OpenObserve / SIP alt',
        5341:'Seq log server', 7070:'IPTV proxy / media', 8080:'HTTP app server',
        8081:'HTTP alt', 8082:'HTTP alt', 8083:'HTTP alt',
        8086:'InfluxDB / HTTP alt', 8088:'Splunk HEC', 8089:'Splunk management',
        8101:'HTTP alt', 8181:'HTTP alt', 8383:'App server',
        8443:'HTTPS alt', 8888:'Jupyter / HTTP alt',
        9000:'Portainer / Minio / PHP-FPM', 9001:'Minio console',
        9090:'Prometheus', 9091:'Prometheus pushgateway',
        9443:'Portainer HTTPS', 9925:'FastAPI / Uvicorn',
    };

    // Aggregate product signals from per-port banners + merged HTTP probe blob.
    const SERVICE_SIGS = [
        ['Uptime Kuma', /uptime.?kuma/i],
        ['Zabbix', /zabbix/i],
        ['ntfy', /\bntfy\b/i],
        ['Kasm Workspaces', /\bkasm(web|vnc)?\b|kasmtechnologies/i],
        ['Proxmox VE', /proxmox|pve\./i],
        ['Portainer', /portainer/i],
        ['Grafana', /\bgrafana\b/i],
        ['Prometheus', /prometheus/i],
        ['Docker Engine', /docker/i],
        ['Jellyfin', /jellyfin/i],
        ['Gitea', /\bgitea\b/i],
        ['Nextcloud', /nextcloud/i],
        ['Mastodon', /mastodon/i],
        ['OpenObserve', /openobserve/i],
    ];
    const serviceHits = new Set();
    const addServiceHit = (txt) => {
        if (!txt) return;
        for (const [name, rx] of SERVICE_SIGS) {
            if (rx.test(txt)) serviceHits.add(name);
        }
    };

    const portRows = ports.length ? ports.map(p => {
        const rawBanner = banners[String(p)] || '';
        // Banner format: "protocol service product version extrainfo"
        // Split into service name and detail
        const parts = rawBanner.split(' ');
        const proto = parts[0] || '';  // e.g. "ssh", "http", "ssl/http"
        const rest  = parts.slice(1).join(' '); // e.g. "OpenSSH 9.6p1 Ubuntu..."

        // Determine what to show
        let serviceLabel = '';
        let detailLabel  = '';
        let labelColor   = 'var(--tx3)';

        if (rest) {
            // Real banner detected — show it prominently
            serviceLabel = rest;
            labelColor   = 'var(--tx2)';
            addServiceHit(rest);
        } else if (MISLEADING_PORTS[p]) {
            // Known misleading IANA name — show our hint instead
            serviceLabel = MISLEADING_PORTS[p];
            labelColor   = 'var(--tx3)';
        } else if (proto) {
            // Use protocol from banner as fallback
            serviceLabel = proto;
            labelColor   = 'var(--tx3)';
        } else {
            serviceLabel = 'open';
            labelColor   = 'var(--tx3)';
        }
        addServiceHit(rawBanner);

        return `<div style="display:flex;align-items:flex-start;gap:10px;padding:7px 0;border-bottom:1px solid var(--bd)">
          <span style="font-family:var(--mf);font-size:12px;color:var(--acc);min-width:48px;flex-shrink:0">${p}</span>
          <div style="min-width:0">
            <div style="font-size:11px;color:${labelColor};word-break:break-all;line-height:1.4">${esc(serviceLabel)}</div>
            ${rest && MISLEADING_PORTS[p] ? `<div style="font-size:10px;color:var(--tx3);margin-top:1px">hint: ${esc(MISLEADING_PORTS[p])}</div>` : ''}
            ${rawBanner ? `<details style="margin-top:4px"><summary style="cursor:pointer;font-size:10px;color:var(--tx3)">raw banner</summary>
              <div style="margin-top:2px;font-size:10px;color:var(--tx2);font-family:var(--mf);word-break:break-all">${esc(rawBanner)}</div>
            </details>` : ''}
          </div>
        </div>`;
    }).join('') : '<div style="color:var(--tx3);font-size:11px;padding:8px 0">No open ports detected</div>';

    addServiceHit(httpProbe);
    const serviceRows = serviceHits.size
        ? `<div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:14px">${
            Array.from(serviceHits).sort().map(s =>
                `<span style="font-size:10px;font-family:var(--mf);padding:4px 7px;border:1px solid var(--bd2);border-radius:999px;color:var(--tx)">${esc(s)}</span>`
            ).join('')
          }</div>`
        : `<div style="color:var(--tx3);font-size:11px;padding:4px 0 12px">No specific app fingerprints detected yet</div>`;

    const findingRows = findings.length ? findings.map(f => `
        <div style="padding:8px 0;border-bottom:1px solid var(--bd)">
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:3px">
            <span style="font-family:var(--mf);font-size:10px;color:${sevColor[f.severity]||'var(--tx3)'}">
              ${f.cvss||'?'} ${(f.severity||'').toUpperCase()}
            </span>
            <span style="font-family:var(--mf);font-size:10px;color:var(--tx3)">${esc(f.cve_id)}</span>
            <span style="font-size:10px;color:var(--tx3);margin-left:auto">${localDate(f.published)}</span>
          </div>
          <div style="font-size:11px;color:var(--tx2);line-height:1.5">${esc(f.description||'').slice(0,180)}${(f.description||'').length>180?'…':''}</div>
          ${!f.resolved ? `<button class="tbtn" style="font-size:10px;margin-top:4px" onclick="resolveFinding(${f.id},this);loadHostPanel(${id},'${esc(ip)}')">Resolve</button>` : '<span style="font-size:10px;color:var(--green);font-family:var(--mf)">resolved</span>'}
        </div>`).join('') : '<div style="color:var(--tx3);font-size:11px;padding:8px 0">No vulnerabilities found</div>';

    document.getElementById('hp-body').innerHTML = `
      <div style="margin-bottom:16px">
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:10px">
          <span class="cat ${esc(a.category||'unk')}">${esc(a.category||'unk')}</span>
          <span style="font-size:13px;color:var(--tx)">${esc(a.hostname||'—')}</span>
        </div>
        <table style="width:100%;font-size:11px;font-family:var(--mf)">
          <tr><td style="color:var(--tx3);padding:3px 0;width:80px">IP</td><td style="color:var(--tx)">${esc(a.ip)}</td></tr>
          <tr><td style="color:var(--tx3);padding:3px 0">MAC</td><td style="color:var(--tx)">
            ${esc(a.mac||'—')}
            ${a.mac && parseInt(a.mac.split(':')[0],16) & 2 ?
              '<span style="font-family:var(--mf);font-size:9px;color:var(--tx3);margin-left:6px" title="Locally administered (randomized) MAC — OUI lookup not available">randomized</span>'
              : ''}
          </td></tr>
          <tr><td style="color:var(--tx3);padding:3px 0">Vendor</td><td style="color:var(--tx)">${esc(a.vendor||'—')}</td></tr>
          <tr><td style="color:var(--tx3);padding:3px 0">OS</td><td style="color:var(--tx)">${esc(a.os_guess||'—')}</td></tr>
          <tr><td style="color:var(--tx3);padding:3px 0">CPE</td><td style="color:var(--tx2);word-break:break-all">${esc(a.cpe||'—')}</td></tr>
          <tr><td style="color:var(--tx3);padding:3px 0">First seen</td><td style="color:var(--tx2)">${localTime(a.first_seen)}</td></tr>
          <tr><td style="color:var(--tx3);padding:3px 0">Last seen</td><td style="color:var(--tx2)">${relTime(a.last_seen)}</td></tr>
          <tr><td style="color:var(--tx3);padding:3px 0;vertical-align:top">Discovery</td>
              <td style="color:var(--tx2)">${(a.discovery_sources||[]).length ? esc((a.discovery_sources||[]).join(', ')) : '—'}</td></tr>
          ${a.notes ? `<tr><td style="color:var(--tx3);padding:3px 0;vertical-align:top">Notes</td><td style="color:var(--tx2)">${esc(a.notes)}</td></tr>` : ''}
        </table>
      </div>

      <div style="font-family:var(--mf);font-size:10px;color:var(--tx3);letter-spacing:.05em;text-transform:uppercase;margin-bottom:8px;display:flex;align-items:center;gap:8px">
        Detected services
        <div style="flex:1;height:1px;background:var(--bd)"></div>
      </div>
      ${serviceRows}

      <div style="font-family:var(--mf);font-size:10px;color:var(--tx3);letter-spacing:.05em;text-transform:uppercase;margin-bottom:8px;display:flex;align-items:center;gap:8px">
        Open ports (${ports.length})
        <div style="flex:1;height:1px;background:var(--bd)"></div>
      </div>
      <div style="margin-bottom:16px">${portRows}</div>

      <div style="font-family:var(--mf);font-size:10px;color:var(--tx3);letter-spacing:.05em;text-transform:uppercase;margin-bottom:8px;display:flex;align-items:center;gap:8px">
        Vulnerabilities (${findings.length})
        <div style="flex:1;height:1px;background:var(--bd)"></div>
        ${findings.length ? `<button class="tbtn" style="font-size:10px" onclick="filterVulnsByIP('${esc(a.ip)}');closeHostPanel()">View all</button>` : ''}
      </div>
      <div style="margin-bottom:16px">${findingRows}</div>

      <div style="font-family:var(--mf);font-size:10px;color:var(--tx3);letter-spacing:.05em;text-transform:uppercase;margin-bottom:8px;display:flex;align-items:center;gap:8px">
        Port history
        <div style="flex:1;height:1px;background:var(--bd)"></div>
      </div>
      <div style="margin-bottom:8px">${
        (assetData.asset.port_history||[]).slice(0,5).map(h => `
          <div style="display:flex;gap:10px;font-family:var(--mf);font-size:10px;padding:4px 0;border-bottom:1px solid var(--bd)">
            <span style="color:var(--tx3);min-width:100px">${esc((h.seen_at||'').slice(0,16))}</span>
            <span style="color:var(--tx2)">${(h.ports||[]).join(', ')||'none'}</span>
          </div>`).join('') || '<div style="color:var(--tx3);font-size:11px;padding:4px 0">No history yet</div>'
      }</div>

      <div style="margin-top:12px;display:flex;gap:8px">
        <button class="btnp" style="font-size:11px" onclick="openReclassify(${a.id},'${esc(a.ip)}','${esc(a.hostname||'')}','${esc(a.category||'unk')}','${esc(a.vendor||'')}','${esc(a.notes||'')}')">&#9998; Edit</button>
        <button class="tbtn" style="font-size:11px" onclick="filterVulnsByIP('${esc(a.ip)}');closeHostPanel()">View CVEs</button>
      </div>`;
}

function closeHostPanel() {
    document.getElementById('host-panel').style.display = 'none';
    document.getElementById('host-panel-bg').style.display = 'none';
}

// close on Escape key
document.addEventListener('keydown', e => { if (e.key === 'Escape') closeHostPanel(); });

// ==========================================================================
// Export
// ==========================================================================
function exportAssets(format) {
    const q    = document.getElementById('af-q').value;
    const cat  = document.getElementById('af-cat').value;
    const sev  = document.getElementById('af-sev').value;
    const incf = document.getElementById('af-findings')?.checked ? '1' : '0';
    const url  = `/api/export.php?format=${format}&q=${enc(q)}&category=${enc(cat)}&severity=${enc(sev)}&findings=${incf}`;
    // Trigger download
    const a = document.createElement('a');
    a.href = url;
    a.download = `surveytrace_assets_${new Date().toISOString().slice(0,10)}.${format}`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    toast(`Exporting assets as ${format.toUpperCase()}…`, 'ok');
}

// ==========================================================================
// Init
// ==========================================================================
// Always load dashboard data first to populate sidebar badges
loadDashboard();

// Restore last active tab from session storage
const lastTab = (() => { try { return sessionStorage.getItem('st_tab'); } catch(e) { return null; } })();
if (lastTab && document.getElementById('t-' + lastTab)) {
    goTab(lastTab);
    const navMap = {dash:'ndash',assets:'nassets',vulns:'nvulns',logs:'nlogs',scan:'nscan',enrich:'nenrich',settings:'nsettings',sched:'nsched'};
    if (navMap[lastTab]) hiNav(navMap[lastTab]);
} else {
    goTab('dash');
    hiNav('ndash');
}
loadEnrichment();  // Pre-load so enrichment tab is ready immediately
// Refresh dashboard every 30s
dashTimer = setInterval(() => { if (currentTab === 'dash') loadDashboard(); }, 30000);
// Check for already-running scan on load
loadScanStatus();
</script>
</body>
</html>
