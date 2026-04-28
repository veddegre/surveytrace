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
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=Lato:wght@300;400;600;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="css/app.css?v=<?= rawurlencode(defined('ST_VERSION') ? ST_VERSION : '0.6.0') ?>">
</head>
<body>
<div class="shell">

<!-- Top bar -->
<div class="bar">
  <div class="logo"><div class="logo-dot" id="logodot"></div>SurveyTrace</div>
  <div class="bar-meta" id="bar-meta">v<?= defined('ST_VERSION') ? ST_VERSION : '0.6.0' ?></div>
  <div class="sep"></div>
  <div class="pill" id="status-pill"><div class="pdot"></div><span id="status-txt">Idle</span></div>
  <button type="button" class="tbtn" id="theme-toggle-btn" onclick="toggleThemeOverride()" title="Switch between light and dark. New visits follow your system until you choose here.">Theme: Dark</button>
  <button class="tbtn" onclick="goTab('scan');hiNav('nscan')">+ New scan</button>
  <button class="tbtn" onclick="goTab('access');hiNav('naccess')">Access control</button>
  <button class="tbtn" onclick="goTab('settings');hiNav('nsettings')">Settings</button>
  <button class="tbtn" id="btn-profile" onclick="openProfileModal()">My profile</button>
  <button class="tbtn" onclick="logoutSession()">Sign out</button>
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
  <div class="ni" id="ndevices" onclick="goTab('devices');hiNav('ndevices')">
    <svg width="13" height="13" viewBox="0 0 14 14" fill="none" stroke="currentColor" stroke-width="1.2"><rect x="2" y="3" width="10" height="8" rx="1"/><path d="M5 11v1.5M9 11v1.5M4 6h2M8 6h2"/></svg>
    Devices
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
  <div class="ni" id="nscanhist" onclick="goTab('scanhist');hiNav('nscanhist')">
    <svg width="13" height="13" viewBox="0 0 14 14" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M3 2h8v10H3z"/><path d="M5 5h4M5 8h4M5 11h2"/></svg>
    Scan history
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
  <div class="ni" id="nhealth" onclick="goTab('health');hiNav('nhealth')">
    <svg width="13" height="13" viewBox="0 0 14 14" fill="none" stroke="currentColor" stroke-width="1.2"><rect x="1" y="3" width="2.5" height="5" rx="0.3"/><rect x="4" y="1" width="2.5" height="7" rx="0.3"/><rect x="7" y="2" width="2.5" height="6" rx="0.3"/><rect x="10" y="4" width="2.5" height="4" rx="0.3"/></svg>
    System health
  </div>
  <div class="ni" id="naccess" onclick="goTab('access');hiNav('naccess')">
    <svg width="13" height="13" viewBox="0 0 14 14" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="1.5" y="6.5" width="11" height="6" rx="1.2"/><path d="M4.5 6V4.8A2.5 2.5 0 0 1 7 2.3a2.5 2.5 0 0 1 2.5 2.5V6"/><circle cx="7" cy="9.5" r="0.8"/></svg>
    Access control
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
  <div class="dash-actions">
    <div class="dash-actions-left">
      <button class="tbtn mode-toggle" id="dash-mode-btn" onclick="toggleDashMode()">Executive view: off</button>
    </div>
    <div class="dash-actions-right">
      <label class="mono-sm text-dim" for="exec-trend-range">Trend window</label>
      <select class="finp narrow" id="exec-trend-range" onchange="loadDashboard()">
        <option value="7">7d</option>
        <option value="14" selected>14d</option>
        <option value="30">30d</option>
      </select>
    </div>
  </div>
  <div id="dash-exec">
    <div class="exec-top-grid">
      <div class="card exec-top-card">
        <div class="ct">Executive highlights</div>
        <div class="exec-brief-deltas" id="exec-brief-deltas"></div>
        <div class="exec-brief-list" id="exec-brief-list">Loading…</div>
      </div>
      <div class="card exec-top-card">
        <div class="ct">Recommended actions (next 24h)</div>
        <div id="exec-actions" class="exec-brief-list">Loading…</div>
      </div>
    </div>
    <div class="sth">Security posture overview</div>
    <div class="sgrid" id="exec-kpis">
      <div class="sc g"><div class="sl">Total systems tracked</div><div class="sv" id="ex-assets">—</div><div class="ss" id="ex-assets-new">—</div></div>
      <div class="sc r"><div class="sl">Open security issues</div><div class="sv" id="ex-findings">—</div><div class="ss" id="ex-findings-sev">—</div></div>
      <div class="sc"><div class="sl">Scans run (7d)</div><div class="sv" id="ex-scans">—</div><div class="ss" id="ex-scans-fail">—</div></div>
      <div class="sc a"><div class="sl">New issues found (7d)</div><div class="sv" id="ex-findings-new">—</div><div class="ss">new issues this week</div></div>
      <div class="sc r"><div class="sl">Critical issues open</div><div class="sv" id="ex-critical-open">—</div><div class="ss">highest urgency</div></div>
      <div class="sc"><div class="sl">High-priority issues open</div><div class="sv" id="ex-high-open">—</div><div class="ss">near-term remediation</div></div>
      <div class="sc"><div class="sl">Scan success rate (14d)</div><div class="sv" id="ex-comp-rate">—</div><div class="ss">completed successfully</div></div>
      <div class="sc"><div class="sl">Avg scan time (7d)</div><div class="sv" id="ex-avg-dur">—</div><div class="ss" id="ex-sla">—</div></div>
    </div>
    <div class="sgrid exec-grid-2" style="margin-top:12px">
      <div class="card">
        <div class="ct">Issues identified (14d)</div>
        <div id="exec-trend-findings" class="exec-chart"></div>
      </div>
      <div class="card">
        <div class="ct">New systems discovered (14d)</div>
        <div id="exec-trend-assets" class="exec-chart"></div>
      </div>
    </div>
    <div class="sgrid exec-grid-2" style="margin-top:12px">
      <div class="card">
        <div class="ct">Scan reliability + risk trend (14d)</div>
        <div id="exec-trend-scans" class="exec-chart"></div>
      </div>
      <div class="card">
        <div class="ct">Issue severity mix</div>
        <div id="exec-severity" class="help-mono">Loading…</div>
      </div>
    </div>
    <div class="sth section-top">Highest-priority systems</div>
    <div class="tbl-wrap mb16">
      <table class="tbl"><thead><tr><th>IP</th><th class="mono-sm">Device</th><th>Hostname</th><th>Type</th><th>Top CVE</th><th>CVSS</th><th>Findings</th></tr></thead>
      <tbody id="exec-top-risky"><tr><td colspan="7" class="loading">Loading…</td></tr></tbody></table>
    </div>
  </div>
  <div id="dash-ops">
  <div class="sgrid" id="dash-stats">
    <div class="sc g"><div class="sl">Total assets</div><div class="sv" id="d-total">—</div><div class="ss" id="d-new">loading…</div></div>
    <div class="sc a"><div class="sl">Unclassified</div><div class="sv" id="d-unk">—</div><div class="ss">needs review</div></div>
    <div class="sc r"><div class="sl">Open CVEs</div><div class="sv" id="d-cves">—</div><div class="ss" id="d-crit">— critical</div></div>
    <div class="sc"><div class="sl">Last scan</div><div class="sv sv-sm" id="d-age">—</div><div class="ss" id="d-scan-target">—</div></div>
  </div>

  <div class="sgrid" id="dash-cats">
    <div class="sc"><div class="sl">Servers</div><div class="sv sv-md" id="dc-srv">—</div></div>
    <div class="sc"><div class="sl">Workstations</div><div class="sv sv-md" id="dc-ws">—</div></div>
    <div class="sc"><div class="sl">Network gear</div><div class="sv sv-md" id="dc-net">—</div></div>
    <div class="sc"><div class="sl">IoT / OT / other</div><div class="sv sv-md" id="dc-iot">—</div></div>
  </div>

  <div class="sth">Top vulnerable assets</div>
  <div class="tbl-wrap mb16">
    <table class="tbl"><thead><tr><th>IP</th><th class="mono-sm">Device</th><th>Hostname</th><th>Type</th><th>Vendor</th><th>Top CVE</th><th>CVSS</th><th>Findings</th></tr></thead>
    <tbody id="dash-top-vuln"><tr><td colspan="8" class="loading">Loading…</td></tr></tbody></table>
  </div>

  <div class="sth">Recent activity <button class="sth-btn" onclick="loadDashboard()">&#8635; Refresh</button></div>
  <div class="feed" id="dash-feed"><div class="loading">Loading…</div></div>
  </div>
</div>

<!-- ================================================================ ASSETS -->
<div class="tab" id="t-assets">
  <div class="fbar">
    <input class="finp wide" id="af-q" placeholder="Search IP, hostname, vendor, MAC… (numeric device id + Enter filters by device)" autocomplete="off"
      oninput="debounceAssets()" onkeydown="assetMainSearchKeydown(event)">
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
      <option value="ip">Sort: IP</option><option value="device_id">Sort: Device ID</option>
      <option value="hostname">Hostname</option>
      <option value="category">Type</option><option value="top_cvss">CVSS</option>
      <option value="last_seen">Last seen</option><option value="open_findings">CVEs</option>
    </select>
    <button class="tbtn" onclick="exportAssets('csv')" title="Export as CSV">&#8595; CSV</button>
    <button class="tbtn" onclick="exportAssets('json')" title="Export as JSON">&#8595; JSON</button>
    <button type="button" class="tbtn" onclick="clearAllAssetFilters()" title="Clear search, type, severity, sort, and device filter">Clear filters</button>
  </div>
  <div id="af-device-banner" class="device-filter-banner hide">
    <span class="text-secondary">Assets for device</span> <span class="mono" id="af-device-banner-id"></span>
  </div>
  <div class="tbl-wrap">
    <table class="tbl">
      <thead><tr>
        <th onclick="sortAssets('ip')">IP address</th>
        <th class="mono-sm" onclick="sortAssets('device_id')" title="Logical device (stable across future merges)">Device</th>
        <th onclick="sortAssets('hostname')">Hostname</th>
        <th onclick="sortAssets('category')">Type</th>
        <th>Vendor / model</th>
        <th>Open ports</th>
        <th onclick="sortAssets('open_findings')">CVEs</th>
        <th onclick="sortAssets('top_cvss')">CVSS</th>
        <th onclick="sortAssets('last_seen')">Last seen</th>
        <th>Edit</th>
      </tr></thead>
      <tbody id="asset-tbody"><tr><td colspan="10" class="loading">Loading…</td></tr></tbody>
    </table>
  </div>
  <div class="hint-micro mt6">Tip: click <strong>Details</strong> (or the IP address) to open full host details.</div>
  <div class="pgn">
    <button id="aprev" onclick="loadAssets(assetPage-1)" disabled>&#8592; Prev</button>
    <span id="apgn-info">—</span>
    <button id="anext" onclick="loadAssets(assetPage+1)" disabled>Next &#8594;</button>
  </div>
</div>

<!-- ================================================================ DEVICES -->
<div class="tab" id="t-devices">
  <div class="fbar">
    <input class="finp wide" id="df-q" placeholder="Search device id, MAC, label, or linked IP/hostname…" oninput="debounceDevices()">
    <select class="finp narrow" id="df-sort" onchange="loadDevices(1)">
      <option value="id">Sort: ID</option>
      <option value="asset_count">Sort: # assets</option>
      <option value="last_seen">Sort: Last activity</option>
      <option value="primary_mac_norm">Sort: MAC</option>
    </select>
    <button class="tbtn" onclick="loadDevices(1)" title="Reload">&#8635; Refresh</button>
  </div>
  <div class="tbl-wrap">
    <table class="tbl">
      <thead><tr>
        <th>ID</th>
        <th>MAC (norm)</th>
        <th># Assets</th>
        <th>IP sample</th>
        <th>Last activity</th>
        <th>Created</th>
        <th></th>
      </tr></thead>
      <tbody id="device-tbody"><tr><td colspan="7" class="loading">Loading…</td></tr></tbody>
    </table>
  </div>
  <div class="pgn">
    <button id="dprev" onclick="loadDevices(devicePage-1)" disabled>&#8592; Prev</button>
    <span id="dpgn-info">—</span>
    <button id="dnext" onclick="loadDevices(devicePage+1)" disabled>Next &#8594;</button>
  </div>
</div>

<!-- ================================================================ VULNERABILITIES -->
<div class="tab" id="t-vulns">
  <div class="fbar">
    <input class="finp wide" id="vf-cve" placeholder="Search CVE ID or description…" oninput="debounceFindings()">
    <input class="finp narrow w130" id="vf-ip" placeholder="Filter by IP…" oninput="debounceFindings()">
    <button class="tbtn btn-xs hide" id="vf-clear-ip" onclick="clearIPFilter()">✕ clear</button>
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
      <div class="card">
        <div class="ct">Discovery mode</div>
        <div class="tr2">
          <div>
            <div class="tl">Auto</div>
            <div class="tsubl">ARP for same-subnet, ping scan for routed</div>
          </div>
          <input class="accent-radio" type="radio" name="scan_mode" id="sm-auto" value="auto" checked>
        </div>
        <div class="tr2">
          <div>
            <div class="tl">Routed</div>
            <div class="tsubl">ICMP/TCP ping scan only — no ARP (cross-router)</div>
          </div>
          <input class="accent-radio" type="radio" name="scan_mode" id="sm-routed" value="routed">
        </div>
        <div class="tr2">
          <div>
            <div class="tl">Force (-Pn)</div>
            <div class="tsubl warn-text">&#9888; Scan all IPs regardless of ping — use for firewalled hosts</div>
          </div>
          <input class="accent-radio" type="radio" name="scan_mode" id="sm-force" value="force">
        </div>
      </div>
      <div class="card">
        <div class="ct">Scan phases</div>
        <div class="tr2"><div><div class="tl">Passive discovery</div><div class="tsubl">ARP watch, mDNS/Bonjour sniff — zero packets sent</div></div><label class="tog"><input type="checkbox" id="ph-passive" checked><div class="trk"></div><div class="tth"></div></label></div>
        <div class="tr2"><div><div class="tl">ICMP sweep</div><div class="tsubl">Ping / ARP sweep all hosts in scope</div></div><label class="tog"><input type="checkbox" id="ph-icmp" checked><div class="trk"></div><div class="tth"></div></label></div>
        <div class="tr2"><div><div class="tl">Port &amp; banner probe</div><div class="tsubl">TCP connect on safe port list only</div></div><label class="tog"><input type="checkbox" id="ph-banner" checked><div class="trk"></div><div class="tth"></div></label></div>
        <div class="tr2"><div><div class="tl">Service fingerprinting</div><div class="tsubl">OUI + banner + port profile → CPE</div></div><label class="tog"><input type="checkbox" id="ph-fingerprint" checked><div class="trk"></div><div class="tth"></div></label></div>
        <div class="tr2"><div><div class="tl">SNMP GET (read-only)</div><div class="tsubl">sysDescr, sysName, ifTable — no SET</div></div><label class="tog"><input type="checkbox" id="ph-snmp"><div class="trk"></div><div class="tth"></div></label></div>
        <div class="tr2"><div><div class="tl">OT protocol probes</div><div class="tsubl warn-text">&#9888; Modbus/S7 read coils only — no writes</div></div><label class="tog"><input type="checkbox" id="ph-ot"><div class="trk"></div><div class="tth"></div></label></div>
        <div class="tr2"><div><div class="tl">CVE correlation</div><div class="tsubl">Match CPE strings against local NVD db</div></div><label class="tog"><input type="checkbox" id="ph-cve" checked><div class="trk"></div><div class="tth"></div></label></div>
      </div>
    </div>
    <div>
      <div class="card">
        <div class="ct">Scan profile</div>
        <div class="profile-grid">
          <label class="profile-card on" id="prof-standard_inventory" title="Balanced default: common ports, light banners, CVE correlation">
            <input class="radio-hidden" type="radio" name="scan_profile" value="standard_inventory" checked>
            <div class="pc-icon">&#128203;</div>
            <div class="profile-copy">
              <div class="pc-name">Standard Inventory</div>
              <div class="pc-desc">Common ports, light banner probing, CVE correlation</div>
            </div>
          </label>
          <label class="profile-card" id="prof-iot_safe" title="Safest option: passive-first, no banner probing">
            <input class="radio-hidden" type="radio" name="scan_profile" value="iot_safe">
            <div class="pc-icon">&#128737;</div>
            <div class="profile-copy">
              <div class="pc-name">IoT Safe</div>
              <div class="pc-desc">Passive only — ARP/ICMP, no port scanning, no banners</div>
            </div>
            <div class="pc-badge safe">Safe for IoT</div>
          </label>
          <label class="profile-card" id="prof-deep_scan" title="Deep inspection: more probes, higher traffic, best for targeted investigations">
            <input class="radio-hidden" type="radio" name="scan_profile" value="deep_scan">
            <div class="pc-icon">&#128300;</div>
            <div class="profile-copy">
              <div class="pc-name">Deep Scan</div>
              <div class="pc-desc">Full nmap -sV, SNMP, all ports — requires confirmation</div>
            </div>
            <div class="pc-badge warn">Confirmation required</div>
          </label>
          <label class="profile-card" id="prof-full_tcp" title="All 65,535 TCP ports with stronger service detection; slowest but deepest coverage">
            <input class="radio-hidden" type="radio" name="scan_profile" value="full_tcp">
            <div class="pc-icon">&#129517;</div>
            <div class="profile-copy">
              <div class="pc-name">Full TCP</div>
              <div class="pc-desc">All TCP ports (-p-) + service detect — slower, high coverage</div>
            </div>
            <div class="pc-badge warn">Confirmation required</div>
          </label>
          <label class="profile-card" id="prof-fast_full_tcp" title="All TCP ports with lighter detection for faster host turnover">
            <input class="radio-hidden" type="radio" name="scan_profile" value="fast_full_tcp">
            <div class="pc-icon">&#9889;</div>
            <div class="profile-copy">
              <div class="pc-name">Fast Full TCP</div>
              <div class="pc-desc">All TCP ports (-p-) + lighter detection — faster turnover</div>
            </div>
            <div class="pc-badge warn">Confirmation required</div>
          </label>
          <label class="profile-card" id="prof-ot_careful" title="OT-safe baseline: read-only OT probes on by default; strict rate limits">
            <input class="radio-hidden" type="radio" name="scan_profile" value="ot_careful">
            <div class="pc-icon">&#9888;</div>
            <div class="profile-copy">
              <div class="pc-name">OT Careful</div>
              <div class="pc-desc">Passive only, 2pps max — safe for industrial networks</div>
            </div>
            <div class="pc-badge safe">Safe for OT</div>
          </label>
        </div>
        <div id="profile-help" class="help-box">
          <strong class="text-strong">Standard Inventory:</strong>
          Balanced default for general-purpose networks. Scans common ports with light banner probing, then correlates CVEs.
        </div>
      </div>
      <div class="card" id="scan-enrich-card">
        <div class="ct">Network enrichment (this scan)</div>
        <div class="tsubl" style="margin-bottom:8px">Phase 3b runs the sources you configure under <strong>Enrichment</strong> (controllers, SNMP, logs, and other integrations). All enabled sources are used by default; uncheck any you want to skip for this job only, or turn all off to skip the phase.</div>
        <div id="scan-enrichment-wrap" data-ready="0"><div class="hint-micro">Loading…</div></div>
      </div>
      <div class="card">
        <div class="ct">Launch</div>
        <div class="brow">
          <button class="btnp" id="btn-start" onclick="startScan()">&#9654; Queue scan</button>
        </div>
        <div id="scan-stats" class="scan-stats">
          Hosts found: <span id="ss-found">0</span> &nbsp;·&nbsp;
          Scanned: <span id="ss-scanned">0</span> &nbsp;·&nbsp;
          Elapsed: <span id="ss-elapsed">0s</span>
        </div>
      </div>
    </div>
  </div>
  <div class="hint-micro mb4" style="margin-top:2px">
    Queue and past runs: <button type="button" class="tbtn text-micro" onclick="goTab('scanhist');hiNav('nscanhist')">Open Scan history</button>
  </div>
  <div class="sth section-top">Job queue</div>
  <div id="job-queue-wrap-scan">
    <div id="job-queue-scan" class="mb8" style="display:none">
      <div class="tbl-wrap">
        <table class="tbl">
          <thead><tr><th>#</th><th>Label</th><th>Target</th><th>Profile</th><th>Status / Progress</th><th>Priority</th><th>Queued</th><th></th></tr></thead>
          <tbody id="queue-tbody-scan"></tbody>
        </table>
      </div>
    </div>
    <div id="job-queue-empty-scan" class="hint-micro mb8 pad8y">No jobs queued or running</div>
  </div>
</div>

<!-- ================================================================ SCAN HISTORY -->
<div class="tab" id="t-scanhist">
  <div class="hint-micro mb10">
    Job queue and finished scans. New jobs: <button type="button" class="tbtn text-micro" onclick="goTab('scan');hiNav('nscan')">Scan control</button>.
  </div>
  <!-- Job queue — primary status view -->
  <div class="sth section-top">Job queue</div>
  <div id="job-queue-wrap">
    <div id="job-queue" class="mb8" style="display:none">
      <div class="tbl-wrap">
        <table class="tbl">
          <thead><tr><th>#</th><th>Label</th><th>Target</th><th>Profile</th><th>Status / Progress</th><th>Priority</th><th>Queued</th><th></th></tr></thead>
          <tbody id="queue-tbody"></tbody>
        </table>
      </div>
    </div>
    <div id="job-queue-empty" class="hint-micro mb8 pad8y">No jobs queued or running</div>
  </div>

  <div class="sth section-top">Scan history</div>
  <div class="fbar">
    <input class="finp wide" id="scan-hist-q" type="search" placeholder="Filter by scan label, target CIDR, or job #…" autocomplete="off" aria-label="Filter scan history by label, target, or job id" oninput="debounceScanHistSearch()">
    <button type="button" class="tbtn" onclick="loadScanHistory()" title="Reload scan history">&#8635; Refresh</button>
  </div>
  <div class="tbl-wrap">
    <table class="tbl">
      <thead><tr><th>#</th><th>Label</th><th>Target</th><th>Status</th><th>Profile</th><th>Hosts</th><th>Duration</th><th>Completed</th><th></th></tr></thead>
      <tbody id="scan-hist"><tr><td colspan="9" class="loading">Loading…</td></tr></tbody>
    </table>
  </div>
</div>

<!-- ================================================================ AUDIT LOG -->
<div class="tab" id="t-sched">
  <!-- Schedule modal -->
  <div id="sched-bg" class="modal-bg z100">
    <div class="modal-card modal-w560">
      <div class="row-between mb14" style="gap:12px;align-items:center">
        <div class="modal-title" style="margin-bottom:0" id="sched-title">New schedule</div>
        <button type="button" class="modal-close-x" onclick="closeSchedModal()" title="Close without saving" aria-label="Close without saving">×</button>
      </div>
      <input type="hidden" id="sched-id" value="">
      <input type="hidden" id="sched-paused" value="0">

      <label class="flbl">Schedule name</label>
      <input class="finp w100 mb10" id="sched-name" placeholder="Weekly full scan">

      <label class="flbl">Target CIDR</label>
      <input class="finp w100 mb10" id="sched-cidr" placeholder="192.168.86.0/24">

      <label class="flbl">Cron expression</label>
      <div class="row-wrap mb6 gap6" id="cron-presets">
        <button class="tbtn" onclick="setCron('@daily')">Daily</button>
        <button class="tbtn" onclick="setCron('@weekly')">Weekly</button>
        <button class="tbtn" onclick="setCron('@monthly')">Monthly</button>
        <button class="tbtn" onclick="setCron('0 2 * * 0')">Sun 2am</button>
        <button class="tbtn" onclick="setCron('0 3 * * 1-5')">Weekdays 3am</button>
        <button class="tbtn" onclick="setCron('0 */6 * * *')">Every 6h</button>
      </div>
      <input class="finp w100 mb4" id="sched-cron" placeholder="0 3 * * 0">
      <div class="hint-micro mb10" id="sched-cron-desc">
        Format: minute hour day-of-month month day-of-week
      </div>

      <label class="flbl">Profile</label>
      <select class="finp w100 mb10" id="sched-profile">
        <option value="standard_inventory">Standard Inventory</option>
        <option value="iot_safe">IoT Safe</option>
        <option value="deep_scan">Deep Scan</option>
        <option value="full_tcp">Full TCP</option>
        <option value="fast_full_tcp">Fast Full TCP</option>
        <option value="ot_careful">OT Careful</option>
      </select>
      <div id="sched-profile-help" class="help-box mb8"></div>
      <div id="sched-profile-warn" class="help-box mb8" style="display:none;border-color:var(--amber);color:var(--amber)"></div>

      <label class="flbl">Discovery mode</label>
      <select class="finp w100 mb10" id="sched-mode">
        <option value="auto">Auto</option>
        <option value="routed">Routed</option>
        <option value="force">Force (-Pn)</option>
      </select>

      <label class="flbl">Rate limiting</label>
      <div class="rr">
        <label class="flbl">Max packets/sec per host</label>
        <div class="rv"><span>1</span><span id="sched-pps-val">5 pps</span><span>50</span></div>
        <input class="rng" type="range" id="sched-pps" min="1" max="50" step="1" value="5"
          oninput="document.getElementById('sched-pps-val').textContent=this.value+' pps'">
      </div>
      <div class="rr mb10">
        <label class="flbl">Inter-host delay</label>
        <div class="rv"><span>0</span><span id="sched-delay-val">200 ms</span><span>2000</span></div>
        <input class="rng" type="range" id="sched-delay" min="0" max="2000" step="10" value="200"
          oninput="document.getElementById('sched-delay-val').textContent=this.value+' ms'">
      </div>

      <label class="flbl">Job priority in queue</label>
      <div class="hint-micro mb4">1 = highest, 100 = lowest. Default 20 for scheduled runs.</div>
      <input class="finp w100 mb10" type="number" id="sched-priority" min="1" max="100" value="20">

      <label class="flbl">Scan phases</label>
      <div class="hint-micro mb6">Same as the Scan tab — pick at least one.</div>
      <div class="tr2"><div><div class="tl">Passive discovery</div><div class="tsubl">ARP / mDNS — no active probes</div></div><label class="tog"><input type="checkbox" id="sched-ph-passive" checked><div class="trk"></div><div class="tth"></div></label></div>
      <div class="tr2"><div><div class="tl">ICMP sweep</div><div class="tsubl">Ping / ARP discovery</div></div><label class="tog"><input type="checkbox" id="sched-ph-icmp" checked><div class="trk"></div><div class="tth"></div></label></div>
      <div class="tr2"><div><div class="tl">Port &amp; banner probe</div><div class="tsubl">Safe TCP port list</div></div><label class="tog"><input type="checkbox" id="sched-ph-banner" checked><div class="trk"></div><div class="tth"></div></label></div>
      <div class="tr2"><div><div class="tl">Service fingerprinting</div><div class="tsubl">OUI + banners → CPE</div></div><label class="tog"><input type="checkbox" id="sched-ph-fingerprint" checked><div class="trk"></div><div class="tth"></div></label></div>
      <div class="tr2"><div><div class="tl">SNMP GET (read-only)</div><div class="tsubl">sysDescr, ifTable — no SET</div></div><label class="tog"><input type="checkbox" id="sched-ph-snmp"><div class="trk"></div><div class="tth"></div></label></div>
      <div class="tr2"><div><div class="tl">OT protocol probes</div><div class="tsubl warn-text">&#9888; Read-only OT probes</div></div><label class="tog"><input type="checkbox" id="sched-ph-ot"><div class="trk"></div><div class="tth"></div></label></div>
      <div class="tr2 mb10"><div><div class="tl">CVE correlation</div><div class="tsubl">Local NVD match</div></div><label class="tog"><input type="checkbox" id="sched-ph-cve" checked><div class="trk"></div><div class="tth"></div></label></div>

      <label class="flbl">Network enrichment (Phase 3b)</label>
      <div class="hint-micro mb6">Same sources as <strong>Enrichment</strong> — matches the Scan tab; all enabled on = default.</div>
      <div id="sched-enrichment-wrap" data-ready="0" class="mb10"><div class="hint-micro">Sources load when you open this form.</div></div>

      <label class="flbl">Timezone</label>
      <select class="finp w100 mb10" id="sched-tz">
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
      <div class="hint-micro mb10" id="sched-tz-note">
        Cron times are interpreted in this timezone
      </div>

      <label class="flbl">Exclusions (optional)</label>
      <textarea class="finp w100 mb10" id="sched-excl" placeholder="192.168.86.1&#10;10.0.0.0/8" style="min-height:100px;resize:vertical"></textarea>

      <label class="flbl">Notes (optional)</label>
      <input class="finp w100 mb10" id="sched-notes" placeholder="Description or reason for this schedule">

      <label class="flbl">If a run is missed (daemon down, pause, etc.)</label>
      <select class="finp w100 mb6" id="sched-missed-pol">
        <option value="run_once">Run one catch-up scan, then resume cadence</option>
        <option value="skip_no_run">Skip scan — only move next run forward</option>
        <option value="run_all">Queue one job per missed slot (capped)</option>
      </select>
      <div class="row-wrap mb10 gap10">
        <label class="status-text nowrap">Max jobs per wake</label>
        <input class="finp minw72" type="number" id="sched-missed-max" min="1" max="100" value="5">
      </div>
      <div class="hint-micro mb12">
        “Run all” uses this cap so a long outage cannot flood the queue.
      </div>

      <label class="row-wrap mb14 gap8" style="font-family:var(--mf);font-size:13px;color:var(--tx2)">
        <input type="checkbox" id="sched-en" checked> Cron enabled (off = schedule dormant; use Pause on the list to freeze without turning off)
      </label>

      <div class="stack8">
        <button class="btnp" onclick="saveSchedule()">Save schedule</button>
        <button class="tbtn" onclick="closeSchedModal()">Cancel</button>
      </div>
    </div>
  </div>

  <div id="sched-hist-bg" class="modal-bg z101">
    <div class="modal-card modal-w560">
      <div class="modal-title mb10" id="sched-hist-title">Run history</div>
      <div class="tbl-wrap">
        <table class="tbl">
          <thead><tr>
            <th>#</th><th>Status</th><th>Label</th><th>Hosts</th><th>Queued</th><th>Finished</th>
          </tr></thead>
          <tbody id="sched-hist-tbody"><tr><td colspan="6" class="loading">Loading…</td></tr></tbody>
        </table>
      </div>
      <button class="tbtn mt10" onclick="closeSchedHistModal()">Close</button>
    </div>
  </div>

  <div id="scan-hist-detail-bg" class="modal-bg z101">
    <div class="modal-card modal-w760">
      <div class="row-between mb10 gap10">
        <div class="modal-title section-title-reset" id="scan-hist-detail-title">Scan detail</div>
        <div class="row-wrap gap6" style="align-items:center">
          <button type="button" class="tbtn" id="scan-hist-detail-rerun" style="display:none" onclick="rerunScanJob(parseInt(document.getElementById('scan-hist-detail-rerun').dataset.jobId||'0',10))">Re-run</button>
          <button type="button" class="tbtn" id="scan-hist-detail-delete" style="display:none;color:var(--red)" onclick="deleteScanJob(parseInt(document.getElementById('scan-hist-detail-delete').dataset.jobId||'0',10))">Delete</button>
          <button type="button" class="tbtn" onclick="closeScanHistDetailModal()">Close</button>
        </div>
      </div>
      <div id="scan-hist-detail-meta" class="status-text mb8"></div>
      <div class="row-wrap gap6 mb8" style="align-items:center">
        <label for="scan-hist-compare-select" class="text-micro" style="color:var(--tx3)">Compare against</label>
        <select id="scan-hist-compare-select" class="finp narrow w130"></select>
        <label class="text-micro" style="display:flex;align-items:center;gap:4px;color:var(--tx3)"><input type="checkbox" id="scan-hist-compare-same-target"> same target</label>
        <label class="text-micro" style="display:flex;align-items:center;gap:4px;color:var(--tx3)"><input type="checkbox" id="scan-hist-compare-same-profile"> same profile/mode</label>
        <button type="button" class="tbtn btn-xs" id="scan-hist-compare-btn">Apply</button>
      </div>
      <div id="scan-hist-detail-summary" class="help-mono mb10"></div>
      <div id="scan-hist-detail-diff" class="help-mono mb10"></div>
      <div class="tbl-wrap">
        <table class="tbl">
          <thead><tr><th>IP</th><th>Hostname</th><th>Category</th><th>Ports</th><th>Top CVE</th><th>CVSS</th></tr></thead>
          <tbody id="scan-hist-detail-assets"><tr><td colspan="6" class="loading">Loading…</td></tr></tbody>
        </table>
      </div>
      <p id="scan-hist-detail-assets-hint" class="hint-micro mt8" style="display:none">Click a row to open the linked <strong>device</strong> (when assigned) or the <strong>host</strong> (asset) at that IP in Inventory.</p>
    </div>
  </div>

  <div class="row-between mb12">
    <div class="sth section-title-reset">Scan schedules</div>
    <button class="btnp btn-sm" onclick="openSchedModal()">+ New schedule</button>
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
        <div class="mt12">
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
        <div class="help-line" style="line-height:1.8">
          Enrichment sources run as <b class="text-strong">Phase 3b</b> during each scan (you can narrow or skip them per job on the <b>Scan</b> tab).<br>
          They add hostnames, MACs, VLANs, and other context the scanner may not see on its own — especially across routers or for hosts that barely respond to probes.<br><br>
          <b class="text-strong">Integrations</b> — vendor APIs and dashboards you already use can return many clients in one call when that system already knows them.<br><br>
          <b class="text-strong">SNMP</b> — read-only walks on routers or switches (ARP tables, bridge data) as a vendor-neutral option.<br><br>
          <b class="text-strong">Files and logs</b> — DHCP leases, DNS or firewall exports, and similar paths pull names and clients from your own records.
        </div>
      </div>
    </div>
  </div>
</div>

<!-- ================================================================ SYSTEM HEALTH -->
<div class="tab" id="t-health">
  <div class="row-between mb12">
    <div class="sth section-title-reset">System health</div>
    <button type="button" class="tbtn" onclick="loadHealth()">&#8635; Refresh</button>
  </div>
  <p class="help-line mb16" style="max-width:min(100%, 52rem)">
    Use this view to see whether the installation is in good order: services, disk, DB files, the scan queue, and feed
    activity. It is <strong>read only</strong> and does not change configuration—use the other tabs for that.
    <b>Refresh</b> loads the latest snapshot.
  </p>
  <div class="card health-page">
    <div class="ct">Summary</div>
    <div id="health-snapshot"><div class="text-dim">Select this tab to load, or use Refresh for the latest data.</div></div>
  </div>
</div>

<!-- ================================================================ ACCESS CONTROL -->
<div class="tab" id="t-access">
  <div class="card">
    <div class="ct">Access control</div>
    <div class="help-line mb8">Manage sign-in mode, local users, and recovery options.</div>
    <div class="help-box mb10">
      <div class="help-line"><strong>Setup quick guide:</strong></div>
      <div class="help-line">1) Choose auth mode: <strong>Session</strong> (local accounts) or <strong>OIDC</strong>.</div>
      <div class="help-line">2) Keep <strong>Breakglass local access</strong> enabled so one emergency account can still sign in if SSO is unavailable.</div>
      <div class="help-line">3) Choose <strong>SSO role assignment</strong>: manage roles here in SurveyTrace (recommended) or map from IdP groups.</div>
    </div>
    <details class="mb10" open>
      <summary class="flbl text-secondary">Daily admin tasks</summary>
      <label class="flbl mt6">Authentication mode</label>
      <div class="row-wrap mb10">
        <select class="finp" id="st-auth-mode" onchange="updateAccessControlModeVisibility()" style="min-width:180px" title="Session uses local SurveyTrace users. OIDC uses SSO with optional breakglass local login.">
          <option value="session">Session (local users)</option>
          <option value="oidc">OIDC SSO</option>
        </select>
        <button class="btnp" type="button" onclick="saveAccessControlSettings()">Save mode</button>
      </div>
      <div class="hint-micro mb8">Legacy Basic Auth remains backend-compatible for upgrades, but is intentionally not shown as a selectable mode here.</div>
      <div class="row-wrap mb10 oidc-only">
        <label class="flbl">SSO role assignment</label>
        <select class="finp" id="sso-role-source" style="min-width:220px" title="SurveyTrace-managed keeps role assignment in this UI. IdP-mapped derives role from group/claim mapping below.">
          <option value="surveytrace">Manage roles in SurveyTrace</option>
          <option value="idp">Map roles from IdP groups/claims</option>
        </select>
        <button class="tbtn" type="button" onclick="saveAccessControlSettings()">Save role source</button>
      </div>
      <div class="hint-micro mb10 oidc-only">Local accounts remain available for breakglass (if enabled), even when primary authentication uses OIDC.</div>

      <div class="flbl oidc-only">Breakglass local access</div>
      <div class="row-wrap mb12 oidc-only">
        <label class="stack8" title="Recommended: keep enabled so at least one local emergency account can sign in if your IdP is unavailable."><input type="checkbox" id="breakglass-enabled" class="accent-radio"> <span class="text-secondary">Allow emergency local login during SSO outage</span></label>
        <input class="finp" id="breakglass-username" placeholder="Emergency username (default admin)" style="min-width:220px" title="This local username is allowed to sign in directly while in OIDC mode.">
        <button class="tbtn" type="button" onclick="saveAccessControlSettings()">Save breakglass</button>
      </div>
      <div class="flbl">Local users and roles</div>
      <div class="hint-micro mb6">Use this table to assign application roles. In SurveyTrace-managed mode, SSO users keep the role assigned here.</div>
      <div class="tbl-wrap mb8">
        <table class="tbl" id="auth-users-table">
          <thead><tr><th>User</th><th>Name</th><th>Email</th><th>Role</th><th>MFA</th><th>Disabled</th><th>Actions</th></tr></thead>
          <tbody id="auth-users-tbody"><tr><td colspan="7" class="loading">Loading…</td></tr></tbody>
        </table>
      </div>
      <div class="hint-micro mb8"><strong>Save</strong> updates fields. <strong>Password</strong> sets a temporary password.</div>
      <div class="row-wrap mb10">
        <input class="finp" id="new-auth-user" placeholder="new username">
        <select class="finp" id="new-auth-role">
          <option value="viewer">viewer</option>
          <option value="scan_editor">scan_editor</option>
          <option value="admin">admin</option>
        </select>
        <button class="btnp" type="button" onclick="createAuthUser()">Add user</button>
      </div>
      <div class="flbl">Live auth operations (non-historical)</div>
      <div class="hint-micro mb6">Operational view of current failed/locked sign-in state. This is not a permanent history.</div>
      <div class="tbl-wrap mb8">
        <table class="tbl">
          <thead><tr><th>User</th><th>Failed attempts</th><th>Last failed (UTC)</th><th>Locked until (UTC)</th><th>IP</th></tr></thead>
          <tbody id="auth-live-tbody"><tr><td colspan="5" class="loading">Loading…</td></tr></tbody>
        </table>
      </div>
      <div class="flbl">Historical user audit</div>
      <div class="hint-micro mb6">Persistent trail of sign-ins, account, and scan operator actions.</div>
      <div class="tbl-wrap">
        <table class="tbl">
          <thead><tr><th>When (UTC)</th><th>Action</th><th>Actor</th><th>Target</th><th>IP</th></tr></thead>
          <tbody id="auth-audit-tbody"><tr><td colspan="5" class="loading">Loading…</td></tr></tbody>
        </table>
      </div>
    </details>
    <details class="mb10">
      <summary class="flbl text-secondary">Advanced security and SSO settings</summary>
      <div class="flbl mt6">Password requirements</div>
      <div class="row-wrap mb8">
        <label class="flbl">Minimum length</label>
        <input class="finp" type="number" min="8" max="128" step="1" id="pp-min-len" style="width:110px">
      </div>
      <div class="row-wrap mb10">
        <label class="stack8"><input type="checkbox" id="pp-upper" class="accent-radio"> <span class="text-secondary">Require uppercase letter</span></label>
        <label class="stack8"><input type="checkbox" id="pp-lower" class="accent-radio"> <span class="text-secondary">Require lowercase letter</span></label>
        <label class="stack8"><input type="checkbox" id="pp-number" class="accent-radio"> <span class="text-secondary">Require number</span></label>
        <label class="stack8"><input type="checkbox" id="pp-symbol" class="accent-radio"> <span class="text-secondary">Require symbol</span></label>
      </div>
      <div class="row-wrap mb10">
        <label class="flbl">Password hashing</label>
        <select class="finp" id="pp-hash-algo" style="min-width:140px">
          <option value="argon2id">Argon2id (preferred)</option>
          <option value="bcrypt">bcrypt</option>
        </select>
        <label class="flbl">Max failed attempts</label>
        <input class="finp" type="number" min="3" max="20" step="1" id="pp-max-attempts" style="width:90px">
        <label class="flbl">Lockout minutes</label>
        <input class="finp" type="number" min="1" max="1440" step="1" id="pp-lockout-min" style="width:100px">
      </div>
      <div class="row-wrap mb12">
        <button class="tbtn" type="button" onclick="savePasswordPolicy()">Save policy</button>
      </div>

      <div class="flbl oidc-only">OIDC configuration</div>
      <div class="profile-grid mb10 oidc-only">
        <input class="finp" id="oidc-issuer-url" placeholder="Issuer URL (https://idp.example.com/realms/main)">
        <input class="finp" id="oidc-client-id" placeholder="Client ID">
        <input class="finp" id="oidc-client-secret" type="password" placeholder="Client secret">
        <input class="finp" id="oidc-redirect-uri" placeholder="Redirect URI (https://app.example.com/api/auth_oidc.php?callback=1)">
        <input class="finp" id="oidc-role-claim" placeholder="Role claim (e.g. groups)">
        <input class="finp" id="oidc-role-map" placeholder="Role map (e.g. sec-admin:admin,scan-ops:scan_editor,*:viewer)">
      </div>
      <div class="row-wrap mb12 oidc-only">
        <label class="stack8"><input type="checkbox" id="oidc-enabled" class="accent-radio"> <span class="text-secondary">Enable OIDC sign-in</span></label>
        <button class="tbtn" type="button" onclick="saveAccessControlSettings()">Save OIDC</button>
      </div>
    </details>
  </div>
</div>

<!-- ================================================================ SETTINGS -->
<div class="tab" id="t-settings">
  <div class="scgrid">
    <div>
      <div class="card">
        <div class="ct">Sign-in session</div>
        <div class="help-line mb10">
          Idle timeout for the PHP session cookie after you sign in (session auth) or after the first successful
          basic-auth request. Each API request while signed in resets the idle clock. Range 5 minutes to 7 days.
        </div>
        <label class="flbl">Session idle timeout (minutes)</label>
        <div class="row-wrap mt6">
          <input class="finp" type="number" id="st-session-timeout-min" min="5" max="10080" step="1" style="width:120px" value="480">
          <button class="btnp" type="button" onclick="saveSessionTimeout()">Save</button>
        </div>
        <label class="flbl mt10">Extra routed safe ports (comma-separated)</label>
        <div class="help-line mb6 text-dim">
          Added only to routed <code class="code-accent">fast_full_tcp</code> safe-port scans.
          Example: <code class="code-accent">10000,15672,11434</code>
        </div>
        <div class="row-wrap">
          <input class="finp" type="text" id="st-extra-safe-ports" style="min-width:280px;flex:1" placeholder="10000,15672,11434">
          <button class="tbtn" type="button" onclick="saveExtraSafePorts()">Save ports</button>
        </div>
      </div>
      <div class="card">
        <div class="ct">NVD &amp; offline fingerprint feeds</div>
        <p class="help-line mb10">
          One server job and one log per run in <code class="code-accent">data/feed_sync_result.json</code>. The sections that follow describe each feed; you can also run NVD, OUI, and WebFP in a single job at the bottom of this card.
        </p>

        <div class="flbl mt2">NVD (CVE / CPE correlation)</div>
        <div class="help-mono mb10">
          Last sync: <span id="nvd-sync-ts" class="text-strong">—</span>
        </div>
        <div class="help-line mb10 text-dim" style="font-size:12px">
          Maps CPE strings to CVE IDs for offline correlation. Refreshed weekly via cron; <code class="code-accent">sync_nvd.py</code> or use the button below.
        </div>
        <label class="flbl">NVD API key (optional)</label>
        <div class="help-line mb6 text-dim">
          Request a free key at
          <a href="https://nvd.nist.gov/developers/request-an-api-key" target="_blank" rel="noopener">nvd.nist.gov</a>
          for higher rate limits. Stored in the local database (never sent back to the browser).
          If <code class="code-accent">NVD_API_KEY</code> is set in the server environment, it overrides the saved key.
          To replace a saved key, remove it first, then paste the new one.
        </div>
        <div id="st-nvd-api-key-row-empty" class="row-wrap mb6 gap6">
          <input class="finp" type="password" id="st-nvd-api-key" style="min-width:260px;flex:1" autocomplete="new-password" placeholder="Paste NVD API key">
          <button class="btnp" type="button" id="btn-nvd-key-save" onclick="saveNvdApiKey()">Save key</button>
        </div>
        <div id="st-nvd-api-key-row-set" class="row-wrap mb6 gap6 hide">
          <span class="mono text-strong" id="st-nvd-api-key-masked" title="Key is stored; value is not shown">••••••••••••••••</span>
          <span class="text-dim" style="font-size:12px">NVD API key saved</span>
          <button class="tbtn" type="button" id="btn-nvd-key-remove" onclick="clearNvdApiKey()">Remove key</button>
        </div>
        <div class="hint-micro mb8" id="st-nvd-api-key-status"></div>
        <div class="row-wrap mt10">
          <button class="tbtn" id="btn-sync-nvd" onclick="runFeedSync('nvd')">Sync NVD now</button>
          <button class="tbtn" type="button" id="btn-cancel-feed-sync" onclick="requestFeedSyncCancel()" disabled>Cancel sync</button>
          <button class="tbtn" type="button" onclick="requestFeedSyncClearStuckState()">Reset sync lock</button>
        </div>
        <p class="help-line text-dim mt6" style="font-size:12px">The browser returns immediately. Incremental NVD often takes <strong>several minutes</strong> (10+ is normal for large NIST batches, or longer <strong>without an API key</strong>). <strong>Cancel</strong> stops after the current fetch. If you killed a process on the host and the UI is stuck, <strong>Reset sync lock</strong>. If the network drops, the job retries; run again when the link is back.</p>
        <div id="sync-status-nvd" class="sync-status"></div>

        <div class="flbl mt12">OUI &amp; WebFP (MAC vendors &amp; web fingerprints)</div>
        <div class="help-mono mb6">
          OUI last sync: <span id="oui-sync-ts" class="text-strong">—</span> ·
          prefixes: <span id="oui-sync-count" class="text-strong">0</span><br>
          WebFP last sync: <span id="webfp-sync-ts" class="text-strong">—</span> ·
          rules: <span id="webfp-sync-count" class="text-strong">0</span>
        </div>
        <div class="help-line mb10 text-dim" style="font-size:12px">
          IEEE OUI registries and Wappalyzer technologies (synced daily via cron). These two buttons do <strong>not</strong> run NVD; use <strong>Sync NVD now</strong> (above) or <strong>Sync all feeds</strong> (below) if you need CVE data refreshed too.
        </div>
        <div class="row-wrap">
          <button class="tbtn" id="btn-sync-oui" onclick="runFeedSync('oui')">Sync OUI now</button>
          <button class="tbtn" id="btn-sync-webfp" onclick="runFeedSync('webfp')">Sync WebFP now</button>
        </div>
        <div id="sync-status-fp" class="sync-status mt6"></div>

        <div class="flbl mt12">NVD + OUI + WebFP in one job</div>
        <div class="row-wrap">
          <button class="btnp" id="btn-sync-all" onclick="runFeedSync('all')">Sync all feeds</button>
        </div>
        <p class="help-line text-dim mt6" style="font-size:12px">Runs the CVE feed, then OUI, then WebFP in order (this is the full stack, not fingerprints only). Expect a long run—NVD alone is often many minutes. The sections <em>above</em> let you refresh each feed on its own.</p>

        <div class="row-wrap mt10">
          <button class="tbtn" type="button" onclick="openFeedSyncOutput()">View last feed sync log</button>
        </div>
        <p class="help-line text-dim mt6" style="font-size:12px">Shows the most recent run (whichever set of buttons you used). <strong>Sync all</strong> appends NVD, OUI, and WebFP sections in one file. The same log loads after a page reload.</p>
      </div>
    </div>
    <div>
      <div class="card">
        <div class="ct">About</div>
        <div class="help-mono">
          SurveyTrace v<?= htmlspecialchars(defined('ST_VERSION') ? ST_VERSION : '0.6.0', ENT_QUOTES, 'UTF-8') ?><br>
          PHP + SQLite + Python scanner daemon<br>
          <span class="text-dim">Data stored in data/surveytrace.db</span>
        </div>
      </div>
      <div class="card">
        <div class="ct">Asset categories</div>
        <table class="table-mini">
          <tr><td><span class="cat srv">srv</span></td><td>Server (Linux, Windows Server)</td></tr>
          <tr><td><span class="cat ws">ws</span></td><td>Workstation / desktop</td></tr>
          <tr><td><span class="cat net">net</span></td><td>Network gear (switch, router, firewall)</td></tr>
          <tr><td><span class="cat iot">iot</span></td><td>IoT device</td></tr>
          <tr><td><span class="cat ot">ot</span></td><td>OT / ICS (PLC, SCADA, HMI)</td></tr>
          <tr><td><span class="cat voi">voi</span></td><td>VoIP phone / PBX</td></tr>
          <tr><td><span class="cat prn">prn</span></td><td>Printer / MFP</td></tr>
          <tr><td><span class="cat hv">hv</span></td><td>Hypervisor (ESXi, Proxmox, Hyper-V)</td></tr>
        </table>
      </div>
    </div>
  </div>
</div>

</div><!-- .main -->
</div><!-- .shell -->

<div class="toast-wrap" id="toasts"></div>

<!-- Session login modal -->
<div id="login-bg" class="modal-bg z260">
  <div class="modal-card modal-w360">
    <div class="modal-title">Sign in</div>
    <div class="text-muted mb10" id="login-msg">
      Session authentication required.
    </div>
    <div id="login-local-fields">
      <label class="flbl">Username</label>
      <input class="finp w100 mb10" id="login-user" value="admin" autocomplete="username">
      <label class="flbl">Password</label>
      <input class="finp w100 mb10" id="login-pass" type="password" autocomplete="current-password">
      <div id="login-mfa-step" class="hide">
        <label class="flbl">Verification code</label>
        <input class="finp w100 mb12" id="login-verify-code" placeholder="Authenticator OTP or recovery code" autocomplete="one-time-code">
      </div>
    </div>
    <div id="login-oidc-fields" class="hide mb12">
      <div class="help-line mb10" id="login-sso-msg">Single sign-on is enabled for this deployment.</div>
      <button class="btnp w100 mb8" type="button" id="btn-login-sso" onclick="startSsoLogin()">Sign in with SSO</button>
      <button class="tbtn w100 hide" type="button" id="btn-breakglass-show" onclick="toggleBreakglassLogin(true)">Use emergency local sign-in</button>
      <div class="hint-micro mt6">Emergency local sign-in is for IdP outages only; day-to-day users should sign in through SSO.</div>
    </div>
    <div class="row-end">
      <button class="tbtn" onclick="closeLoginModal()">Close</button>
      <button class="btnp" id="btn-login" onclick="submitLogin()">Sign in</button>
    </div>
  </div>
</div>

<!-- Host detail panel -->
<div id="host-panel" class="host-panel">
  <div class="host-panel-head">
    <div class="host-panel-title" id="hp-title">Host detail</div>
    <button class="tbtn host-panel-close" onclick="closeHostPanel()">✕</button>
  </div>
  <div id="hp-body" class="host-panel-body"></div>
</div>
<div id="host-panel-bg" class="host-panel-backdrop" onclick="closeHostPanel()"></div>

<!-- Device detail panel (logical identity + linked addresses) -->
<div id="device-panel" class="host-panel device-panel">
  <div class="host-panel-head">
    <div class="host-panel-title" id="dp-title">Device</div>
    <button type="button" class="tbtn host-panel-close" onclick="closeDevicePanel()">✕</button>
  </div>
  <div id="dp-body" class="host-panel-body"></div>
</div>
<div id="device-panel-bg" class="host-panel-backdrop device-panel-backdrop" onclick="closeDevicePanel()"></div>

<!-- Feed sync output modal -->
<div id="fsync-bg" class="modal-bg z210">
  <div class="modal-card modal-feed">
    <div class="row-between mb10">
      <div class="modal-title section-title-reset" id="fsync-title">Last feed sync log</div>
      <button class="tbtn" onclick="closeFeedSyncOutput()">Close</button>
    </div>
    <pre id="fsync-out" class="fsync-pre">Loading last feed sync output…</pre>
  </div>
</div>

<!-- Confirm modal -->
<div id="confirm-bg" class="modal-bg z215">
  <div class="modal-card modal-confirm">
    <div id="confirm-title" class="modal-title mb8">Confirm action</div>
    <div id="confirm-msg" class="text-muted mb14" style="line-height:1.45;white-space:pre-wrap"></div>
    <div class="row-end">
      <button class="tbtn" id="confirm-cancel-btn" onclick="closeConfirmModal(false)">Cancel</button>
      <button class="btnp" id="confirm-ok-btn" onclick="closeConfirmModal(true)">Confirm</button>
    </div>
  </div>
</div>

<!-- Profile modal -->
<div id="profile-bg" class="modal-bg z220">
  <div class="modal-card modal-w440">
    <div class="modal-title">My profile</div>
    <div class="text-muted mb10">Manage your personal account settings.</div>
    <label class="flbl">Username</label>
    <input class="finp w100 mb8" id="profile-username" readonly>
    <div class="row-wrap mb8">
      <div class="grow">
        <label class="flbl">Role</label>
        <input class="finp w100" id="profile-role" readonly>
      </div>
      <div class="grow">
        <label class="flbl">Auth source</label>
        <input class="finp w100" id="profile-auth-source" readonly>
      </div>
    </div>
    <label class="flbl">Display name</label>
    <input class="finp w100 mb8" id="profile-display-name" placeholder="Optional">
    <label class="flbl">Email</label>
    <input class="finp w100 mb12" id="profile-email" type="email" placeholder="Optional">
    <div class="hint-micro mb10 hide" id="profile-idp-managed-note">
      Password and MFA are managed by your identity provider (OIDC) for this account.
    </div>
    <div class="row-wrap mb8">
      <button class="tbtn" type="button" onclick="saveMyProfile()">Save profile</button>
      <button class="tbtn" type="button" id="btn-profile-password" onclick="openPasswordChangeModal(false)">Change password</button>
      <button class="tbtn" type="button" id="btn-profile-mfa-generate" onclick="beginMfaSetup()">Set up MFA</button>
      <button class="tbtn" type="button" id="btn-profile-mfa-disable" onclick="openMfaDisableModal()">Turn off MFA</button>
    </div>
    <div id="mfa-setup-box" class="help-box hide">
      <div class="help-line mb6">Secret: <code class="code-accent" id="mfa-secret"></code></div>
      <div class="help-line mb8">Copy the setup link (or enter the secret manually), then type the 6-digit code to finish setup.</div>
      <div class="mb8">
        <img id="mfa-qr" src="" alt="MFA setup QR code" class="hide" style="width:160px;height:160px;border-radius:8px;border:1px solid var(--bd);padding:6px;background:#fff">
      </div>
      <div id="mfa-qr-status" class="hint-micro mb8"></div>
      <div class="row-wrap mb8">
        <button class="tbtn" type="button" id="mfa-copy-uri-btn">Copy setup URI</button>
      </div>
      <div class="row-wrap">
        <input class="finp" id="mfa-enable-otp" placeholder="123456" style="width:140px">
        <button class="btnp" type="button" onclick="confirmMfaEnable()">Enable MFA</button>
      </div>
      <div class="hint-micro mt6">Recovery codes are shown once. Save them in a secure place.</div>
      <div id="mfa-recovery-box" class="mt10 hide">
        <div class="help-line mb6"><strong>Recovery codes (save now)</strong></div>
        <textarea id="mfa-recovery-codes" class="finp w100" rows="6" readonly></textarea>
        <div class="row-wrap mt8">
          <button class="tbtn" type="button" onclick="copyMfaRecoveryCodes()">Copy codes</button>
          <button class="tbtn" type="button" onclick="downloadMfaRecoveryCodesTxt()">Download .txt</button>
          <button class="tbtn" type="button" onclick="printMfaRecoveryCodes()">Print / Save PDF</button>
        </div>
      </div>
    </div>
    <div class="row-end mt10">
      <button class="tbtn" type="button" onclick="closeProfileModal()">Close</button>
    </div>
  </div>
</div>

<!-- MFA disable modal -->
<div id="mfa-disable-bg" class="modal-bg z220">
  <div class="modal-card modal-w360">
    <div class="modal-title">Disable MFA</div>
    <div class="text-muted mb10">Enter your authenticator code or a single recovery code to turn off MFA.</div>
    <label class="flbl">Authenticator code</label>
    <input class="finp w100 mb8" id="mfa-disable-otp" placeholder="123456">
    <label class="flbl">Recovery code (optional)</label>
    <input class="finp w100 mb12" id="mfa-disable-recovery" placeholder="ABCD-1234">
    <div class="row-end">
      <button class="tbtn" type="button" onclick="closeMfaDisableModal()">Cancel</button>
      <button class="btnp" type="button" onclick="confirmDisableMfa()">Disable MFA</button>
    </div>
  </div>
</div>

<!-- Password change modal -->
<div id="pw-change-bg" class="modal-bg z220">
  <div class="modal-card modal-w360">
    <div class="modal-title">Change your password</div>
    <div class="text-muted mb10" id="pw-change-msg">Enter your current password, then choose a new one.</div>
    <label class="flbl">Current password</label>
    <input class="finp w100 mb8" id="pw-change-current" type="password" autocomplete="current-password">
    <label class="flbl">New password</label>
    <input class="finp w100 mb8" id="pw-change-new" type="password" autocomplete="new-password">
    <label class="flbl">Confirm new password</label>
    <input class="finp w100 mb12" id="pw-change-confirm" type="password" autocomplete="new-password">
    <div class="row-end">
      <button class="tbtn" type="button" onclick="closePasswordChangeModal()">Cancel</button>
      <button class="btnp" type="button" onclick="submitPasswordChange()">Save password</button>
    </div>
  </div>
</div>

<!-- Admin user password update modal -->
<div id="user-pw-bg" class="modal-bg z220">
  <div class="modal-card modal-w360">
    <div class="modal-title">Edit user + temporary password</div>
    <div class="text-muted mb10" id="user-pw-msg">Leave blank to keep the current password.</div>
    <label class="flbl">New temporary password (optional)</label>
    <input class="finp w100 mb8" id="user-pw-new" type="password" autocomplete="new-password" placeholder="Leave blank to keep current">
    <label class="flbl">Confirm temporary password</label>
    <input class="finp w100 mb12" id="user-pw-confirm" type="password" autocomplete="new-password" placeholder="Must match temporary password">
    <div class="row-end">
      <button class="tbtn" type="button" onclick="closeUserPasswordModal()">Cancel</button>
      <button class="btnp" type="button" onclick="submitAuthUserSave()">Save changes</button>
    </div>
  </div>
</div>

<!-- Enrichment source modal -->
<div id="esrc-bg" class="modal-bg z100">
  <div class="modal-card modal-w440">
    <div class="modal-title mb14">
      <span id="esrc-title">Add enrichment source</span>
    </div>
    <input type="hidden" id="esrc-id" value="0">
    <label class="flbl">Source type</label>
    <select class="finp w100 mb10" id="esrc-type" onchange="updateSourceFields()">
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
    <input class="finp w100 mb10" id="esrc-label" type="text" placeholder="e.g. Home UDM">
    <div id="esrc-fields"></div>
    <div class="tr2 mb14">
      <div><div class="tl">Enabled</div><div class="tsubl">Run this source during scans</div></div>
      <label class="tog"><input type="checkbox" id="esrc-enabled" checked><div class="trk"></div><div class="tth"></div></label>
    </div>
    <div id="esrc-test-result" class="help-mono mb10 hide"></div>
    <div class="row-end">
      <button class="tbtn" onclick="testSource()">Test</button>
      <button class="tbtn" onclick="closeSourceModal()">Cancel</button>
      <button class="btnp" onclick="saveSource()">Save</button>
    </div>
  </div>
</div>

<!-- Reclassify modal -->
<div id="modal-bg" class="modal-bg z100">
  <div class="modal-card modal-w380">
    <div class="modal-title">Edit asset — <span id="modal-ip" class="text-strong"></span></div>
    <input type="hidden" id="modal-asset-id">
    <label class="form-label">Hostname</label>
    <input class="finp w100 mb10" id="modal-hostname" type="text">
    <label class="form-label">Category</label>
    <select class="finp w100 mb10" id="modal-cat">
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
    <label class="form-label">Vendor override</label>
    <input class="finp w100 mb10" id="modal-vendor" type="text" placeholder="Leave blank to keep existing">
    <label class="form-label">Notes</label>
    <textarea class="finp w100 mb14" id="modal-notes" style="min-height:56px" placeholder="Optional notes about this asset"></textarea>
    <div class="row-end">
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
/** When > 0, assets list is limited to this logical device (from Devices tab). */
var assetDeviceFilter = 0;
var devicePage   = 1;
var vulnPage     = 1;
var activeJobId  = null;
var pollTimer    = null;
var logSinceId   = 0;
var autoscroll   = true;
var allLogRows   = [];
var dashTimer    = null;
var feedSyncLastOutput = 'Loading last feed sync output…';
var authMode = 'basic';
var loginRequired = false;
var loginNeedsMfaCode = false;
var csrfToken = '';
var currentUser = null;
var currentUserRole = 'admin';
var currentUserMfaEnabled = false;
var currentUserAuthSource = 'local';
var currentProfileDisplayName = '';
var currentProfileEmail = '';
var breakglassEnabled = true;
var breakglassUsername = 'admin';
var scanDetailReturnDeviceId = 0;
var confirmResolve = null;
var themeMediaQuery = null;
var themeMediaListener = null;
var execPreviousTab = null;
/** Which feed syncs are in flight (NVD / OUI / WebFP may run in parallel; "all" is exclusive). */
var feedSyncRunning = { nvd: false, oui: false, webfp: false, all: false };
/** If any OUI/WebFP/all job in the current fingerprint wave failed, set before the wave ends. */
var fpSyncHadError = false;

const FEED_SYNC_BTN_IDS = ['btn-sync-nvd', 'btn-sync-oui', 'btn-sync-webfp', 'btn-sync-all'];
const FEED_SYNC_BTN_LABELS = {
    'btn-sync-nvd': 'Sync NVD now',
    'btn-sync-oui': 'Sync OUI now',
    'btn-sync-webfp': 'Sync WebFP now',
    'btn-sync-all': 'Sync all feeds',
};

var feedSyncStartedAt = { nvd: 0, oui: 0, webfp: 0, all: 0 };
var feedSyncUiTimer = null;
var feedSyncStatePollTimer = null;
var execChartSelection = {};
var pendingMfaSecret = '';
var pendingMfaOtpUri = '';
var pendingMfaQrUrl = '';
var pendingRecoveryCodes = [];
var mustChangePasswordPending = false;
var pendingUserSave = null;

function stRoleCanManageScans() {
    return currentUserRole === 'scan_editor' || currentUserRole === 'admin';
}

function stRoleIsAdmin() {
    return currentUserRole === 'admin';
}

function applyRoleAwareUi() {
    const canScanManage = stRoleCanManageScans();
    const isAdmin = stRoleIsAdmin();
    const setHidden = (id, hidden) => {
        const el = document.getElementById(id);
        if (el) el.style.display = hidden ? 'none' : '';
    };
    setHidden('nscan', !canScanManage);
    setHidden('nsched', !canScanManage);
    setHidden('nenrich', !isAdmin);
    setHidden('nsettings', !isAdmin);
    setHidden('naccess', !isAdmin);

    const topNewScan = document.querySelector('button[onclick*="goTab(\'scan\')"]');
    if (topNewScan) topNewScan.style.display = canScanManage ? '' : 'none';
    const topSettings = document.querySelector('button[onclick*="goTab(\'settings\')"]');
    if (topSettings) topSettings.style.display = isAdmin ? '' : 'none';
    const topAccess = document.querySelector('button[onclick*="goTab(\'access\')"]');
    if (topAccess) topAccess.style.display = isAdmin ? '' : 'none';

    const disableByOnclick = (needle, disabled) => {
        document.querySelectorAll(`button[onclick*="${needle}"]`).forEach(btn => {
            btn.disabled = !!disabled;
            btn.classList.toggle('is-disabled', !!disabled);
        });
    };
    disableByOnclick('startScan(', !canScanManage);
    disableByOnclick('rerunScanJob(', !canScanManage);
    disableByOnclick('deleteScanJob(', !canScanManage);
    disableByOnclick('openSchedModal(', !canScanManage);
    disableByOnclick('saveSchedule(', !canScanManage);
    disableByOnclick('runSchedNow(', !canScanManage);
    disableByOnclick('deleteSchedule(', !canScanManage);
    disableByOnclick('toggleSchedule(', !canScanManage);
    disableByOnclick('pauseSchedule(', !canScanManage);
    disableByOnclick('resumeSchedule(', !canScanManage);
    disableByOnclick('saveReclassify(', !canScanManage);
    disableByOnclick('resolveFinding(', !canScanManage);
    disableByOnclick('saveAccessControlSettings(', !isAdmin);
    disableByOnclick('savePasswordPolicy(', !isAdmin);
    disableByOnclick('createAuthUser(', !isAdmin);
    disableByOnclick('saveAuthUser(', !isAdmin);
    disableByOnclick('deleteAuthUser(', !isAdmin);
    disableByOnclick('resetUserMfa(', !isAdmin);
    disableByOnclick('runFeedSync(', !isAdmin);
    disableByOnclick('requestFeedSyncCancel(', !isAdmin);
    disableByOnclick('requestFeedSyncClearStuckState(', !isAdmin);
    disableByOnclick('openAddSource(', !isAdmin);
    disableByOnclick('saveSource(', !isAdmin);
    disableByOnclick('deleteSource(', !isAdmin);
}

function updateAccessControlModeVisibility() {
    const mode = document.getElementById('st-auth-mode')?.value || 'session';
    const showOidc = mode === 'oidc';
    document.querySelectorAll('.oidc-only').forEach(el => {
        el.classList.toggle('hide', !showOidc);
    });
}

function updateMfaActionButtons() {
    const isLocal = currentUserAuthSource === 'local';
    const genBtn = document.getElementById('btn-profile-mfa-generate');
    const disBtn = document.getElementById('btn-profile-mfa-disable');
    const pwBtn = document.getElementById('btn-profile-password');
    const idpNote = document.getElementById('profile-idp-managed-note');
    if (genBtn) genBtn.classList.toggle('hide', !isLocal || currentUserMfaEnabled);
    if (disBtn) disBtn.classList.toggle('hide', !isLocal || !currentUserMfaEnabled);
    if (pwBtn) pwBtn.classList.toggle('hide', !isLocal);
    if (idpNote) idpNote.classList.toggle('hide', isLocal);
}

function openProfileModal() {
    const bg = document.getElementById('profile-bg');
    if (!bg) return;
    const username = document.getElementById('profile-username');
    const role = document.getElementById('profile-role');
    const authSource = document.getElementById('profile-auth-source');
    const displayName = document.getElementById('profile-display-name');
    const email = document.getElementById('profile-email');
    if (username) username.value = currentUser?.username || '';
    if (role) role.value = currentUserRole || '';
    if (authSource) authSource.value = currentUserAuthSource || '';
    if (displayName) displayName.value = currentProfileDisplayName || '';
    if (email) email.value = currentProfileEmail || '';
    updateMfaActionButtons();
    bg.style.display = 'flex';
}

function closeProfileModal() {
    const bg = document.getElementById('profile-bg');
    if (bg) bg.style.display = 'none';
}

async function saveMyProfile() {
    const body = {
        display_name: (document.getElementById('profile-display-name')?.value || '').trim(),
        email: (document.getElementById('profile-email')?.value || '').trim(),
    };
    const r = await apiPost('/api/auth.php?profile=1', body);
    if (r && r.ok) {
        currentProfileDisplayName = r.display_name || '';
        currentProfileEmail = r.email || '';
        toast('Profile updated', 'ok');
    } else {
        toast((r && r.error) ? r.error : 'Profile update failed', 'err');
    }
}

function fmtFeedElapsed(ms) {
    if (ms < 0) ms = 0;
    const sec = Math.floor(ms / 1000);
    if (sec < 60) return 'elapsed ' + sec + 's';
    const m = Math.floor(sec / 60);
    const s = sec % 60;
    return 'elapsed ' + m + 'm ' + s + 's';
}

function buildFeedSyncRunningFooter() {
    if (!feedSyncRunning.nvd && !feedSyncRunning.oui && !feedSyncRunning.webfp && !feedSyncRunning.all) return '';
    const lines = [];
    lines.push('────────────────────────────────────────');
    lines.push('SERVER SYNC IN PROGRESS');
    lines.push('Script log output is appended above when each Python step finishes (stdout is not streamed live).');
    lines.push('The browser usually got an immediate HTTP response; work continues on the server.');
    lines.push('');
    if (feedSyncRunning.all && feedSyncStartedAt.all) {
        lines.push('Full feed sync (NVD + OUI + WebFP): ' + fmtFeedElapsed(Date.now() - feedSyncStartedAt.all));
    } else {
        if (feedSyncRunning.nvd && feedSyncStartedAt.nvd) {
            lines.push('NVD (CVE / CPE correlation): ' + fmtFeedElapsed(Date.now() - feedSyncStartedAt.nvd));
        }
        if (feedSyncRunning.oui && feedSyncStartedAt.oui) {
            lines.push('OUI (MAC vendor prefixes): ' + fmtFeedElapsed(Date.now() - feedSyncStartedAt.oui));
        }
        if (feedSyncRunning.webfp && feedSyncStartedAt.webfp) {
            lines.push('WebFP (fingerprints): ' + fmtFeedElapsed(Date.now() - feedSyncStartedAt.webfp));
        }
    }
    lines.push('');
    lines.push('Live tick · ' + new Date().toLocaleTimeString());
    return lines.join('\n');
}

function renderFeedSyncOutputPanel() {
    const out = document.getElementById('fsync-out');
    if (!out) return;
    const base = feedSyncLastOutput || 'No sync output yet.';
    const foot = buildFeedSyncRunningFooter();
    out.textContent = foot ? (base + '\n\n' + foot) : base;
}

function tickFeedSyncStatusLines() {
    const nvdEl = document.getElementById('sync-status-nvd');
    if (nvdEl && (feedSyncRunning.nvd || feedSyncRunning.all)) {
        nvdEl.className = 'sync-status run';
        const t0 = feedSyncRunning.all ? feedSyncStartedAt.all : feedSyncStartedAt.nvd;
        if (t0) {
            const head = feedSyncRunning.all ? 'Full feed sync (includes NVD)' : 'NVD CVE feed sync';
            nvdEl.textContent = head + ' — ' + fmtFeedElapsed(Date.now() - t0);
        }
    }
    const fpEl = document.getElementById('sync-status-fp');
    if (fpEl && (feedSyncRunning.oui || feedSyncRunning.webfp || feedSyncRunning.all)) {
        fpEl.className = 'sync-status run';
        if (feedSyncRunning.all && feedSyncStartedAt.all) {
            fpEl.textContent = 'OUI + WebFP (full sync) — ' + fmtFeedElapsed(Date.now() - feedSyncStartedAt.all);
        } else {
            const bits = [];
            if (feedSyncRunning.oui && feedSyncStartedAt.oui) {
                bits.push('OUI — ' + fmtFeedElapsed(Date.now() - feedSyncStartedAt.oui));
            }
            if (feedSyncRunning.webfp && feedSyncStartedAt.webfp) {
                bits.push('WebFP — ' + fmtFeedElapsed(Date.now() - feedSyncStartedAt.webfp));
            }
            fpEl.textContent = bits.join('  ·  ');
        }
    }
}

function ensureFeedSyncUiTimer() {
    if (feedSyncUiTimer !== null) return;
    feedSyncUiTimer = setInterval(() => {
        tickFeedSyncStatusLines();
        const any = feedSyncRunning.nvd || feedSyncRunning.oui || feedSyncRunning.webfp || feedSyncRunning.all;
        if (any) {
            // Keep <pre> fresh every second while a job runs (even if modal is closed), so
            // elapsed + footer text stay fresh when the user opens the feed sync log modal.
            renderFeedSyncOutputPanel();
        }
    }, 1000);
    tickFeedSyncStatusLines();
    const any0 = feedSyncRunning.nvd || feedSyncRunning.oui || feedSyncRunning.webfp || feedSyncRunning.all;
    if (any0) renderFeedSyncOutputPanel();
}

function stopFeedSyncUiTimerIfIdle() {
    const any = feedSyncRunning.nvd || feedSyncRunning.oui || feedSyncRunning.webfp || feedSyncRunning.all;
    if (any) return;
    if (feedSyncUiTimer !== null) {
        clearInterval(feedSyncUiTimer);
        feedSyncUiTimer = null;
    }
    renderFeedSyncOutputPanel();
}

function stopFeedSyncStatePolling() {
    if (feedSyncStatePollTimer !== null) {
        clearInterval(feedSyncStatePollTimer);
        feedSyncStatePollTimer = null;
    }
}

async function fetchFeedSyncServerState() {
    const r = await api('/api/feeds.php?status=1', { quiet: true });
    if (!r || !r.ok) {
        return { running: false, target: '', started_at: 0, last_feed_sync: null };
    }
    const fs = r.feed_sync && typeof r.feed_sync === 'object' ? r.feed_sync : { running: false };
    const startedAt = parseInt(fs.started_at, 10) || 0;
    const last = r.last_feed_sync && typeof r.last_feed_sync === 'object' ? r.last_feed_sync : null;
    let running = !!fs.running;
    // If the state file is stale but feed_sync_result.json was already written for this
    // run, treat as done (matches server-side self-heal in st_feed_sync_state_read).
    if (running && last && startedAt > 0) {
        const fin = parseInt(last.finished_at, 10) || 0;
        const st = String(fs.target || '').toLowerCase();
        const lt = String(last.target || '').toLowerCase();
        if (fin >= startedAt && st !== '' && st === lt) {
            running = false;
        }
    }
    return {
        running,
        target: String(fs.target || ''),
        started_at: startedAt,
        last_feed_sync: last,
    };
}

async function hydrateFeedSyncFromServer() {
    const fs = await fetchFeedSyncServerState();
    if (!fs) return;
    const anyClient = feedSyncRunning.nvd || feedSyncRunning.oui || feedSyncRunning.webfp || feedSyncRunning.all;
    // Server has no lock — drop stale “Syncing…” / elapsed timer (e.g. finished while
    // another tab was open, or loadDashboard refreshed Last sync before poll ran).
    if (!fs.running) {
        if (anyClient) {
            resetFeedSyncClientAfterServerClear();
        }
        return;
    }
    const tgt = String(fs.target || '').toLowerCase();
    if (!['nvd', 'oui', 'webfp', 'all'].includes(tgt)) return;
    const startedSec = parseInt(fs.started_at, 10) || 0;
    const startedMs = startedSec > 0 ? startedSec * 1000 : Date.now();
    feedSyncRunning = { nvd: false, oui: false, webfp: false, all: false };
    feedSyncStartedAt = { nvd: 0, oui: 0, webfp: 0, all: 0 };
    if (tgt === 'all') {
        feedSyncRunning.all = true;
        feedSyncStartedAt.all = startedMs;
    } else {
        feedSyncRunning[tgt] = true;
        feedSyncStartedAt[tgt] = startedMs;
    }
    feedSyncLastOutput = `[client] ${new Date().toISOString()} — reconnected: a ${tgt} feed sync is still running on the server (e.g. after reload).\nScript output will appear when the job finishes.`;
    ensureFeedSyncUiTimer();
    refreshFeedSyncButtons();
    tickFeedSyncStatusLines();
    renderFeedSyncOutputPanel();
    startFeedSyncStatePolling();
}

function formatFeedSyncResultBlock(target, payload) {
    if (!payload || typeof payload !== 'object') return '';
    const lines = [];
    lines.push(`target=${target} ok=${!!payload.ok}${payload.cancelled ? ' cancelled=1' : ''}`);
    if (payload.cancelled) {
        lines.push('(stopped by user — partial data may have been written)');
    }
    for (const res of (payload.results || [])) {
        lines.push(`\n=== ${res.script} | ok=${!!res.ok} exit=${res.exit_code} ===`);
        lines.push((res.output || '').trim() || '(no output)');
    }
    if (payload.error) {
        lines.push('\n=== error ===');
        lines.push(String(payload.error));
    }
    return lines.join('\n');
}

/**
 * Restores the output panel from feed_sync_result.json (GET feeds?status=1) after reload
 * or when opening Settings. In-memory text alone is lost on refresh.
 */
async function hydrateFeedSyncLastOutputFromServer() {
    const s = await fetchFeedSyncServerState();
    if (!s) {
        feedSyncLastOutput = 'Could not load feed sync status. Try again.';
        renderFeedSyncOutputPanel();
        return;
    }
    const last = s.last_feed_sync;
    const reconn = typeof feedSyncLastOutput === 'string' && feedSyncLastOutput.indexOf('reconnected:') !== -1;
    if (last && typeof last === 'object') {
        const t = String(last.target || 'all');
        const block = formatFeedSyncResultBlock(t, last);
        const fin = parseInt(last.finished_at, 10) || 0;
        const ts = fin > 0 ? (new Date(fin * 1000).toISOString().replace('T', ' ').replace(/\.\d{3}Z$/, ' UTC')) : 'unknown time';
        const head = 'Last feed sync on server (finished ' + ts + ')';
        if (s.running && reconn) {
            feedSyncLastOutput = head + '\n' + block + '\n\n' + feedSyncLastOutput;
        } else {
            feedSyncLastOutput = head + '\n' + block;
        }
    } else if (s.running && reconn) {
        // No saved result file yet; keep reconnected line from hydrate
    } else {
        feedSyncLastOutput = 'No saved feed sync log on the server yet. When a run finishes, it is stored server-side; open this panel after a sync to see it, including after you reload the page.';
    }
    renderFeedSyncOutputPanel();
}

/** When client thinks a sync is in progress but feeds.php says otherwise, clear UI. */
async function reconcileFeedSyncClientIfServerIdle() {
    const any = feedSyncRunning.nvd || feedSyncRunning.oui || feedSyncRunning.webfp || feedSyncRunning.all;
    if (!any) return;
    const fs = await fetchFeedSyncServerState();
    if (!fs || fs.running) return;
    resetFeedSyncClientAfterServerClear();
}

function appendFeedSyncResultToOutput(target, payload) {
    const block = formatFeedSyncResultBlock(target, payload);
    feedSyncLastOutput = (feedSyncLastOutput ? feedSyncLastOutput + '\n\n' : '') + block;
}

function startFeedSyncStatePolling() {
    if (feedSyncStatePollTimer !== null) return;
    const pollTick = async () => {
        const fs = await fetchFeedSyncServerState();
        if (fs && fs.running) return;
        stopFeedSyncStatePolling();
        const was = feedSyncRunning.nvd || feedSyncRunning.oui || feedSyncRunning.webfp || feedSyncRunning.all;
        if (!was) return;

        let doneTarget = 'all';
        if (feedSyncRunning.all) doneTarget = 'all';
        else if (feedSyncRunning.nvd) doneTarget = 'nvd';
        else if (feedSyncRunning.oui) doneTarget = 'oui';
        else if (feedSyncRunning.webfp) doneTarget = 'webfp';
        if (fs.last_feed_sync && fs.last_feed_sync.target) {
            doneTarget = String(fs.last_feed_sync.target);
        }

        feedSyncRunning = { nvd: false, oui: false, webfp: false, all: false };
        feedSyncStartedAt = { nvd: 0, oui: 0, webfp: 0, all: 0 };
        stopFeedSyncUiTimerIfIdle();
        refreshFeedSyncButtons();

        const last = fs.last_feed_sync;
        if (last) {
            appendFeedSyncResultToOutput(doneTarget, last);
            if (!last.ok && !last.cancelled && feedSyncTouchesFp(doneTarget)) {
                fpSyncHadError = true;
            }
            if (last.cancelled) {
                toast('Feed sync cancelled.', 'ok');
                refreshNvdStatusLineAfterEnd(doneTarget, null, 'Cancelled (partial run).');
                refreshFpStatusLineAfterEnd(doneTarget, null, 'Cancelled (partial run).');
                openFeedSyncOutput();
            } else if (!last.ok) {
                const msg = (last.results && last.results.find(x => !x.ok)?.output) || last.error || 'Sync failed';
                toast(String(msg).slice(0, 120), 'err');
                refreshNvdStatusLineAfterEnd(doneTarget, 'Sync failed. See output for details.', null);
                refreshFpStatusLineAfterEnd(doneTarget, 'Sync failed. See output for details.', null);
                openFeedSyncOutput();
            } else {
                refreshNvdStatusLineAfterEnd(doneTarget, null, 'Sync complete.');
                refreshFpStatusLineAfterEnd(doneTarget, null, 'Sync complete.');
                const names = (last.results || []).map(x => String(x.script || '').replace('.py', '')).filter(Boolean).join(', ');
                toast(names ? ('Feed sync complete: ' + names) : 'Feed sync complete.', 'ok');
                openFeedSyncOutput();
            }
        } else {
            const nvdEl = document.getElementById('sync-status-nvd');
            const fpEl = document.getElementById('sync-status-fp');
            if (nvdEl) { nvdEl.className = 'sync-status'; nvdEl.textContent = ''; }
            if (fpEl) { fpEl.className = 'sync-status'; fpEl.textContent = ''; }
            toast('Feed sync finished on the server.', 'ok');
        }

        await loadDashboard();
    };
    feedSyncStatePollTimer = setInterval(() => { void pollTick(); }, 4000);
    void pollTick();
}

// ==========================================================================
// Nav
// ==========================================================================
function goTab(name) {
    if (name === 'access' && !stRoleIsAdmin()) {
        toast('Access control is available to admin users only.', 'err');
        name = 'dash';
    }
    if (name === 'settings' && !stRoleIsAdmin()) {
        toast('Settings are available to admin users only.', 'err');
        name = 'dash';
    }
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('on'));
    document.getElementById('t-' + name).classList.add('on');
    currentTab = name;
    try { sessionStorage.setItem('st_tab', name); } catch(e) {}
    if (name === 'dash')     loadDashboard();
    if (name === 'assets')   loadAssets(1);
    if (name === 'devices')  loadDevices(1);
    if (name === 'vulns')    loadFindings(1);
    if (name === 'logs')     loadLog();
    if (name === 'scan')     loadScanStatus();
    if (name === 'scanhist') loadScanStatus();
    if (name === 'enrich')   loadEnrichment();
    if (name === 'sched')    loadSchedules();
    if (name === 'health')   loadHealth();
    if (name === 'access') {
        loadUiSettings();
        loadAuthUsers();
    }
    if (name === 'settings') {
        loadEnrichment(); // NVD sync status on settings tab
        loadUiSettings();
        loadDashboard();
        void (async () => {
            await hydrateFeedSyncFromServer();
            await hydrateFeedSyncLastOutputFromServer();
        })();
    }
}

function hiNav(id) {
    document.querySelectorAll('.ni').forEach(n => n.classList.remove('on'));
    document.getElementById(id).classList.add('on');
}

// ==========================================================================
// Fetch helper
// ==========================================================================
async function api(url, opts) {
    const quiet = !!(opts && opts.quiet);
    try {
        const r = await fetch(url, {credentials: 'same-origin'});
        if (!r.ok) {
            if (r.status === 401) {
                handleAuthRequired();
            } else if (!quiet) {
                toast('API request failed: HTTP ' + r.status, 'err');
            }
            throw new Error('HTTP ' + r.status);
        }
        return await r.json();
    } catch (e) {
        console.error('API error', url, e);
        return null;
    }
}

async function apiPost(url, body) {
    try {
        const headers = {'Content-Type': 'application/json'};
        if (csrfToken) headers['X-CSRF-Token'] = csrfToken;
        const r = await fetch(url, {
            method: 'POST',
            headers: headers,
            body: JSON.stringify(body),
            credentials: 'same-origin'
        });
        const txt = await r.text();
        let data = null;
        if (txt && txt.trim()) {
            try {
                data = JSON.parse(txt);
            } catch (e) {
                console.error('POST non-JSON', url, e, txt.slice(0, 800));
                const snippet = txt.replace(/\s+/g, ' ').trim().slice(0, 280);
                if (!r.ok) {
                    toast(
                        snippet
                            ? ('Request failed: HTTP ' + r.status + ' — ' + snippet)
                            : ('Request failed: HTTP ' + r.status),
                        'err'
                    );
                } else {
                    toast('Server returned non-JSON (often a PHP warning before the response)', 'err');
                }
                return {
                    ok: false,
                    error: 'Non-JSON body (HTTP ' + r.status + '): ' + snippet,
                    _notJson: true,
                };
            }
        }
        if (!r.ok) {
            if (r.status === 401) {
                // Login step-up (MFA required) intentionally uses 401 with JSON payload.
                if (data && typeof data === 'object' && data.mfa_required) {
                    return data;
                }
                handleAuthRequired();
                return null;
            }
            if (data && typeof data === 'object') {
                return data;
            }
            const hint = (txt && txt.trim())
                ? txt.replace(/\s+/g, ' ').trim().slice(0, 220)
                : '';
            toast(
                hint
                    ? ('Request failed: HTTP ' + r.status + ' — ' + hint)
                    : ('Request failed: HTTP ' + r.status + ' (empty body — check PHP / nginx error log)'),
                'err'
            );
            return { ok: false, error: 'HTTP ' + r.status + (hint ? ': ' + hint : ''), _httpError: true };
        }
        if (data === null || typeof data !== 'object') {
            toast('Empty response from server', 'err');
            return { ok: false, error: 'Empty response body', _emptyBody: true };
        }
        return data;
    } catch (e) {
        console.error('POST error', url, e);
        toast('Network error: ' + (e.message || String(e)), 'err');
        return null;
    }
}

function handleAuthRequired() {
    if (authMode === 'session' || authMode === 'oidc') {
        loginRequired = true;
        openLoginModal();
        toast(authMode === 'session' ? 'Session expired. Please sign in again.' : 'Session expired. Sign in with SSO again.', 'err');
    } else {
        toast('Authentication required. Refresh to re-authenticate browser credentials.', 'err');
    }
}

function openLoginModal(msg) {
    const bg = document.getElementById('login-bg');
    if (!bg) return;
    const m = document.getElementById('login-msg');
    if (m && msg) m.textContent = msg;
    loginNeedsMfaCode = false;
    const vEl = document.getElementById('login-verify-code');
    if (vEl) vEl.value = '';
    updateLoginModeUI();
    bg.style.display = 'flex';
    const p = document.getElementById('login-pass');
    if (p) p.focus();
}

function updateLoginModeUI() {
    const local = document.getElementById('login-local-fields');
    const oidc = document.getElementById('login-oidc-fields');
    const btn = document.getElementById('btn-login');
    const mfaStep = document.getElementById('login-mfa-step');
    const ssoMsg = document.getElementById('login-sso-msg');
    const ssoBtn = document.getElementById('btn-login-sso');
    const bgBtn = document.getElementById('btn-breakglass-show');
    const isSso = authMode === 'oidc';
    if (local) local.classList.toggle('hide', isSso);
    if (oidc) oidc.classList.toggle('hide', !isSso);
    if (btn) btn.classList.toggle('hide', isSso);
    if (mfaStep) mfaStep.classList.toggle('hide', !loginNeedsMfaCode || isSso);
    if (ssoMsg) ssoMsg.textContent = 'OIDC single sign-on is enabled for this deployment.';
    if (ssoBtn) ssoBtn.textContent = 'Sign in with OIDC';
    if (bgBtn) bgBtn.classList.toggle('hide', !isSso || !breakglassEnabled);
}

function startSsoLogin() {
    window.location.href = '/api/auth_oidc.php?start=1';
}

function toggleBreakglassLogin(show) {
    const local = document.getElementById('login-local-fields');
    const oidc = document.getElementById('login-oidc-fields');
    const btn = document.getElementById('btn-login');
    const bgBtn = document.getElementById('btn-breakglass-show');
    if (!local || !oidc || !btn || !bgBtn) return;
    if (show) {
        local.classList.remove('hide');
        btn.classList.remove('hide');
        bgBtn.textContent = 'Use SSO sign-in instead';
        bgBtn.onclick = () => toggleBreakglassLogin(false);
        const userInput = document.getElementById('login-user');
        if (userInput && breakglassUsername) userInput.value = breakglassUsername;
    } else {
        local.classList.add('hide');
        btn.classList.add('hide');
        bgBtn.textContent = 'Use emergency local sign-in';
        bgBtn.onclick = () => toggleBreakglassLogin(true);
    }
}

function closeLoginModal() {
    const bg = document.getElementById('login-bg');
    if (bg) bg.style.display = 'none';
}

async function submitLogin() {
    const s = await api('/api/auth.php?status=1', { quiet: true });
    if (s && s.csrf_token) csrfToken = s.csrf_token;
    const u = (document.getElementById('login-user')?.value || '').trim();
    const p = document.getElementById('login-pass')?.value || '';
    const verifyCode = (document.getElementById('login-verify-code')?.value || '').trim();
    if (!u || !p) {
        toast('Enter username and password', 'err');
        return;
    }
    const btn = document.getElementById('btn-login');
    if (btn) btn.disabled = true;
    const r = await apiPost('/api/auth.php?login=1', {
        username: u,
        password: p,
        otp: verifyCode,
        recovery_code: verifyCode
    });
    if (btn) btn.disabled = false;
    if (r && r.ok) {
        loginRequired = false;
        loginNeedsMfaCode = false;
        closeLoginModal();
        const pass = document.getElementById('login-pass');
        if (pass) pass.value = '';
        const vEl = document.getElementById('login-verify-code');
        if (vEl) vEl.value = '';
        toast('Signed in', 'ok');
        await initAuthMode();
        loadDashboard();
        if (currentTab === 'assets') loadAssets(assetPage || 1);
        if (currentTab === 'vulns') loadFindings(vulnPage || 1);
        if (currentTab === 'logs') loadLog();
        if (currentTab === 'scan' || currentTab === 'scanhist') loadScanStatus();
        if (currentTab === 'sched') loadSchedules();
        if (currentTab === 'enrich' || currentTab === 'settings') loadEnrichment();
        if (currentTab === 'health') loadHealth();
    } else {
        if (r && r.mfa_required) {
            loginNeedsMfaCode = true;
            updateLoginModeUI();
            toast('Enter your authenticator code or recovery code', 'ok');
            document.getElementById('login-verify-code')?.focus();
            return;
        }
        toast((r && r.error) ? r.error : 'Sign-in failed', 'err');
    }
}

async function logoutSession() {
    const r = await apiPost('/api/logout.php', {});
    if (r && r.ok) {
        loginRequired = true;
        if (authMode === 'session') {
            openLoginModal('Signed out. Sign in to continue.');
        } else {
            window.location.reload();
        }
    } else {
        toast('Sign-out failed. Try refreshing the page.', 'err');
    }
}

// ==========================================================================
// Dashboard
// ==========================================================================
async function loadDashboard() {
    const trendSel = document.getElementById('exec-trend-range');
    const trendDays = trendSel ? Number(trendSel.value || 14) : 14;
    const d = await api('/api/dashboard.php?trend_days=' + encodeURIComponent(trendDays));
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
            <td class="mono click-ip" onclick="openHostPanel(${a.id},'${esc(a.ip)}')" title="View host detail">${esc(a.ip)}</td>
            <td class="mono mono-sm">${a.device_id != null && a.device_id !== '' ? `<span class="click-ip" onclick="openDevicePanel(${a.device_id})" title="Device overview">${esc(String(a.device_id))}</span>` : '—'}</td>
            <td class="text-primary">${esc(a.hostname||'—')}</td>
            <td><span class="cat ${esc(a.category)}">${esc(a.category)}</span></td>
            <td class="text-primary" style="font-size:12px">${esc(a.vendor||'—')}</td>
            <td class="mono mono-sm">${esc(a.top_cve||'—')}</td>
            <td><span class="sev ${sevClass(a.top_cvss)}">${a.top_cvss||'—'}</span></td>
            <td class="mono">${a.finding_count}</td>
          </tr>`).join('')
        : '<tr><td colspan="8" class="loading">No vulnerable assets found</td></tr>';

    // Activity feed
    const act = d.activity || [];
    document.getElementById('dash-feed').innerHTML = act.length
        ? act.map(e => feedRow(e)).join('')
        : '<div class="empty-feed">No activity yet</div>';

    renderExecutiveDashboard(d.executive || {}, d.top_vulnerable || []);

    // Check for active scan and update status pill
    updateStatusPill(d.last_scan);

    // Feed sync may have finished without a poll tick (tab switch, or slow 4s interval).
    void reconcileFeedSyncClientIfServerIdle();
}

function renderExecBars(targetId, values, labels, opts = {}) {
    const el = document.getElementById(targetId);
    if (!el) return;
    const safeVals = Array.isArray(values) ? values.map(v => Number(v) || 0) : [];
    if (!safeVals.length) {
        el.innerHTML = '<div class="text-dim">No data yet</div>';
        return;
    }
    const max = Math.max(1, ...safeVals);
    const last = safeVals[safeVals.length - 1] || 0;
    const total = safeVals.reduce((a, b) => a + b, 0);
    const tip = opts.tip || '';
    el.innerHTML = `
      <div class="exec-bars-wrap">
        ${safeVals.map((v, i) => `<div class="exec-bar-col" title="${esc((labels?.[i] || '') + ': ' + v + (tip ? ' ' + tip : ''))}">
          <div class="exec-bar" style="height:${Math.max(6, Math.round((v / max) * 84))}px"></div>
        </div>`).join('')}
      </div>
      <div class="exec-bars-meta">
        <span>Total: <strong>${total}</strong></span>
        <span>Latest: <strong>${last}</strong></span>
      </div>
    `;
}

function renderExecLineChart(targetId, series, labels) {
    const el = document.getElementById(targetId);
    if (!el) return;
    const lines = Array.isArray(series) ? series.filter(s => Array.isArray(s.values) && s.values.length) : [];
    if (!lines.length) {
        el.innerHTML = '<div class="text-dim">No trend data yet</div>';
        return;
    }
    const count = Math.max(...lines.map(s => s.values.length));
    const allVals = lines.flatMap(s => s.values.map(v => Number(v) || 0));
    const vmax = Math.max(1, ...allVals);
    const w = 640, h = 160, px = 28, py = 14;
    const x = idx => count <= 1 ? px : px + (idx * ((w - (px * 2)) / (count - 1)));
    const y = val => h - py - (((Number(val) || 0) / vmax) * (h - (py * 2)));
    const mkPath = vals => vals.map((v, i) => `${i === 0 ? 'M' : 'L'}${x(i).toFixed(2)},${y(v).toFixed(2)}`).join(' ');
    const latest = lines.map(s => `${s.name}: ${s.values[s.values.length - 1] || 0}`).join(' | ');

    el.innerHTML = `
      <div class="exec-chart-focus" tabindex="0" role="group" aria-label="Executive trend chart. Use left and right arrow keys to inspect daily values.">
      <svg viewBox="0 0 ${w} ${h}" class="exec-line-svg" role="img" aria-label="Executive trend chart">
        <line x1="${px}" y1="${h-py}" x2="${w-px}" y2="${h-py}" class="exec-grid-line"></line>
        <line x1="${px}" y1="${py}" x2="${px}" y2="${h-py}" class="exec-grid-line"></line>
        ${lines.map(s => `<path d="${mkPath(s.values)}" fill="none" stroke="${esc(s.color)}" stroke-width="2.6"></path>`).join('')}
        <line id="${esc(targetId)}-cursor" x1="${px}" y1="${py}" x2="${px}" y2="${h-py}" class="exec-cursor-line" style="display:none"></line>
      </svg>
      </div>
      <div class="exec-legend">${lines.map(s => `<span class="exec-legend-item"><i style="background:${esc(s.color)}"></i>${esc(s.name)}</span>`).join('')}</div>
      <div id="${esc(targetId)}-sel" class="exec-selected-chip">Selected: latest</div>
      <div id="${esc(targetId)}-tip" class="exec-fixed-tip">Hover chart for exact day values</div>
      <div class="exec-bars-meta">
        <span>Latest: <strong>${esc(latest)}</strong></span>
        <span>${esc((labels && labels.length) ? labels[0] : '')} to ${esc((labels && labels.length) ? labels[labels.length - 1] : '')}</span>
      </div>
    `;

    const focusWrap = el.querySelector('.exec-chart-focus');
    const svg = el.querySelector('svg');
    const cursor = el.querySelector(`#${CSS.escape(targetId)}-cursor`);
    const selectedChip = el.querySelector(`#${CSS.escape(targetId)}-sel`);
    const tip = el.querySelector(`#${CSS.escape(targetId)}-tip`);
    if (!svg || !cursor || !tip || !focusWrap || !selectedChip) return;
    const savedIdx = Object.prototype.hasOwnProperty.call(execChartSelection, targetId)
        ? Number(execChartSelection[targetId])
        : (count - 1);
    let activeIdx = Math.max(0, Math.min(count - 1, savedIdx));

    const setTooltipByIndex = idx => {
        const safeIdx = Math.max(0, Math.min(count - 1, idx));
        activeIdx = safeIdx;
        execChartSelection[targetId] = safeIdx;
        const vx = x(safeIdx);
        cursor.setAttribute('x1', String(vx));
        cursor.setAttribute('x2', String(vx));
        cursor.style.display = '';
        const day = labels?.[safeIdx] || `Day ${safeIdx + 1}`;
        const rows = lines.map(s => `<span class="exec-tip-item"><i style="background:${esc(s.color)}"></i>${esc(s.name)}: <strong>${Number(s.values[safeIdx] || 0)}</strong></span>`).join('');
        selectedChip.textContent = `Selected: ${day}`;
        tip.innerHTML = `<span class="exec-tip-day">${esc(day)}</span>${rows}`;
    };
    const setTooltipAt = clientX => {
        const r = svg.getBoundingClientRect();
        const xr = Math.max(0, Math.min(r.width, clientX - r.left));
        const idx = count <= 1 ? 0 : Math.max(0, Math.min(count - 1, Math.round((xr / r.width) * (count - 1))));
        setTooltipByIndex(idx);
    };

    svg.addEventListener('mousemove', ev => setTooltipAt(ev.clientX));
    svg.addEventListener('mouseenter', ev => setTooltipAt(ev.clientX));
    svg.addEventListener('mouseleave', () => {
        cursor.style.display = 'none';
        setTooltipByIndex(activeIdx);
    });
    focusWrap.addEventListener('focus', () => setTooltipByIndex(activeIdx));
    focusWrap.addEventListener('keydown', ev => {
        if (ev.key === 'ArrowLeft') {
            ev.preventDefault();
            setTooltipByIndex(activeIdx - 1);
        } else if (ev.key === 'ArrowRight') {
            ev.preventDefault();
            setTooltipByIndex(activeIdx + 1);
        } else if (ev.key === 'Home') {
            ev.preventDefault();
            setTooltipByIndex(0);
        } else if (ev.key === 'End') {
            ev.preventDefault();
            setTooltipByIndex(count - 1);
        }
    });
    // Restore last selected point after redraw/auto-refresh.
    setTooltipByIndex(activeIdx);
    cursor.style.display = 'none';
}

function renderExecutiveDashboard(exec, fallbackTopVuln) {
    const k = exec.kpis || {};
    document.getElementById('ex-assets').textContent = k.assets_total ?? 0;
    document.getElementById('ex-assets-new').textContent = `+${k.assets_new_7d ?? 0} added in last 7 days`;
    document.getElementById('ex-findings').textContent = k.open_findings ?? 0;
    document.getElementById('ex-findings-sev').textContent = `${k.critical_open ?? 0} critical, ${k.high_open ?? 0} high priority`;
    document.getElementById('ex-scans').textContent = k.scans_7d ?? 0;
    document.getElementById('ex-scans-fail').textContent = `${k.scan_fail_7d ?? 0} did not complete`;
    document.getElementById('ex-findings-new').textContent = k.findings_new_7d ?? 0;
    document.getElementById('ex-critical-open').textContent = k.critical_open ?? 0;
    document.getElementById('ex-high-open').textContent = k.high_open ?? 0;
    document.getElementById('ex-comp-rate').textContent = `${k.completion_rate_14d ?? 0}%`;
    const avgDur = Number(k.avg_scan_duration_7d_sec || 0);
    document.getElementById('ex-avg-dur').textContent = avgDur >= 3600
        ? `${(avgDur / 3600).toFixed(1)}h`
        : `${Math.max(0, Math.round(avgDur / 60))}m`;
    document.getElementById('ex-sla').textContent = `${k.scan_sla_7d ?? 0} scans finished within 60m`;

    const trend = Array.isArray(exec.trend_14d) ? exec.trend_14d : [];
    const trendSel = document.getElementById('exec-trend-range');
    if (trendSel && exec.trend_days) trendSel.value = String(exec.trend_days);
    const labels = trend.map(r => String(r.day || '').slice(5));
    renderExecLineChart('exec-trend-findings', [
        { name: 'New findings', color: '#e95f5f', values: trend.map(r => r.findings_new || 0) },
        { name: 'Critical', color: '#ff3b30', values: trend.map(r => r.findings_critical_new || 0) },
    ], labels);
    renderExecLineChart('exec-trend-assets', [
        { name: 'New assets', color: '#1787fb', values: trend.map(r => r.assets_new || 0) },
    ], labels);
    renderExecLineChart('exec-trend-scans', [
        { name: 'Scans done', color: '#42c77a', values: trend.map(r => r.scans_done || 0) },
        { name: 'Scans failed', color: '#f3a73f', values: trend.map(r => r.scans_failed || 0) },
        { name: 'Risk pressure', color: '#c86cf5', values: trend.map(r => r.risk_pressure || 0) },
    ], labels);

    const cmp = exec.comparison || {};
    const metricChip = (label, obj, positiveIsGood = true) => {
        const d = obj && obj.delta ? obj.delta : { abs: 0, pct: null };
        const dir = (d.abs || 0) > 0 ? 'up' : ((d.abs || 0) < 0 ? 'down' : 'flat');
        let cls = 'exec-delta-flat';
        if (dir !== 'flat') {
            const positive = dir === 'up';
            const good = positiveIsGood ? positive : !positive;
            cls = good ? 'exec-delta-good' : 'exec-delta-bad';
        }
        const pct = d.pct == null ? 'n/a' : `${d.pct > 0 ? '+' : ''}${d.pct}%`;
        return `<div class="exec-delta-chip ${cls}">
          <span class="exec-delta-label">${esc(label)}</span>
          <span class="exec-delta-main">${obj?.current ?? 0}</span>
          <span class="exec-delta-sub">${esc(dir)} (${pct}) vs previous</span>
        </div>`;
    };
    document.getElementById('exec-brief-deltas').innerHTML = [
        metricChip('Risk trend', cmp.risk_pressure, false),
        metricChip('Scan success rate', cmp.completion_rate, true),
        metricChip('New issues', cmp.findings_new, false),
        metricChip('New systems', cmp.assets_new, false),
    ].join('');
    const brief = Array.isArray(exec.brief) ? exec.brief : [];
    document.getElementById('exec-brief-list').innerHTML = brief.length
        ? `<ul class="exec-brief-ul">${brief.map(line => `<li>${esc(line)}</li>`).join('')}</ul>`
        : '<div class="text-dim">No executive brief available yet.</div>';

    const actions = [];
    if ((k.critical_open || 0) > 0) {
        actions.push(`Address the ${k.critical_open} critical issues first, starting with externally accessible systems.`);
    }
    if ((k.completion_rate_14d || 0) < 90) {
        actions.push(`Scan success is ${k.completion_rate_14d || 0}% over 14 days; reduce failed runs to improve coverage.`);
    }
    if ((k.scan_fail_7d || 0) > 0) {
        actions.push(`${k.scan_fail_7d} scans did not complete this week; confirm network reachability and scheduling stability.`);
    }
    const topRisk = (Array.isArray(exec.top_risky) ? exec.top_risky : fallbackTopVuln || [])[0];
    if (topRisk && topRisk.ip) {
        actions.push(`Top priority system is ${topRisk.ip} (risk score ${topRisk.top_cvss || 'n/a'}); confirm remediation plan and owner.`);
    }
    if (!actions.length) {
        actions.push('No urgent actions are currently flagged. Continue weekly monitoring and keep scan coverage consistent.');
    }
    document.getElementById('exec-actions').innerHTML = `<ul class="exec-brief-ul">${actions.map(line => `<li>${esc(line)}</li>`).join('')}</ul>`;

    const sev = exec.severity_open || {};
    const sevRows = [
        ['critical', sev.critical || 0],
        ['high', sev.high || 0],
        ['medium', sev.medium || 0],
        ['low', sev.low || 0],
    ];
    const sevTotal = sevRows.reduce((sum, r) => sum + r[1], 0) || 1;
    document.getElementById('exec-severity').innerHTML = sevRows.map(([name, count]) => {
        const pct = Math.round((count / sevTotal) * 100);
        return `<div class="exec-sev-row">
          <span class="sev ${sevClass(name)}">${esc(name)}</span>
          <span class="mono">${count}</span>
          <div class="exec-sev-track"><div class="exec-sev-fill" style="width:${pct}%"></div></div>
          <span class="mono-sm text-dim">${pct}%</span>
        </div>`;
    }).join('');

    const risky = Array.isArray(exec.top_risky) && exec.top_risky.length ? exec.top_risky : (fallbackTopVuln || []);
    document.getElementById('exec-top-risky').innerHTML = risky.length
        ? risky.map(a => `<tr>
            <td class="mono click-ip" onclick="openHostPanel(${a.id},'${esc(a.ip)}')" title="View host detail">${esc(a.ip)}</td>
            <td class="mono mono-sm">${a.device_id != null && a.device_id !== '' ? `<span class="click-ip" onclick="openDevicePanel(${a.device_id})" title="Device overview">${esc(String(a.device_id))}</span>` : '—'}</td>
            <td class="text-primary">${esc(a.hostname||'—')}</td>
            <td><span class="cat ${esc(a.category)}">${esc(a.category)}</span></td>
            <td class="mono mono-sm">${esc(a.top_cve||'—')}</td>
            <td><span class="sev ${sevClass(a.top_cvss)}">${a.top_cvss||'—'}</span></td>
            <td class="mono">${a.finding_count}</td>
          </tr>`).join('')
        : '<tr><td colspan="7" class="loading">No high-risk assets yet</td></tr>';
}

function applyExecutiveModeUI(on) {
    const ops = document.getElementById('dash-ops');
    const ex = document.getElementById('dash-exec');
    const right = document.querySelector('.dash-actions-right');
    if (ops) ops.style.display = on ? 'none' : '';
    if (ex) ex.style.display = on ? 'block' : 'none';
    if (right) {
        right.style.visibility = on ? 'visible' : 'hidden';
        right.style.pointerEvents = on ? 'auto' : 'none';
    }
}

function healthStateClass(state) {
    if (state === 'active' || state === 'ok') return 'hstate-ok';
    if (state === 'inactive') return 'hstate-err';
    if (state === 'degraded') return 'hstate-warn';
    return 'hstate-unk';
}

function healthFmtTime(iso) {
    if (!iso) return '—';
    return String(iso).replace('T', ' ').replace(/\.\d{3}Z$/, ' UTC');
}

/**
 * @param {object} h — GET /api/health.php (read-only health snapshot for the System health tab)
 */
function renderHealthHtml(h) {
    const rows = [];
    const r = (label, valueHtml) => {
        rows.push(`<div class="health-row"><span class="health-label">${esc(label)}</span><span class="health-value">${valueHtml}</span></div>`);
    };

    const daemon = h.services && h.services.daemon;
    if (daemon) {
        r('Scanner daemon (systemd)', `<span class="${healthStateClass(daemon.state)}">${esc(daemon.state)}</span><span class="h-vsep text-dim">${esc(daemon.detail)}</span>`);
    }
    const schedS = h.services && h.services.scheduler;
    if (schedS) {
        r('Job scheduler (systemd)', `<span class="${healthStateClass(schedS.state)}">${esc(schedS.state)}</span><span class="h-vsep text-dim">${esc(schedS.detail)}</span>`);
    }

    r('Data directory', h.data_dir && h.data_dir.writable
        ? '<span class="hstate-ok">writable</span>'
        : '<span class="hstate-err">not writable</span>');

    if (h.disk && h.disk.data_dir_free_human) {
        const low = h.disk.data_dir_free_bytes && h.disk.data_dir_free_bytes < 100 * 1024 * 1024;
        r('Free space (data dir)', low
            ? `<span class="hstate-warn">${esc(h.disk.data_dir_free_human)}</span><span class="h-vsep text-dim">(low)</span>`
            : esc(h.disk.data_dir_free_human));
    } else if (h.disk && h.disk.source === 'unavailable') {
        r('Free space (data dir)', `<span class="hstate-warn">unavailable</span><span class="h-vsep text-dim">${h.disk.hint ? esc(h.disk.hint) : '—'}</span>`);
    }

    r('App database', h.database && h.database.file_bytes_human
        ? `<span class="hstate-ok">ok</span><span class="h-vsep text-dim">${esc(h.database.file_bytes_human)}</span>`
        : '<span class="hstate-warn">missing or empty</span>');

    if (h.nvd) {
        const nd = h.nvd.db_exists
            ? `<span class="hstate-ok">present</span><span class="h-vsep text-dim">${esc(h.nvd.db_bytes_human || '')}</span>`
            : '<span class="hstate-warn">not found — run NVD sync in Settings</span>';
        r('NVD database', nd);
        if (h.nvd.last_config_sync) {
            r('NVD last sync (config)', esc(String(h.nvd.last_config_sync)));
        }
    }

    if (h.scans) {
        const qd = h.scans.queued || 0;
        const run = h.scans.running || 0;
        const rt = h.scans.retrying || 0;
        const jobW = run > 0
            ? `<span class="hstate-warn">${run} running</span>`
            : '<span class="hstate-ok">none running</span>';
        r('Scan jobs', `${jobW}<span class="h-vsep text-dim">${qd} queued · ${rt} retrying</span>`);
    }

    if (h.last_completed_scan) {
        const s = h.last_completed_scan;
        r('Last finished scan', esc(`${s.status || '—'} · ${s.target_cidr || '—'} · ${healthFmtTime(s.finished_at)}`));
    } else {
        r('Last finished scan', '<span class="text-dim">none yet</span>');
    }

    if (h.schedules && h.schedules.table_ok) {
        r('Schedules (enabled, not paused)', String(h.schedules.enabled_active != null ? h.schedules.enabled_active : '—'));
    }

    if (h.feeds) {
        if (h.feeds.job_running) {
            r('Feed sync', `<span class="hstate-warn">running</span><span class="h-vsep text-dim">${esc(h.feeds.job_target || '?')}</span>`);
        } else {
            r('Feed sync', '<span class="hstate-ok">idle</span>');
        }
        const fr = h.feeds.last_result;
        if (fr && fr.finished_at) {
            const ok = fr.ok && !fr.error;
            const tag = fr.cancelled ? 'cancelled' : (ok ? 'ok' : 'failed');
            const cls = ok ? 'hstate-ok' : (fr.cancelled ? 'hstate-warn' : 'hstate-err');
            r('Last feed job', `<span class="${cls}">${esc(tag)}</span><span class="h-vsep text-dim">${esc(fr.target || '—')} · ${esc(new Date(fr.finished_at * 1000).toISOString().replace('T', ' ').replace(/\.\d{3}Z$/, ' UTC'))}</span>`);
        }
    }

    r('Server time', esc(h.server_time || '—'));
    r('PHP', esc((h.php && h.php.sapi) ? h.php.sapi : '—'));

    return `<div class="health-panel">${rows.join('')}</div>
      <p class="help-line text-dim mt8" style="font-size:11px">Figures are a point-in-time picture for monitoring. To act on them, use Scan, Schedules, Enrichment, and Settings.</p>`;
}

async function loadHealth() {
    const el = document.getElementById('health-snapshot');
    if (!el) return;
    const h = await api('/api/health.php?cb=' + Date.now(), { quiet: true });
    if (!h) {
        el.innerHTML = '<div class="text-dim">Health check failed (not signed in or network error).</div>';
        return;
    }
    el.innerHTML = renderHealthHtml(h);
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

/** Filter Assets to one logical device; clears the main search box so `q` does not fight `device_id`. */
function applyAssetDeviceFilter(id) {
    const did = parseInt(String(id), 10);
    if (!did) return;
    const qIn = document.getElementById('af-q');
    if (qIn) qIn.value = '';
    assetDeviceFilter = did;
    const b = document.getElementById('af-device-banner');
    const idEl = document.getElementById('af-device-banner-id');
    if (b && idEl) {
        idEl.textContent = String(did);
        b.classList.remove('hide');
    }
    loadAssets(1);
}

function assetMainSearchKeydown(e) {
    if (e.key !== 'Enter') return;
    const inp = document.getElementById('af-q');
    if (!inp) return;
    const t = inp.value.trim();
    if (/^\d{1,12}$/.test(t)) {
        e.preventDefault();
        applyAssetDeviceFilter(parseInt(t, 10));
    }
}

function clearAllAssetFilters() {
    const q = document.getElementById('af-q');
    const cat = document.getElementById('af-cat');
    const sev = document.getElementById('af-sev');
    const srt = document.getElementById('af-sort');
    if (q) q.value = '';
    if (cat) cat.value = '';
    if (sev) sev.value = '';
    if (srt) srt.value = 'ip';
    assetSort = 'ip';
    assetOrder = 'asc';
    assetDeviceFilter = 0;
    const b = document.getElementById('af-device-banner');
    if (b) b.classList.add('hide');
    const idEl = document.getElementById('af-device-banner-id');
    if (idEl) idEl.textContent = '';
    loadAssets(1);
}

function viewDeviceAssets(did) {
    assetDeviceFilter = parseInt(String(did), 10) || 0;
    const b = document.getElementById('af-device-banner');
    const idEl = document.getElementById('af-device-banner-id');
    if (assetDeviceFilter > 0 && b && idEl) {
        idEl.textContent = String(assetDeviceFilter);
        b.classList.remove('hide');
    }
    const qIn = document.getElementById('af-q');
    if (qIn) qIn.value = '';
    goTab('assets');
    hiNav('nassets');
    loadAssets(1);
}

var deviceDebounce = null;
var scanHistDebounce = null;
function debounceDevices() {
    clearTimeout(deviceDebounce);
    deviceDebounce = setTimeout(() => loadDevices(1), 350);
}
function debounceScanHistSearch() {
    clearTimeout(scanHistDebounce);
    scanHistDebounce = setTimeout(() => loadScanHistory(), 320);
}

async function loadDevices(page) {
    devicePage = page;
    const q    = document.getElementById('df-q')?.value    || '';
    const sort = document.getElementById('df-sort')?.value || 'id';
    let order  = 'asc';
    if (sort === 'last_seen' || sort === 'asset_count') {
        order = 'desc';
    }
    document.getElementById('device-tbody').innerHTML =
        '<tr><td colspan="7" class="loading">Loading devices…</td></tr>';

    const url = `/api/devices.php?page=${page}&per_page=50&q=${enc(q)}&sort=${enc(sort)}&order=${order}`;
    const d   = await api(url);
    if (!d) return;

    document.getElementById('device-tbody').innerHTML = (d.devices || []).map(dev => {
        const mac = dev.primary_mac_norm ? esc(dev.primary_mac_norm) : '—';
        const ips = dev.ip_sample ? esc(dev.ip_sample) : '—';
        const last = dev.last_seen_max ? relTime(dev.last_seen_max) : '—';
        const created = dev.created_at ? relTime(dev.created_at) : '—';
        return `<tr>
          <td class="mono mono-sm"><span class="click-ip" onclick="openDevicePanel(${dev.id})" title="Device detail">${dev.id}</span></td>
          <td class="mono mono-sm">${mac}</td>
          <td class="mono">${dev.asset_count}</td>
          <td class="mono mono-sm" style="max-width:240px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${ips}">${ips}</td>
          <td class="mono mono-sm">${last}</td>
          <td class="mono mono-sm">${created}</td>
          <td><button type="button" class="tbtn btn-xs" onclick="viewDeviceAssets(${dev.id})">Assets</button></td>
        </tr>`;
    }).join('') || '<tr><td colspan="7" class="loading">No devices found</td></tr>';

    document.getElementById('dpgn-info').textContent = `Page ${d.page} of ${d.pages} (${d.total} devices)`;
    document.getElementById('dprev').disabled = page <= 1;
    document.getElementById('dnext').disabled = page >= d.pages;
}

function detectServiceHitsFromAsset(asset) {
    const banners = asset.banners || {};
    const httpProbe = String(banners._http || '');
    const ports = asset.open_ports || [];
    return collectDetectedServiceChips(ports, banners, httpProbe);
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
        '<tr><td colspan="10" class="loading">Loading assets…</td></tr>';

    const b = document.getElementById('af-device-banner');
    const idEl = document.getElementById('af-device-banner-id');
    if (assetDeviceFilter > 0 && b && idEl) {
        idEl.textContent = String(assetDeviceFilter);
        b.classList.remove('hide');
    } else if (b) {
        b.classList.add('hide');
        if (idEl) idEl.textContent = '';
    }

    const devQ = assetDeviceFilter > 0 ? `&device_id=${encodeURIComponent(String(assetDeviceFilter))}` : '';
    const url = `/api/assets.php?page=${page}&per_page=50&q=${enc(q)}&category=${enc(cat)}&severity=${enc(sev)}&sort=${sort}&order=${assetOrder}${devQ}`;
    const d   = await api(url);
    if (!d) return;

    document.getElementById('asset-tbody').innerHTML = (d.assets || []).map(a => {
        const ports = (a.open_ports || []).slice(0,6).map(p => `<span class="pt">${Number(p)}</span>`).join('');
        const more  = a.open_ports && a.open_ports.length > 6 ? `<span class="pt">+${a.open_ports.length-6}</span>` : '';
        const svcHits = detectServiceHitsFromAsset(a);
        const primaryVendor = a.vendor || '—';
        let vendorCell = esc(primaryVendor) + (a.model ? '<span class="text-secondary"> ' + esc(a.model) + '</span>' : '');
        if (svcHits.length > 1) {
            const extra = svcHits.filter(s => s.toLowerCase() !== String(primaryVendor).toLowerCase());
            if (extra.length) {
                vendorCell += ` <span class="status-text" title="${esc(svcHits.join(', '))}">+${extra.length} services</span>`;
            }
        }
        return `<tr>
          <td class="mono click-ip" onclick="openHostPanel(${a.id},'${esc(a.ip)}')" title="View host detail">${esc(a.ip)}</td>
          <td class="mono mono-sm">${a.device_id != null && a.device_id !== '' ? `<span class="click-ip" onclick="event.stopPropagation();openDevicePanel(${a.device_id})" title="Device overview">${esc(String(a.device_id))}</span>` : '—'}</td>
          <td class="text-primary">${esc(a.hostname||'—')}</td>
          <td><span class="cat ${esc(a.category||'unk')}">${esc(a.category||'unk')}</span></td>
          <td class="text-primary" style="font-size:12px">${vendorCell}</td>
          <td><div class="pts">${ports}${more}</div></td>
          <td class="mono">${a.open_findings||0}</td>
          <td><span class="sev ${sevClass(a.top_cvss)}">${a.top_cvss?a.top_cvss:'—'}</span></td>
          <td class="mono mono-sm">${relTime(a.last_seen)}</td>
          <td>
            <button type="button" class="tbtn btn-xs" onclick="openHostPanel(${a.id},'${esc(a.ip)}')">Details</button>
            <button type="button" class="tbtn btn-xs" onclick="openReclassify(${a.id},'${esc(a.ip)}','${esc(a.hostname||'')}','${esc(a.category)}','${esc(a.vendor||'')}','${esc(a.notes||'')}')">&#9998;</button>
          </td>
        </tr>`;
    }).join('') || '<tr><td colspan="10" class="loading">No assets found</td></tr>';

    document.getElementById('apgn-info').textContent =
        assetDeviceFilter > 0
            ? `Page ${d.page} of ${d.pages} (${d.total} assets for device ${assetDeviceFilter})`
            : `Page ${d.page} of ${d.pages} (${d.total} assets)`;
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
      <td class="mono mono-sm">${esc(f.cve_id)}</td>
      <td class="mono click-ip"
          onclick="filterVulnsByIP('${esc(f.ip)}')"
          title="Filter to this host">${esc(f.ip)}</td>
      <td class="click-ip" style="font-size:12px"
          onclick="filterVulnsByIP('${esc(f.ip)}')"
          title="Filter to this host">${esc(f.hostname||'—')}</td>
      <td><span class="cat ${esc(f.category||'unk')}">${esc(f.category||'unk')}</span></td>
      <td class="text-secondary" style="font-size:12px;max-width:260px">${esc(f.description||'—')}</td>
      <td><span class="sev ${sevClass(f.cvss)}">${f.cvss||'—'}</span></td>
      <td class="mono mono-sm">${localDate(f.published)}</td>
      <td>${f.resolved ? '<span class="status-text" style="color:var(--green)">resolved</span>'
          : `<button class="tbtn btn-xs" onclick="resolveFinding(${f.id}, this)">Resolve</button>`}</td>
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
            const ok = await showConfirmModal(
                `/${prefix} covers ${hosts} hosts and may take hours.\n\nAre you sure you want to scan ${c}?`,
                {title: 'Large scope warning', okText: 'Scan anyway'}
            );
            if (!ok) {
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
    if (['deep_scan', 'full_tcp', 'fast_full_tcp', 'ot_careful'].includes(profileVal)) {
        const ok = await showConfirmModal(
            `Profile "${profileVal}" generates significant network traffic and requires confirmation.\n\nProceed?`,
            {title: 'High-impact scan profile', okText: 'Proceed'}
        );
        if (!ok) return;
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
    const enrSel = scanEnrichmentPayloadField();
    if (enrSel !== undefined) body.enrichment_source_ids = enrSel;

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
    const d = await api(`/api/scan_status.php?job_id=${jobId}&since_log_id=${logSinceId}&log_limit=100`, {quiet:true});
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
            const next = await api('/api/scan_status.php?log_limit=1', {quiet:true});
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
    const d = await api('/api/scan_status.php?log_limit=50', {quiet:true});
    if (!d) return;
    if (d.job) {
        if (d.job.status === 'running' || d.job.status === 'queued') {
            activeJobId = d.job.id;
            showScanRunning(activeJobId);
            startPoll(activeJobId);
        }
    }
    loadScanHistory(d.history);
    refreshScanEnrichmentPicker();
}

/** Per-scan enrichment toggles; returns undefined = default (all enabled), [] = none, else id subset */
function scanEnrichmentPayloadField() {
    const wrap = document.getElementById('scan-enrichment-wrap');
    if (!wrap || wrap.dataset.ready !== '1') return undefined;
    const enabledBoxes = wrap.querySelectorAll('input[data-enr-id]');
    if (!enabledBoxes.length) return undefined;
    const checked = [];
    enabledBoxes.forEach(cb => { if (cb.checked) checked.push(parseInt(cb.dataset.enrId, 10)); });
    if (checked.length === enabledBoxes.length) return undefined;
    return checked;
}

async function refreshScanEnrichmentPicker() {
    const wrap = document.getElementById('scan-enrichment-wrap');
    if (!wrap) return;
    wrap.dataset.ready = '0';
    wrap.innerHTML = '<div class="hint-micro">Loading…</div>';
    let data;
    try {
        data = await api('/api/enrichment.php', {quiet:true});
    } catch (e) {
        wrap.innerHTML = '<div class="hint-micro">Could not load enrichment sources</div>';
        return;
    }
    const srcs = (data && data.sources) ? data.sources : [];
    if (!srcs.length) {
        wrap.innerHTML = '<div class="hint-micro">No sources configured yet — add them under <strong>Enrichment</strong>.</div>';
        wrap.dataset.ready = '1';
        return;
    }
    const parts = [];
    for (const s of srcs) {
        const en = parseInt(s.enabled, 10) === 1;
        const id = parseInt(s.id, 10);
        const label = esc(s.label || s.source_type || '');
        const typ = esc(s.source_type || '');
        if (en) {
            parts.push(`<div class="tr2"><div><div class="tl">${label}</div><div class="tsubl">${typ}</div></div><label class="tog"><input type="checkbox" data-enr-id="${id}" checked><div class="trk"></div><div class="tth"></div></label></div>`);
        } else {
            parts.push(`<div class="tr2" style="opacity:0.55"><div><div class="tl">${label}</div><div class="tsubl">${typ} (disabled in Enrichment)</div></div><label class="tog"><input type="checkbox" disabled><div class="trk"></div><div class="tth"></div></label></div>`);
        }
    }
    wrap.innerHTML = parts.join('');
    wrap.dataset.ready = '1';
}

function scanHistSearchQ() {
    const el = document.getElementById('scan-hist-q');
    if (!el) return '';
    return (el.value || '').trim().slice(0, 120);
}

async function loadScanHistory(history) {
    let queueHistory = history;
    if (!queueHistory) {
        const d = await api('/api/scan_status.php?log_limit=1', {quiet:true});
        queueHistory = d ? d.history : [];
    }
    const statColors = {done:'var(--green)', failed:'var(--red)', aborted:'var(--amber)', running:'var(--acc)', queued:'var(--tx3)'};
    const statColors2 = {done:'var(--green)',failed:'var(--red)',aborted:'var(--amber)',running:'var(--acc)',queued:'var(--tx3)',retrying:'var(--amber)'};
    updateQueuePanel(queueHistory);

    const q = scanHistSearchQ();
    let completedRows;
    if (q) {
        const hd = await api('/api/scan_history.php?limit=200&q=' + encodeURIComponent(q), {quiet:true});
        completedRows = (hd && hd.history) ? hd.history : [];
    } else {
        completedRows = (queueHistory || []).filter(j => !['queued','running','retrying'].includes(j.status));
    }

    const emptyMsg = q ? 'No scans match this search' : 'No previous scans';
    const canRerun = (st) => ['done', 'aborted', 'failed'].includes(st);
    const canDelete = (st) => ['done', 'aborted', 'failed'].includes(st);
    document.getElementById('scan-hist').innerHTML = (completedRows||[]).filter(j => !['queued','running','retrying'].includes(j.status)).map(j => `<tr class="scan-hist-row" data-job-id="${j.id}" title="Open scan details">
      <td class="mono"><button type="button" class="tbtn text-micro" data-scan-action="details" data-job-id="${j.id}">#${j.id}</button></td>
      <td class="text-primary font11"><button type="button" class="tbtn text-micro" data-scan-action="details" data-job-id="${j.id}" style="padding:0;border:none;background:none;color:inherit;font:inherit;text-align:left">${esc(j.label||'\u2014')}</button>${j.retry_count > 0 ? ` <span class="text-micro" style="color:var(--amber)">retry ${j.retry_count}</span>` : ''}</td>
      <td class="mono font10">${esc(j.target_cidr)}</td>
      <td><span class="status-chip" style="color:${statColors2[j.status]||'var(--tx2)'}">${j.status}</span>${j.status==='failed'&&j.error_msg?`<div class="text-micro" style="color:var(--red);margin-top:1px" title="${esc(j.error_msg)}">${esc((j.error_msg||'').slice(0,50))}</div>`:''}</td>
      <td class="text-micro">${j.profile?esc(j.profile.replace(/_/g,' ')):'\u2014'}</td>
      <td class="mono">${j.hosts_scanned||0}/${j.hosts_found||0}</td>
      <td class="mono font10">${fmtDuration(j.duration_secs)}</td>
      <td class="mono font10">${localDate(j.finished_at)}</td>
      <td class="nowrap-cell">
        <button type="button" class="tbtn text-micro" data-scan-action="details" data-job-id="${j.id}">Details</button>
        ${canRerun(j.status) ? `<button type="button" class="tbtn text-micro" data-scan-action="rerun" data-job-id="${j.id}">Re-run</button>` : ''}
        ${canDelete(j.status) ? `<button type="button" class="tbtn text-micro" data-scan-action="delete" data-job-id="${j.id}" style="color:var(--red)">Delete</button>` : ''}
      </td>
    </tr>`).join('') || '<tr><td colspan="9" class="loading">' + emptyMsg + '</td></tr>';
    bindScanHistoryDelegates();
}

// ==========================================================================
// Job queue panel
// ==========================================================================
function updateQueuePanel(history) {
    const queued = (history||[]).filter(j =>
        ['queued','running','retrying'].includes(j.status)
    ).sort((a,b) => (a.priority||10)-(b.priority||10) || a.id-b.id);

    const queueBlocks = [
        {
            wrap: document.getElementById('job-queue'),
            empty: document.getElementById('job-queue-empty'),
            tbody: document.getElementById('queue-tbody'),
        },
        {
            wrap: document.getElementById('job-queue-scan'),
            empty: document.getElementById('job-queue-empty-scan'),
            tbody: document.getElementById('queue-tbody-scan'),
        },
    ].filter(b => b.wrap && b.empty && b.tbody);

    if (!queued.length) {
        queueBlocks.forEach((b) => {
            b.wrap.style.display = 'none';
            b.empty.style.display = 'block';
            b.tbody.innerHTML = '';
        });
        // Hide scan stats if nothing running
        document.getElementById('scan-stats').style.display = 'none';
        return;
    }

    queueBlocks.forEach((b) => {
        b.wrap.style.display = 'block';
        b.empty.style.display = 'none';
    });

    const statusColor = {running:'var(--acc)',queued:'var(--tx3)',retrying:'var(--amber)'};
    const rowsHtml = queued.map(j => {
        const pct  = j.progress_pct || 0;
        const isRun = j.status === 'running';
        const msgEl = isRun ? `
            <div class="text-micro" style="margin-top:3px;max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" id="qmsg-${j.id}">
              ${j.hosts_found > 0 ? j.hosts_scanned+'/'+ j.hosts_found+' hosts &nbsp;·&nbsp; '+pct+'%' : 'Starting…'}
            </div>
            <div class="track">
              <div class="fill" style="width:${pct}%"></div>
            </div>` : '';
        return `<tr class="scan-hist-row" data-job-id="${j.id}" title="Open scan details">
          <td class="mono"><button type="button" class="tbtn text-micro" data-scan-action="details" data-job-id="${j.id}">#${j.id}</button></td>
          <td class="text-primary font11"><button type="button" class="tbtn text-micro" data-scan-action="details" data-job-id="${j.id}" style="padding:0;border:none;background:none;color:inherit;font:inherit;text-align:left">${esc(j.label||'—')}</button></td>
          <td class="mono font10">${esc(j.target_cidr)}</td>
          <td class="text-micro">${j.profile?esc(j.profile.replace(/_/g,' ')):'—'}</td>
          <td>
            <span class="status-chip" style="color:${statusColor[j.status]||'var(--tx2)'}">
              ${isRun ? '&#9654; running' : j.status}
            </span>
            ${msgEl}
          </td>
          <td class="mono font10">${j.priority||10}</td>
          <td class="mono font10">${localTime(j.created_at,{hour:'2-digit',minute:'2-digit'})}</td>
          <td>
            ${isRun
              ? `<button type="button" class="btnd btn-xxs" data-scan-action="abort" data-job-id="${j.id}">&#9632; Abort</button>`
              : `<button type="button" class="tbtn btn-xxs danger" data-scan-action="cancel" data-job-id="${j.id}">Cancel</button>`}
          </td>
        </tr>`;
    }).join('');
    queueBlocks.forEach((b) => { b.tbody.innerHTML = rowsHtml; });
    bindScanHistoryDelegates();
}

function handleScanHistoryTableClick(ev) {
    const t = ev.target instanceof Element ? ev.target : null;
    if (!t) return;

    const btn = t.closest('button[data-scan-action][data-job-id]');
    if (btn) {
        const jid = parseInt(btn.getAttribute('data-job-id') || '0', 10);
        if (jid <= 0) return;
        const action = btn.getAttribute('data-scan-action') || '';
        if (action === 'details') { void openScanHistDetail(jid); return; }
        if (action === 'rerun')   { void rerunScanJob(jid); return; }
        if (action === 'delete')  { void deleteScanJob(jid); return; }
        if (action === 'abort')   { void abortJobById(jid); return; }
        if (action === 'cancel')  { void cancelJob(jid); return; }
        return;
    }

    if (t.closest('a,input,label,select,textarea')) return;
    const row = t.closest('tr.scan-hist-row[data-job-id]');
    if (!row) return;
    const jid = parseInt(row.getAttribute('data-job-id') || '0', 10);
    if (jid > 0) void openScanHistDetail(jid);
}

function bindScanHistoryDelegates() {
    ['scan-hist', 'queue-tbody', 'queue-tbody-scan'].forEach((id) => {
        const tbody = document.getElementById(id);
        if (!tbody) return;
        if (tbody.dataset.scanDelegatesBound === '1') return;
        tbody.addEventListener('click', handleScanHistoryTableClick);
        tbody.dataset.scanDelegatesBound = '1';
    });
}
bindScanHistoryDelegates();

function bindScanDetailAssetDelegates() {
    const tbody = document.getElementById('scan-hist-detail-assets');
    if (!tbody || tbody.dataset.scanAssetDelegatesBound === '1') return;
    tbody.addEventListener('click', (ev) => {
        const t = ev.target instanceof Element ? ev.target : null;
        if (!t) return;
        const row = t.closest('tr.scan-hist-asset-row[data-asset-id]');
        if (!row) return;
        const aid = parseInt(row.getAttribute('data-asset-id') || '0', 10);
        const didRaw = row.getAttribute('data-device-id');
        const did = didRaw && didRaw !== 'null' ? parseInt(didRaw, 10) : 0;
        const ip = row.getAttribute('data-ip') || '';
        openScanHistAssetNav(aid, did > 0 ? did : null, ip);
    });
    tbody.dataset.scanAssetDelegatesBound = '1';
}
bindScanDetailAssetDelegates();

// ==========================================================================
// Job queue management
// ==========================================================================
async function abortJobById(id) {
    if (!(await showConfirmModal(
        'Abort job #' + id + '? The scan will stop after the current batch.',
        {title: 'Abort scan job', okText: 'Abort'}
    ))) return;
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
    if (!(await showConfirmModal(
        'Cancel job #' + id + '?',
        {title: 'Cancel queued job', okText: 'Cancel job'}
    ))) return;
    const r = await apiPost('/api/scan_abort.php', {job_id: id});
    if (r && r.ok) { toast('Job #' + id + ' cancelled', 'ok'); loadScanHistory(); }
    else toast((r && r.error) || 'Cancel failed', 'err');
}

async function rerunScanJob(id) {
    const r = await apiPost('/api/scan_start.php', {retry_job_id: id});
    if (r && r.job_id) {
        closeScanHistDetailModal(false);
        toast('New job #' + r.job_id + ' queued with the same target and options', 'ok');
        loadScanHistory();
    } else {
        toast((r && r.error) || 'Re-run failed', 'err');
    }
}

async function deleteScanJob(id) {
    const jid = parseInt(String(id), 10);
    if (!jid) return;
    const ok = await showConfirmModal(
        `Delete historical scan #${jid}?\n\nThis removes the job record and saved run evidence for that scan.`,
        {title: 'Delete scan', okText: 'Delete'}
    );
    if (!ok) return;
    const r = await apiPost('/api/scan_delete.php', {job_id: jid});
    if (r && r.ok) {
        const delBtn = document.getElementById('scan-hist-detail-delete');
        const openId = delBtn ? parseInt(delBtn.dataset.jobId || '0', 10) : 0;
        if (openId === jid) closeScanHistDetailModal(false);
        toast('Scan #' + jid + ' deleted', 'ok');
        loadScanHistory();
    } else {
        toast((r && r.error) || 'Delete failed', 'err');
    }
}

function closeScanHistDetailModal(restoreDevice = true) {
    const bg = document.getElementById('scan-hist-detail-bg');
    if (bg) bg.style.display = 'none';
    const hint = document.getElementById('scan-hist-detail-assets-hint');
    if (hint) hint.style.display = 'none';
    if (restoreDevice && scanDetailReturnDeviceId > 0) {
        const did = scanDetailReturnDeviceId;
        scanDetailReturnDeviceId = 0;
        goTab('devices');
        hiNav('ndevices');
        setTimeout(() => { void openDevicePanel(did); }, 0);
    }
}

/** From scan detail modal: prefer Devices when `device_id` is set, else host panel (asset by IP). */
function openScanHistAssetNav(assetId, deviceId, ip) {
    const aid = parseInt(String(assetId), 10);
    const did = deviceId != null && deviceId !== '' ? parseInt(String(deviceId), 10) : 0;
    closeScanHistDetailModal(false);
    scanDetailReturnDeviceId = 0;
    if (did > 0) {
        goTab('devices');
        hiNav('ndevices');
        void openDevicePanel(did);
        return;
    }
    if (aid > 0 && ip) {
        goTab('assets');
        hiNav('nassets');
        void openHostPanel(aid, ip);
    }
}

function renderScanSummary(summary) {
    if (!summary || typeof summary !== 'object') {
        return '<span class="summary-empty">No summary snapshot recorded for this run.</span>';
    }
    const topPorts = Array.isArray(summary.top_ports) ? summary.top_ports : [];
    const cats = summary.categories && typeof summary.categories === 'object'
        ? Object.entries(summary.categories).map(([k,v]) => `${k}:${v}`).join(', ')
        : '';
    const portText = topPorts.length
        ? topPorts.slice(0, 6).map(p => `${p.port}(${p.hosts})`).join(', ')
        : '—';
    return `
      <div>Profile: <b>${esc(summary.profile || '—')}</b> &nbsp;|&nbsp; Mode: <b>${esc(summary.scan_mode || '—')}</b></div>
      <div class="summary-line">Assets catalogued: <b>${summary.assets_catalogued || 0}</b> &nbsp;|&nbsp; Open findings: <b>${summary.open_findings || 0}</b> &nbsp;|&nbsp; Open ports observed: <b>${summary.open_ports_total || 0}</b></div>
      <div class="summary-line">Top ports: <span class="mono">${esc(portText)}</span></div>
      <div class="summary-line">Categories: <span class="mono">${esc(cats || '—')}</span></div>
    `;
}

function renderScanDiff(diff) {
    if (!diff || !diff.compared_job) return '';
    const cj = diff.compared_job || {};
    const h = diff.hosts || {};
    const p = diff.ports || {};
    const c = diff.cves || {};
    const addHosts = Array.isArray(h.added) ? h.added : [];
    const remHosts = Array.isArray(h.removed) ? h.removed : [];
    const newCves = Array.isArray(c.new_open) ? c.new_open : [];
    const resCves = Array.isArray(c.resolved) ? c.resolved : [];
    const addPorts = Array.isArray(p.added_ports) ? p.added_ports : [];
    const remPorts = Array.isArray(p.removed_ports) ? p.removed_ports : [];
    return `
      <div><strong>Diff vs scan #${esc(cj.id || '—')}</strong> (${esc(cj.label || 'untitled')})</div>
      <div class="summary-line">Hosts: <b>${h.current || 0}</b> now vs <b>${h.previous || 0}</b> prior &nbsp;|&nbsp; +${addHosts.length} / -${remHosts.length}</div>
      <div class="summary-line">Ports: +<b>${p.added || 0}</b> / -<b>${p.removed || 0}</b> host-port pairs</div>
      ${(addPorts.length || remPorts.length) ? `<div class="summary-line">Ports changed: ${addPorts.length ? `+ ${esc(addPorts.join(', '))}` : ''}${remPorts.length ? `${addPorts.length ? ' &nbsp;|&nbsp; ' : ''}- ${esc(remPorts.join(', '))}` : ''}</div>` : ''}
      <div class="summary-line">Open CVEs: <b>${c.open_current || 0}</b> now vs <b>${c.open_previous || 0}</b> prior &nbsp;|&nbsp; new <b>${newCves.length}</b> / resolved <b>${resCves.length}</b></div>
      ${(addHosts.length || remHosts.length) ? `<div class="summary-line">Hosts changed: ${addHosts.length ? `+ ${esc(addHosts.slice(0, 8).join(', '))}` : ''}${remHosts.length ? `${addHosts.length ? ' &nbsp;|&nbsp; ' : ''}- ${esc(remHosts.slice(0, 8).join(', '))}` : ''}</div>` : ''}
      ${(newCves.length || resCves.length) ? `<div class="summary-line">CVEs changed: ${newCves.length ? `+ ${esc(newCves.slice(0, 6).join(', '))}` : ''}${resCves.length ? `${newCves.length ? ' &nbsp;|&nbsp; ' : ''}resolved ${esc(resCves.slice(0, 6).join(', '))}` : ''}</div>` : ''}
    `;
}

function currentCompareScope() {
    const sameTarget = !!document.getElementById('scan-hist-compare-same-target')?.checked;
    const sameProfile = !!document.getElementById('scan-hist-compare-same-profile')?.checked;
    if (sameTarget && sameProfile) return 'both';
    if (sameTarget) return 'target';
    if (sameProfile) return 'profile';
    return 'any';
}

function applyCompareScope(scope) {
    const sameTarget = document.getElementById('scan-hist-compare-same-target');
    const sameProfile = document.getElementById('scan-hist-compare-same-profile');
    if (sameTarget) sameTarget.checked = (scope === 'target' || scope === 'both');
    if (sameProfile) sameProfile.checked = (scope === 'profile' || scope === 'both');
}

function renderCompareOptions(jobId, job, options, selectedCompareId, scope) {
    const sel = document.getElementById('scan-hist-compare-select');
    const btn = document.getElementById('scan-hist-compare-btn');
    const sameTargetEl = document.getElementById('scan-hist-compare-same-target');
    const sameProfileEl = document.getElementById('scan-hist-compare-same-profile');
    if (!sel || !btn) return;
    applyCompareScope(scope || 'any');
    const opts = Array.isArray(options) ? options : [];
    const filtered = opts.filter(o => {
        if (!job || typeof job !== 'object') return true;
        const needsTarget = !!sameTargetEl?.checked;
        const needsProfile = !!sameProfileEl?.checked;
        if (needsTarget && String(o.target_cidr || '') !== String(job.target_cidr || '')) return false;
        if (needsProfile) {
            if (String(o.profile || '') !== String(job.profile || '')) return false;
            if (String(o.scan_mode || '') !== String(job.scan_mode || '')) return false;
        }
        return true;
    });
    const current = parseInt(String(selectedCompareId || 0), 10);
    sel.innerHTML = ['<option value="">Previous completed run (auto)</option>']
        .concat(filtered.map(o => {
            const id = parseInt(o.id, 10);
            const label = esc(o.label || 'untitled');
            const tgt = esc(o.target_cidr || '');
            const fin = esc(localDate(o.finished_at));
            const tag = id === current ? ' selected' : '';
            return `<option value="${id}"${tag}>#${id} · ${label} · ${tgt} · ${fin}</option>`;
        })).join('');
    const runCompare = () => {
        const cmp = parseInt(sel.value || '0', 10);
        void openScanHistDetail(jobId, cmp > 0 ? cmp : 0, currentCompareScope());
    };
    btn.onclick = runCompare;
    sel.onchange = runCompare;
    if (sameTargetEl) sameTargetEl.onchange = runCompare;
    if (sameProfileEl) sameProfileEl.onchange = runCompare;
}

async function openScanHistDetail(id, compareToId = 0, compareScope = 'any') {
    const bg = document.getElementById('scan-hist-detail-bg');
    const title = document.getElementById('scan-hist-detail-title');
    const meta = document.getElementById('scan-hist-detail-meta');
    const sum = document.getElementById('scan-hist-detail-summary');
    const diff = document.getElementById('scan-hist-detail-diff');
    const tbody = document.getElementById('scan-hist-detail-assets');
    if (!bg || !title || !meta || !sum || !diff || !tbody) return;
    // Modal is declared near tab markup; ensure it is attached to body so it
    // can render even when its original tab container is hidden.
    if (bg.parentElement !== document.body) {
        document.body.appendChild(bg);
    }
    bg.style.display = 'flex';
    const rerunBtn = document.getElementById('scan-hist-detail-rerun');
    if (rerunBtn) { rerunBtn.style.display = 'none'; rerunBtn.dataset.jobId = ''; }
    const delBtn = document.getElementById('scan-hist-detail-delete');
    if (delBtn) { delBtn.style.display = 'none'; delBtn.dataset.jobId = ''; }
    const hint0 = document.getElementById('scan-hist-detail-assets-hint');
    if (hint0) hint0.style.display = 'none';
    title.textContent = 'Scan #' + id + ' detail';
    meta.textContent = 'Loading…';
    sum.innerHTML = '';
    diff.innerHTML = '';
    tbody.innerHTML = '<tr><td colspan="6" class="loading">Loading…</td></tr>';

    const cmpQ = compareToId > 0 ? '&compare_to=' + encodeURIComponent(String(compareToId)) : '';
    const scopeQ = '&compare_scope=' + encodeURIComponent(compareScope || 'any');
    const d = await api('/api/scan_history.php?id=' + encodeURIComponent(id) + cmpQ + scopeQ, {quiet:true});
    if (!d || !d.job) {
        meta.textContent = 'Could not load scan details';
        tbody.innerHTML = '<tr><td colspan="6" class="loading">No data</td></tr>';
        return;
    }

    const j = d.job;
    if (rerunBtn) {
        rerunBtn.dataset.jobId = String(j.id);
        rerunBtn.style.display = ['done', 'aborted', 'failed'].includes(j.status) ? '' : 'none';
    }
    if (delBtn) {
        delBtn.dataset.jobId = String(j.id);
        delBtn.style.display = ['done', 'aborted', 'failed'].includes(j.status) ? '' : 'none';
    }
    title.textContent = `Scan #${j.id} — ${j.label || 'Untitled run'}`;
    const phasesRan = Array.isArray(j.phases) && j.phases.length ? j.phases.join(', ') : '—';
    meta.innerHTML = `
      Target: <span class="mono">${esc(j.target_cidr || '—')}</span>
      &nbsp;|&nbsp; Status: <b>${esc(j.status || '—')}</b>
      &nbsp;|&nbsp; Started: ${esc(localTime(j.started_at))}
      &nbsp;|&nbsp; Finished: ${esc(localTime(j.finished_at))}
      &nbsp;|&nbsp; Duration: <b>${esc(fmtDuration(j.duration_secs || 0))}</b>
      <div style="margin-top:4px">Phases run: <span class="mono">${esc(phasesRan)}</span></div>
    `;
    renderCompareOptions(j.id, j, d.compare_options || [], compareToId, d.compare_scope || compareScope || 'any');
    sum.innerHTML = renderScanSummary(j.summary);
    diff.innerHTML = renderScanDiff(d.compare);

    const assets = Array.isArray(d.assets) ? d.assets : [];
    const hint = document.getElementById('scan-hist-detail-assets-hint');
    if (!assets.length) {
        if (hint) hint.style.display = 'none';
        tbody.innerHTML = '<tr><td colspan="6" class="loading">No assets available for this run. Older runs can be empty because inventory rows keep only the most recent `last_scan_id` per asset.</td></tr>';
        return;
    }
    if (hint) hint.style.display = 'block';
    tbody.innerHTML = assets.map(a => {
        const ports = Array.isArray(a.open_ports) && a.open_ports.length
            ? a.open_ports.join(', ')
            : '—';
        const did = a.device_id != null && a.device_id !== '' ? parseInt(String(a.device_id), 10) : 0;
        const tip = did > 0 ? 'Open device #' + did : 'Open host at ' + (a.ip || '');
        const ipAttr = esc(String(a.ip || ''));
        const devAttr = did > 0 ? String(did) : 'null';
        return `<tr class="scan-hist-asset-row" style="cursor:pointer" title="${esc(tip)}" data-asset-id="${a.id}" data-device-id="${devAttr}" data-ip="${ipAttr}">
          <td class="mono">${esc(a.ip || '')}</td>
          <td>${esc(a.hostname || '—')}</td>
          <td><span class="chip">${esc((a.category || 'unk').toUpperCase())}</span></td>
          <td class="mono" style="font-size:11px">${esc(ports)}</td>
          <td class="mono" style="font-size:11px">${esc(a.top_cve || '—')}</td>
          <td class="mono">${a.top_cvss != null ? esc(a.top_cvss) : '—'}</td>
        </tr>`;
    }).join('');
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

function showConfirmModal(message, opts) {
    const o = opts || {};
    const bg = document.getElementById('confirm-bg');
    const titleEl = document.getElementById('confirm-title');
    const msgEl = document.getElementById('confirm-msg');
    const okBtn = document.getElementById('confirm-ok-btn');
    const cancelBtn = document.getElementById('confirm-cancel-btn');
    if (!bg || !titleEl || !msgEl || !okBtn || !cancelBtn) return Promise.resolve(false);
    if (confirmResolve) {
        try { confirmResolve(false); } catch (e) {}
        confirmResolve = null;
    }
    titleEl.textContent = o.title || 'Confirm action';
    msgEl.textContent = String(message || '');
    okBtn.textContent = o.okText || 'Confirm';
    cancelBtn.textContent = o.cancelText || 'Cancel';
    bg.style.display = 'flex';
    return new Promise(resolve => {
        confirmResolve = resolve;
    });
}

function closeConfirmModal(accepted) {
    const bg = document.getElementById('confirm-bg');
    if (bg) bg.style.display = 'none';
    if (confirmResolve) {
        const r = confirmResolve;
        confirmResolve = null;
        r(!!accepted);
    }
}

document.getElementById('confirm-bg')?.addEventListener('click', function(e) {
    if (e.target === this) closeConfirmModal(false);
});
document.getElementById('profile-bg')?.addEventListener('click', function(e) {
    if (e.target === this) closeProfileModal();
});
document.getElementById('mfa-disable-bg')?.addEventListener('click', function(e) {
    if (e.target === this) closeMfaDisableModal();
});
document.getElementById('pw-change-bg')?.addEventListener('click', function(e) {
    if (e.target === this) closePasswordChangeModal();
});
document.getElementById('user-pw-bg')?.addEventListener('click', function(e) {
    if (e.target === this) closeUserPasswordModal();
});

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

async function loadUiSettings() {
    const d = await api('/api/settings.php');
    if (!d || !d.ok) return;
    const inp = document.getElementById('st-session-timeout-min');
    if (inp) inp.value = String(d.session_timeout_minutes);
    const extra = document.getElementById('st-extra-safe-ports');
    if (extra) extra.value = String(d.extra_safe_ports || '');
    syncNvdKeyFormVisibility(!!d.nvd_api_key_configured);
    const nvdSt = document.getElementById('st-nvd-api-key-status');
    if (nvdSt) {
        nvdSt.textContent = d.nvd_api_key_configured
            ? 'Use Remove key if you need to paste a different one.'
            : 'No key saved — sync uses the slower public rate limit unless NVD_API_KEY is set on the server.';
    }
    const authModeSel = document.getElementById('st-auth-mode');
    if (authModeSel) authModeSel.value = d.auth_mode || 'session';
    updateAccessControlModeVisibility();
    const oidcEnabled = document.getElementById('oidc-enabled');
    if (oidcEnabled) oidcEnabled.checked = !!d.oidc_enabled;
    const oidcFields = {
        'oidc-issuer-url': d.oidc_issuer_url || '',
        'oidc-client-id': d.oidc_client_id || '',
        'oidc-redirect-uri': d.oidc_redirect_uri || '',
        'oidc-role-claim': d.oidc_role_claim || 'groups',
        'oidc-role-map': d.oidc_role_map || '',
        'breakglass-username': d.breakglass_username || 'admin',
    };
    Object.keys(oidcFields).forEach(id => {
        const el = document.getElementById(id);
        if (el) el.value = oidcFields[id];
    });
    const pp = d.password_policy || {};
    const brkEnabled = document.getElementById('breakglass-enabled');
    if (brkEnabled) brkEnabled.checked = !!d.breakglass_enabled;
    const ssoRoleSource = document.getElementById('sso-role-source');
    if (ssoRoleSource) ssoRoleSource.value = d.sso_role_source || 'surveytrace';
    const minLen = document.getElementById('pp-min-len');
    if (minLen) minLen.value = String(pp.min_length || 12);
    const setChk = (id, v) => { const el = document.getElementById(id); if (el) el.checked = !!v; };
    setChk('pp-upper', pp.require_upper);
    setChk('pp-lower', pp.require_lower);
    setChk('pp-number', pp.require_number);
    setChk('pp-symbol', pp.require_symbol);
    const hashAlgo = document.getElementById('pp-hash-algo');
    if (hashAlgo) hashAlgo.value = d.password_hash_algo || 'argon2id';
    const maxAtt = document.getElementById('pp-max-attempts');
    if (maxAtt) maxAtt.value = String(d.login_max_attempts || 5);
    const lockMin = document.getElementById('pp-lockout-min');
    if (lockMin) lockMin.value = String(d.login_lockout_minutes || 15);
    await loadAuthUsers();
    updateMfaActionButtons();
}

async function savePasswordPolicy() {
    const body = {
        password_policy: {
            min_length: Number(document.getElementById('pp-min-len')?.value || 12),
            require_upper: !!document.getElementById('pp-upper')?.checked,
            require_lower: !!document.getElementById('pp-lower')?.checked,
            require_number: !!document.getElementById('pp-number')?.checked,
            require_symbol: !!document.getElementById('pp-symbol')?.checked,
        },
        password_hash_algo: document.getElementById('pp-hash-algo')?.value || 'argon2id',
        login_max_attempts: Number(document.getElementById('pp-max-attempts')?.value || 5),
        login_lockout_minutes: Number(document.getElementById('pp-lockout-min')?.value || 15),
    };
    const r = await apiPost('/api/settings.php', body);
    if (r && r.ok) {
        toast('Password policy updated', 'ok');
        await loadUiSettings();
    } else {
        toast((r && r.error) ? r.error : 'Save failed', 'err');
    }
}

async function saveAccessControlSettings() {
    const body = {
        auth_mode: document.getElementById('st-auth-mode')?.value || 'session',
        oidc_enabled: !!document.getElementById('oidc-enabled')?.checked,
        oidc_issuer_url: document.getElementById('oidc-issuer-url')?.value || '',
        oidc_client_id: document.getElementById('oidc-client-id')?.value || '',
        oidc_client_secret: document.getElementById('oidc-client-secret')?.value || '',
        oidc_redirect_uri: document.getElementById('oidc-redirect-uri')?.value || '',
        oidc_role_claim: document.getElementById('oidc-role-claim')?.value || 'groups',
        oidc_role_map: document.getElementById('oidc-role-map')?.value || '',
        sso_role_source: document.getElementById('sso-role-source')?.value || 'surveytrace',
        breakglass_enabled: !!document.getElementById('breakglass-enabled')?.checked,
        breakglass_username: document.getElementById('breakglass-username')?.value || 'admin',
    };
    const r = await apiPost('/api/settings.php', body);
    if (r && r.ok) {
        const sec = document.getElementById('oidc-client-secret');
        if (sec) sec.value = '';
        updateAccessControlModeVisibility();
        toast('Access settings updated', 'ok');
        await initAuthMode();
    } else {
        toast((r && r.error) ? r.error : 'Save failed', 'err');
    }
}

async function loadAuthUsers() {
    const tbody = document.getElementById('auth-users-tbody');
    if (!tbody) return;
    const r = await api('/api/auth.php?users=1');
    if (!r || !r.ok) {
        tbody.innerHTML = '<tr><td colspan="7" class="text-dim">Role management unavailable for current account.</td></tr>';
        const liveTbody = document.getElementById('auth-live-tbody');
        if (liveTbody) liveTbody.innerHTML = '<tr><td colspan="5" class="text-dim">Live auth view unavailable for current account.</td></tr>';
        const auditTbody = document.getElementById('auth-audit-tbody');
        if (auditTbody) auditTbody.innerHTML = '<tr><td colspan="5" class="text-dim">Audit log unavailable for current account.</td></tr>';
        return;
    }
    const users = r.users || [];
    tbody.innerHTML = users.length ? users.map(u => `
      <tr>
        <td><input class="finp" id="u-name-${u.id}" value="${esc(u.username)}"></td>
        <td><input class="finp" id="u-dn-${u.id}" value="${esc(u.display_name || '')}" placeholder="Optional"></td>
        <td><input class="finp" id="u-em-${u.id}" value="${esc(u.email || '')}" placeholder="Optional"></td>
        <td>
          <select class="finp" id="u-role-${u.id}">
            <option value="viewer"${u.role==='viewer'?' selected':''}>viewer</option>
            <option value="scan_editor"${u.role==='scan_editor'?' selected':''}>scan_editor</option>
            <option value="admin"${u.role==='admin'?' selected':''}>admin</option>
          </select>
        </td>
        <td class="mono-sm">${u.mfa_enabled ? 'enabled' : 'off'}</td>
        <td><input type="checkbox" id="u-dis-${u.id}" ${u.disabled ? 'checked' : ''}></td>
        <td class="user-row-actions">
          <button class="tbtn btn-xs" onclick="saveAuthUserQuick(${u.id})" title="Save account settings without changing password">Save</button>
          <button class="tbtn btn-xs" onclick="saveAuthUser(${u.id})" title="Set temporary password">Password</button>
          ${u.auth_source === 'local' && u.mfa_enabled ? `<button class="tbtn btn-xs" onclick="resetUserMfa(${u.id})">Clear MFA</button>` : ''}
          <button class="tbtn btn-xs" onclick="deleteAuthUser(${u.id})">Delete</button>
        </td>
      </tr>`).join('')
      : '<tr><td colspan="7" class="text-dim">No users</td></tr>';
    void Promise.allSettled([loadAuthLive(), loadAuthAudit()]);
}

function renderAuditAction(action) {
    const s = String(action || '');
    if (!s) return 'event';
    return s.replace(/^admin\./, '').replace(/^auth\./, '').replace(/_/g, ' ');
}

async function loadAuthLive() {
    const tbody = document.getElementById('auth-live-tbody');
    if (!tbody) return;
    try {
        const resp = await fetch('/api/auth.php?audit_live=1', { credentials: 'same-origin' });
        const raw = await resp.text();
        let r = null;
        try { r = raw ? JSON.parse(raw) : null; } catch (e) { r = null; }
        if (!resp.ok || !r || !r.ok) {
            const msg = (r && (r.error || r.detail)) ? String(r.error || r.detail) : (`HTTP ${resp.status}`);
            tbody.innerHTML = `<tr><td colspan="5" class="text-dim">Live auth view unavailable (${esc(msg.slice(0, 220))}).</td></tr>`;
            return;
        }
        const rows = Array.isArray(r.live) ? r.live : [];
        if (r.warning) {
            const detail = r.detail ? ` (${String(r.detail).slice(0, 180)})` : '';
            tbody.innerHTML = `<tr><td colspan="5" class="text-dim">Live auth view unavailable${esc(detail)}.</td></tr>`;
            return;
        }
        tbody.innerHTML = rows.length ? rows.map(ev => `
          <tr>
            <td class="mono-sm">${esc(ev.username_norm || '—')}</td>
            <td class="mono-sm">${esc(String(ev.failed_count ?? 0))}</td>
            <td class="mono-sm">${esc(localTime(ev.last_failed_at || ''))}</td>
            <td class="mono-sm">${esc(localTime(ev.locked_until || ''))}</td>
            <td class="mono-sm">${esc(ev.source_ip || '—')}</td>
          </tr>`).join('')
          : '<tr><td colspan="5" class="text-dim">No active sign-in failures or lockouts.</td></tr>';
    } catch (e) {
        tbody.innerHTML = '<tr><td colspan="5" class="text-dim">Live auth view unavailable for current account.</td></tr>';
    }
}

async function loadAuthAudit() {
    const tbody = document.getElementById('auth-audit-tbody');
    if (!tbody) return;
    try {
        const resp = await fetch('/api/auth.php?audit=1&limit=50', { credentials: 'same-origin' });
        const raw = await resp.text();
        let r = null;
        try { r = raw ? JSON.parse(raw) : null; } catch (e) { r = null; }
        if (!resp.ok || !r || !r.ok) {
            const msg = (r && (r.error || r.detail)) ? String(r.error || r.detail) : (`HTTP ${resp.status}`);
            tbody.innerHTML = `<tr><td colspan="5" class="text-dim">Audit log unavailable (${esc(msg.slice(0, 220))}).</td></tr>`;
            return;
        }
        const rows = Array.isArray(r.audit) ? r.audit : [];
        if (r.warning) {
            const detail = r.detail ? ` (${String(r.detail).slice(0, 180)})` : '';
            tbody.innerHTML = `<tr><td colspan="5" class="text-dim">Audit log unavailable${esc(detail)}.</td></tr>`;
            return;
        }
        tbody.innerHTML = rows.length ? rows.map(ev => `
          <tr>
            <td class="mono-sm">${esc(localTime(ev.created_at || ''))}</td>
            <td class="mono-sm">${esc(renderAuditAction(ev.action || ''))}</td>
            <td class="mono-sm">${esc(ev.actor_username || 'system')}</td>
            <td class="mono-sm">${esc(ev.target_username || '—')}</td>
            <td class="mono-sm">${esc(ev.source_ip || '—')}</td>
          </tr>`).join('')
          : '<tr><td colspan="5" class="text-dim">No user activity yet.</td></tr>';
    } catch (e) {
        tbody.innerHTML = '<tr><td colspan="5" class="text-dim">Audit log unavailable for current account.</td></tr>';
    }
}

async function deleteAuthUser(id) {
    const username = (document.getElementById(`u-name-${id}`)?.value || '').trim() || `#${id}`;
    const ok = await showConfirmModal(
        `Delete user ${username}? This removes account access and MFA/recovery records.`,
        { title: 'Delete user account', okText: 'Delete user' }
    );
    if (!ok) return;
    const r = await apiPost('/api/auth.php?users=1', { id, delete_user: true });
    if (r && r.ok) {
        toast('User deleted', 'ok');
        loadAuthUsers();
    } else {
        toast((r && r.error) ? r.error : 'Delete failed', 'err');
    }
}

async function saveAuthUser(id) {
    const username = (document.getElementById(`u-name-${id}`)?.value || '').trim();
    const displayName = (document.getElementById(`u-dn-${id}`)?.value || '').trim();
    const email = (document.getElementById(`u-em-${id}`)?.value || '').trim();
    const role = document.getElementById(`u-role-${id}`)?.value || 'viewer';
    const disabled = !!document.getElementById(`u-dis-${id}`)?.checked;
    if (!username) {
        toast('Username is required', 'err');
        return;
    }
    pendingUserSave = { id, username, displayName, email, role, disabled, requirePassword: false };
    openUserPasswordModal(username);
}

async function saveAuthUserQuick(id) {
    const username = (document.getElementById(`u-name-${id}`)?.value || '').trim();
    const displayName = (document.getElementById(`u-dn-${id}`)?.value || '').trim();
    const email = (document.getElementById(`u-em-${id}`)?.value || '').trim();
    const role = document.getElementById(`u-role-${id}`)?.value || 'viewer';
    const disabled = !!document.getElementById(`u-dis-${id}`)?.checked;
    if (!username) {
        toast('Username is required', 'err');
        return;
    }
    const body = {
        id,
        username,
        display_name: displayName,
        email,
        role,
        disabled
    };
    const r = await apiPost('/api/auth.php?users=1', body);
    if (r && r.ok) {
        toast('User updated', 'ok');
        loadAuthUsers();
    } else {
        toast((r && r.error) ? r.error : 'Update failed', 'err');
    }
}

function openUserPasswordModal(username) {
    const bg = document.getElementById('user-pw-bg');
    const msg = document.getElementById('user-pw-msg');
    const pw = document.getElementById('user-pw-new');
    const pwc = document.getElementById('user-pw-confirm');
    const required = !!(pendingUserSave && pendingUserSave.requirePassword);
    if (msg) {
        msg.textContent = required
            ? `Set a temporary password for ${username}. They will be required to change it at first sign-in.`
            : `Set a temporary password for ${username} or leave blank to keep current.`;
    }
    if (pw) pw.value = '';
    if (pwc) pwc.value = '';
    if (pw) pw.placeholder = required ? 'Temporary password' : 'Leave blank to keep current';
    if (pwc) pwc.placeholder = required ? 'Confirm temporary password' : 'Must match temporary password';
    if (bg) bg.style.display = 'flex';
    if (pw) pw.focus();
}

function closeUserPasswordModal() {
    const bg = document.getElementById('user-pw-bg');
    if (bg) bg.style.display = 'none';
    pendingUserSave = null;
}

async function submitAuthUserSave() {
    if (!pendingUserSave) return;
    const body = {
        username: pendingUserSave.username,
        display_name: pendingUserSave.displayName || '',
        email: pendingUserSave.email || '',
        role: pendingUserSave.role,
        disabled: pendingUserSave.disabled
    };
    if (pendingUserSave.id > 0) body.id = pendingUserSave.id;
    const pwd = document.getElementById('user-pw-new')?.value || '';
    const pwdConfirm = document.getElementById('user-pw-confirm')?.value || '';
    const required = !!pendingUserSave.requirePassword;
    if (required && String(pwd).trim() === '') {
        toast('Temporary password is required', 'err');
        return;
    }
    if (String(pwd).trim() !== '' || String(pwdConfirm).trim() !== '') {
        if (pwd !== pwdConfirm) {
            toast('Temporary password fields do not match', 'err');
            return;
        }
    }
    if (String(pwd).trim() !== '') body.password = String(pwd);
    const r = await apiPost('/api/auth.php?users=1', body);
    if (r && r.ok) {
        const wasCreate = !pendingUserSave.id;
        closeUserPasswordModal();
        if (wasCreate) {
            const un = document.getElementById('new-auth-user');
            if (un) un.value = '';
            const ur = document.getElementById('new-auth-role');
            if (ur) ur.value = 'viewer';
        }
        toast(wasCreate ? 'User created' : 'User updated', 'ok');
        loadAuthUsers();
    } else {
        toast((r && r.error) ? r.error : (pendingUserSave.id ? 'Update failed' : 'Create failed'), 'err');
    }
}

async function createAuthUser() {
    const username = (document.getElementById('new-auth-user')?.value || '').trim();
    const role = document.getElementById('new-auth-role')?.value || 'viewer';
    if (!username) {
        toast('Username is required', 'err');
        return;
    }
    pendingUserSave = { id: 0, username, role, disabled: false, requirePassword: true };
    openUserPasswordModal(username);
}

async function beginMfaSetup() {
    const r = await apiPost('/api/auth.php?mfa_setup=1', {});
    if (!(r && r.ok && r.secret)) {
        toast((r && r.error) ? r.error : 'Could not start MFA setup', 'err');
        return;
    }
    pendingMfaSecret = r.secret;
    pendingMfaOtpUri = String(r.otpauth_uri || '');
    const box = document.getElementById('mfa-setup-box');
    const sec = document.getElementById('mfa-secret');
    const qr = document.getElementById('mfa-qr');
    const qrStatus = document.getElementById('mfa-qr-status');
    const copyBtn = document.getElementById('mfa-copy-uri-btn');
    const recBox = document.getElementById('mfa-recovery-box');
    const recTa = document.getElementById('mfa-recovery-codes');
    if (sec) sec.textContent = pendingMfaSecret;
    if (pendingMfaQrUrl) {
        URL.revokeObjectURL(pendingMfaQrUrl);
        pendingMfaQrUrl = '';
    }
    if (qr) {
        qr.classList.add('hide');
        qr.src = '';
    }
    if (qrStatus) qrStatus.textContent = 'Generating local QR code...';
    if (pendingMfaOtpUri) {
        try {
            const headers = {'Content-Type': 'application/json'};
            if (csrfToken) headers['X-CSRF-Token'] = csrfToken;
            const qrr = await fetch('/api/auth_qr.php', {
                method: 'POST',
                credentials: 'same-origin',
                headers: headers,
                body: JSON.stringify({otpauth_uri: pendingMfaOtpUri})
            });
            const ct = (qrr.headers.get('content-type') || '').toLowerCase();
            if (qrr.ok && ct.includes('image/png')) {
                const blob = await qrr.blob();
                pendingMfaQrUrl = URL.createObjectURL(blob);
                if (qr) {
                    qr.src = pendingMfaQrUrl;
                    qr.classList.remove('hide');
                }
                if (qrStatus) qrStatus.textContent = 'Scan this QR with your authenticator app.';
            } else {
                let msg = 'Local QR generation unavailable; use setup link or manual secret';
                const err = await qrr.json().catch(() => null);
                if (err && err.error) {
                    msg = String(err.error);
                    if (err.detail) {
                        msg += ` (${String(err.detail)})`;
                    }
                }
                else {
                    const raw = await qrr.text().catch(() => '');
                    if (raw && raw.trim()) msg = `QR request failed (HTTP ${qrr.status}): ${raw.replace(/\s+/g, ' ').trim().slice(0, 160)}`;
                    else msg = `QR request failed (HTTP ${qrr.status})`;
                }
                if (qrStatus) qrStatus.textContent = msg;
                toast(msg, 'err');
            }
        } catch (e) {
            const msg = 'Local QR generation unavailable; use setup link or manual secret';
            if (qrStatus) qrStatus.textContent = msg;
            toast(msg, 'err');
        }
    }
    if (copyBtn) {
        copyBtn.onclick = async () => {
            if (!pendingMfaOtpUri) return;
            try {
                await navigator.clipboard.writeText(pendingMfaOtpUri);
                toast('Setup link copied', 'ok');
            } catch (e) {
                toast('Could not copy setup link; use the secret above instead', 'err');
            }
        };
    }
    pendingRecoveryCodes = [];
    if (recTa) recTa.value = '';
    if (recBox) recBox.classList.add('hide');
    if (box) box.classList.remove('hide');
    toast('MFA setup ready. Scan the local QR, or use setup link/manual secret.', 'ok');
}

async function confirmMfaEnable() {
    const otp = (document.getElementById('mfa-enable-otp')?.value || '').trim();
    if (!pendingMfaSecret || !otp) {
        toast('Generate setup secret and enter OTP code', 'err');
        return;
    }
    const r = await apiPost('/api/auth.php?mfa_enable=1', { secret: pendingMfaSecret, otp });
    if (r && r.ok) {
        pendingMfaSecret = '';
        pendingMfaOtpUri = '';
        currentUserMfaEnabled = true;
        updateMfaActionButtons();
        const box = document.getElementById('mfa-setup-box');
        if (box) box.classList.remove('hide');
        const otpEl = document.getElementById('mfa-enable-otp');
        if (otpEl) otpEl.value = '';
        const qr = document.getElementById('mfa-qr');
        if (qr) {
            qr.classList.add('hide');
            qr.src = '';
        }
        if (pendingMfaQrUrl) {
            URL.revokeObjectURL(pendingMfaQrUrl);
            pendingMfaQrUrl = '';
        }
        pendingRecoveryCodes = Array.isArray(r.recovery_codes) ? r.recovery_codes.slice() : [];
        const recBox = document.getElementById('mfa-recovery-box');
        const recTa = document.getElementById('mfa-recovery-codes');
        if (recTa) recTa.value = pendingRecoveryCodes.join('\n');
        if (recBox) recBox.classList.toggle('hide', pendingRecoveryCodes.length === 0);
        toast(pendingRecoveryCodes.length ? 'MFA is now enabled. Save your recovery codes now.' : 'MFA is now enabled', 'ok');
        loadAuthUsers();
    } else {
        toast((r && r.error) ? r.error : 'Could not enable MFA', 'err');
    }
}

async function disableMfaForSelf() {
    const otp = (document.getElementById('mfa-disable-otp')?.value || '').trim();
    const recovery = (document.getElementById('mfa-disable-recovery')?.value || '').trim();
    if (!otp && !recovery) {
        toast('Enter an authenticator code or recovery code', 'err');
        return;
    }
    const body = recovery ? { recovery_code: recovery } : { otp: otp };
    const r = await apiPost('/api/auth.php?mfa_disable=1', body);
    if (r && r.ok) {
        closeMfaDisableModal();
        currentUserMfaEnabled = false;
        updateMfaActionButtons();
        toast('MFA is now disabled', 'ok');
        loadAuthUsers();
    } else {
        toast((r && r.error) ? r.error : 'Could not disable MFA', 'err');
    }
}

function openMfaDisableModal() {
    const bg = document.getElementById('mfa-disable-bg');
    const otp = document.getElementById('mfa-disable-otp');
    const recovery = document.getElementById('mfa-disable-recovery');
    if (otp) otp.value = '';
    if (recovery) recovery.value = '';
    if (bg) bg.style.display = 'flex';
    if (otp) otp.focus();
}

function closeMfaDisableModal() {
    const bg = document.getElementById('mfa-disable-bg');
    if (bg) bg.style.display = 'none';
}

function confirmDisableMfa() {
    disableMfaForSelf();
}

async function resetUserMfa(id) {
    const username = (document.getElementById(`u-name-${id}`)?.value || '').trim() || `#${id}`;
    const displayName = (document.getElementById(`u-dn-${id}`)?.value || '').trim();
    const email = (document.getElementById(`u-em-${id}`)?.value || '').trim();
    const role = document.getElementById(`u-role-${id}`)?.value || 'viewer';
    const disabled = !!document.getElementById(`u-dis-${id}`)?.checked;
    const ok = await showConfirmModal(
        `Clear MFA for ${username}? They will need to enroll MFA again at next sign-in.`,
        { title: 'Clear user MFA', okText: 'Clear MFA' }
    );
    if (!ok) return;
    const r = await apiPost('/api/auth.php?users=1', {
        id,
        username,
        display_name: displayName,
        email: email,
        role,
        disabled,
        reset_mfa: true
    });
    if (r && r.ok) {
        toast('User MFA cleared', 'ok');
        loadAuthUsers();
    } else {
        toast((r && r.error) ? r.error : 'Could not clear user MFA', 'err');
    }
}

function openPasswordChangeModal(required) {
    mustChangePasswordPending = !!required;
    const bg = document.getElementById('pw-change-bg');
    const msg = document.getElementById('pw-change-msg');
    const cur = document.getElementById('pw-change-current');
    const nw = document.getElementById('pw-change-new');
    const cf = document.getElementById('pw-change-confirm');
    if (msg) msg.textContent = required
        ? 'Password update required before continuing. Enter your temporary/current password, then choose a new password.'
        : 'Enter your current password, then choose a new password.';
    if (cur) cur.value = '';
    if (nw) nw.value = '';
    if (cf) cf.value = '';
    if (bg) bg.style.display = 'flex';
    if (cur) cur.focus();
}

function closePasswordChangeModal() {
    if (mustChangePasswordPending) return;
    const bg = document.getElementById('pw-change-bg');
    if (bg) bg.style.display = 'none';
}

async function submitPasswordChange() {
    const currentPassword = document.getElementById('pw-change-current')?.value || '';
    const newPassword = document.getElementById('pw-change-new')?.value || '';
    const confirmPassword = document.getElementById('pw-change-confirm')?.value || '';
    if (!currentPassword || !newPassword || !confirmPassword) {
        toast('Fill in all password fields', 'err');
        return;
    }
    if (newPassword !== confirmPassword) {
        toast('New passwords do not match', 'err');
        return;
    }
    const r = await apiPost('/api/auth.php?password_change=1', {
        current_password: currentPassword,
        new_password: newPassword
    });
    if (r && r.ok) {
        mustChangePasswordPending = false;
        const bg = document.getElementById('pw-change-bg');
        if (bg) bg.style.display = 'none';
        if (currentUser) currentUser.must_change_password = false;
        toast('Password updated successfully', 'ok');
    } else {
        toast((r && r.error) ? r.error : 'Could not change password', 'err');
    }
}

function copyMfaRecoveryCodes() {
    const text = pendingRecoveryCodes.join('\n');
    if (!text) {
        toast('No recovery codes to copy', 'err');
        return;
    }
    navigator.clipboard.writeText(text).then(
        () => toast('Recovery codes copied', 'ok'),
        () => toast('Copy failed', 'err')
    );
}

function downloadMfaRecoveryCodesTxt() {
    const text = pendingRecoveryCodes.join('\n');
    if (!text) {
        toast('No recovery codes to download', 'err');
        return;
    }
    const blob = new Blob([text + '\n'], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'surveytrace-mfa-recovery-codes.txt';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

function printMfaRecoveryCodes() {
    const text = pendingRecoveryCodes.join('\n');
    if (!text) {
        toast('No recovery codes to print', 'err');
        return;
    }
    const w = window.open('', '_blank', 'width=640,height=720');
    if (!w) {
        toast('Popup blocked; use Download .txt instead', 'err');
        return;
    }
    const html = `
<!doctype html><html><head><title>SurveyTrace MFA Recovery Codes</title>
<style>body{font-family:ui-monospace,Menlo,Consolas,monospace;padding:24px}h1{font-family:system-ui,sans-serif;font-size:20px}pre{font-size:16px;line-height:1.5}</style>
</head><body><h1>SurveyTrace MFA Recovery Codes</h1><pre>${esc(text)}</pre></body></html>`;
    w.document.open();
    w.document.write(html);
    w.document.close();
    w.focus();
    w.print();
}

/** Show either the paste+Save row or the masked+Remove row (never both). */
function syncNvdKeyFormVisibility(configured) {
    const emptyRow = document.getElementById('st-nvd-api-key-row-empty');
    const setRow = document.getElementById('st-nvd-api-key-row-set');
    const inp = document.getElementById('st-nvd-api-key');
    if (!emptyRow || !setRow) return;
    if (configured) {
        emptyRow.classList.add('hide');
        setRow.classList.remove('hide');
        if (inp) inp.value = '';
    } else {
        setRow.classList.add('hide');
        emptyRow.classList.remove('hide');
        if (inp) inp.value = '';
    }
}

async function saveSessionTimeout() {
    const inp = document.getElementById('st-session-timeout-min');
    let m = parseInt(String(inp && inp.value !== '' ? inp.value : '480'), 10);
    if (!Number.isFinite(m)) m = 480;
    m = Math.max(5, Math.min(10080, m));
    const r = await apiPost('/api/settings.php', { session_timeout_minutes: m });
    if (r && r.ok) {
        if (inp) inp.value = String(r.session_timeout_minutes);
        toast('Session timeout updated', 'ok');
    } else {
        toast((r && r.error) ? r.error : 'Save failed', 'err');
    }
}

async function saveExtraSafePorts() {
    const inp = document.getElementById('st-extra-safe-ports');
    const raw = String(inp && inp.value ? inp.value : '').trim();
    const r = await apiPost('/api/settings.php', { extra_safe_ports: raw });
    if (r && r.ok) {
        if (inp) inp.value = String(r.extra_safe_ports || '');
        toast('Extra routed safe ports updated', 'ok');
    } else {
        toast((r && r.error) ? r.error : 'Save failed', 'err');
    }
}

async function saveNvdApiKey() {
    const inp = document.getElementById('st-nvd-api-key');
    const v = String(inp && inp.value ? inp.value : '').trim();
    if (!v) {
        toast('Paste your NVD API key first', 'err');
        return;
    }
    const r = await apiPost('/api/settings.php', { nvd_api_key: v });
    if (r && r.ok) {
        if (inp) inp.value = '';
        syncNvdKeyFormVisibility(true);
        const nvdSt = document.getElementById('st-nvd-api-key-status');
        if (nvdSt) nvdSt.textContent = 'Use Remove key if you need to paste a different one.';
        toast('NVD API key saved', 'ok');
    } else {
        toast((r && r.error) ? r.error : 'Save failed', 'err');
    }
}

async function clearNvdApiKey() {
    if (!confirm('Remove the stored NVD API key from this server?')) return;
    const r = await apiPost('/api/settings.php', { nvd_api_key_remove: true });
    if (r && r.ok) {
        syncNvdKeyFormVisibility(false);
        const nvdSt = document.getElementById('st-nvd-api-key-status');
        if (nvdSt) {
            nvdSt.textContent = 'No key saved — sync uses the slower public rate limit unless NVD_API_KEY is set on the server.';
        }
        toast('NVD API key removed', 'ok');
    } else {
        toast((r && r.error) ? r.error : 'Remove failed', 'err');
    }
}

async function loadEnrichment() {
    const d = await api('/api/enrichment.php');
    if (!d) return;

    // Active sources list
    const list = d.sources || [];
    document.getElementById('enrich-list').innerHTML = list.length
        ? list.map(s => `
            <div class="enrich-row">
              <div class="grow">
                <div class="text-primary font11">${esc(s.label)}</div>
                <div class="status-text">${esc(s.source_type)} · priority ${s.priority}</div>
                ${s.last_test_msg ? `<div class="status-text" style="color:${s.last_test_ok?'var(--green)':'var(--red)'}">${esc(s.last_test_msg)}</div>` : ''}
              </div>
              <div class="badge-mini ${s.enabled ? 'badge-on' : 'badge-off'}">
                ${s.enabled ? 'enabled' : 'disabled'}
              </div>
              <button class="tbtn btn-xs"
                      data-id="${s.id}" data-type="${esc(s.source_type)}"
                      data-label="${esc(s.label)}" data-enabled="${s.enabled}"
                      data-priority="${s.priority}"
                      data-config="${esc(JSON.stringify(JSON.parse(s.config_json||'{}'))  )}"
                      onclick="editSourceFromBtn(this)">Edit</button>
              <button class="tbtn btn-xs danger" onclick="deleteSource(${s.id})">✕</button>
            </div>`).join('')
        : '<div class="hint-micro pad8y">No enrichment sources configured. Add one below.</div>';

    // Available types
    const types = d.available_types || [];
    document.getElementById('enrich-types').innerHTML = types.map(t => `
        <div class="mini-row">
          <div class="grow text-primary font11">${esc(t.label)}</div>
          <div class="badge-mini ${t.status==='ready'?'badge-ready':t.status==='partial'?'badge-partial':'badge-missing'}">
            ${t.status}
          </div>
          ${t.status==='ready'||t.status==='partial' ? `<button class="tbtn btn-xs" onclick="openAddSource('${t.type}')">+ Add</button>` : ''}
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
                    <select class="finp w100 mb10" id="esrc-f-${f.id}">
                      ${f.options.map(o => `<option value="${o}"${o===val?' selected':''}>${o}</option>`).join('')}
                    </select>`;
        }
        return `<label class="flbl">${esc(f.label)}</label>
                <input class="finp w100 mb10" id="esrc-f-${f.id}" type="${f.type}"
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
    if (!(await showConfirmModal(
        'Delete this enrichment source?',
        {title: 'Delete enrichment source', okText: 'Delete'}
    ))) return;
    const r = await fetch('/api/enrichment.php?id=' + id, {
        method: 'DELETE',
        credentials: 'same-origin',
        headers: csrfToken ? {'X-CSRF-Token': csrfToken} : {}
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

function feedSyncConflictReason(target) {
    const r = feedSyncRunning;
    if (target === 'nvd' && r.nvd && !r.all) return 'NVD sync is already running.';
    if (target === 'oui' && r.oui && !r.all) return 'OUI sync is already running.';
    if (target === 'webfp' && r.webfp && !r.all) return 'WebFP sync is already running.';
    if (target === 'all' && r.all) return 'A full feed sync is already running.';
    const any = r.nvd || r.oui || r.webfp || r.all;
    if (any) return 'A feed sync is already running. Wait for it to finish.';
    return null;
}

function refreshFeedSyncButtons() {
    const ra = feedSyncRunning;
    const any = ra.nvd || ra.oui || ra.webfp || ra.all;
    const cfg = {
        'btn-sync-nvd': { disabled: !!any, busy: ra.nvd && !ra.all },
        'btn-sync-oui': { disabled: !!any, busy: ra.oui && !ra.all },
        'btn-sync-webfp': { disabled: !!any, busy: ra.webfp && !ra.all },
        'btn-sync-all': { disabled: !!any, busy: !!ra.all },
    };
    FEED_SYNC_BTN_IDS.forEach(id => {
        const b = document.getElementById(id);
        if (!b) return;
        const c = cfg[id];
        b.disabled = c.disabled;
        b.classList.toggle('btn-busy', !!c.busy);
        b.textContent = c.busy ? 'Syncing…' : (FEED_SYNC_BTN_LABELS[id] || b.textContent);
    });
    const cancelFeed = document.getElementById('btn-cancel-feed-sync');
    if (cancelFeed) {
        cancelFeed.disabled = !(any && (ra.nvd || ra.all));
    }
}

function markFeedSyncStart(target) {
    const hadFp = feedSyncRunning.oui || feedSyncRunning.webfp || feedSyncRunning.all;
    if ((target === 'oui' || target === 'webfp' || target === 'all') && !hadFp) {
        fpSyncHadError = false;
    }
    if (target === 'all') {
        feedSyncRunning.all = true;
        feedSyncStartedAt.all = Date.now();
    } else {
        feedSyncRunning[target] = true;
        feedSyncStartedAt[target] = Date.now();
    }
    refreshFeedSyncButtons();
    ensureFeedSyncUiTimer();
}

function markFeedSyncEnd(target) {
    if (target === 'all') {
        feedSyncRunning.all = false;
        feedSyncStartedAt.all = 0;
    } else {
        feedSyncRunning[target] = false;
        feedSyncStartedAt[target] = 0;
    }
    refreshFeedSyncButtons();
    stopFeedSyncUiTimerIfIdle();
    const anyLeft = feedSyncRunning.nvd || feedSyncRunning.oui || feedSyncRunning.webfp || feedSyncRunning.all;
    if (!anyLeft) stopFeedSyncStatePolling();
}

function feedSyncTouchesNvd(t) { return t === 'nvd' || t === 'all'; }
function feedSyncTouchesFp(t) { return t === 'oui' || t === 'webfp' || t === 'all'; }

function refreshNvdStatusLineAfterEnd(target, errText, okText) {
    const el = document.getElementById('sync-status-nvd');
    if (!el || !feedSyncTouchesNvd(target)) return;
    const still = feedSyncRunning.nvd || feedSyncRunning.all;
    if (still) {
        tickFeedSyncStatusLines();
        return;
    }
    el.className = errText ? 'sync-status err' : 'sync-status ok';
    el.textContent = errText || okText || 'Sync complete.';
}

function refreshFpStatusLineAfterEnd(target, errText, okText) {
    const el = document.getElementById('sync-status-fp');
    if (!el || !feedSyncTouchesFp(target)) return;
    const still = feedSyncRunning.oui || feedSyncRunning.webfp || feedSyncRunning.all;
    if (still) {
        tickFeedSyncStatusLines();
        return;
    }
    const useErr = errText || fpSyncHadError;
    el.className = useErr ? 'sync-status err' : 'sync-status ok';
    el.textContent = useErr
        ? (errText || 'One or more fingerprint feeds had errors. See output.')
        : (okText || 'Sync complete.');
    fpSyncHadError = false;
}

async function requestFeedSyncCancel() {
    const r = await apiPost('/api/feeds.php?cancel=1', {});
    if (r && r.ok) {
        toast('Stop requested — NVD sync should stop within a few seconds.', 'ok');
    } else {
        toast((r && r.error) ? String(r.error).slice(0, 140) : 'Cancel failed', 'err');
    }
}

function resetFeedSyncClientAfterServerClear() {
    feedSyncRunning = { nvd: false, oui: false, webfp: false, all: false };
    feedSyncStartedAt = { nvd: 0, oui: 0, webfp: 0, all: 0 };
    stopFeedSyncStatePolling();
    stopFeedSyncUiTimerIfIdle();
    refreshFeedSyncButtons();
    tickFeedSyncStatusLines();
    renderFeedSyncOutputPanel();
}

async function requestFeedSyncClearStuckState() {
    if (!(await showConfirmModal(
        'This removes the server “sync running” flag and the cancel marker. '
            + 'Use only when no feed sync is actually running (for example after you killed sync scripts on the server). '
            + 'If a sync is still running, stop it first or use Cancel sync.',
        { title: 'Reset sync lock', okText: 'Clear server state' }
    ))) return;
    const r = await apiPost('/api/feeds.php?clear_sync_state=1', {});
    if (r && r.ok) {
        resetFeedSyncClientAfterServerClear();
        toast('Feed sync lock cleared. You can start a new sync.', 'ok');
    } else {
        toast((r && r.error) ? String(r.error).slice(0, 140) : 'Reset failed', 'err');
    }
}

async function runFeedSync(target) {
    const conflict = feedSyncConflictReason(target);
    if (conflict) {
        toast(conflict, 'err');
        return;
    }
    markFeedSyncStart(target);

    toast('Starting ' + target + ' feed sync…', 'ok');
    feedSyncLastOutput = `[client] ${new Date().toISOString()} — starting ${target} feed sync...`;
    const r = await apiPost('/api/feeds.php?sync=1', {target});

    if (!r) {
        markFeedSyncEnd(target);
        if (feedSyncTouchesFp(target)) fpSyncHadError = true;
        feedSyncLastOutput = '[client] Feed sync request failed (no response)';
        toast('Feed sync request failed', 'err');
        refreshNvdStatusLineAfterEnd(target, 'Sync failed (no response).', null);
        refreshFpStatusLineAfterEnd(target, 'Sync failed (no response).', null);
        return;
    }
    if (!r.ok) {
        markFeedSyncEnd(target);
        if (feedSyncTouchesFp(target)) fpSyncHadError = true;
        const msg = (r.results && r.results.find(x => !x.ok)?.output) || r.error || 'Sync failed';
        toast(String(msg).slice(0, 120), 'err');
        refreshNvdStatusLineAfterEnd(target, 'Sync failed. See output for details.', null);
        refreshFpStatusLineAfterEnd(target, 'Sync failed. See output for details.', null);
        openFeedSyncOutput();
        return;
    }

    if (r.async && r.started) {
        toast('Feed sync running on the server — NVD can take several minutes. Status updates below.', 'ok');
        startFeedSyncStatePolling();
        return;
    }

    appendFeedSyncResultToOutput(target, r);

    markFeedSyncEnd(target);

    refreshNvdStatusLineAfterEnd(target, null, 'Sync complete.');
    refreshFpStatusLineAfterEnd(target, null, 'Sync complete.');

    const names = (r.results || []).map(x => x.script.replace('.py', '')).join(', ');
    toast('Feed sync complete: ' + names, 'ok');
    await loadDashboard();
    openFeedSyncOutput();
}

function openFeedSyncOutput() {
    const bg = document.getElementById('fsync-bg');
    if (!bg) return;
    renderFeedSyncOutputPanel();
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
            ? '<span class="paused-chip">Paused</span>'
            : '';

        // next_run is stored as UTC — display as local browser time
        let nextRun = '<span class="pending">pending</span>';
        if (s.next_run) {
            const nr = new Date(s.next_run + 'Z');  // append Z to treat as UTC
            const secs = s.secs_until_next;
            const timeStr = nr.toLocaleString([], {month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'});
            if (secs <= 0) {
                nextRun = '<span class="due-now">due now</span>';
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
            ? `<span class="status-text" style="color:${statColor[s.last_job_status]||'var(--tx2)'}">${s.last_job_status}</span>`
              + (s.last_hosts_found ? ` <span class="status-text">${s.last_hosts_found} hosts</span>` : '')
            : '—';

        const pauseResume = isOn
            ? (isPaused
                ? `<button class="tbtn btn-xxs" onclick="resumeSchedule(${s.id})" title="Resume schedule">Resume</button>`
                : `<button class="tbtn btn-xxs" onclick="pauseSchedule(${s.id})" title="Pause without deleting">Pause</button>`)
            : '';

        return `<tr>
          <td class="text-primary">${esc(s.name)}${pausedTag}</td>
          <td class="mono">${esc(s.target_cidr)}</td>
          <td class="status-text">${esc((s.profile||'').replace(/_/g,' '))}</td>
          <td class="mono">${esc(s.cron_expr)}</td>
          <td class="status-text" title="Catch-up when overdue">${missedLbl}</td>
          <td class="status-text">${nextRun}</td>
          <td class="status-text">${lastRun}</td>
          <td>${lastStat}</td>
          <td>
            <button class="tbtn btn-xs ${isOn ? 'toggle-on' : 'toggle-off'}"
              onclick="toggleSchedule(${s.id})"
              title="${isOn ? 'Click to disable' : 'Click to enable'}">
              ${isOn ? '● ON' : '○ OFF'}
            </button>
          </td>
          <td class="row-actions">
            <button class="tbtn btn-xxs" onclick="openSchedHist(${s.id})" title="Run history">Hist</button>
            ${pauseResume}
            <button class="tbtn btn-xs" onclick="runSchedNow(${s.id})" title="Run now">&#9654;</button>
            <button class="tbtn btn-xs" onclick="editSchedule(${s.id})">&#9998;</button>
            <button class="tbtn btn-xs" style="color:var(--red)" onclick="deleteSchedule(${s.id})">&#10005;</button>
          </td>
        </tr>`;
    }).join('');
}

function parseSchedEnrichmentIds(s) {
    if (!s) return null;
    const raw = s.enrichment_source_ids;
    if (raw === undefined || raw === null || raw === '') return null;
    if (Array.isArray(raw)) return raw;
    try {
        const j = JSON.parse(String(raw));
        return Array.isArray(j) ? j : null;
    } catch (e) {
        return null;
    }
}

async function refreshSchedEnrichmentPicker(selectedIds) {
    const wrap = document.getElementById('sched-enrichment-wrap');
    if (!wrap) return;
    wrap.dataset.ready = '0';
    wrap.innerHTML = '<div class="hint-micro">Loading…</div>';
    let data;
    try {
        data = await api('/api/enrichment.php', {quiet:true});
    } catch (e) {
        wrap.innerHTML = '<div class="hint-micro">Could not load enrichment sources</div>';
        return;
    }
    const srcs = (data && data.sources) ? data.sources : [];
    if (!srcs.length) {
        wrap.innerHTML = '<div class="hint-micro">No sources configured — add them under Enrichment.</div>';
        wrap.dataset.ready = '1';
        return;
    }
    const parts = [];
    for (const src of srcs) {
        const en = parseInt(src.enabled, 10) === 1;
        const id = parseInt(src.id, 10);
        const label = esc(src.label || src.source_type || '');
        const typ = esc(src.source_type || '');
        let checked = true;
        if (en) {
            if (selectedIds === null) checked = true;
            else if (Array.isArray(selectedIds) && selectedIds.length === 0) checked = false;
            else if (Array.isArray(selectedIds)) checked = selectedIds.includes(id);
            parts.push(`<div class="tr2"><div><div class="tl">${label}</div><div class="tsubl">${typ}</div></div><label class="tog"><input type="checkbox" data-enr-id="${id}" ${checked ? 'checked' : ''}><div class="trk"></div><div class="tth"></div></label></div>`);
        } else {
            parts.push(`<div class="tr2" style="opacity:0.55"><div><div class="tl">${label}</div><div class="tsubl">${typ} (disabled in Enrichment)</div></div><label class="tog"><input type="checkbox" disabled><div class="trk"></div><div class="tth"></div></label></div>`);
        }
    }
    wrap.innerHTML = parts.join('');
    wrap.dataset.ready = '1';
}

function schedEnrichmentPayloadField() {
    const wrap = document.getElementById('sched-enrichment-wrap');
    if (!wrap || wrap.dataset.ready !== '1') return undefined;
    const enabledBoxes = wrap.querySelectorAll('input[data-enr-id]');
    if (!enabledBoxes.length) return undefined;
    const checked = [];
    enabledBoxes.forEach(cb => { if (cb.checked) checked.push(parseInt(cb.dataset.enrId, 10)); });
    if (checked.length === enabledBoxes.length) return undefined;
    return checked;
}

async function openSchedModal(s) {
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
        const browserTz = Intl.DateTimeFormat().resolvedOptions().timeZone;
        tzSel.value = s ? (s.timezone||'UTC') : (browserTz||'UTC');
        if (tzSel.value !== (s ? (s.timezone||'UTC') : (browserTz||'UTC'))) {
            const opt = document.createElement('option');
            opt.value = browserTz;
            opt.textContent = browserTz;
            tzSel.appendChild(opt);
            tzSel.value = browserTz;
        }
    }

    document.getElementById('sched-priority').value = String(s ? (parseInt(s.priority, 10) || 20) : 20);

    if (!s) {
        applySchedProfileDefaults(document.getElementById('sched-profile').value);
    } else {
        const rp = parseInt(s.rate_pps, 10) || 5;
        document.getElementById('sched-pps').value = String(Math.max(1, Math.min(50, rp)));
        document.getElementById('sched-pps-val').textContent = document.getElementById('sched-pps').value + ' pps';
        const idel = parseInt(s.inter_delay, 10) || 200;
        document.getElementById('sched-delay').value = String(Math.max(0, Math.min(2000, idel)));
        document.getElementById('sched-delay-val').textContent = document.getElementById('sched-delay').value + ' ms';

        const defPh = ['passive','icmp','banner','fingerprint','cve'];
        let pArr = defPh;
        if (s.phases) {
            try {
                pArr = typeof s.phases === 'string' ? JSON.parse(s.phases) : (Array.isArray(s.phases) ? s.phases : defPh);
            } catch (e) {
                pArr = defPh;
            }
        }
        if (!Array.isArray(pArr)) pArr = defPh;
        ['passive','icmp','banner','fingerprint','snmp','ot','cve'].forEach(p => {
            const el = document.getElementById('sched-ph-' + p);
            if (el) el.checked = pArr.includes(p);
        });
        const prof = document.getElementById('sched-profile').value;
        updateSchedProfileHelp(prof);
        updateSchedProfileWarn(prof);
        syncSchedPhaseRowOpacityFromProfile();
    }

    await refreshSchedEnrichmentPicker(parseSchedEnrichmentIds(s));
    updateCronDesc();
    const schedBg = document.getElementById('sched-bg');
    schedBg.style.display = 'flex';
    const schedCard = schedBg.querySelector('.modal-card');
    if (schedCard) {
        const top = () => { schedCard.scrollTop = 0; };
        top();
        requestAnimationFrame(top);
    }
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
    if (s) await openSchedModal(s);
}

async function saveSchedule() {
    const id      = document.getElementById('sched-id').value;
    let mx = parseInt(document.getElementById('sched-missed-max')?.value || '5', 10);
    if (mx < 1) mx = 1;
    if (mx > 100) mx = 100;
    const schedPhKeys = ['passive','icmp','banner','fingerprint','snmp','ot','cve'];
    const phases = [];
    schedPhKeys.forEach(p => {
        if (document.getElementById('sched-ph-' + p)?.checked) phases.push(p);
    });
    if (!phases.length) { toast('Select at least one scan phase', 'err'); return; }

    let pr = parseInt(document.getElementById('sched-priority')?.value || '20', 10);
    if (pr < 1) pr = 1;
    if (pr > 100) pr = 100;

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
        phases:      phases,
        rate_pps:    parseInt(document.getElementById('sched-pps')?.value || '5', 10) || 5,
        inter_delay: parseInt(document.getElementById('sched-delay')?.value || '200', 10) || 0,
        priority:    pr,
    };
    const enrSel = schedEnrichmentPayloadField();
    if (enrSel !== undefined) payload.enrichment_source_ids = enrSel;

    const profileVal = payload.profile;
    if (['deep_scan', 'full_tcp', 'fast_full_tcp', 'ot_careful'].includes(profileVal)) {
        const ok = await showConfirmModal(
            `Profile "${profileVal}" can generate significant network traffic and is meant for controlled use.\n\n` +
            `You are saving a recurring schedule — each run will repeat with these settings until you change or disable it.\n\n` +
            `Save this schedule?`,
            {title: 'Confirm high-impact scheduled scan', okText: 'Save schedule'}
        );
        if (!ok) return;
        payload.confirmed = true;
    }

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
    if (!(await showConfirmModal(
        'Delete this schedule? This cannot be undone.',
        {title: 'Delete schedule', okText: 'Delete'}
    ))) return;
    const r = await fetch(`/api/schedules.php?id=${id}`, {
        method: 'DELETE',
        credentials: 'same-origin',
        headers: csrfToken ? {'X-CSRF-Token': csrfToken} : {}
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
          <td class="mono font11"><a href="#" onclick="openJobFromHist(${r.id});return false">${r.id}</a></td>
          <td class="status-text">${esc(r.status || '')}</td>
          <td class="text-secondary font11">${esc(r.label || '')}</td>
          <td class="status-text">${hosts}</td>
          <td class="status-text">${toLoc(r.created_at)}</td>
          <td class="status-text">${toLoc(r.finished_at)}</td>
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

    const headers = {'Content-Type': 'application/json'};
    if (csrfToken) headers['X-CSRF-Token'] = csrfToken;
    const r = await fetch(`/api/assets.php?id=${id}`, {
        method: 'PUT',
        headers: headers,
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
const PROFILE_HELP_TEXT = {
    standard_inventory: {
        title: 'Standard Inventory',
        text:  'Balanced default for general-purpose networks. Scans common ports with light banner probing, then correlates CVEs.'
    },
    iot_safe: {
        title: 'IoT Safe',
        text:  'Passive-first and low risk. No banner probing or aggressive checks. Best for smart-home and sensitive embedded devices.'
    },
    deep_scan: {
        title: 'Deep Scan',
        text:  'Higher depth and higher traffic. Uses stronger service detection and enrichment for detailed investigations of selected scopes.'
    },
    full_tcp: {
        title: 'Full TCP',
        text:  'Scans all 65,535 TCP ports with deeper service detection. Highest coverage, longest runtime.'
    },
    fast_full_tcp: {
        title: 'Fast Full TCP',
        text:  'Scans all TCP ports with lighter detection and shorter host timeouts. Better responsiveness on /24 and larger sweeps.'
    },
    ot_careful: {
        title: 'OT Careful',
        text:  'Conservative profile for industrial environments. Passive-oriented defaults and strict pacing to minimize disruption risk. New schedules default read-only OT protocol probes on — clear the toggle for passive-only.'
    }
};

function updateProfileHelp(profile) {
    const box = document.getElementById('profile-help');
    if (!box) return;
    const info = PROFILE_HELP_TEXT[profile] || PROFILE_HELP_TEXT.standard_inventory;
    box.innerHTML = `<strong style="color:var(--tx)">${esc(info.title)}:</strong> ${esc(info.text)}`;
}

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
        const snmpScan = document.getElementById('ph-snmp');
        const otScan = document.getElementById('ph-ot');
        if (profile === 'deep_scan' || profile === 'full_tcp' || profile === 'fast_full_tcp') {
            if (snmpScan) snmpScan.checked = true;
            if (otScan) otScan.checked = false;
        } else if (profile === 'ot_careful') {
            if (snmpScan) snmpScan.checked = false;
            if (otScan) otScan.checked = true;
        } else {
            if (snmpScan) snmpScan.checked = false;
            if (otScan) otScan.checked = false;
        }
        updateProfileHelp(profile);
    });
});

// ---------------------------------------------------------------------------
// Schedule modal — profile presets (aligned with manual Scan tab)
// ---------------------------------------------------------------------------
const SCHED_HIGH_IMPACT_PROFILES = ['deep_scan', 'full_tcp', 'fast_full_tcp', 'ot_careful'];
const SCHED_PROFILE_RATE_DEFAULTS = {
    iot_safe:             { pps: 2,  delay: 500 },
    ot_careful:           { pps: 1,  delay: 1000 },
    standard_inventory:   { pps: 5,  delay: 200 },
    deep_scan:            { pps: 50, delay: 50 },
    full_tcp:             { pps: 50, delay: 25 },
    fast_full_tcp:        { pps: 50, delay: 10 },
};

function applySchedProfileDefaults(profile) {
    const allowBanner = !['iot_safe', 'ot_careful'].includes(profile);
    ['sched-ph-banner', 'sched-ph-fingerprint', 'sched-ph-cve'].forEach(id => {
        const el = document.getElementById(id);
        if (el) {
            el.checked = allowBanner;
            const tr = el.closest('.tr2');
            if (tr) tr.style.opacity = allowBanner ? '1' : '0.4';
        }
    });
    const passive = document.getElementById('sched-ph-passive');
    const icmp = document.getElementById('sched-ph-icmp');
    if (passive) passive.checked = true;
    if (icmp) icmp.checked = true;
    const snmpEl = document.getElementById('sched-ph-snmp');
    const otEl = document.getElementById('sched-ph-ot');
    if (profile === 'deep_scan' || profile === 'full_tcp' || profile === 'fast_full_tcp') {
        if (snmpEl) snmpEl.checked = true;
        if (otEl) otEl.checked = false;
    } else if (profile === 'ot_careful') {
        if (snmpEl) snmpEl.checked = false;
        if (otEl) otEl.checked = true;
    } else {
        if (snmpEl) snmpEl.checked = false;
        if (otEl) otEl.checked = false;
    }
    const rdef = SCHED_PROFILE_RATE_DEFAULTS[profile] || SCHED_PROFILE_RATE_DEFAULTS.standard_inventory;
    const pps = Math.max(1, Math.min(50, rdef.pps));
    const del = Math.max(0, Math.min(2000, rdef.delay));
    const ppsEl = document.getElementById('sched-pps');
    const delEl = document.getElementById('sched-delay');
    const ppsVal = document.getElementById('sched-pps-val');
    const delVal = document.getElementById('sched-delay-val');
    if (ppsEl) ppsEl.value = String(pps);
    if (ppsVal) ppsVal.textContent = pps + ' pps';
    if (delEl) delEl.value = String(del);
    if (delVal) delVal.textContent = del + ' ms';

    const modeEl = document.getElementById('sched-mode');
    if (modeEl && (profile === 'iot_safe' || profile === 'ot_careful') && modeEl.value === 'force') {
        modeEl.value = 'auto';
        toast('Discovery mode set to Auto — this profile does not allow Force (-Pn).', 'ok');
    }
    if (!['iot_safe', 'ot_careful'].includes(profile)) {
        ['sched-ph-banner', 'sched-ph-fingerprint', 'sched-ph-cve'].forEach(id => {
            const el = document.getElementById(id);
            const tr = el && el.closest('.tr2');
            if (tr) tr.style.opacity = '1';
        });
    }
    updateSchedProfileHelp(profile);
    updateSchedProfileWarn(profile);
}

function updateSchedProfileHelp(profile) {
    const box = document.getElementById('sched-profile-help');
    if (!box) return;
    const info = PROFILE_HELP_TEXT[profile] || PROFILE_HELP_TEXT.standard_inventory;
    box.innerHTML = `<strong style="color:var(--tx)">${esc(info.title)}:</strong> ${esc(info.text)}`;
}

function updateSchedProfileWarn(profile) {
    const w = document.getElementById('sched-profile-warn');
    if (!w) return;
    if (SCHED_HIGH_IMPACT_PROFILES.includes(profile)) {
        w.style.display = 'block';
        const lines = {
            deep_scan: 'Deep Scan uses stronger service detection and more probes. Traffic and runtime are higher than Standard Inventory.',
            full_tcp: 'Full TCP probes all 65,535 TCP ports. Expect high traffic and long runtimes on larger ranges.',
            fast_full_tcp: 'Fast Full TCP still scans all TCP ports with lighter detection — traffic remains high across the full target.',
            ot_careful: 'OT Careful limits active probing, but the scanner still requires explicit confirmation before recurring use of this profile.',
        };
        w.innerHTML = '<strong>Warning:</strong> ' + esc(lines[profile] || 'This profile has elevated network impact.');
    } else {
        w.style.display = 'none';
        w.innerHTML = '';
    }
}

function syncSchedPhaseRowOpacityFromProfile() {
    const profile = document.getElementById('sched-profile')?.value || 'standard_inventory';
    const allowBanner = !['iot_safe', 'ot_careful'].includes(profile);
    ['sched-ph-banner', 'sched-ph-fingerprint', 'sched-ph-cve'].forEach(id => {
        const el = document.getElementById(id);
        const tr = el && el.closest('.tr2');
        if (tr) tr.style.opacity = allowBanner ? '1' : '0.4';
    });
}

document.getElementById('sched-profile')?.addEventListener('change', function() {
    applySchedProfileDefaults(this.value);
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
// Host detail — friendly port labels (title + common homelab stacks)
// ==========================================================================
function extractBracketTitles(text) {
    const s = String(text || '');
    const out = [];
    const re = /\[([^\]]+)\]/g;
    let m;
    while ((m = re.exec(s)) !== null) {
        const t = m[1].trim();
        if (t && !out.includes(t)) out.push(t);
    }
    return out;
}

function firstHttpTitle(rawBanner, httpProbe) {
    for (const t of extractBracketTitles(rawBanner)) {
        if (/^https?$/i.test(t)) continue;
        return t;
    }
    for (const t of extractBracketTitles(httpProbe)) {
        if (/^https?$/i.test(t)) continue;
        return t;
    }
    return '';
}

/**
 * NPM (Nginx Proxy Manager) — only label when evidence is strong.
 * Avoid: generic "Default Site" titles, bare OpenResty, or plain nginx (false positives).
 */
function likelyNpmReverseProxy(allPorts, raw, probe) {
    const set = new Set((allPorts || []).map(Number));
    const blob = (String(raw || '') + '\n' + String(probe || '')).toLowerCase();
    // NPM exposes admin on 81 by default — strongest signal with other ports.
    if (set.has(81)) return true;
    // Explicit product strings from NPM UI / docs / responses
    if (/nginx[-\s]?proxy[-\s]?manager|nginxproxymanager|nginx proxy manager/.test(blob)) return true;
    return false;
}

function buildFriendlyOpenPortLine(port, rawBanner, httpProbe, allPorts) {
    const raw = String(rawBanner || '');
    const probe = String(httpProbe || '');
    const low = raw.toLowerCase();
    const title = firstHttpTitle(raw, probe);
    const npm = likelyNpmReverseProxy(allPorts, raw, probe);

    if (port === 80) {
        if (npm) {
            const t = title ? `HTTP (${title})` : 'HTTP';
            return t + ' — NPM reverse proxy';
        }
        return title ? `HTTP (${title})` : (raw ? raw : 'HTTP');
    }
    if (port === 443) {
        if (npm) {
            const t = title ? `HTTPS (${title})` : 'HTTPS';
            return t + ' — NPM reverse proxy';
        }
        return title ? `HTTPS (${title})` : (raw ? raw : 'HTTPS');
    }
    if (port === 81) {
        return likelyNpmReverseProxy(allPorts, raw, probe)
            ? 'NPM Proxy Manager (admin UI)'
            : 'HTTP — port 81';
    }

    if (port === 445) return 'SMB — Windows file sharing';
    if (port === 3389) return 'RDP — Remote Desktop';

    if (port === 3000) {
        const t = firstHttpTitle(raw, probe);
        if (/homarr/i.test(raw + probe + t)) return 'Homarr (dashboard)';
        if (/homepage/i.test(raw + probe + t)) return 'Homepage (dashboard)';
        if (/grafana/i.test(raw + probe + t)) return 'Grafana';
        return 'Web dashboard (Homarr / Grafana / dev)';
    }

    if (port === 5000 && /werkzeug/i.test(low)) return 'Python app (Werkzeug)';
    if (port === 8080) {
        const t = firstHttpTitle(raw, probe);
        if (/it tools/i.test(raw + probe + t)) return 'IT Tools (developer utilities)';
    }
    if (port === 8089) {
        const t = firstHttpTitle(raw, probe);
        if (/channels/i.test(raw + probe + t)) return 'Channels';
    }
    if (port === 8888) {
        const t = firstHttpTitle(raw, probe);
        if (/web check/i.test(raw + probe + t)) return 'Web Check';
    }

    if (port === 9000) return 'Portainer (HTTP)';
    if (port === 9443) return 'Portainer (HTTPS)';

    const parts = raw.split(' ');
    const proto = parts[0] || '';
    const rest = parts.slice(1).join(' ');
    if (rest) return rest;
    return proto || 'open';
}

function collectDetectedServiceChips(ports, banners, httpProbe) {
    const chips = new Set();
    const probe = String(httpProbe || '');
    const all = ports || [];
    for (const p of all) {
        const raw = String((banners || {})[String(p)] || '');
        const low = raw.toLowerCase();
        if (p === 80 || p === 443 || p === 81) {
            if (likelyNpmReverseProxy(all, raw, probe)) chips.add('NPM');
        }
        if (p === 3389) chips.add('RDP');
        if (p === 445) chips.add('SMB');
        if (p === 3000) {
            const t = firstHttpTitle(raw, probe);
            if (/homarr/i.test(raw + probe + t)) chips.add('Homarr');
            else if (/homepage/i.test(raw + probe + t)) chips.add('Homepage');
            else if (/grafana/i.test(raw + probe + t)) chips.add('Grafana');
        }
        if (p === 5000 && /werkzeug/i.test(low)) chips.add('Werkzeug');
        if (p === 8080) {
            const t = firstHttpTitle(raw, probe);
            if (/it tools/i.test(raw + probe + t)) chips.add('IT Tools');
        }
        if (p === 8089) {
            const t = firstHttpTitle(raw, probe);
            if (/channels/i.test(raw + probe + t)) chips.add('Channels');
        }
        if (p === 8888) {
            const t = firstHttpTitle(raw, probe);
            if (/web check/i.test(raw + probe + t)) chips.add('Web Check');
        }
        if (p === 9000 || p === 9443) chips.add('Portainer');
        if (/splunk/i.test(raw + probe) && (p === 8088 || p === 8089 || p === 8000)) chips.add('Splunk');
        if (/jupyter/i.test(raw + probe)) chips.add('Jupyter');
        if (/minio/i.test(raw + probe)) chips.add('MinIO');
    }
    if (/portainer/i.test(probe)) chips.add('Portainer');

    const blob = all.map(pr => String((banners || {})[String(pr)] || '')).join('\n') + '\n' + probe;
    const EXTRA_SIGS = [
        ['Zabbix', /zabbix/i], ['ntfy', /\bntfy\b/i],
        ['Kasm Workspaces', /\bkasm(web|vnc)?\b|kasmtechnologies/i],
        ['Proxmox VE', /proxmox|pve\./i], ['Docker Engine', /\bdocker engine\b|docker\/v|\bdockerd\b/i],
        ['Jellyfin', /jellyfin/i], ['Gitea', /\bgitea\b/i], ['Nextcloud', /nextcloud/i],
        ['Mastodon', /mastodon/i], ['OpenObserve', /openobserve/i],
        ['Uptime Kuma', /uptime.?kuma/i], ['InfluxDB', /\binfluxdb?\b/i],
    ];
    for (const [name, rx] of EXTRA_SIGS) {
        if (rx.test(blob)) chips.add(name);
    }
    return Array.from(chips).sort();
}

// ==========================================================================
// Host detail panel
// ==========================================================================
async function openHostPanel(id, ip) {
    closeDevicePanel();
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

    const hn = String(a.hostname || '').trim();
    document.getElementById('hp-title').textContent = hn
        ? `${a.ip} (${a.category || 'unk'} / ${hn})`
        : `${a.ip} (${a.category || 'unk'})`;

    const serviceChips = collectDetectedServiceChips(ports, banners, httpProbe);

    const portRows = ports.length ? ports.map(p => {
        const rawBanner = banners[String(p)] || '';
        const friendly = buildFriendlyOpenPortLine(p, rawBanner, httpProbe, ports);

        return `<div class="hp-port-row">
          <span class="hp-port-num">${p}</span>
          <div class="minw0 grow">
            <div class="hp-port-text">
              <span class="hp-arrow">→</span>
              ${esc(friendly)}
            </div>
            ${rawBanner ? `<details class="mt4"><summary class="hp-raw-summary">raw banner</summary>
              <div class="hp-raw-body">${esc(rawBanner)}</div>
            </details>` : ''}
          </div>
        </div>`;
    }).join('') : '<div class="hp-empty">No open ports detected</div>';

    const serviceRows = serviceChips.length
        ? `<div class="hp-chips">${
            serviceChips.map(s =>
                `<span class="hp-chip">${esc(s)}</span>`
            ).join('')
          }</div>`
        : `<div class="hp-empty" style="padding:4px 0 12px">No specific app fingerprints detected yet</div>`;

    const findingRows = findings.length ? findings.map(f => `
        <div class="hp-block">
          <div class="hp-row">
            <span class="sev ${sevClass(f.cvss)} hp-sev-chip">${f.cvss != null ? esc(f.cvss) : '?'} ${esc((f.severity||'').toUpperCase())}</span>
            <span class="hp-cve">${esc(f.cve_id)}</span>
            <span class="hp-date">${localDate(f.published)}</span>
          </div>
          <div class="hp-desc">${esc(f.description||'').slice(0,180)}${(f.description||'').length>180?'…':''}</div>
          ${!f.resolved ? `<button class="tbtn btn-xs mt4" onclick="resolveFinding(${f.id},this);openHostPanel(${id},'${esc(ip)}')">Resolve</button>` : '<span class="status-text" style="color:var(--green)">resolved</span>'}
        </div>`).join('') : '<div class="hp-empty">No vulnerabilities found</div>';

    const scanHistoryRows = (assetData.asset.scan_history || []).length
        ? (assetData.asset.scan_history || []).map(h => {
            const ch = h.changes || {};
            const plusPorts = (ch.new_ports || []).slice(0, 6).join(', ');
            const minusPorts = (ch.closed_ports || []).slice(0, 6).join(', ');
            const plusCves = (ch.new_cves || []).slice(0, 4).join(', ');
            const minusCves = (ch.resolved_cves || []).slice(0, 4).join(', ');
            const portsTotal = Array.isArray(h.ports) ? h.ports.length : 0;
            const when = h.finished_at || h.started_at || h.created_at;
            return `<div class="hp-history-row">
              <span class="hp-history-ts">#${h.job_id} · ${esc(localDate(when))}</span>
              <span class="hp-history-ports">${portsTotal} ports · ${h.open_findings || 0} open CVEs</span>
              ${(plusPorts || minusPorts || plusCves || minusCves) ? `
                <div class="status-text" style="margin-top:2px">
                  ${plusPorts ? `+ports ${esc(plusPorts)} ` : ''}${minusPorts ? `-ports ${esc(minusPorts)} ` : ''}${plusCves ? `+CVEs ${esc(plusCves)} ` : ''}${minusCves ? `resolved ${esc(minusCves)}` : ''}
                </div>` : ''}
            </div>`;
        }).join('')
        : '<div class="hp-empty" style="padding:4px 0">No per-scan history yet</div>';

    document.getElementById('hp-body').innerHTML = `
      <div class="hp-meta">
        <div class="hp-meta-title">
          <span class="cat ${esc(a.category||'unk')}">${esc(a.category||'unk')}</span>
          <span class="hp-meta-host">${esc(a.hostname||'—')}</span>
        </div>
        <table class="hp-meta-table">
          <tr><td class="hp-meta-key">IP</td><td class="hp-meta-val">${esc(a.ip)}</td></tr>
          <tr><td class="hp-meta-key">Device ID</td><td class="hp-meta-val mono">${a.device_id != null && a.device_id !== '' ? `<span class="click-ip" onclick="openDevicePanel(${a.device_id})" title="Logical device overview">${esc(String(a.device_id))}</span>` : '—'}</td></tr>
          <tr><td class="hp-meta-key">MAC</td><td class="hp-meta-val">
            ${esc(a.mac||'—')}
            ${a.mac && parseInt(a.mac.split(':')[0],16) & 2 ?
              '<span class="hp-randomized" title="Locally administered (randomized) MAC — OUI lookup not available">randomized</span>'
              : ''}
          </td></tr>
          <tr><td class="hp-meta-key">Vendor</td><td class="hp-meta-val">${esc(a.vendor||'—')}</td></tr>
          <tr><td class="hp-meta-key">OS</td><td class="hp-meta-val">${esc(a.os_guess||'—')}</td></tr>
          <tr><td class="hp-meta-key">CPE</td><td class="hp-meta-val-dim cpe-break">${esc(a.cpe||'—')}</td></tr>
          <tr><td class="hp-meta-key">Connected via</td><td class="hp-meta-val-dim">${esc(a.connected_via||'—')}</td></tr>
          <tr><td class="hp-meta-key">First seen</td><td class="hp-meta-val-dim">${localTime(a.first_seen)}</td></tr>
          <tr><td class="hp-meta-key">Last seen</td><td class="hp-meta-val-dim">${relTime(a.last_seen)}</td></tr>
          <tr><td class="hp-meta-key">Discovery</td><td class="hp-meta-val-dim">${(a.discovery_sources||[]).length ? esc((a.discovery_sources||[]).join(', ')) : '—'}</td></tr>
          ${a.notes ? `<tr><td class="hp-meta-key">Notes</td><td class="hp-meta-val-dim">${esc(a.notes)}</td></tr>` : ''}
        </table>
      </div>

      <div class="hp-head">
        Detected services
        <div class="hp-head-line"></div>
      </div>
      ${serviceRows}

      <div class="hp-head">
        Open ports (${ports.length})
        <div class="hp-head-line"></div>
      </div>
      <div class="mb14">${portRows}</div>

      <div class="hp-head">
        Vulnerabilities (${findings.length})
        <div class="hp-head-line"></div>
        ${findings.length ? `<button class="tbtn btn-xs" onclick="filterVulnsByIP('${esc(a.ip)}');closeHostPanel()">View all</button>` : ''}
      </div>
      <div class="mb14">${findingRows}</div>

      <div class="hp-head">
        Port history
        <div class="hp-head-line"></div>
      </div>
      <div class="mb8">${
        (assetData.asset.port_history||[]).slice(0,5).map(h => `
          <div class="hp-history-row">
            <span class="hp-history-ts">${esc((h.seen_at||'').slice(0,16))}</span>
            <span class="hp-history-ports">${(h.ports||[]).join(', ')||'none'}</span>
          </div>`).join('') || '<div class="hp-empty" style="padding:4px 0">No history yet</div>'
      }</div>

      <div class="hp-head">
        Scan change history
        <div class="hp-head-line"></div>
      </div>
      <div class="mb10">${scanHistoryRows}</div>

      <div class="hp-actions">
        <button class="btnp btn-xs" onclick="openReclassify(${a.id},'${esc(a.ip)}','${esc(a.hostname||'')}','${esc(a.category||'unk')}','${esc(a.vendor||'')}','${esc(a.notes||'')}')">&#9998; Edit</button>
        <button class="tbtn btn-xs" onclick="filterVulnsByIP('${esc(a.ip)}');closeHostPanel()">View CVEs</button>
      </div>`;
}

function closeHostPanel() {
    document.getElementById('host-panel').style.display = 'none';
    document.getElementById('host-panel-bg').style.display = 'none';
}

// ==========================================================================
// Device detail panel
// ==========================================================================
async function openDevicePanel(deviceId) {
    closeHostPanel();
    const did = parseInt(String(deviceId), 10);
    if (!did) return;

    document.getElementById('device-panel').style.display = 'block';
    document.getElementById('device-panel-bg').style.display = 'block';
    document.getElementById('dp-body').innerHTML = '<div class="loading">Loading…</div>';

    const data = await api('/api/devices.php?id=' + encodeURIComponent(String(did)));
    if (!data || !data.device) {
        document.getElementById('dp-body').innerHTML = '<div class="loading">Device not found</div>';
        return;
    }

    const d = data.device;
    const assets = data.assets || [];
    const deviceScanHistory = data.scan_history || [];
    const mac = d.primary_mac_norm ? esc(d.primary_mac_norm) : '—';
    const label = d.label ? esc(d.label) : '—';

    const assetRows = assets.length
        ? assets.map(a => {
            const cv = a.top_cvss != null && a.top_cvss !== '' ? esc(String(a.top_cvss)) : '—';
            return `<tr class="dp-asset-row" onclick="openHostPanel(${a.id},'${esc(a.ip)}')" title="Open host detail">
              <td class="mono mono-sm">${esc(a.ip)}</td>
              <td>${esc(a.hostname || '—')}</td>
              <td><span class="cat ${esc(a.category || 'unk')}">${esc(a.category || 'unk')}</span></td>
              <td class="mono mono-sm">${cv}</td>
              <td class="mono mono-sm">${relTime(a.last_seen)}</td>
            </tr>`;
        }).join('')
        : '<tr><td colspan="5" class="text-secondary" style="padding:10px 0">No linked addresses</td></tr>';

    const scanHistoryRows = deviceScanHistory.length
        ? deviceScanHistory.map(h => {
            const ch = h.changes || {};
            const plusPorts = (ch.new_ports || []).slice(0, 6).join(', ');
            const minusPorts = (ch.closed_ports || []).slice(0, 6).join(', ');
            const plusCves = (ch.new_cves || []).slice(0, 4).join(', ');
            const minusCves = (ch.resolved_cves || []).slice(0, 4).join(', ');
            const when = h.finished_at || h.started_at || h.created_at;
            const pCount = Array.isArray(h.ports) ? h.ports.length : 0;
            return `<div class="hp-history-row">
              <span class="hp-history-ts">#${h.job_id} · ${esc(localDate(when))}</span>
              <span class="hp-history-ports">${h.asset_count || 0} assets · ${pCount} ports · ${h.open_findings || 0} open CVEs</span>
              <button type="button" class="tbtn btn-xs" style="margin-top:3px" onclick="openScanDetailFromDeviceHistory(${h.job_id})">View run details</button>
              ${(plusPorts || minusPorts || plusCves || minusCves) ? `
                <div class="status-text" style="margin-top:2px">
                  ${plusPorts ? `+ports ${esc(plusPorts)} ` : ''}${minusPorts ? `-ports ${esc(minusPorts)} ` : ''}${plusCves ? `+CVEs ${esc(plusCves)} ` : ''}${minusCves ? `resolved ${esc(minusCves)}` : ''}
                </div>` : ''}
            </div>`;
        }).join('')
        : '<div class="hp-empty" style="padding:4px 0">No device scan history yet</div>';

    document.getElementById('dp-body').innerHTML = `
      <div class="hp-meta">
        <div class="hp-meta-title">
          <span class="mono mono-sm">#${did}</span>
          <span class="hp-meta-host" style="margin-left:8px">${assets.length} address${assets.length === 1 ? '' : 'es'}</span>
        </div>
        <table class="hp-meta-table">
          <tr><td class="hp-meta-key">MAC (norm)</td><td class="hp-meta-val mono">${mac}</td></tr>
          <tr><td class="hp-meta-key">Label</td><td class="hp-meta-val">${label}</td></tr>
          <tr><td class="hp-meta-key">Created</td><td class="hp-meta-val-dim">${localTime(d.created_at)}</td></tr>
          <tr><td class="hp-meta-key">Updated</td><td class="hp-meta-val-dim">${localTime(d.updated_at)}</td></tr>
        </table>
      </div>
      <div class="hp-actions" style="margin-top:12px;margin-bottom:14px">
        <button type="button" class="btnp btn-xs" onclick="viewDeviceAssets(${did});closeDevicePanel()">View in Assets</button>
      </div>
      <div class="hp-head" style="margin-top:16px">Merge other devices into this one</div>
      <p class="text-secondary" style="font-size:12px;line-height:1.45;margin:0 0 10px">All assets on the listed devices are reassigned here; those device rows are removed. A line is written to the audit log. Cannot be undone.</p>
      <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:14px">
        <input type="text" class="finp" id="dp-merge-ids" placeholder="Other device ids, e.g. 12, 18" autocomplete="off" style="min-width:0;flex:1;max-width:280px">
        <button type="button" class="tbtn" onclick="requestDeviceMerge(${did})">Merge…</button>
      </div>
      <div class="hp-head">
        Linked addresses
        <div class="hp-head-line"></div>
      </div>
      <div class="tbl-wrap" style="margin-bottom:12px">
        <table class="tbl">
          <thead><tr>
            <th>IP</th><th>Hostname</th><th>Type</th><th>CVSS</th><th>Last seen</th>
          </tr></thead>
          <tbody>${assetRows}</tbody>
        </table>
      </div>
      <div class="hp-head">
        Device scan history
        <div class="hp-head-line"></div>
      </div>
      <div class="mb12">${scanHistoryRows}</div>
      <p class="text-secondary" style="font-size:12px;margin:0">Click a row for full host detail (ports, CVEs, history).</p>`;

    const hnHint = (assets[0] && assets[0].hostname) ? String(assets[0].hostname) : '';
    document.getElementById('dp-title').textContent = hnHint
        ? `Device #${did} — ${esc(hnHint)}`
        : `Device #${did}`;
}

function closeDevicePanel() {
    const p = document.getElementById('device-panel');
    const bg = document.getElementById('device-panel-bg');
    if (p) p.style.display = 'none';
    if (bg) bg.style.display = 'none';
}

function openScanDetailFromDeviceHistory(jobId) {
    const jid = parseInt(String(jobId), 10);
    if (!jid) return;
    const title = document.getElementById('dp-title')?.textContent || '';
    const m = title.match(/Device #(\d+)/);
    scanDetailReturnDeviceId = m ? parseInt(m[1], 10) : 0;
    closeDevicePanel();
    goTab('scanhist');
    hiNav('nscanhist');
    // Open after tab switch/render settles.
    setTimeout(() => { void openScanHistDetail(jid); }, 0);
}

async function requestDeviceMerge(survivorId) {
    const sid = parseInt(String(survivorId), 10);
    if (!sid) return;
    const raw = (document.getElementById('dp-merge-ids')?.value || '').trim();
    const mergeIds = [...new Set(
        raw.split(/[\s,]+/).map(s => parseInt(s, 10)).filter(n => n > 0 && n !== sid)
    )];
    if (!mergeIds.length) {
        toast('Enter one or more other device ids (comma or space separated).', 'err');
        return;
    }
    const ok = await showConfirmModal(
        'Merge devices ' + mergeIds.join(', ') + ' into device ' + sid + '?\n\n'
        + 'All assets on those devices will be reassigned here. The merged device rows will be deleted. This cannot be undone.',
        { title: 'Merge devices', okText: 'Merge' }
    );
    if (!ok) return;
    const res = await apiPost('/api/devices.php', {
        action: 'merge',
        survivor_id: sid,
        merge_ids: mergeIds,
    });
    if (res && res.ok === true) {
        toast('Merged ' + res.merged_count + ' device(s); ' + res.assets_updated + ' asset(s) updated.', 'ok');
        if (mergeIds.includes(assetDeviceFilter)) {
            assetDeviceFilter = sid;
        }
        closeDevicePanel();
        if (currentTab === 'devices') loadDevices(typeof devicePage === 'number' ? devicePage : 1);
        if (currentTab === 'assets') loadAssets(typeof assetPage === 'number' ? assetPage : 1);
        return;
    }
    toast((res && res.error) ? res.error : 'Merge failed', 'err');
}

// close on Escape key
document.addEventListener('keydown', e => {
    if (e.key !== 'Escape') return;
    closeDevicePanel();
    closeHostPanel();
    closeProfileModal();
    closeMfaDisableModal();
    closePasswordChangeModal();
    closeUserPasswordModal();
});

// ==========================================================================
// Export
// ==========================================================================
function exportAssets(format) {
    const q    = document.getElementById('af-q').value;
    const cat  = document.getElementById('af-cat').value;
    const sev  = document.getElementById('af-sev').value;
    const incf = document.getElementById('af-findings')?.checked ? '1' : '0';
    const devQ = assetDeviceFilter > 0 ? `&device_id=${encodeURIComponent(String(assetDeviceFilter))}` : '';
    const url  = `/api/export.php?format=${format}&q=${enc(q)}&category=${enc(cat)}&severity=${enc(sev)}&findings=${incf}${devQ}`;
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
async function initAuthMode() {
    const r = await api('/api/auth.php?status=1');
    if (!r) return;
    authMode = r.auth_mode || 'basic';
    csrfToken = r.csrf_token || '';
    breakglassEnabled = !!r.breakglass_enabled;
    breakglassUsername = r.breakglass_username || 'admin';
    currentUser = r.user || null;
    currentUserRole = (currentUser && currentUser.role) ? currentUser.role : 'admin';
    currentUserMfaEnabled = !!r.current_mfa_enabled;
    currentUserAuthSource = r.current_auth_source || 'local';
    currentProfileDisplayName = (r.profile && r.profile.display_name) ? r.profile.display_name : '';
    currentProfileEmail = (r.profile && r.profile.email) ? r.profile.email : '';
    updateMfaActionButtons();
    const profileBtn = document.getElementById('btn-profile');
    if (profileBtn) {
        const showProfile = !!(currentUser && currentUser.id > 0);
        profileBtn.style.display = showProfile ? '' : 'none';
    }
    applyRoleAwareUi();
    if ((authMode === 'session' || authMode === 'oidc') && r.requires_auth && !r.authed) {
        loginRequired = true;
        openLoginModal(authMode === 'session' ? 'Session sign-in required.' : 'Single sign-on required.');
        return;
    }
    if (currentUser && currentUser.must_change_password) {
        openPasswordChangeModal(true);
    }
}

function readThemeModePref() {
    try {
        const raw = localStorage.getItem('st_theme_mode');
        if (raw === 'light' || raw === 'dark') return raw;
        if (raw === 'auto') return 'auto';
    } catch (e) {}
    return 'auto';
}

function systemPrefersDark() {
    return !!(window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches);
}

function effectiveTheme() {
    const mode = readThemeModePref();
    if (mode === 'auto') return systemPrefersDark() ? 'dark' : 'light';
    return mode;
}

function applyThemeMode(mode) {
    const effective = (mode === 'auto') ? (systemPrefersDark() ? 'dark' : 'light') : mode;
    document.body.classList.toggle('light-mode', effective === 'light');
}

function updateThemeToggleLabel() {
    const btn = document.getElementById('theme-toggle-btn');
    if (!btn) return;
    const eff = effectiveTheme();
    btn.textContent = 'Theme: ' + (eff === 'light' ? 'Light' : 'Dark');
}

function setupSystemThemeWatcher() {
    if (!window.matchMedia) return;
    themeMediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
    themeMediaListener = () => {
        if (readThemeModePref() === 'auto') {
            applyThemeMode('auto');
            updateThemeToggleLabel();
        }
    };
    if (themeMediaQuery.addEventListener) {
        themeMediaQuery.addEventListener('change', themeMediaListener);
    } else if (themeMediaQuery.addListener) {
        themeMediaQuery.addListener(themeMediaListener);
    }
}

function toggleThemeOverride() {
    const next = effectiveTheme() === 'light' ? 'dark' : 'light';
    try { localStorage.setItem('st_theme_mode', next); } catch (e) {}
    applyThemeMode(next);
    updateThemeToggleLabel();
}

async function initApp() {
    await initAuthMode();
    const mode = readThemeModePref();
    applyThemeMode(mode);
    updateThemeToggleLabel();
    setupSystemThemeWatcher();

    const execMode = (() => {
        try { return localStorage.getItem('st_exec_mode') === '1'; }
        catch (e) { return false; }
    })();
    document.body.classList.toggle('exec-mode', execMode);
    applyExecutiveModeUI(execMode);
    const mb = document.getElementById('dash-mode-btn');
    if (mb) mb.textContent = 'Executive view: ' + (execMode ? 'on' : 'off');
    // Always load dashboard data first to populate sidebar badges
    await loadDashboard();
    await hydrateFeedSyncFromServer();
    await hydrateFeedSyncLastOutputFromServer();
}

function toggleDashMode() {
    const on = !document.body.classList.contains('exec-mode');
    document.body.classList.toggle('exec-mode', on);
    applyExecutiveModeUI(on);
    try { localStorage.setItem('st_exec_mode', on ? '1' : '0'); } catch (e) {}
    const mb = document.getElementById('dash-mode-btn');
    if (mb) mb.textContent = 'Executive view: ' + (on ? 'on' : 'off');
    const navMap = {dash:'ndash',assets:'nassets',devices:'ndevices',vulns:'nvulns',logs:'nlogs',scan:'nscan',scanhist:'nscanhist',enrich:'nenrich',health:'nhealth',access:'naccess',settings:'nsettings',sched:'nsched'};

    if (on) {
        // Remember where the user was, then switch to dashboard presentation.
        execPreviousTab = currentTab !== 'dash' ? currentTab : null;
        goTab('dash');
        hiNav('ndash');
        return;
    }

    // Restore prior tab when exiting executive mode.
    const restore = (execPreviousTab && document.getElementById('t-' + execPreviousTab))
        ? execPreviousTab
        : 'dash';
    goTab(restore);
    if (navMap[restore]) hiNav(navMap[restore]);
    execPreviousTab = null;
}

initApp();

// Restore last active tab from session storage
const lastTab = (() => { try { return sessionStorage.getItem('st_tab'); } catch(e) { return null; } })();
if (lastTab && document.getElementById('t-' + lastTab)) {
    goTab(lastTab);
    const navMap = {dash:'ndash',assets:'nassets',devices:'ndevices',vulns:'nvulns',logs:'nlogs',scan:'nscan',scanhist:'nscanhist',enrich:'nenrich',health:'nhealth',access:'naccess',settings:'nsettings',sched:'nsched'};
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
