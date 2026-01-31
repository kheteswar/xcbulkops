/**
 * XC BulkOps – WAF Status Scanner
 * Scans WAF configurations and modes with detailed progress feedback.
 * (Exclusion Rule features have been removed)
 */

/* ============================================================
   STATE
   ============================================================ */
const WAFScannerState = {
    selectedNamespaces: [],
    rows: [],
    wafPolicies: {}, // Cache for WAF policies
    filter: 'all',
    search: '',
    cancelled: false,
    startTime: null,
    logCount: 0,
    stats: {
        namespaces: 0,
        loadBalancers: 0,
        routes: 0,
        wafs: 0
    }
};

/* ============================================================
   WIZARD NAVIGATION
   ============================================================ */
function goToStep(step) {
    document.querySelectorAll('.wizard-step').forEach((el, i) =>
        el.classList.toggle('active', i + 1 === step)
    );

    document.querySelectorAll('.progress-step').forEach((el, i) => {
        el.classList.remove('active', 'completed');
        if (i + 1 < step) el.classList.add('completed');
        if (i + 1 === step) el.classList.add('active');
    });
}

/* ============================================================
   LOGGING & PROGRESS
   ============================================================ */
function logScan(msg, type = 'info') {
    const log = document.getElementById('scan-log');
    if (!log) return;
    
    WAFScannerState.logCount++;
    document.getElementById('log-count').textContent = `${WAFScannerState.logCount} entries`;
    
    const time = new Date().toLocaleTimeString();
    const icons = {
        info: '📋',
        success: '✅',
        warning: '⚠️',
        error: '❌',
        fetch: '🔄',
        waf: '🛡️',
        route: '🔀'
    };
    
    const line = document.createElement('div');
    line.className = `log-entry log-${type}`;
    line.innerHTML = `
        <span class="log-time">${time}</span>
        <span class="log-icon">${icons[type] || icons.info}</span>
        <span class="log-message">${msg}</span>
    `;
    log.appendChild(line);
    log.scrollTop = log.scrollHeight;
}

function setOperation(title, subtitle) {
    document.getElementById('operation-title').textContent = title;
    document.getElementById('operation-subtitle').textContent = subtitle;
}

function updateProgress(percent, text) {
    document.getElementById('scan-progress-bar').style.width = `${percent}%`;
    document.getElementById('scan-progress-percent').textContent = `${Math.round(percent)}%`;
    document.getElementById('scan-progress-detail').textContent = text;
    
    if (WAFScannerState.startTime && percent > 5) {
        const elapsed = Date.now() - WAFScannerState.startTime;
        const estimated = (elapsed / percent) * (100 - percent);
        const seconds = Math.round(estimated / 1000);
        if (seconds > 60) {
            document.getElementById('scan-eta').textContent = `Estimated time remaining: ${Math.round(seconds / 60)} min`;
        } else {
            document.getElementById('scan-eta').textContent = `Estimated time remaining: ${seconds} sec`;
        }
    }
}

function updateStatsUI() {
    document.getElementById('stat-namespaces').textContent = WAFScannerState.stats.namespaces;
    document.getElementById('stat-loadbalancers').textContent = WAFScannerState.stats.loadBalancers;
    document.getElementById('stat-routes').textContent = WAFScannerState.stats.routes;
    document.getElementById('stat-wafs').textContent = WAFScannerState.stats.wafs;
}

/* ============================================================
   API HELPERS
   ============================================================ */
async function fetchWafPolicy(name, ns) {
    const cacheKey = `${ns}/${name}`;
    if (WAFScannerState.wafPolicies[cacheKey]) {
        return WAFScannerState.wafPolicies[cacheKey];
    }
    
    try {
        const waf = await F5XCClient.get(`/api/config/namespaces/${ns}/app_firewalls/${name}`);
        WAFScannerState.wafPolicies[cacheKey] = { ...waf, shared: false };
        return WAFScannerState.wafPolicies[cacheKey];
    } catch {
        try {
            const waf = await F5XCClient.get(`/api/config/namespaces/shared/app_firewalls/${name}`);
            WAFScannerState.wafPolicies[`shared/${name}`] = { ...waf, shared: true };
            return WAFScannerState.wafPolicies[`shared/${name}`];
        } catch {
            return null;
        }
    }
}

function getWafMode(wafPolicy) {
    if (!wafPolicy?.spec) return 'unknown';
    
    if (wafPolicy.spec.mode) {
        const m = wafPolicy.spec.mode.toUpperCase();
        if (m === 'BLOCKING') return 'blocking';
        if (m === 'MONITORING') return 'monitoring';
    }

    if (wafPolicy.spec.blocking) return 'blocking';
    if (wafPolicy.spec.monitoring) return 'monitoring';

    if (wafPolicy.spec.app_firewall?.mode) {
         const m = wafPolicy.spec.app_firewall.mode.toUpperCase();
         if (m === 'BLOCKING') return 'blocking';
         if (m === 'MONITORING') return 'monitoring';
    }

    return 'unknown';
}

async function resolveRoutePath(route, ns) {
    if (route.simple_route?.path) {
        const p = route.simple_route.path;
        if (p.prefix) return `prefix:${p.prefix}`;
        if (p.regex) return `regex:${p.regex}`;
        if (p.exact) return `exact:${p.exact}`;
    }
    if (route.redirect_route?.path) {
        const p = route.redirect_route.path;
        if (p.prefix) return `redirect:${p.prefix}`;
    }
    if (route.direct_response_route) return 'direct-response';
    return 'default';
}

/* ============================================================
   MAIN SCAN ENGINE
   ============================================================ */
async function scanNamespace(ns, totalNs, index) {
    if (WAFScannerState.cancelled) return [];

    const rows = [];

    setOperation(`Scanning namespace: ${ns}`, `Namespace ${index + 1} of ${totalNs}`);
    logScan(`Scanning namespace: ${ns}`, 'info');
    
    WAFScannerState.stats.namespaces++;
    updateStatsUI();

    let lbs;
    try {
        const lbResponse = await F5XCClient.get(`/api/config/namespaces/${ns}/http_loadbalancers`);
        lbs = lbResponse.items || [];
        logScan(`Found ${lbs.length} HTTP Load Balancers in ${ns}`, 'success');
    } catch (err) {
        logScan(`Error fetching LBs from ${ns}: ${err.message}`, 'error');
        return rows;
    }

    for (const lb of lbs) {
        if (WAFScannerState.cancelled) break;
        const lbName = lb.name;
        WAFScannerState.stats.loadBalancers++;
        updateStatsUI();
        
        setOperation(`Analyzing: ${lbName}`, `Namespace: ${ns}`);
        logScan(`Analyzing LB: ${lbName}`, 'fetch');

        let lbDetails;
        try {
            lbDetails = await F5XCClient.get(`/api/config/namespaces/${ns}/http_loadbalancers/${lbName}`);
        } catch (err) {
            logScan(`Error fetching ${lbName}: ${err.message}`, 'error');
            continue;
        }

        const spec = lbDetails.spec || {};
        
        // --- Analyze LB-level WAF ---
        let lbWafName = 'disabled';
        let lbWafMode = 'disabled';
        let wafDisplayName = 'N/A';

        if (!spec.disable_waf && spec.app_firewall?.name) {
            const wafName = spec.app_firewall.name;
            const wafNs = spec.app_firewall.namespace || ns;
            
            const wafPolicy = await fetchWafPolicy(wafName, wafNs);
            
            if (wafPolicy) {
                WAFScannerState.stats.wafs++;
                lbWafName = wafPolicy.shared ? `${wafName} (shared)` : wafName;
                lbWafMode = getWafMode(wafPolicy);
                wafDisplayName = lbWafName;
            }
        }

        rows.push({
            namespace: ns,
            lb_name: lbName,
            route: 'LB Default',
            waf_name: wafDisplayName,
            waf_mode: lbWafMode
        });

        // --- Scan Routes ---
        const includeRoutes = document.getElementById('opt-include-routes')?.checked;
        if (includeRoutes && spec.routes?.length > 0) {
            for (const route of spec.routes) {
                if (WAFScannerState.cancelled) break;
                
                WAFScannerState.stats.routes++;
                const routePath = await resolveRoutePath(route, ns);
                const adv = route.simple_route?.advanced_options || {};
                
                let routeWafName = 'inherit';
                let routeWafMode = lbWafMode;

                if (adv.disable_waf) {
                    routeWafName = 'disabled';
                    routeWafMode = 'disabled';
                } else if (adv.app_firewall?.name) {
                    const routeWafPolicyName = adv.app_firewall.name;
                    const routeWafNs = adv.app_firewall.namespace || ns;
                    const routeWafPolicy = await fetchWafPolicy(routeWafPolicyName, routeWafNs);
                    if (routeWafPolicy) {
                        routeWafName = routeWafPolicy.shared ? `${routeWafPolicyName} (shared)` : routeWafPolicyName;
                        routeWafMode = getWafMode(routeWafPolicy);
                    }
                }

                rows.push({
                    namespace: ns,
                    lb_name: lbName,
                    route: routePath,
                    waf_name: routeWafName === 'inherit' ? `↳ ${wafDisplayName}` : routeWafName,
                    waf_mode: routeWafMode,
                    inherited: routeWafName === 'inherit'
                });
            }
        }
    }

    const percent = Math.round(((index + 1) / totalNs) * 100);
    updateProgress(percent, `Completed ${index + 1} of ${totalNs} namespaces`);

    return rows;
}

/* ============================================================
   LOAD NAMESPACES
   ============================================================ */
async function loadNamespaces() {
    try {
        const resp = await F5XCClient.get('/api/web/namespaces');
        const list = document.getElementById('namespace-list');
        const count = document.getElementById('selected-ns-count');
        const startBtn = document.getElementById('btn-start-scan');
        const loader = document.getElementById('namespace-loader');

        list.innerHTML = '';

        resp.items.forEach(ns => {
            const item = document.createElement('label');
            item.className = 'namespace-item';
            item.innerHTML = `
                <input type="checkbox" value="${ns.name}">
                <span class="ns-name">${ns.name}</span>
            `;
            item.querySelector('input').addEventListener('change', () => {
                WAFScannerState.selectedNamespaces = 
                    [...list.querySelectorAll('input:checked')].map(i => i.value);
                count.textContent = WAFScannerState.selectedNamespaces.length;
                startBtn.disabled = WAFScannerState.selectedNamespaces.length === 0;
                
                const nsCount = WAFScannerState.selectedNamespaces.length;
                document.getElementById('scan-estimate').textContent = nsCount === 0 
                    ? 'Select namespaces to continue' 
                    : `Ready to scan ${nsCount} namespace${nsCount > 1 ? 's' : ''}`;
            });
            list.appendChild(item);
        });

        if (loader) loader.style.display = 'none';
        
    } catch (err) {
        Toast.error('Failed to load namespaces: ' + err.message);
    }
}

/* ============================================================
   RESULTS DISPLAY
   ============================================================ */
function updateSummary() {
    let blockingCount = 0;
    let monitoringCount = 0;
    let disabledCount = 0;

    WAFScannerState.rows.forEach(r => {
        if (r.waf_mode === 'blocking') blockingCount++;
        else if (r.waf_mode === 'monitoring') monitoringCount++;
        else disabledCount++;
    });

    document.getElementById('summary-blocking').textContent = blockingCount;
    document.getElementById('summary-monitoring').textContent = monitoringCount;
    document.getElementById('summary-disabled').textContent = disabledCount;
    
    document.getElementById('results-summary').textContent = 
        `Found ${WAFScannerState.rows.length} configuration records across ${WAFScannerState.stats.loadBalancers} load balancers`;
}

function applyFilterAndSearch() {
    let rows = [...WAFScannerState.rows];
    
    if (WAFScannerState.filter === 'blocking') rows = rows.filter(r => r.waf_mode === 'blocking');
    else if (WAFScannerState.filter === 'monitoring') rows = rows.filter(r => r.waf_mode === 'monitoring');
    else if (WAFScannerState.filter === 'nowaf') rows = rows.filter(r => r.waf_mode === 'disabled');

    if (WAFScannerState.search) {
        const q = WAFScannerState.search.toLowerCase();
        rows = rows.filter(r =>
            r.namespace.toLowerCase().includes(q) ||
            r.lb_name.toLowerCase().includes(q) ||
            r.route.toLowerCase().includes(q) ||
            r.waf_name.toLowerCase().includes(q)
        );
    }
    renderResults(rows);
}

function renderResults(rows) {
    const tbody = document.getElementById('results-tbody');
    const noResults = document.getElementById('no-results');
    
    if (rows.length === 0) {
        tbody.innerHTML = '';
        noResults.classList.remove('hidden');
        return;
    }
    noResults.classList.add('hidden');
    
    tbody.innerHTML = rows.map((r, idx) => {
        const modeClass = r.waf_mode === 'blocking' ? 'mode-blocking' : 
                          r.waf_mode === 'monitoring' ? 'mode-monitoring' : 'mode-disabled';
        const modeIcon = r.waf_mode === 'blocking' ? '🛡️' :
                         r.waf_mode === 'monitoring' ? '👁️' : '⚠️';
        
        const routeClass = r.inherited ? 'route-inherited' : '';
        
        return `
            <tr class="${routeClass}">
                <td class="cell-namespace">${r.namespace}</td>
                <td class="cell-lb">${r.lb_name}</td>
                <td class="cell-route">${r.route}</td>
                <td class="cell-waf">${r.waf_name}</td>
                <td class="cell-mode"><span class="mode-badge ${modeClass}">${modeIcon} ${r.waf_mode}</span></td>
            </tr>
        `;
    }).join('');
}

/* ============================================================
   EXPORT FUNCTIONS
   ============================================================ */
function exportExcelXLS() {
    if (!WAFScannerState.rows.length) {
        Toast.warning('No data to export');
        return;
    }

    // Sheet 1: Main Status
    let mainRows = `<Row>
        <Cell><Data ss:Type="String">Namespace</Data></Cell>
        <Cell><Data ss:Type="String">Load Balancer</Data></Cell>
        <Cell><Data ss:Type="String">Route</Data></Cell>
        <Cell><Data ss:Type="String">WAF Policy</Data></Cell>
        <Cell><Data ss:Type="String">Mode</Data></Cell>
    </Row>`;
    
    WAFScannerState.rows.forEach(r => {
        mainRows += `<Row>
            <Cell><Data ss:Type="String">${r.namespace}</Data></Cell>
            <Cell><Data ss:Type="String">${r.lb_name}</Data></Cell>
            <Cell><Data ss:Type="String">${r.route}</Data></Cell>
            <Cell><Data ss:Type="String">${r.waf_name}</Data></Cell>
            <Cell><Data ss:Type="String">${r.waf_mode}</Data></Cell>
        </Row>`;
    });

    const template = `<?xml version="1.0"?>
    <?mso-application progid="Excel.Sheet"?>
    <Workbook xmlns="urn:schemas-microsoft-com:office:spreadsheet"
     xmlns:o="urn:schemas-microsoft-com:office:office"
     xmlns:x="urn:schemas-microsoft-com:office:excel"
     xmlns:ss="urn:schemas-microsoft-com:office:spreadsheet"
     xmlns:html="http://www.w3.org/TR/REC-html40">
     <Worksheet ss:Name="WAF Status Summary">
      <Table>
       ${mainRows}
      </Table>
     </Worksheet>
    </Workbook>`;

    downloadFile(template, 'waf-scan-results.xls', 'application/vnd.ms-excel');
    Toast.success('Excel file exported successfully');
}

function exportReport() {
    if (!WAFScannerState.rows.length) {
        Toast.warning('No data to export');
        return;
    }
    const report = {
        generated_at: new Date().toISOString(),
        tool: 'WAF Status Scanner',
        summary: { ...WAFScannerState.stats },
        lb_status: WAFScannerState.rows
    };
    downloadFile(JSON.stringify(report, null, 2), 'waf-status-report.json', 'application/json');
    Toast.success('JSON Report exported successfully');
}

function downloadFile(content, filename, mimeType) {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

/* ============================================================
   EVENT HANDLERS & INIT
   ============================================================ */
document.addEventListener('DOMContentLoaded', async () => {
    // 1. REHYDRATE / CHECK CONNECTION
    if (!AppState.connected) {
         const creds = StorageManager?.loadCredentials?.();
         if (creds?.tenant && creds?.apiToken) {
             F5XCClient.init(creds.tenant, creds.apiToken);
             AppState.connected = true;
         }
    }

    // 2. SYNC UI
    if (AppState.connected) {
        document.getElementById('connection-notice')?.classList.add('hidden');
        document.getElementById('wizard-container')?.classList.remove('hidden');
        await loadNamespaces(); 
    }

    document.getElementById('select-all-ns')?.addEventListener('click', () => {
        document.querySelectorAll('#namespace-list input[type="checkbox"]').forEach(cb => cb.checked = true);
        document.querySelector('#namespace-list input')?.dispatchEvent(new Event('change'));
    });
    
    document.getElementById('deselect-all-ns')?.addEventListener('click', () => {
        document.querySelectorAll('#namespace-list input[type="checkbox"]').forEach(cb => cb.checked = false);
        document.querySelector('#namespace-list input')?.dispatchEvent(new Event('change'));
    });

    document.getElementById('btn-start-scan')?.addEventListener('click', async () => {
        WAFScannerState.cancelled = false;
        WAFScannerState.rows = [];
        WAFScannerState.wafPolicies = {};
        WAFScannerState.logCount = 0;
        WAFScannerState.startTime = Date.now();
        WAFScannerState.stats = { namespaces: 0, loadBalancers: 0, routes: 0, wafs: 0 };

        document.getElementById('scan-log').innerHTML = '';
        document.getElementById('log-count').textContent = '0 entries';
        updateProgress(0, 'Initializing...');
        updateStatsUI();

        goToStep(2);
        logScan('🚀 Starting WAF Status Scan...', 'info');

        const total = WAFScannerState.selectedNamespaces.length;
        for (let i = 0; i < total; i++) {
            if (WAFScannerState.cancelled) break;
            const ns = WAFScannerState.selectedNamespaces[i];
            const rows = await scanNamespace(ns, total, i);
            WAFScannerState.rows.push(...rows);
        }

        if (!WAFScannerState.cancelled) {
            logScan(`✅ Scan complete!`, 'success');
            goToStep(3);
            updateSummary();
            applyFilterAndSearch();
        } else {
            logScan('⛔ Scan cancelled by user', 'warning');
        }
    });

    document.getElementById('btn-cancel-scan')?.addEventListener('click', () => {
        WAFScannerState.cancelled = true;
        setOperation('Cancelling...', 'Please wait');
    });

    document.getElementById('btn-new-scan')?.addEventListener('click', () => goToStep(1));

    document.querySelectorAll('.filter-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            WAFScannerState.filter = btn.dataset.filter;
            applyFilterAndSearch();
        });
    });

    document.getElementById('results-search')?.addEventListener('input', (e) => {
        WAFScannerState.search = e.target.value;
        applyFilterAndSearch();
    });

    document.getElementById('btn-export-excel')?.addEventListener('click', exportExcelXLS);
    document.getElementById('btn-export-report')?.addEventListener('click', exportReport);
});