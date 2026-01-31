/**
 * XC BulkOps - Config Visualizer v8.0
 * Intelligent Configuration Analysis Agent
 */

const OBJECT_REGISTRY = {
    'app_firewall': { apiPath: 'app_firewalls', category: 'security', displayName: 'WAF Policy' },
    'service_policy': { apiPath: 'service_policys', category: 'security', displayName: 'Service Policy' },
    'user_identification': { apiPath: 'user_identifications', category: 'security', displayName: 'User ID' },
    'bot_defense': { apiPath: 'bot_defense_policys', category: 'security', displayName: 'Bot Defense' },
    'malicious_user_mitigation': { apiPath: 'malicious_user_mitigations', category: 'security', displayName: 'Threat Mitigation' },
    'origin_pool': { apiPath: 'origin_pools', category: 'traffic', displayName: 'Origin Pool' },
    'pool': { apiPath: 'origin_pools', category: 'traffic', displayName: 'Origin Pool' },
    'healthcheck': { apiPath: 'healthchecks', category: 'traffic', displayName: 'Health Check' },
    'api_definition': { apiPath: 'api_definitions', category: 'api', displayName: 'API Definition' },
    'rate_limiter': { apiPath: 'rate_limiters', category: 'traffic', displayName: 'Rate Limiter' }
};

const ViewerState = {
    rootLB: null, namespace: null, objects: new Map(), routes: [], domains: [],
    originPools: new Map(), wafPolicies: new Map(), healthChecks: new Map(), crawlLog: []
};

document.addEventListener('DOMContentLoaded', async () => {
    const creds = StorageManager?.loadCredentials?.();
    if (creds?.tenant && creds?.apiToken) {
        F5XCClient.init(creds.tenant, creds.apiToken);
        AppState.connected = true;
        document.getElementById('connection-notice')?.classList.add('hidden');
        document.getElementById('viewer-wrapper')?.classList.remove('hidden');
        await loadNamespaces();
    } else {
        document.getElementById('connection-notice')?.classList.remove('hidden');
    }
    setupEventListeners();
});

async function loadNamespaces() {
    try {
        const resp = await F5XCClient.get('/api/web/namespaces');
        const select = document.getElementById('namespace-select');
        select.innerHTML = '<option value="">Select Namespace</option>';
        resp.items.sort((a, b) => a.name.localeCompare(b.name));
        resp.items.forEach(ns => select.innerHTML += `<option value="${ns.name}">${ns.name}</option>`);
        select.disabled = false;
    } catch (e) { Toast.error("Failed to load namespaces"); }
}

async function loadLoadBalancers(ns) {
    const lbSelect = document.getElementById('lb-select');
    const btn = document.getElementById('btn-view');
    lbSelect.innerHTML = '<option value="">Loading...</option>';
    lbSelect.disabled = true; btn.disabled = true;
    try {
        const resp = await F5XCClient.get(`/api/config/namespaces/${ns}/http_loadbalancers`);
        lbSelect.innerHTML = '<option value="">Select Load Balancer</option>';
        if (resp.items?.length > 0) {
            resp.items.sort((a, b) => a.name.localeCompare(b.name));
            resp.items.forEach(lb => lbSelect.innerHTML += `<option value="${lb.name}">${lb.name}</option>`);
            lbSelect.disabled = false;
        } else { lbSelect.innerHTML = '<option value="">No load balancers</option>'; }
        lbSelect.onchange = () => btn.disabled = !lbSelect.value;
    } catch (e) { lbSelect.innerHTML = '<option value="">Error</option>'; }
}

async function fetchObject(ns, apiPath, name) {
    const id = `${apiPath}:${ns}:${name}`;
    if (ViewerState.objects.has(id)) return ViewerState.objects.get(id);
    try {
        const obj = await F5XCClient.get(`/api/config/namespaces/${ns}/${apiPath}/${name}`);
        ViewerState.objects.set(id, obj);
        return obj;
    } catch {
        try {
            const obj = await F5XCClient.get(`/api/config/namespaces/shared/${apiPath}/${name}`);
            ViewerState.objects.set(`${apiPath}:shared:${name}`, obj);
            return obj;
        } catch { return null; }
    }
}

async function startViewer() {
    const ns = document.getElementById('namespace-select').value;
    const lbName = document.getElementById('lb-select').value;
    if (!ns || !lbName) return;
    
    // Reset state
    ViewerState.rootLB = null; ViewerState.namespace = ns;
    ViewerState.objects = new Map(); ViewerState.routes = [];
    ViewerState.originPools = new Map(); ViewerState.wafPolicies = new Map();
    ViewerState.healthChecks = new Map(); ViewerState.crawlLog = [];
    
    showLoading();
    
    try {
        logCrawl(`Fetching Load Balancer: ${lbName}`);
        const lb = await F5XCClient.get(`/api/config/namespaces/${ns}/http_loadbalancers/${lbName}`);
        if (!lb) throw new Error("Load Balancer not found");
        ViewerState.rootLB = lb;
        logCrawl(`✓ Fetched ${lbName}`);
        
        // Parse routes
        if (lb.spec?.routes) {
            ViewerState.routes = lb.spec.routes.map((r, i) => parseRoute(r, i));
            logCrawl(`Found ${ViewerState.routes.length} routes`);
        }
        
        // Crawl linked objects
        await crawlLinkedObjects(lb.spec, ns);
        
        // Fetch origin pool details  
        await fetchOriginPoolDetails(ns);
        
        // Render
        logCrawl(`Generating report...`);
        renderReport();
        hideLoading();
        document.getElementById('report-content').classList.remove('hidden');
        
    } catch (e) {
        console.error(e);
        Toast.error(e.message);
        hideLoading();
        document.getElementById('empty-state').classList.remove('hidden');
    }
}

function parseRoute(route, index) {
    const parsed = { index, type: 'unknown', path: '/', pathMatch: 'prefix', methods: ['ANY'], origins: [], waf: null };
    
    if (route.simple_route) {
        parsed.type = 'simple';
        const sr = route.simple_route;
        if (sr.path) {
            if (sr.path.prefix) { parsed.path = sr.path.prefix; parsed.pathMatch = 'prefix'; }
            else if (sr.path.regex) { parsed.path = sr.path.regex; parsed.pathMatch = 'regex'; }
            else if (sr.path.path) { parsed.path = sr.path.path; parsed.pathMatch = 'exact'; }
        }
        if (sr.http_method?.methods) parsed.methods = sr.http_method.methods;
        if (sr.origin_pools) {
            parsed.origins = sr.origin_pools.map(op => ({
                name: op.pool?.name, namespace: op.pool?.namespace, weight: op.weight, priority: op.priority
            }));
        }
        if (sr.advanced_options) {
            if (sr.advanced_options.app_firewall) {
                parsed.waf = { name: sr.advanced_options.app_firewall.name, namespace: sr.advanced_options.app_firewall.namespace };
            }
            if (sr.advanced_options.disable_waf) parsed.waf = { disabled: true };
            parsed.timeout = sr.advanced_options.request_timeout;
            parsed.retries = sr.advanced_options.retry_policy;
            parsed.corsPolicy = sr.advanced_options.cors_policy;
        }
        parsed.headerMatchers = sr.headers;
        parsed.queryParams = sr.query_params;
    } else if (route.redirect_route) {
        parsed.type = 'redirect';
        const rr = route.redirect_route;
        if (rr.path?.prefix) parsed.path = rr.path.prefix;
        parsed.redirectConfig = { host: rr.host_redirect, path: rr.path_redirect, code: rr.response_code || '301' };
    } else if (route.direct_response_route) {
        parsed.type = 'direct_response';
        const dr = route.direct_response_route;
        if (dr.path?.prefix) parsed.path = dr.path.prefix;
        parsed.directResponse = { code: dr.response_code, body: dr.response_body };
    }
    return parsed;
}

async function crawlLinkedObjects(spec, ns) {
    if (!spec) return;
    const promises = [];
    
    // WAF
    if (spec.app_firewall && !spec.disable_waf) {
        logCrawl(`Found WAF: ${spec.app_firewall.name}`);
        promises.push(fetchAndStore('app_firewall', spec.app_firewall.name, spec.app_firewall.namespace || ns));
    }
    
    // Service Policies
    if (spec.active_service_policies?.policies) {
        for (const p of spec.active_service_policies.policies) {
            if (p.name) { logCrawl(`Found Service Policy: ${p.name}`); promises.push(fetchAndStore('service_policy', p.name, p.namespace || ns)); }
        }
    }
    
    // User Identification
    if (spec.user_identification) {
        logCrawl(`Found User ID: ${spec.user_identification.name}`);
        promises.push(fetchAndStore('user_identification', spec.user_identification.name, spec.user_identification.namespace || ns));
    }
    
    // Bot Defense
    if (spec.bot_defense?.policy) {
        logCrawl(`Found Bot Defense: ${spec.bot_defense.policy.name}`);
        promises.push(fetchAndStore('bot_defense', spec.bot_defense.policy.name, spec.bot_defense.policy.namespace || ns));
    }
    
    // Malicious User Mitigation
    if (spec.malicious_user_mitigation) {
        logCrawl(`Found Threat Mitigation: ${spec.malicious_user_mitigation.name}`);
        promises.push(fetchAndStore('malicious_user_mitigation', spec.malicious_user_mitigation.name, spec.malicious_user_mitigation.namespace || ns));
    }
    
    // API Definition
    if (spec.api_definition) {
        logCrawl(`Found API Definition: ${spec.api_definition.name}`);
        promises.push(fetchAndStore('api_definition', spec.api_definition.name, spec.api_definition.namespace || ns));
    }
    
    // Rate Limiter
    if (spec.rate_limiter) {
        logCrawl(`Found Rate Limiter: ${spec.rate_limiter.name}`);
        promises.push(fetchAndStore('rate_limiter', spec.rate_limiter.name, spec.rate_limiter.namespace || ns));
    }
    
    // Default route pools
    if (spec.default_route_pools) {
        for (const poolRef of spec.default_route_pools) {
            if (poolRef.pool) {
                logCrawl(`Found Origin Pool: ${poolRef.pool.name}`);
                promises.push(fetchAndStore('origin_pool', poolRef.pool.name, poolRef.pool.namespace || ns));
            }
        }
    }
    
    // Route pools
    if (spec.routes) {
        for (const route of spec.routes) {
            if (route.simple_route?.origin_pools) {
                for (const poolRef of route.simple_route.origin_pools) {
                    if (poolRef.pool) {
                        logCrawl(`Found Origin Pool (route): ${poolRef.pool.name}`);
                        promises.push(fetchAndStore('origin_pool', poolRef.pool.name, poolRef.pool.namespace || ns));
                    }
                }
            }
            if (route.simple_route?.advanced_options?.app_firewall) {
                const waf = route.simple_route.advanced_options.app_firewall;
                logCrawl(`Found Route WAF: ${waf.name}`);
                promises.push(fetchAndStore('app_firewall', waf.name, waf.namespace || ns));
            }
        }
    }
    
    await Promise.allSettled(promises);
}

async function fetchAndStore(type, name, ns) {
    const reg = OBJECT_REGISTRY[type];
    if (!reg) return null;
    const obj = await fetchObject(ns, reg.apiPath, name);
    if (obj) {
        if (type === 'origin_pool' || type === 'pool') ViewerState.originPools.set(name, obj);
        else if (type === 'app_firewall') ViewerState.wafPolicies.set(name, obj);
        else if (type === 'healthcheck') ViewerState.healthChecks.set(name, obj);
    }
    return obj;
}

async function fetchOriginPoolDetails(ns) {
    for (const [name, pool] of ViewerState.originPools) {
        if (pool.spec?.healthcheck) {
            for (const hc of pool.spec.healthcheck) {
                if (hc.name) {
                    logCrawl(`Found Health Check: ${hc.name}`);
                    await fetchAndStore('healthcheck', hc.name, hc.namespace || ns);
                }
            }
        }
    }
}

function logCrawl(msg) {
    ViewerState.crawlLog.push({ msg, time: new Date() });
    const el = document.getElementById('scan-log');
    if (el) el.textContent = msg;
}

function showLoading() {
    document.getElementById('loading-state')?.classList.remove('hidden');
    document.getElementById('empty-state')?.classList.add('hidden');
    document.getElementById('report-content')?.classList.add('hidden');
}

function hideLoading() {
    document.getElementById('loading-state')?.classList.add('hidden');
}

/* ============================================================
   REPORT RENDERER
   ============================================================ */
function renderReport() {
    const container = document.getElementById('report-content');
    const lb = ViewerState.rootLB;
    const spec = lb.spec || {};
    
    let html = '';
    html += renderHeader(lb);
    html += renderQuickStats(lb);
    html += renderDomainsSection(spec);
    if (ViewerState.routes.length > 0) html += renderRoutesSection();
    if (ViewerState.originPools.size > 0) html += renderOriginPoolsSection();
    html += renderSecuritySection(spec);
    html += renderAPISection(spec);
    html += renderTLSSection(spec);
    html += renderAdvancedSection(spec);
    html += renderJsonModal();
    
    container.innerHTML = html;
    attachReportEventListeners();
}

function renderHeader(lb) {
    const spec = lb.spec || {};
    const meta = lb.metadata || {};
    
    let lbType = 'HTTP', lbTypeClass = 'type-http';
    if (spec.https_auto_cert) { lbType = 'HTTPS (Auto Cert)'; lbTypeClass = 'type-https-auto'; }
    else if (spec.https) { lbType = 'HTTPS (Custom Cert)'; lbTypeClass = 'type-https'; }
    
    let advertiseType = 'Unknown';
    if (spec.advertise_on_public_default_vip) advertiseType = 'Public (Default VIP)';
    else if (spec.advertise_on_public) advertiseType = 'Public (Custom)';
    else if (spec.advertise_custom) advertiseType = 'Custom';
    else if (spec.do_not_advertise) advertiseType = 'Not Advertised';
    
    return `
        <div class="report-header-v2">
            <div class="header-top">
                <div class="header-icon">${getIcon('globe')}</div>
                <div class="header-info">
                    <div class="header-badges">
                        <span class="badge badge-type ${lbTypeClass}">${lbType}</span>
                        <span class="badge badge-advertise">${advertiseType}</span>
                    </div>
                    <h1 class="header-title">${meta.name}</h1>
                    <div class="header-meta">
                        <span class="meta-item">${getIcon('home', 14)} ${meta.namespace}</span>
                        <span class="meta-item">${getIcon('clock', 14)} Created: ${formatDate(lb.system_metadata?.creation_timestamp)}</span>
                    </div>
                </div>
                <div class="header-actions">
                    <button class="btn btn-secondary btn-sm" onclick="showFullJson()">
                        ${getIcon('code', 16)} View JSON
                    </button>
                </div>
            </div>
        </div>`;
}

function renderQuickStats(lb) {
    const spec = lb.spec || {};
    const stats = [
        { label: 'Domains', value: spec.domains?.length || 0, icon: 'globe', color: '#3b82f6' },
        { label: 'Routes', value: ViewerState.routes.length, icon: 'route', color: '#8b5cf6' },
        { label: 'Origin Pools', value: ViewerState.originPools.size, icon: 'server', color: '#10b981' },
        { label: 'WAF', value: spec.app_firewall ? 'Enabled' : 'Disabled', icon: 'shield', color: spec.app_firewall ? '#22c55e' : '#6b7280', isStatus: true },
        { label: 'Bot Defense', value: spec.bot_defense ? 'Enabled' : 'Disabled', icon: 'bot', color: spec.bot_defense ? '#22c55e' : '#6b7280', isStatus: true },
        { label: 'API Discovery', value: spec.enable_api_discovery ? 'Enabled' : 'Disabled', icon: 'api', color: spec.enable_api_discovery ? '#22c55e' : '#6b7280', isStatus: true }
    ];
    return `<div class="quick-stats">${stats.map(s => `
        <div class="stat-card" style="--stat-color: ${s.color}">
            <div class="stat-icon">${getIcon(s.icon)}</div>
            <div class="stat-content">
                <div class="stat-value ${s.isStatus ? (s.value === 'Enabled' ? 'status-enabled' : 'status-disabled') : ''}">${s.value}</div>
                <div class="stat-label">${s.label}</div>
            </div>
        </div>`).join('')}</div>`;
}

function renderDomainsSection(spec) {
    const domains = spec.domains || [];
    if (domains.length === 0) {
        return `<section class="report-section"><div class="section-header">${getIcon('globe')}<h2 class="section-title">Domains</h2></div><div class="empty-section">No domains configured</div></section>`;
    }
    
    let listenerPort = '80', protocol = 'HTTP';
    if (spec.https_auto_cert || spec.https) { listenerPort = '443'; protocol = 'HTTPS'; }
    
    return `
        <section class="report-section">
            <div class="section-header"><div class="section-icon">${getIcon('globe')}</div><h2 class="section-title">Domains & Listeners</h2><span class="section-count">${domains.length}</span></div>
            <div class="domains-grid">${domains.map(domain => `
                <div class="domain-card">
                    <div class="domain-icon">${getIcon('globe')}</div>
                    <div class="domain-info">
                        <div class="domain-name">${domain}</div>
                        <div class="domain-meta">${protocol} · Port ${listenerPort}</div>
                    </div>
                    <a href="https://${domain}" target="_blank" class="domain-link" title="Open">${getIcon('external')}</a>
                </div>`).join('')}
            </div>
            ${spec.add_hsts_header ? `<div class="info-banner info-success">${getIcon('check')} HSTS Header enabled</div>` : ''}
            ${spec.http_redirect ? `<div class="info-banner info-success">${getIcon('check')} HTTP → HTTPS redirect enabled</div>` : ''}
        </section>`;
}

function renderRoutesSection() {
    const routes = ViewerState.routes;
    const typeColors = { 'simple': '#10b981', 'redirect': '#f59e0b', 'direct_response': '#8b5cf6' };
    const typeLabels = { 'simple': 'Route', 'redirect': 'Redirect', 'direct_response': 'Direct' };
    const pathIcons = { 'prefix': '≈', 'regex': '.*', 'exact': '=' };
    
    return `
        <section class="report-section">
            <div class="section-header"><div class="section-icon">${getIcon('route')}</div><h2 class="section-title">Routes & Path Matching</h2><span class="section-count">${routes.length}</span></div>
            <div class="routes-table-container">
                <table class="routes-table">
                    <thead><tr><th>#</th><th>Type</th><th>Methods</th><th>Path</th><th>Origins</th><th>WAF</th><th></th></tr></thead>
                    <tbody>${routes.map((r, idx) => {
                        let originsHtml = '<span class="text-muted">Inherited</span>';
                        if (r.type === 'redirect') originsHtml = `<span class="route-redirect">→ ${r.redirectConfig?.host || r.redirectConfig?.path || 'Redirect'}</span>`;
                        else if (r.type === 'direct_response') originsHtml = `<span class="route-direct">HTTP ${r.directResponse?.code}</span>`;
                        else if (r.origins.length > 0) originsHtml = r.origins.map(o => `<span class="origin-tag">${o.name}</span>`).join('');
                        
                        let wafHtml = '<span class="text-muted">Inherited</span>';
                        if (r.waf) wafHtml = r.waf.disabled ? '<span class="waf-disabled">Disabled</span>' : `<span class="waf-override">${r.waf.name}</span>`;
                        
                        return `<tr class="route-row">
                            <td class="route-index">${idx + 1}</td>
                            <td><span class="route-type-badge" style="--type-color: ${typeColors[r.type] || '#6b7280'}">${typeLabels[r.type] || r.type}</span></td>
                            <td class="route-methods">${r.methods.map(m => `<span class="method-badge method-${m.toLowerCase()}">${m}</span>`).join('')}</td>
                            <td class="route-path"><span class="path-match-type" title="${r.pathMatch}">${pathIcons[r.pathMatch] || ''}</span><code>${r.path}</code></td>
                            <td class="route-origins">${originsHtml}</td>
                            <td class="route-waf">${wafHtml}</td>
                            <td><button class="btn-icon" onclick="showRouteJson(${idx})" title="View JSON">${getIcon('code')}</button></td>
                        </tr>`;
                    }).join('')}</tbody>
                </table>
            </div>
        </section>`;
}

function renderOriginPoolsSection() {
    const pools = Array.from(ViewerState.originPools.entries());
    return `
        <section class="report-section">
            <div class="section-header"><div class="section-icon">${getIcon('server')}</div><h2 class="section-title">Origin Pools & Backends</h2><span class="section-count">${pools.length}</span></div>
            <div class="origin-pools-grid">${pools.map(([name, pool]) => renderOriginPoolCard(name, pool)).join('')}</div>
        </section>`;
}

function renderOriginPoolCard(name, pool) {
    const spec = pool.spec || {};
    const meta = pool.metadata || {};
    const originCount = spec.origin_servers?.length || 0;
    
    let originType = 'Unknown', originDetails = [];
    if (spec.origin_servers?.length > 0) {
        const first = spec.origin_servers[0];
        if (first.public_ip) { originType = 'Public IP'; originDetails = spec.origin_servers.map(o => o.public_ip?.ip); }
        else if (first.public_name) { originType = 'Public DNS'; originDetails = spec.origin_servers.map(o => o.public_name?.dns_name); }
        else if (first.private_ip) { originType = 'Private IP'; originDetails = spec.origin_servers.map(o => o.private_ip?.ip); }
        else if (first.private_name) { originType = 'Private DNS'; originDetails = spec.origin_servers.map(o => o.private_name?.dns_name); }
        else if (first.k8s_service) { originType = 'K8s Service'; originDetails = spec.origin_servers.map(o => o.k8s_service?.service_name); }
        else if (first.consul_service) originType = 'Consul Service';
        else if (first.vn_private_ip) originType = 'VN Private IP';
    }
    
    const port = spec.port || 'N/A';
    const tlsEnabled = !!spec.use_tls;
    const lbAlgo = spec.loadbalancer_algorithm || 'ROUND_ROBIN';
    const hcCount = spec.healthcheck?.length || 0;
    
    return `
        <div class="origin-pool-card">
            <div class="pool-header">
                <div class="pool-icon">${getIcon('server')}</div>
                <div class="pool-title"><h3 class="pool-name">${name}</h3><span class="pool-ns">${meta.namespace}</span></div>
                <button class="btn-icon" onclick="showObjectJson('origin_pool', '${name}')" title="View JSON">${getIcon('code')}</button>
            </div>
            <div class="pool-body">
                <div class="pool-stat-row">
                    <span class="pool-stat"><span class="pool-stat-label">Type</span><span class="pool-stat-value">${originType}</span></span>
                    <span class="pool-stat"><span class="pool-stat-label">Port</span><span class="pool-stat-value">${port}</span></span>
                    <span class="pool-stat"><span class="pool-stat-label">TLS</span><span class="pool-stat-value ${tlsEnabled ? 'text-success' : 'text-muted'}">${tlsEnabled ? 'Yes' : 'No'}</span></span>
                </div>
                <div class="pool-origins">
                    <div class="pool-origins-header"><span>Origin Servers</span><span class="origins-count">${originCount}</span></div>
                    <div class="pool-origins-list">
                        ${originDetails.slice(0, 5).map(o => `<div class="origin-item"><code>${o || 'N/A'}</code></div>`).join('')}
                        ${originDetails.length > 5 ? `<div class="origin-item text-muted">+${originDetails.length - 5} more</div>` : ''}
                    </div>
                </div>
                <div class="pool-footer">
                    <span class="pool-tag">${formatAlgorithm(lbAlgo)}</span>
                    ${hcCount > 0 ? `<span class="pool-tag tag-health">${hcCount} Health Check${hcCount > 1 ? 's' : ''}</span>` : ''}
                </div>
            </div>
        </div>`;
}

function renderSecuritySection(spec) {
    const features = [];
    
    // WAF
    if (spec.app_firewall) {
        const waf = ViewerState.wafPolicies.get(spec.app_firewall.name);
        const mode = getWafMode(waf);
        features.push({ name: 'Web Application Firewall', icon: 'shield', status: 'enabled', value: spec.app_firewall.name, mode, obj: waf });
    } else {
        features.push({ name: 'Web Application Firewall', icon: 'shield', status: 'disabled', value: 'Not configured' });
    }
    
    // Bot Defense
    features.push(spec.bot_defense 
        ? { name: 'Bot Defense', icon: 'bot', status: 'enabled', value: spec.bot_defense.policy?.name || 'Enabled', details: spec.bot_defense.regional_endpoint ? `Region: ${spec.bot_defense.regional_endpoint}` : '' }
        : { name: 'Bot Defense', icon: 'bot', status: 'disabled', value: 'Not configured' });
    
    // Service Policies
    if (spec.active_service_policies?.policies?.length > 0) {
        features.push({ name: 'Service Policies', icon: 'policy', status: 'enabled', value: `${spec.active_service_policies.policies.length} policies`, details: spec.active_service_policies.policies.map(p => p.name).join(', ') });
    }
    
    // User Identification
    if (spec.user_identification) {
        features.push({ name: 'User Identification', icon: 'user', status: 'enabled', value: spec.user_identification.name });
    }
    
    // Malicious User Mitigation
    if (spec.malicious_user_mitigation) {
        features.push({ name: 'Malicious User Mitigation', icon: 'alert', status: 'enabled', value: spec.malicious_user_mitigation.name });
    }
    
    // IP Reputation
    if (spec.enable_ip_reputation) {
        features.push({ name: 'IP Reputation', icon: 'network', status: 'enabled', value: 'Enabled' });
    }
    
    // DDoS
    if (spec.enable_ddos_detection) {
        features.push({ name: 'DDoS Detection', icon: 'ddos', status: 'enabled', value: 'Enabled' });
    }
    
    // Client-Side Defense
    if (spec.client_side_defense) {
        features.push({ name: 'Client-Side Defense', icon: 'browser', status: 'enabled', value: 'Enabled' });
    }
    
    return `
        <section class="report-section section-security">
            <div class="section-header"><div class="section-icon">${getIcon('shield')}</div><h2 class="section-title">Security Configuration</h2></div>
            <div class="security-grid">${features.map(f => `
                <div class="security-card ${f.status}">
                    <div class="security-card-header">
                        <div class="security-icon ${f.status}">${getIcon(f.icon)}</div>
                        <div class="security-info">
                            <h3 class="security-name">${f.name}</h3>
                            <div class="security-value"><span class="status-indicator ${f.status}"></span>${f.value}</div>
                            ${f.mode ? `<span class="security-mode mode-${f.mode}">${f.mode}</span>` : ''}
                        </div>
                        ${f.obj ? `<button class="btn-icon" onclick="showObjectJson('app_firewall', '${f.value}')" title="View JSON">${getIcon('code')}</button>` : ''}
                    </div>
                    ${f.details ? `<div class="security-card-details">${f.details}</div>` : ''}
                </div>`).join('')}
            </div>
        </section>`;
}

function renderAPISection(spec) {
    const features = [];
    if (spec.api_definition) features.push({ name: 'API Definition', icon: 'api', value: spec.api_definition.name });
    if (spec.enable_api_discovery) features.push({ name: 'API Discovery', icon: 'search', value: 'Enabled' });
    if (spec.api_protection_rules) features.push({ name: 'API Protection Rules', icon: 'policy', value: `${spec.api_protection_rules.api_groups?.length || 0} groups` });
    if (spec.sensitive_data_disclosure_rules) features.push({ name: 'Sensitive Data Discovery', icon: 'eye', value: 'Configured' });
    
    if (features.length === 0) {
        return `<section class="report-section"><div class="section-header"><div class="section-icon">${getIcon('api')}</div><h2 class="section-title">API Protection</h2></div><div class="empty-section">No API protection features configured</div></section>`;
    }
    
    return `
        <section class="report-section">
            <div class="section-header"><div class="section-icon">${getIcon('api')}</div><h2 class="section-title">API Protection</h2></div>
            <div class="api-features-grid">${features.map(f => `
                <div class="api-feature-card"><div class="api-feature-icon">${getIcon(f.icon)}</div><div class="api-feature-info"><h4 class="api-feature-name">${f.name}</h4><span class="api-feature-value">${f.value}</span></div></div>`).join('')}
            </div>
        </section>`;
}

function renderTLSSection(spec) {
    let tlsConfig = null, tlsType = '';
    if (spec.https_auto_cert) { tlsConfig = spec.https_auto_cert; tlsType = "Auto Certificate (Let's Encrypt)"; }
    else if (spec.https) { tlsConfig = spec.https; tlsType = 'Custom Certificate'; }
    
    if (!tlsConfig) {
        return `<section class="report-section"><div class="section-header"><div class="section-icon">${getIcon('lock')}</div><h2 class="section-title">TLS & Certificates</h2></div><div class="empty-section">HTTP only - No TLS configured</div></section>`;
    }
    
    const settings = [{ label: 'TLS Type', value: tlsType }];
    if (tlsConfig.tls_config?.min_version) settings.push({ label: 'Min TLS Version', value: tlsConfig.tls_config.min_version });
    if (tlsConfig.tls_config?.max_version) settings.push({ label: 'Max TLS Version', value: tlsConfig.tls_config.max_version });
    if (spec.add_hsts_header) settings.push({ label: 'HSTS', value: 'Enabled' });
    if (spec.http_redirect) settings.push({ label: 'HTTP Redirect', value: 'Enabled' });
    if (tlsConfig.mtls) settings.push({ label: 'mTLS', value: 'Enabled' });
    else if (tlsConfig.no_mtls) settings.push({ label: 'mTLS', value: 'Disabled' });
    
    return `
        <section class="report-section">
            <div class="section-header"><div class="section-icon">${getIcon('lock')}</div><h2 class="section-title">TLS & Certificates</h2></div>
            <div class="tls-grid">${settings.map(s => `<div class="tls-setting"><span class="tls-label">${s.label}</span><span class="tls-value">${s.value}</span></div>`).join('')}</div>
        </section>`;
}

function renderAdvancedSection(spec) {
    const settings = [];
    if (spec.request_headers_to_add?.length) settings.push({ cat: 'Request Headers', items: spec.request_headers_to_add.map(h => `${h.name}: ${h.value || '(dynamic)'}`) });
    if (spec.response_headers_to_add?.length) settings.push({ cat: 'Response Headers', items: spec.response_headers_to_add.map(h => `${h.name}: ${h.value || '(dynamic)'}`) });
    if (spec.cookie_stickiness) settings.push({ cat: 'Session Persistence', items: [`Cookie: ${spec.cookie_stickiness.name || 'Enabled'}`] });
    if (spec.enable_automatic_compression) settings.push({ cat: 'Compression', items: ['Auto compression enabled'] });
    if (spec.disable_buffering) settings.push({ cat: 'Buffering', items: ['Buffering disabled'] });
    if (spec.enable_websocket) settings.push({ cat: 'WebSocket', items: ['WebSocket enabled'] });
    if (spec.idle_timeout) settings.push({ cat: 'Timeouts', items: [`Idle: ${spec.idle_timeout}ms`] });
    
    if (settings.length === 0) return '';
    
    return `
        <section class="report-section section-collapsed">
            <div class="section-header" onclick="toggleSection(this)"><div class="section-icon">${getIcon('settings')}</div><h2 class="section-title">Advanced Settings</h2><span class="section-toggle">${getIcon('chevron')}</span></div>
            <div class="section-content">
                <div class="advanced-settings-grid">${settings.map(s => `<div class="advanced-setting-group"><h4 class="setting-category">${s.cat}</h4><div class="setting-items">${s.items.map(i => `<div class="setting-item"><code>${i}</code></div>`).join('')}</div></div>`).join('')}</div>
            </div>
        </section>`;
}

function renderJsonModal() {
    return `<div id="json-modal" class="modal-overlay"><div class="modal-content"><div class="modal-header"><h3 id="modal-title">Configuration JSON</h3><div class="modal-actions"><button class="btn btn-secondary btn-sm" onclick="copyJsonToClipboard()">${getIcon('copy')} Copy</button><button class="btn-icon" onclick="closeJsonModal()">${getIcon('close')}</button></div></div><div class="modal-body"><pre id="modal-json"></pre></div></div></div>`;
}

/* ============================================================
   HELPER FUNCTIONS
   ============================================================ */
function getWafMode(waf) {
    if (!waf?.spec) return 'unknown';
    if (waf.spec.blocking) return 'blocking';
    if (waf.spec.monitoring) return 'monitoring';
    if (waf.spec.mode) return waf.spec.mode.toLowerCase();
    return 'unknown';
}

function formatDate(timestamp) {
    if (!timestamp) return 'Unknown';
    return new Date(timestamp).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
}

function formatAlgorithm(algo) {
    const map = { 'ROUND_ROBIN': 'Round Robin', 'LEAST_ACTIVE': 'Least Connections', 'RANDOM': 'Random', 'RING_HASH': 'Ring Hash', 'SOURCE_IP_STICKINESS': 'Source IP' };
    return map[algo] || algo;
}

function getIcon(name, size = 20) {
    const icons = {
        globe: `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z"/></svg>`,
        route: `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22,12 18,12 15,21 9,3 6,12 2,12"/></svg>`,
        server: `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>`,
        shield: `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`,
        bot: `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="10" rx="2"/><circle cx="12" cy="5" r="2"/><path d="M12 7v4"/><line x1="8" y1="16" x2="8" y2="16"/><line x1="16" y1="16" x2="16" y2="16"/></svg>`,
        api: `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14,2 14,8 20,8"/><path d="M8 13h2"/><path d="M8 17h2"/><path d="M14 13h2"/><path d="M14 17h2"/></svg>`,
        lock: `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>`,
        settings: `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-2 2 2 2 0 01-2-2v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83 0 2 2 0 010-2.83l.06-.06a1.65 1.65 0 00.33-1.82 1.65 1.65 0 00-1.51-1H3a2 2 0 01-2-2 2 2 0 012-2h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 010-2.83 2 2 0 012.83 0l.06.06a1.65 1.65 0 001.82.33H9a1.65 1.65 0 001-1.51V3a2 2 0 012-2 2 2 0 012 2v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 0 2 2 0 010 2.83l-.06.06a1.65 1.65 0 00-.33 1.82V9a1.65 1.65 0 001.51 1H21a2 2 0 012 2 2 2 0 01-2 2h-.09a1.65 1.65 0 00-1.51 1z"/></svg>`,
        user: `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>`,
        policy: `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14,2 14,8 20,8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>`,
        alert: `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`,
        network: `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="6" height="6"/><rect x="3" y="3" width="4" height="4"/><rect x="17" y="3" width="4" height="4"/><rect x="17" y="17" width="4" height="4"/><rect x="3" y="17" width="4" height="4"/></svg>`,
        eye: `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>`,
        code: `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="16,18 22,12 16,6"/><polyline points="8,6 2,12 8,18"/></svg>`,
        external: `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 13v6a2 2 0 01-2 2H5a2 2 0 01-2-2V8a2 2 0 012-2h6"/><polyline points="15,3 21,3 21,9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>`,
        check: `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20,6 9,17 4,12"/></svg>`,
        copy: `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg>`,
        close: `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>`,
        chevron: `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6,9 12,15 18,9"/></svg>`,
        search: `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>`,
        browser: `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="18" height="18" rx="2"/><line x1="3" y1="9" x2="21" y2="9"/><line x1="9" y1="21" x2="9" y2="9"/></svg>`,
        ddos: `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M12 8v4"/><path d="M12 16h.01"/></svg>`,
        home: `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 9l9-7 9 7v11a2 2 0 01-2 2H5a2 2 0 01-2-2z"/></svg>`,
        clock: `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12,6 12,12 16,14"/></svg>`
    };
    return icons[name] || icons.api;
}

/* ============================================================
   EVENT HANDLERS
   ============================================================ */
function setupEventListeners() {
    document.getElementById('namespace-select').onchange = e => loadLoadBalancers(e.target.value);
    document.getElementById('btn-view').onclick = startViewer;
}

function attachReportEventListeners() {
    const modal = document.getElementById('json-modal');
    if (modal) modal.onclick = e => { if (e.target === modal) closeJsonModal(); };
    document.addEventListener('keydown', e => { if (e.key === 'Escape') closeJsonModal(); });
}

function toggleSection(header) {
    header.closest('.report-section').classList.toggle('section-collapsed');
}

function showFullJson() {
    if (!ViewerState.rootLB) return;
    showJsonInModal('Load Balancer Configuration', ViewerState.rootLB);
}

function showRouteJson(index) {
    const route = ViewerState.rootLB.spec.routes[index];
    showJsonInModal(`Route ${index + 1} JSON`, route);
}

function showObjectJson(type, name) {
    let obj = null;
    if (type === 'origin_pool') obj = ViewerState.originPools.get(name);
    else if (type === 'app_firewall') obj = ViewerState.wafPolicies.get(name);
    else {
        for (const [k, v] of ViewerState.objects) { if (k.includes(name)) { obj = v; break; } }
    }
    if (obj) showJsonInModal(`${name} Configuration`, obj);
    else Toast.warning('Object details not available');
}

function showJsonInModal(title, data) {
    const modal = document.getElementById('json-modal');
    if (!modal) return;
    document.getElementById('modal-title').textContent = title;
    document.getElementById('modal-json').textContent = JSON.stringify(data, null, 2);
    modal.classList.add('visible');
}

function closeJsonModal() {
    document.getElementById('json-modal')?.classList.remove('visible');
}

function copyJsonToClipboard() {
    const json = document.getElementById('modal-json')?.textContent;
    if (json) navigator.clipboard.writeText(json).then(() => Toast.success('Copied!')).catch(() => Toast.error('Copy failed'));
}

// Expose globally
window.showFullJson = showFullJson;
window.showRouteJson = showRouteJson;
window.showObjectJson = showObjectJson;
window.closeJsonModal = closeJsonModal;
window.copyJsonToClipboard = copyJsonToClipboard;
window.toggleSection = toggleSection;
