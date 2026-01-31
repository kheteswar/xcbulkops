<?php
/**
 * XC BulkOps - WAF Status Scanner Tool
 * Audit WAF configurations and modes across HTTP Load Balancers
 */

$config = [
    'appName' => 'XC BulkOps',
    'appVersion' => '1.3.0',
    'toolName' => 'WAF Status Scanner',
    'toolDescription' => 'Audit WAF configurations and modes across all HTTP Load Balancers',
    'proxyEndpoint' => 'proxy.php'
];
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= htmlspecialchars($config['toolName']) ?> - <?= htmlspecialchars($config['appName']) ?></title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&family=Plus+Jakarta+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="styles.css">
    <link rel="stylesheet" href="waf-scanner.css">
    
    <script>
        window.XC_CONFIG = {
            appName: '<?= htmlspecialchars($config['appName']) ?>',
            appVersion: '<?= htmlspecialchars($config['appVersion']) ?>',
            proxyEndpoint: '<?= htmlspecialchars($config['proxyEndpoint']) ?>'
        };
    </script>
</head>
<body>
    <header class="header">
        <div class="header-content">
            <div class="logo">
                <a href="index.php" class="logo-link">
                    <div class="logo-icon">
                        <svg viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg">
                            <rect x="2" y="2" width="36" height="36" rx="8" stroke="currentColor" stroke-width="2.5"/>
                            <path d="M12 20h16M20 12v16" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"/>
                            <circle cx="12" cy="12" r="3" fill="currentColor"/>
                            <circle cx="28" cy="12" r="3" fill="currentColor"/>
                            <circle cx="12" cy="28" r="3" fill="currentColor"/>
                            <circle cx="28" cy="28" r="3" fill="currentColor"/>
                        </svg>
                    </div>
                    <div class="logo-text">
                        <span class="logo-name"><?= htmlspecialchars($config['appName']) ?></span>
                        <span class="logo-tagline">WAF Status Scanner</span>
                    </div>
                </a>
            </div>
            <nav class="nav">
                <a href="index.php" class="nav-link">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16">
                        <path d="M19 12H5M12 19l-7-7 7-7"/>
                    </svg>
                    Back to Tools
                </a>
            </nav>
        </div>
    </header>

    <main class="main">
        <div class="tool-header">
            <div class="tool-icon tool-icon-report">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                    <path d="M9 12l2 2 4-4"/>
                </svg>
            </div>
            <div class="tool-info">
                <h1 class="tool-title"><?= htmlspecialchars($config['toolName']) ?></h1>
                <p class="tool-subtitle"><?= htmlspecialchars($config['toolDescription']) ?></p>
            </div>
            <div class="tool-badges">
                <span class="tool-tag tag-report">Report</span>
                <span class="tool-tag tag-safe">Read-Only</span>
            </div>
        </div>

        <div class="notice notice-warning" id="connection-notice">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/>
                <line x1="12" y1="9" x2="12" y2="13"/>
                <line x1="12" y1="17" x2="12.01" y2="17"/>
            </svg>
            <div class="notice-content">
                <strong>Connection Required</strong>
                <p>Please <a href="index.php">connect to F5 XC</a> first to use this tool.</p>
            </div>
        </div>

        <div class="wizard-container hidden" id="wizard-container">
            <div class="wizard-progress">
                <div class="progress-step active" data-step="1">
                    <div class="step-number">1</div>
                    <div class="step-label">Configure</div>
                </div>
                <div class="progress-line"></div>
                <div class="progress-step" data-step="2">
                    <div class="step-number">2</div>
                    <div class="step-label">Scanning</div>
                </div>
                <div class="progress-line"></div>
                <div class="progress-step" data-step="3">
                    <div class="step-number">3</div>
                    <div class="step-label">Results</div>
                </div>
            </div>

            <div class="wizard-step active" id="step-1">
                <div class="step-card">
                    <div class="step-header">
                        <h2 class="step-title">Select Scan Scope</h2>
                        <p class="step-description">Choose namespaces and options for WAF configuration scan</p>
                    </div>
                    
                    <div class="step-content">
                        <div class="form-group">
                            <label class="form-label">Namespaces</label>
                            <div class="namespace-controls">
                                <button type="button" class="btn btn-secondary btn-sm" id="select-all-ns">Select All</button>
                                <button type="button" class="btn btn-secondary btn-sm" id="deselect-all-ns">Deselect All</button>
                                <span class="namespace-count"><span id="selected-ns-count">0</span> selected</span>
                            </div>
                            <div class="namespace-list" id="namespace-list">
                                <div class="loading-placeholder" id="namespace-loader">
                                    <div class="spinner-sm"></div>
                                    <span>Loading namespaces...</span>
                                </div>
                            </div>
                        </div>

                        <div class="form-group">
                            <label class="form-label">Scan Options</label>
                            <div class="options-grid">
                                <label class="checkbox-card">
                                    <input type="checkbox" id="opt-include-routes" checked>
                                    <div class="checkbox-card-content">
                                        <div class="checkbox-card-icon">
                                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                                <polyline points="22,12 18,12 15,21 9,3 6,12 2,12"/>
                                            </svg>
                                        </div>
                                        <div class="checkbox-card-text">
                                            <strong>Include Route Details</strong>
                                            <span>Scan WAF settings per route</span>
                                        </div>
                                    </div>
                                </label>
                            </div>
                        </div>
                    </div>

                    <div class="step-actions">
                        <div class="step-actions-left">
                            <span class="text-muted" id="scan-estimate">Select namespaces to continue</span>
                        </div>
                        <div class="step-actions-right">
                            <button type="button" class="btn btn-primary" id="btn-start-scan" disabled>
                                Start Scan
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18">
                                    <polyline points="9,18 15,12 9,6"/>
                                </svg>
                            </button>
                        </div>
                    </div>
                </div>
            </div>

            <div class="wizard-step" id="step-2">
                <div class="step-card">
                    <div class="step-header">
                        <h2 class="step-title">Scanning WAF Configurations</h2>
                        <p class="step-description">Analyzing HTTP Load Balancers and WAF policies</p>
                    </div>
                    
                    <div class="step-content">
                        <div class="current-operation" id="current-operation">
                            <div class="operation-icon">
                                <svg class="spinner-lg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <circle cx="12" cy="12" r="10" stroke-opacity="0.25"/>
                                    <path d="M12 2a10 10 0 0 1 10 10" stroke-linecap="round"/>
                                </svg>
                            </div>
                            <div class="operation-details">
                                <div class="operation-title" id="operation-title">Initializing scan...</div>
                                <div class="operation-subtitle" id="operation-subtitle">Preparing to fetch data</div>
                            </div>
                        </div>

                        <div class="scan-progress">
                            <div class="progress-bar-container">
                                <div class="progress-bar" id="scan-progress-bar" style="width: 0%"></div>
                            </div>
                            <div class="progress-stats">
                                <span class="progress-percent" id="scan-progress-percent">0%</span>
                                <span class="progress-detail" id="scan-progress-detail">Starting...</span>
                            </div>
                        </div>

                        <div class="scan-stats">
                            <div class="stat-card">
                                <div class="stat-icon stat-icon-ns">
                                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                        <path d="M3 3h18v18H3zM3 9h18M9 21V9"/>
                                    </svg>
                                </div>
                                <div class="stat-info">
                                    <div class="stat-value" id="stat-namespaces">0</div>
                                    <div class="stat-label">Namespaces</div>
                                </div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-icon stat-icon-lb">
                                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                        <rect x="2" y="3" width="20" height="14" rx="2" ry="2"/>
                                        <line x1="8" y1="21" x2="16" y2="21"/>
                                        <line x1="12" y1="17" x2="12" y2="21"/>
                                    </svg>
                                </div>
                                <div class="stat-info">
                                    <div class="stat-value" id="stat-loadbalancers">0</div>
                                    <div class="stat-label">Load Balancers</div>
                                </div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-icon stat-icon-route">
                                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                        <polyline points="22,12 18,12 15,21 9,3 6,12 2,12"/>
                                    </svg>
                                </div>
                                <div class="stat-info">
                                    <div class="stat-value" id="stat-routes">0</div>
                                    <div class="stat-label">Routes</div>
                                </div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-icon stat-icon-waf">
                                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                                    </svg>
                                </div>
                                <div class="stat-info">
                                    <div class="stat-value" id="stat-wafs">0</div>
                                    <div class="stat-label">WAF Policies</div>
                                </div>
                            </div>
                        </div>

                        <div class="scan-log-container">
                            <div class="scan-log-header">
                                <span>
                                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16">
                                        <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/>
                                        <polyline points="14,2 14,8 20,8"/>
                                        <line x1="16" y1="13" x2="8" y2="13"/>
                                        <line x1="16" y1="17" x2="8" y2="17"/>
                                    </svg>
                                    Activity Log
                                </span>
                                <span class="log-count" id="log-count">0 entries</span>
                            </div>
                            <div class="scan-log" id="scan-log"></div>
                        </div>
                    </div>

                    <div class="step-actions">
                        <div class="step-actions-left">
                            <span class="text-muted" id="scan-eta">Estimated time remaining: calculating...</span>
                        </div>
                        <div class="step-actions-right">
                            <button type="button" class="btn btn-secondary" id="btn-cancel-scan">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18">
                                    <circle cx="12" cy="12" r="10"/>
                                    <line x1="15" y1="9" x2="9" y2="15"/>
                                    <line x1="9" y1="9" x2="15" y2="15"/>
                                </svg>
                                Cancel Scan
                            </button>
                        </div>
                    </div>
                </div>
            </div>

            <div class="wizard-step" id="step-3">
                <div class="step-card">
                    <div class="step-header">
                        <h2 class="step-title">Scan Results</h2>
                        <p class="step-description" id="results-summary">Scan complete</p>
                    </div>
                    
                    <div class="step-content">
                        <div class="results-summary">
                            <div class="summary-card summary-blocking">
                                <div class="summary-icon">
                                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                                        <path d="M9 12l2 2 4-4"/>
                                    </svg>
                                </div>
                                <div class="summary-value" id="summary-blocking">0</div>
                                <div class="summary-label">Blocking</div>
                            </div>
                            <div class="summary-card summary-monitoring">
                                <div class="summary-icon">
                                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                        <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
                                        <circle cx="12" cy="12" r="3"/>
                                    </svg>
                                </div>
                                <div class="summary-value" id="summary-monitoring">0</div>
                                <div class="summary-label">Monitoring</div>
                            </div>
                            <div class="summary-card summary-disabled">
                                <div class="summary-icon">
                                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                        <circle cx="12" cy="12" r="10"/>
                                        <line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/>
                                    </svg>
                                </div>
                                <div class="summary-value" id="summary-disabled">0</div>
                                <div class="summary-label">No WAF</div>
                            </div>
                        </div>

                        <div class="results-toolbar">
                            <div class="search-box">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <circle cx="11" cy="11" r="8"/>
                                    <line x1="21" y1="21" x2="16.65" y2="16.65"/>
                                </svg>
                                <input type="text" id="results-search" placeholder="Search load balancers, namespaces...">
                            </div>
                            <div class="filter-buttons">
                                <button type="button" class="filter-btn active" data-filter="all">All</button>
                                <button type="button" class="filter-btn" data-filter="blocking">Blocking</button>
                                <button type="button" class="filter-btn" data-filter="monitoring">Monitoring</button>
                                <button type="button" class="filter-btn" data-filter="nowaf">No WAF</button>
                            </div>
                        </div>

                        <div class="results-table-container">
                            <table class="results-table" id="results-table">
                                <thead>
                                    <tr>
                                        <th>Namespace</th>
                                        <th>Load Balancer</th>
                                        <th>Route</th>
                                        <th>WAF Policy</th>
                                        <th>Mode</th>
                                    </tr>
                                </thead>
                                <tbody id="results-tbody">
                                </tbody>
                            </table>
                            <div class="no-results hidden" id="no-results">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <circle cx="11" cy="11" r="8"/>
                                    <line x1="21" y1="21" x2="16.65" y2="16.65"/>
                                </svg>
                                <p>No results match your filter</p>
                            </div>
                        </div>
                    </div>

                    <div class="step-actions">
                        <div class="step-actions-left">
                            <button type="button" class="btn btn-secondary" id="btn-new-scan">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18">
                                    <polyline points="23,4 23,10 17,10"/>
                                    <path d="M20.49 15a9 9 0 11-2.12-9.36L23 10"/>
                                </svg>
                                New Scan
                            </button>
                        </div>
                        <div class="step-actions-right">
                            <button type="button" class="btn btn-secondary" id="btn-export-excel">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18">
                                    <rect x="2" y="7" width="20" height="14" rx="2" ry="2"></rect>
                                    <path d="M16 21V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16"></path>
                                </svg>
                                Export Excel (XLS)
                            </button>
                            <button type="button" class="btn btn-primary" id="btn-export-report">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18">
                                    <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/>
                                    <polyline points="14,2 14,8 20,8"/>
                                    <line x1="16" y1="13" x2="8" y2="13"/>
                                    <line x1="16" y1="17" x2="8" y2="17"/>
                                </svg>
                                Export Report
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </main>

    <div id="toast-container" class="toast-container"></div>

    <script src="app.js"></script>
    <script src="waf-scanner.js"></script>
</body>
</html>