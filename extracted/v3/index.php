<?php
/**
 * XC Commander - F5 Distributed Cloud Bulk Operations Toolbox
 * Main landing page
 */

// Configuration
$config = [
    'appName' => 'XC BulkOps',
    'appVersion' => '1.0.0',
    'proxyEndpoint' => 'proxy.php'
];
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= htmlspecialchars($config['appName']) ?> - F5 Distributed Cloud Bulk Operations Toolbox</title>

    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&family=Plus+Jakarta+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="styles.css">

    <script>
        window.XC_CONFIG = {
            appName: '<?= htmlspecialchars($config['appName']) ?>',
            appVersion: '<?= htmlspecialchars($config['appVersion']) ?>',
            proxyEndpoint: '<?= htmlspecialchars($config['proxyEndpoint']) ?>'
        };
    </script>
</head>
<body>

<!-- HEADER -->
<header class="header">
    <div class="header-content">
        <div class="logo">
            <div class="logo-icon">
                <svg viewBox="0 0 40 40">
                    <rect x="2" y="2" width="36" height="36" rx="8"
                          stroke="currentColor" stroke-width="2.5"/>
                    <path d="M12 20h16M20 12v16"
                          stroke="currentColor" stroke-width="2.5"
                          stroke-linecap="round"/>
                </svg>
            </div>
            <div class="logo-text">
                <span class="logo-name"><?= htmlspecialchars($config['appName']) ?></span>
                <span class="logo-tagline">F5 XC Bulk Operations Toolbox</span>
            </div>
        </div>

        <nav class="nav">
            <a href="#tools" class="nav-link">Tools</a>
            <a href="#backup-vault" class="nav-link">Backup Vault</a>
            <a href="#settings" class="nav-link">Settings</a>
            <a href="https://docs.cloud.f5.com/docs-v2/api"
               target="_blank"
               class="nav-link nav-link-external">
                API Docs ↗
            </a>
        </nav>
    </div>
</header>

<!-- MAIN -->
<main class="main">

    <!-- CONNECTION PANEL -->
    <section class="connection-panel" id="connection-panel">
        <div class="connection-card">
            
            <!-- Connection Status (Always visible) -->
            <div class="connection-status disconnected" id="connection-status">
                <div class="status-indicator"></div>
                <span class="status-text">Not Connected</span>
            </div>

            <!-- DISCONNECTED STATE - Form -->
            <div class="connection-form" id="connection-form">
                <h2 class="connection-title">Connect to F5 Distributed Cloud</h2>
                <p class="connection-description">
                    Enter your tenant name and API token to begin. Your credentials are stored locally
                    in your browser and only used to communicate with F5 XC APIs.
                </p>

                <div class="form-group">
                    <label class="form-label">Tenant Name</label>
                    <div class="input-wrapper">
                        <input
                            type="text"
                            id="tenant-name"
                            class="form-input"
                            placeholder="your-tenant"
                            autocomplete="off"
                        >
                        <span class="input-suffix">.console.ves.volterra.io</span>
                    </div>
                    <span class="form-hint">Your F5 XC tenant identifier</span>
                </div>

                <div class="form-group">
                    <label class="form-label">API Token</label>
                    <div class="input-wrapper">
                        <input
                            type="password"
                            id="api-token"
                            class="form-input"
                            placeholder="Enter your API token"
                            autocomplete="off"
                        >
                        <button type="button" class="toggle-visibility" id="toggle-token">
                            <svg class="icon-eye" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
                                <circle cx="12" cy="12" r="3"/>
                            </svg>
                            <svg class="icon-eye-off hidden" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19m-6.72-1.07a3 3 0 11-4.24-4.24"/>
                                <line x1="1" y1="1" x2="23" y2="23"/>
                            </svg>
                        </button>
                    </div>
                    <span class="form-hint">
                        Generate from F5 XC Console → Administration → Credentials
                    </span>
                </div>

                <div class="form-actions">
                    <label class="checkbox-wrapper">
                        <input type="checkbox" id="remember-credentials" checked>
                        <span class="checkbox-custom"></span>
                        <span class="checkbox-label">Remember credentials in this browser</span>
                    </label>

                    <button type="button" class="btn btn-primary" id="connect-btn">
                        <span class="btn-text">Connect</span>
                        <span class="btn-loader hidden">
                            <svg class="spinner" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <circle cx="12" cy="12" r="10" stroke-opacity="0.25"/>
                                <path d="M12 2a10 10 0 0 1 10 10" stroke-linecap="round"/>
                            </svg>
                        </span>
                    </button>
                </div>
            </div>

            <!-- CONNECTED STATE -->
            <div class="connection-info hidden" id="connection-info">
                <div class="tenant-info">
                    <div class="tenant-avatar">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M3 9l9-7 9 7v11a2 2 0 01-2 2H5a2 2 0 01-2-2z"/>
                            <polyline points="9,22 9,12 15,12 15,22"/>
                        </svg>
                    </div>
                    <div class="tenant-details">
                        <span class="tenant-name" id="connected-tenant">—</span>
                        <span class="tenant-url" id="connected-url">—</span>
                    </div>
                </div>

                <button type="button" class="btn btn-secondary" id="disconnect-btn">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18">
                        <path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4"/>
                        <polyline points="16,17 21,12 16,7"/>
                        <line x1="21" y1="12" x2="9" y2="12"/>
                    </svg>
                    Disconnect
                </button>
            </div>

        </div>
    </section>
            
            <!-- Security Notice -->
            <div class="security-notice">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                    <path d="M9 12l2 2 4-4"/>
                </svg>
                <div class="security-text">
                    <strong>Secure API Proxy</strong>
                    <span>Your API token is sent securely through our server-side proxy. No credentials are stored on the server.</span>
                </div>
            </div>
        

        <!-- Backup Vault Summary -->
        <section class="backup-summary" id="backup-vault">
            <div class="backup-card">
                <div class="backup-icon">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M19 21H5a2 2 0 01-2-2V5a2 2 0 012-2h11l5 5v11a2 2 0 01-2 2z"/>
                        <polyline points="17,21 17,13 7,13 7,21"/>
                        <polyline points="7,3 7,8 15,8"/>
                    </svg>
                </div>
                <div class="backup-info">
                    <h3 class="backup-title">Backup Vault</h3>
                    <p class="backup-stats">
                        <span class="backup-count" id="backup-count">0</span> restore points available
                    </p>
                </div>
                <button class="btn btn-ghost" id="view-backups-btn">
                    View All
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <polyline points="9,18 15,12 9,6"/>
                    </svg>
                </button>
            </div>
        </section>

        <!-- Tools Grid -->
        <section class="tools-section" id="tools">
            <div class="section-header">
                <h2 class="section-title">Bulk Operations</h2>
                <p class="section-description">Select a tool to perform bulk configuration operations on your F5 XC environment</p>
            </div>

            <div class="tools-grid">
                
                <!-- XC Config visualizer -->
                <article class="tool-card tool-card-featured" onclick="window.location.href='config-visualizer.php'">
                    <div class="tool-badge">New</div>
                    <div class="tool-icon tool-icon-report">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <rect x="3" y="3" width="7" height="7"></rect>
                            <rect x="14" y="3" width="7" height="7"></rect>
                            <rect x="14" y="14" width="7" height="7"></rect>
                            <rect x="3" y="14" width="7" height="7"></rect>
                            <path d="M10 6.5h4M6.5 10v4M17.5 10v4M10 17.5h4"></path>
                        </svg>
                    </div>
                    <div class="tool-content">
                        <h3 class="tool-name">Config Visualizer</h3>
                        <p class="tool-description">Interactive map of Load Balancer dependencies and configuration settings.</p>
                    </div>
                    <div class="tool-meta">
                        <span class="tool-tag tag-report">Visualize</span>
                        <span class="tool-tag tag-safe">Read-Only</span>
                    </div>
                    <div class="tool-arrow">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <polyline points="9,18 15,12 9,6"/>
                        </svg>
                    </div>
                </article>
                
                
                <!-- LB Forge -->
                <article class="tool-card" data-tool="lb-forge">
                    <div class="tool-icon tool-icon-create">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M14.7 6.3a1 1 0 000 1.4l1.6 1.6a1 1 0 001.4 0l3.77-3.77a6 6 0 01-7.94 7.94l-6.91 6.91a2.12 2.12 0 01-3-3l6.91-6.91a6 6 0 017.94-7.94l-3.76 3.76z"/>
                        </svg>
                    </div>
                    <div class="tool-content">
                        <h3 class="tool-name">LB Forge</h3>
                        <p class="tool-description">Create multiple HTTP Load Balancers at scale from CSV input</p>
                    </div>
                    <div class="tool-meta">
                        <span class="tool-tag tag-create">Create</span>
                    </div>
                    <div class="tool-arrow">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <polyline points="9,18 15,12 9,6"/>
                        </svg>
                    </div>
                </article>

                <!-- CDN Factory -->
                <article class="tool-card" data-tool="cdn-factory">
                    <div class="tool-icon tool-icon-create">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <circle cx="12" cy="12" r="10"/>
                            <line x1="2" y1="12" x2="22" y2="12"/>
                            <path d="M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z"/>
                        </svg>
                    </div>
                    <div class="tool-content">
                        <h3 class="tool-name">CDN Factory</h3>
                        <p class="tool-description">Spin up CDN distributions en masse with bulk configuration</p>
                    </div>
                    <div class="tool-meta">
                        <span class="tool-tag tag-create">Create</span>
                    </div>
                    <div class="tool-arrow">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <polyline points="9,18 15,12 9,6"/>
                        </svg>
                    </div>
                </article>

                <!-- Prefix Builder -->
                <article class="tool-card" data-tool="prefix-builder">
                    <div class="tool-icon tool-icon-create">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <rect x="3" y="3" width="7" height="7"/>
                            <rect x="14" y="3" width="7" height="7"/>
                            <rect x="14" y="14" width="7" height="7"/>
                            <rect x="3" y="14" width="7" height="7"/>
                        </svg>
                    </div>
                    <div class="tool-content">
                        <h3 class="tool-name">Prefix Builder</h3>
                        <p class="tool-description">Build IP prefix sets in bulk for firewall and routing rules</p>
                    </div>
                    <div class="tool-meta">
                        <span class="tool-tag tag-create">Create</span>
                    </div>
                    <div class="tool-arrow">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <polyline points="9,18 15,12 9,6"/>
                        </svg>
                    </div>
                </article>

                <!-- Config Sync -->
                <article class="tool-card" data-tool="config-sync">
                    <div class="tool-icon tool-icon-update">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <polyline points="23,4 23,10 17,10"/>
                            <polyline points="1,20 1,14 7,14"/>
                            <path d="M3.51 9a9 9 0 0114.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0020.49 15"/>
                        </svg>
                    </div>
                    <div class="tool-content">
                        <h3 class="tool-name">Config Sync</h3>
                        <p class="tool-description">Mass update settings across HTTP Load Balancers (HSTS, API Discovery, etc.)</p>
                    </div>
                    <div class="tool-meta">
                        <span class="tool-tag tag-update">Update</span>
                    </div>
                    <div class="tool-arrow">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <polyline points="9,18 15,12 9,6"/>
                        </svg>
                    </div>
                </article>

                <!-- Policy Pusher -->
                <article class="tool-card" data-tool="policy-pusher">
                    <div class="tool-icon tool-icon-update">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                        </svg>
                    </div>
                    <div class="tool-content">
                        <h3 class="tool-name">Policy Pusher</h3>
                        <p class="tool-description">Deploy service policies fleet-wide across load balancers</p>
                    </div>
                    <div class="tool-meta">
                        <span class="tool-tag tag-update">Update</span>
                    </div>
                    <div class="tool-arrow">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <polyline points="9,18 15,12 9,6"/>
                        </svg>
                    </div>
                </article>

                <!-- Identity Roller -->
                <article class="tool-card" data-tool="identity-roller">
                    <div class="tool-icon tool-icon-update">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2"/>
                            <circle cx="12" cy="7" r="4"/>
                        </svg>
                    </div>
                    <div class="tool-content">
                        <h3 class="tool-name">Identity Roller</h3>
                        <p class="tool-description">Roll out user identification policies everywhere</p>
                    </div>
                    <div class="tool-meta">
                        <span class="tool-tag tag-update">Update</span>
                    </div>
                    <div class="tool-arrow">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <polyline points="9,18 15,12 9,6"/>
                        </svg>
                    </div>
                </article>

                <!-- Threat Toggle -->
                <article class="tool-card" data-tool="threat-toggle">
                    <div class="tool-icon tool-icon-update">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/>
                            <line x1="12" y1="9" x2="12" y2="13"/>
                            <line x1="12" y1="17" x2="12.01" y2="17"/>
                        </svg>
                    </div>
                    <div class="tool-content">
                        <h3 class="tool-name">Threat Toggle</h3>
                        <p class="tool-description">Enable/disable Malicious User Detection across all apps</p>
                    </div>
                    <div class="tool-meta">
                        <span class="tool-tag tag-update">Update</span>
                    </div>
                    <div class="tool-arrow">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <polyline points="9,18 15,12 9,6"/>
                        </svg>
                    </div>
                </article>

                <!-- WAF Status Scanner -->
                <article class="tool-card tool-card-featured" data-tool="waf-scanner" onclick="window.location.href='waf-scanner.php'">
                    <div class="tool-badge">Start Here</div>
                    <div class="tool-icon tool-icon-report">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <circle cx="11" cy="11" r="8"/>
                            <line x1="21" y1="21" x2="16.65" y2="16.65"/>
                        </svg>
                    </div>
                    <div class="tool-content">
                        <h3 class="tool-name">WAF Status Scanner</h3>
                        <p class="tool-description">Audit WAF modes, exclusion rules, and security status across all load balancers</p>
                    </div>
                    <div class="tool-meta">
                        <span class="tool-tag tag-report">Report</span>
                        <span class="tool-tag tag-safe">Read-Only</span>
                    </div>
                    <div class="tool-arrow">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <polyline points="9,18 15,12 9,6"/>
                        </svg>
                    </div>
                </article>

                <!-- Log Harvester -->
                <article class="tool-card" data-tool="log-harvester">
                    <div class="tool-icon tool-icon-report">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/>
                            <polyline points="7,10 12,15 17,10"/>
                            <line x1="12" y1="15" x2="12" y2="3"/>
                        </svg>
                    </div>
                    <div class="tool-content">
                        <h3 class="tool-name">Log Harvester</h3>
                        <p class="tool-description">Extract logs for a given duration for offline analysis</p>
                    </div>
                    <div class="tool-meta">
                        <span class="tool-tag tag-report">Export</span>
                    </div>
                    <div class="tool-arrow">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <polyline points="9,18 15,12 9,6"/>
                        </svg>
                    </div>
                </article>

                <!-- Security Auditor -->
                <article class="tool-card" data-tool="security-auditor">
                    <div class="tool-icon tool-icon-report">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/>
                            <polyline points="14,2 14,8 20,8"/>
                            <line x1="16" y1="13" x2="8" y2="13"/>
                            <line x1="16" y1="17" x2="8" y2="17"/>
                            <polyline points="10,9 9,9 8,9"/>
                        </svg>
                    </div>
                    <div class="tool-content">
                        <h3 class="tool-name">Security Auditor</h3>
                        <p class="tool-description">Comprehensive security posture report across all configurations</p>
                    </div>
                    <div class="tool-meta">
                        <span class="tool-tag tag-report">Report</span>
                    </div>
                    <div class="tool-arrow">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <polyline points="9,18 15,12 9,6"/>
                        </svg>
                    </div>
                </article>
            </div>
        </section>

        <!-- Features Section -->
        <section class="features-section">
            <div class="section-header">
                <h2 class="section-title">Built for Safety & Scale</h2>
                <p class="section-description">Enterprise-grade features for production environments</p>
            </div>

            <div class="features-grid">
                <div class="feature-card">
                    <div class="feature-icon">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M19 21H5a2 2 0 01-2-2V5a2 2 0 012-2h11l5 5v11a2 2 0 01-2 2z"/>
                            <polyline points="17,21 17,13 7,13 7,21"/>
                            <polyline points="7,3 7,8 15,8"/>
                        </svg>
                    </div>
                    <h3 class="feature-title">Auto-Backup</h3>
                    <p class="feature-description">Every operation creates a restore point. Roll back with one click if needed.</p>
                </div>

                <div class="feature-card">
                    <div class="feature-icon">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <rect x="3" y="3" width="18" height="18" rx="2" ry="2"/>
                            <line x1="3" y1="9" x2="21" y2="9"/>
                            <line x1="9" y1="21" x2="9" y2="9"/>
                        </svg>
                    </div>
                    <h3 class="feature-title">Before/After Diff</h3>
                    <p class="feature-description">See exactly what changed with side-by-side configuration comparison.</p>
                </div>

                <div class="feature-card">
                    <div class="feature-icon">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <circle cx="12" cy="12" r="10"/>
                            <polyline points="12,6 12,12 16,14"/>
                        </svg>
                    </div>
                    <h3 class="feature-title">Rate Limiting</h3>
                    <p class="feature-description">Smart queue with configurable rate limits. Never hit API throttling.</p>
                </div>

                <div class="feature-card">
                    <div class="feature-icon">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
                            <circle cx="12" cy="12" r="3"/>
                        </svg>
                    </div>
                    <h3 class="feature-title">Dry Run Preview</h3>
                    <p class="feature-description">Preview all changes before execution. Nothing happens until you confirm.</p>
                </div>

                <div class="feature-card">
                    <div class="feature-icon">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <polyline points="22,12 18,12 15,21 9,3 6,12 2,12"/>
                        </svg>
                    </div>
                    <h3 class="feature-title">Live Progress</h3>
                    <p class="feature-description">Real-time progress tracking with ETA. Pause and resume anytime.</p>
                </div>

                <div class="feature-card">
                    <div class="feature-icon">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                            <path d="M9 12l2 2 4-4"/>
                        </svg>
                    </div>
                    <h3 class="feature-title">Secure Proxy</h3>
                    <p class="feature-description">Server-side proxy ensures secure API communication. No CORS issues.</p>
                </div>
            </div>
        </section>
    </main>

    <!-- Footer -->
    <footer class="footer">
        <div class="footer-content">
            <div class="footer-left">
                <span class="footer-brand"><?= htmlspecialchars($config['appName']) ?></span>
                <span class="footer-version">v<?= htmlspecialchars($config['appVersion']) ?></span>
            </div>
            <div class="footer-center">
                <p class="footer-disclaimer">
                    This tool is not affiliated with or endorsed by F5, Inc. Use at your own risk.
                </p>
            </div>
            <div class="footer-right">
                <a href="https://docs.cloud.f5.com/docs-v2/api" target="_blank" class="footer-link">F5 XC API Docs</a>
                <span class="footer-divider">•</span>
                <a href="https://github.com" target="_blank" class="footer-link">GitHub</a>
            </div>
        </div>
    </footer>

    <!-- Toast Container -->
    <div id="toast-container" class="toast-container"></div>

    <script src="app.js"></script>
</body>
</html>