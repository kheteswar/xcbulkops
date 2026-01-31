<?php
/**
 * XC BulkOps - Config Visualizer v8.0
 * Intelligent Configuration Analysis Agent
 */
$config = [
    'appName' => 'XC BulkOps',
    'appVersion' => '2.0.0',
    'toolName' => 'Config Visualizer',
    'toolDescription' => 'Intelligent deep-dive analysis of HTTP Load Balancer configuration with relationship mapping'
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
    <link rel="stylesheet" href="config-visualizer.css">
    <script>
        window.XC_CONFIG = { appName: '<?= $config['appName'] ?>', appVersion: '<?= $config['appVersion'] ?>', proxyEndpoint: 'proxy.php' };
    </script>
</head>
<body>
    <header class="header">
        <div class="header-content">
            <div class="logo">
                <a href="index.php" class="logo-link">
                    <div class="logo-icon">
                        <svg width="40" height="40" viewBox="0 0 40 40" fill="none" stroke="currentColor" stroke-width="2">
                            <rect x="2" y="2" width="36" height="36" rx="8" stroke-width="2.5"/>
                            <path d="M12 20h16M20 12v16" stroke-width="2.5" stroke-linecap="round"/>
                        </svg>
                    </div>
                    <div class="logo-text">
                        <span class="app-name"><?= htmlspecialchars($config['appName']) ?></span>
                        <span class="app-version">v<?= htmlspecialchars($config['appVersion']) ?></span>
                    </div>
                </a>
            </div>
            <nav class="nav">
                <a href="index.php" class="nav-link">Dashboard</a>
                <a href="waf-scanner.php" class="nav-link">WAF Scanner</a>
                <a href="config-visualizer.php" class="nav-link active">Config Visualizer</a>
            </nav>
        </div>
    </header>

    <main class="main-content">
        <div class="container">
            <!-- Tool Header -->
            <div class="tool-header" style="background: linear-gradient(135deg, rgba(139, 92, 246, 0.15) 0%, rgba(59, 130, 246, 0.1) 100%);">
                <div class="tool-icon" style="background: rgba(139, 92, 246, 0.2); color: #a78bfa;">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/>
                        <polyline points="14,2 14,8 20,8"/>
                        <line x1="16" y1="13" x2="8" y2="13"/>
                        <line x1="16" y1="17" x2="8" y2="17"/>
                        <polyline points="10,9 9,9 8,9"/>
                    </svg>
                </div>
                <div class="tool-info">
                    <h1 class="tool-title"><?= htmlspecialchars($config['toolName']) ?></h1>
                    <p class="tool-subtitle"><?= htmlspecialchars($config['toolDescription']) ?></p>
                    <div class="tool-badges">
                        <span class="badge badge-feature">Deep Analysis</span>
                        <span class="badge badge-feature">Relationship Mapping</span>
                        <span class="badge badge-feature">Human Readable</span>
                    </div>
                </div>
            </div>

            <!-- Connection Notice -->
            <div id="connection-notice" class="notice notice-warning">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <circle cx="12" cy="12" r="10"/>
                    <line x1="12" y1="8" x2="12" y2="12"/>
                    <line x1="12" y1="16" x2="12.01" y2="16"/>
                </svg>
                <div class="notice-content">
                    <strong>Connection Required</strong>
                    <p>Please <a href="index.php">connect to your F5 XC tenant</a> first to use this tool.</p>
                </div>
            </div>

            <!-- Main Tool Interface -->
            <div id="viewer-wrapper" class="hidden">
                <!-- Selector Bar -->
                <div class="selector-bar">
                    <div class="selector-group">
                        <label for="namespace-select">Namespace</label>
                        <div class="select-wrapper">
                            <select id="namespace-select" class="form-select" disabled>
                                <option value="">Loading namespaces...</option>
                            </select>
                            <svg class="select-arrow" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16">
                                <polyline points="6,9 12,15 18,9"/>
                            </svg>
                        </div>
                    </div>
                    <div class="selector-group">
                        <label for="lb-select">HTTP Load Balancer</label>
                        <div class="select-wrapper">
                            <select id="lb-select" class="form-select" disabled>
                                <option value="">Select namespace first</option>
                            </select>
                            <svg class="select-arrow" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16">
                                <polyline points="6,9 12,15 18,9"/>
                            </svg>
                        </div>
                    </div>
                    <button id="btn-view" class="btn btn-primary" disabled>
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18">
                            <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
                            <circle cx="12" cy="12" r="3"/>
                        </svg>
                        Analyze
                    </button>
                </div>

                <!-- Report Container -->
                <div id="report-container" class="report-container">
                    <!-- Loading State -->
                    <div id="loading-state" class="loading-state hidden">
                        <div class="spinner-lg"></div>
                        <div class="loading-title">Analyzing Configuration</div>
                        <div class="loading-subtitle">Crawling linked objects and building relationship map...</div>
                        <div id="scan-log" class="scan-log">Initializing...</div>
                    </div>

                    <!-- Empty State -->
                    <div id="empty-state" class="empty-state">
                        <div class="empty-icon">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" width="64" height="64">
                                <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/>
                                <polyline points="14,2 14,8 20,8"/>
                                <line x1="16" y1="13" x2="8" y2="13"/>
                                <line x1="16" y1="17" x2="8" y2="17"/>
                            </svg>
                        </div>
                        <h3>Ready to Analyze</h3>
                        <p>Select a namespace and HTTP Load Balancer above to generate a comprehensive configuration report with all linked objects and settings.</p>
                    </div>

                    <!-- Report Content (populated by JS) -->
                    <div id="report-content" class="report-content hidden"></div>
                </div>
            </div>
        </div>
    </main>

    <!-- Toast Container -->
    <div id="toast-container" class="toast-container"></div>

    <!-- Scripts -->
    <script src="app.js"></script>
    <script src="config-visualizer.js"></script>
</body>
</html>
