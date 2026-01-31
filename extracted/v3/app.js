/**
 * XC Commander – Core App Logic
 * Smooth connection UX with toast notifications
 */

/* ============================================================
   APP STATE
   ============================================================ */
const AppState = {
    connected: false,
    tenant: null,
    apiToken: null
};

/* ============================================================
   STORAGE MANAGER
   ============================================================ */
const StorageManager = {
    KEY: 'xc_commander_credentials',

    saveCredentials(tenant, apiToken) {
        localStorage.setItem(this.KEY, JSON.stringify({ tenant, apiToken }));
    },

    loadCredentials() {
        try {
            return JSON.parse(localStorage.getItem(this.KEY));
        } catch {
            return null;
        }
    },

    clearCredentials() {
        localStorage.removeItem(this.KEY);
    }
};

/* ============================================================
   TOAST NOTIFICATION SYSTEM
   ============================================================ */
const Toast = {
    container: null,

    init() {
        // Create container if not exists
        if (!document.getElementById('toast-container')) {
            this.container = document.createElement('div');
            this.container.id = 'toast-container';
            this.container.className = 'toast-container';
            document.body.appendChild(this.container);
        } else {
            this.container = document.getElementById('toast-container');
        }
    },

    show(message, type = 'info', duration = 4000) {
        if (!this.container) this.init();

        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        
        const icons = {
            success: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M22 11.08V12a10 10 0 11-5.93-9.14"/>
                <polyline points="22,4 12,14.01 9,11.01"/>
            </svg>`,
            error: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <circle cx="12" cy="12" r="10"/>
                <line x1="15" y1="9" x2="9" y2="15"/>
                <line x1="9" y1="9" x2="15" y2="15"/>
            </svg>`,
            warning: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/>
                <line x1="12" y1="9" x2="12" y2="13"/>
                <line x1="12" y1="17" x2="12.01" y2="17"/>
            </svg>`,
            info: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <circle cx="12" cy="12" r="10"/>
                <line x1="12" y1="16" x2="12" y2="12"/>
                <line x1="12" y1="8" x2="12.01" y2="8"/>
            </svg>`
        };

        toast.innerHTML = `
            <div class="toast-icon">${icons[type] || icons.info}</div>
            <div class="toast-content">
                <span class="toast-message">${message}</span>
            </div>
            <button class="toast-close" aria-label="Close">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <line x1="18" y1="6" x2="6" y2="18"/>
                    <line x1="6" y1="6" x2="18" y2="18"/>
                </svg>
            </button>
        `;

        // Close button handler
        toast.querySelector('.toast-close').addEventListener('click', () => {
            this.dismiss(toast);
        });

        this.container.appendChild(toast);

        // Trigger animation
        requestAnimationFrame(() => {
            toast.classList.add('toast-visible');
        });

        // Auto dismiss
        if (duration > 0) {
            setTimeout(() => this.dismiss(toast), duration);
        }

        return toast;
    },

    dismiss(toast) {
        if (!toast || !toast.parentNode) return;
        
        toast.classList.remove('toast-visible');
        toast.classList.add('toast-hiding');
        
        setTimeout(() => {
            if (toast.parentNode) {
                toast.parentNode.removeChild(toast);
            }
        }, 300);
    },

    success(message, duration) {
        return this.show(message, 'success', duration);
    },

    error(message, duration) {
        return this.show(message, 'error', duration);
    },

    warning(message, duration) {
        return this.show(message, 'warning', duration);
    },

    info(message, duration) {
        return this.show(message, 'info', duration);
    }
};

/* ============================================================
   F5 XC API CLIENT (via proxy.php)
   ============================================================ */
const F5XCClient = {
    tenant: null,
    apiToken: null,

    init(tenant, apiToken) {
        this.tenant = tenant;
        this.apiToken = apiToken;
    },

    async get(path) {
        const resp = await fetch('proxy.php', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                method: 'GET',
                path,
                tenant: this.tenant,
                apiToken: this.apiToken
            })
        });

        if (!resp.ok) {
            const error = await resp.json().catch(() => ({}));
            throw new Error(error.message || `API Error: ${resp.status}`);
        }

        return resp.json();
    }
};

/* ============================================================
   CONNECTION MANAGER
   ============================================================ */
const ConnectionManager = {
    elements: {},

    init() {
        this.cacheElements();
        this.bindEvents();
        this.checkSavedCredentials();
    },

    cacheElements() {
        this.elements = {
            connectionStatus: document.getElementById('connection-status'),
            connectionForm: document.getElementById('connection-form'),
            connectionInfo: document.getElementById('connection-info'),
            tenantInput: document.getElementById('tenant-name'),
            apiTokenInput: document.getElementById('api-token'),
            rememberCheckbox: document.getElementById('remember-credentials'),
            connectBtn: document.getElementById('connect-btn'),
            disconnectBtn: document.getElementById('disconnect-btn'),
            toggleTokenBtn: document.getElementById('toggle-token'),
            connectedTenant: document.getElementById('connected-tenant'),
            connectedUrl: document.getElementById('connected-url')
        };
    },

    bindEvents() {
        // Connect button
        this.elements.connectBtn?.addEventListener('click', () => this.connect());

        // Disconnect button
        this.elements.disconnectBtn?.addEventListener('click', () => this.disconnect());

        // Toggle token visibility
        this.elements.toggleTokenBtn?.addEventListener('click', () => this.toggleTokenVisibility());

        // Enter key on inputs
        this.elements.tenantInput?.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.elements.apiTokenInput?.focus();
        });

        this.elements.apiTokenInput?.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.connect();
        });
    },

    checkSavedCredentials() {
        const creds = StorageManager.loadCredentials();
        if (creds?.tenant && creds?.apiToken) {
            // Fill in the form
            if (this.elements.tenantInput) this.elements.tenantInput.value = creds.tenant;
            if (this.elements.apiTokenInput) this.elements.apiTokenInput.value = creds.apiToken;
            
            // Auto-connect silently
            this.connect(true);
        }
    },

    async connect(silent = false) {
        const tenant = this.elements.tenantInput?.value?.trim();
        const apiToken = this.elements.apiTokenInput?.value?.trim();

        if (!tenant) {
            if (!silent) Toast.warning('Please enter your tenant name');
            this.elements.tenantInput?.focus();
            return;
        }

        if (!apiToken) {
            if (!silent) Toast.warning('Please enter your API token');
            this.elements.apiTokenInput?.focus();
            return;
        }

        // Show loading state
        this.setConnecting(true);

        try {
            // Initialize API client
            F5XCClient.init(tenant, apiToken);

            // Test connection
            await F5XCClient.get('/api/web/namespaces');

            // Update app state
            AppState.connected = true;
            AppState.tenant = tenant;
            AppState.apiToken = apiToken;

            // Save credentials if checkbox is checked
            if (this.elements.rememberCheckbox?.checked) {
                StorageManager.saveCredentials(tenant, apiToken);
            }

            // Update UI
            this.setConnected(tenant);

            if (!silent) {
                Toast.success(`Connected to ${tenant}`);
            }

        } catch (error) {
            console.error('Connection error:', error);
            
            AppState.connected = false;
            StorageManager.clearCredentials();
            
            this.setDisconnected();

            if (!silent) {
                Toast.error('Connection failed. Please check your credentials.');
            }
        }

        this.setConnecting(false);
    },

    disconnect() {
        // Clear app state
        AppState.connected = false;
        AppState.tenant = null;
        AppState.apiToken = null;

        // Always clear stored credentials on disconnect
        StorageManager.clearCredentials();

        // Clear the API token input (keep tenant for convenience)
        if (this.elements.apiTokenInput) {
            this.elements.apiTokenInput.value = '';
        }

        // Update UI
        this.setDisconnected();

        Toast.info('Disconnected from F5 XC');
    },

    setConnecting(isConnecting) {
        const btn = this.elements.connectBtn;
        if (!btn) return;

        const btnText = btn.querySelector('.btn-text');
        const btnLoader = btn.querySelector('.btn-loader');

        if (isConnecting) {
            btn.disabled = true;
            btnText?.classList.add('hidden');
            btnLoader?.classList.remove('hidden');
            
            if (this.elements.connectionStatus) {
                this.elements.connectionStatus.className = 'connection-status connecting';
                const statusText = this.elements.connectionStatus.querySelector('.status-text');
                if (statusText) statusText.textContent = 'Connecting...';
            }
        } else {
            btn.disabled = false;
            btnText?.classList.remove('hidden');
            btnLoader?.classList.add('hidden');
        }
    },

    setConnected(tenant) {
        // Update status indicator
        if (this.elements.connectionStatus) {
            this.elements.connectionStatus.className = 'connection-status connected';
            const statusText = this.elements.connectionStatus.querySelector('.status-text');
            if (statusText) statusText.textContent = 'Connected';
        }

        // Hide form, show info
        if (this.elements.connectionForm) {
            this.elements.connectionForm.classList.add('hidden');
        }
        
        if (this.elements.connectionInfo) {
            this.elements.connectionInfo.classList.remove('hidden');
            this.elements.connectionInfo.style.display = 'flex';
        }

        // Update connected info
        if (this.elements.connectedTenant) {
            this.elements.connectedTenant.textContent = tenant;
        }
        if (this.elements.connectedUrl) {
            this.elements.connectedUrl.textContent = `${tenant}.console.ves.volterra.io`;
        }
    },

    setDisconnected() {
        // Update status indicator
        if (this.elements.connectionStatus) {
            this.elements.connectionStatus.className = 'connection-status disconnected';
            const statusText = this.elements.connectionStatus.querySelector('.status-text');
            if (statusText) statusText.textContent = 'Not Connected';
        }

        // Hide info, show form
        if (this.elements.connectionInfo) {
            this.elements.connectionInfo.classList.add('hidden');
            this.elements.connectionInfo.style.display = 'none';
        }
        
        if (this.elements.connectionForm) {
            this.elements.connectionForm.classList.remove('hidden');
        }
    },

    toggleTokenVisibility() {
        const input = this.elements.apiTokenInput;
        const btn = this.elements.toggleTokenBtn;
        if (!input || !btn) return;

        const iconEye = btn.querySelector('.icon-eye');
        const iconEyeOff = btn.querySelector('.icon-eye-off');

        if (input.type === 'password') {
            input.type = 'text';
            iconEye?.classList.add('hidden');
            iconEyeOff?.classList.remove('hidden');
        } else {
            input.type = 'password';
            iconEye?.classList.remove('hidden');
            iconEyeOff?.classList.add('hidden');
        }
    }
};

/* ============================================================
   INIT
   ============================================================ */
document.addEventListener('DOMContentLoaded', () => {
    Toast.init();
    ConnectionManager.init();
    console.log('🚀 XC BulkOps initialized');
});