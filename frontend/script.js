/**
 * Red Team Recon Automation Toolkit - Frontend JavaScript
 * Main application entry point and module orchestrator
 */

// Global App Configuration
const AppConfig = {
    backendUrl: 'http://localhost:5000',
    refreshInterval: 1000,
    maxRetries: 3,
    requestTimeout: 30000,
    version: '1.0.0'
};

// Global App State
const AppState = {
    currentJobId: null,
    isScanning: false,
    currentTarget: null,
    progressInterval: null,
    startTime: null,
    currentResults: null,
    // Track selected services for strict UI filtering of progress and results
    selectedServices: null,
    // Computed list of progress stages to show based on selected services
    progressStages: [],
    settings: {
        darkMode: true,
        autoRefresh: true
    }
};

// Initialize App when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    console.log('🚀 Red Team Recon Toolkit - Initializing...');
    
    // Load saved settings
    loadSettings();
    
    // Initialize modules
    APIModule.init();
    UIModule.init();
    DataModule.init();
    UtilsModule.init();
    
    // Setup matrix background effect
    initMatrixBackground();
    
    // Check backend health
    APIModule.checkHealth();
    
    console.log('✅ Application initialized successfully');
});

// Matrix Background Effect
function initMatrixBackground() {
    const matrixBg = document.getElementById('matrixBg');
    if (!matrixBg) return;
    
    // Create matrix characters
    const chars = '01ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
    let matrix = '';
    
    for (let i = 0; i < 50; i++) {
        const char = chars[Math.floor(Math.random() * chars.length)];
        const x = Math.random() * 100;
        const y = Math.random() * 100;
        const delay = Math.random() * 5;
        
        matrix += `<span style="position: absolute; left: ${x}%; top: ${y}%; animation-delay: ${delay}s; opacity: 0.1;">${char}</span>`;
    }
    
    matrixBg.innerHTML = matrix;
}

// Settings Management
function loadSettings() {
    try {
        const saved = localStorage.getItem('reconToolkitSettings');
        if (saved) {
            Object.assign(AppState.settings, JSON.parse(saved));
            AppConfig.backendUrl = AppState.settings.backendUrl || AppConfig.backendUrl;
        }
    } catch (error) {
        console.warn('Failed to load settings:', error);
    }
}

function saveSettings() {
    try {
        localStorage.setItem('reconToolkitSettings', JSON.stringify(AppState.settings));
        UIModule.showToast('Settings saved successfully', 'success');
    } catch (error) {
        console.error('Failed to save settings:', error);
        UIModule.showToast('Failed to save settings', 'error');
    }
}

// ===========================================
// API Integration Module
// ===========================================
const APIModule = {
    init() {
        console.log('📡 API Module initialized');
    },

    async makeRequest(endpoint, options = {}) {
        const url = `${AppConfig.backendUrl}${endpoint}`;
        const defaultOptions = {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
            },
            timeout: AppConfig.requestTimeout
        };

        const requestOptions = { ...defaultOptions, ...options };
        
        try {
            const response = await fetch(url, requestOptions);
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            const data = await response.json();
            return { success: true, data };
            
        } catch (error) {
            console.error(`API Request failed for ${endpoint}:`, error);
            return { success: false, error: error.message };
        }
    },

    async checkHealth() {
        UIModule.updateStatus('Checking backend connection...', 'pending');
        
        const result = await this.makeRequest('/api/health');
        
        if (result.success) {
            UIModule.updateStatus('Connected', 'online');
            UIModule.showToast('Backend connected successfully', 'success');
            return result.data;
        } else {
            UIModule.updateStatus('Disconnected', 'offline');
            UIModule.showToast('Failed to connect to backend', 'error');
            return null;
        }
    },

    async startRecon(target, authKey, options = {}) {
        UIModule.updateStatus('Starting reconnaissance...', 'pending');
        
        // Prepare data for POST request
        const requestData = {
            target: target,
            reconType: options.reconType || 'quick',
            services: options.services || {},
            useSpiderfoot: options.useSpiderfoot || false,
            customWordlist: options.customWordlist || null
        };
        
        const requestOptions = {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(requestData)
        };
        
        const result = await this.makeRequest('/api/recon', requestOptions);
        
        if (result.success) {
            // Support both shapes:
            // 1) { job_id: "..." }
            // 2) { success: true, data: { job_id: "..." } }
            const payload = result.data;
            let jobId = null;
            if (payload && typeof payload === 'object') {
                if (typeof payload.job_id !== 'undefined') {
                    jobId = payload.job_id;
                } else if (payload.data && typeof payload.data.job_id !== 'undefined') {
                    jobId = payload.data.job_id;
                }
            }
            if (!jobId) {
                throw new Error('Failed to start recon: job id missing in response');
            }
            AppState.currentJobId = jobId;
            AppState.isScanning = true;
            AppState.currentTarget = target;
            AppState.startTime = Date.now();
            
            UIModule.updateStatus('Reconnaissance in progress...', 'pending');
            
            // Start progress monitoring
            this.startProgressMonitoring();
            
            return result.data;
        } else {
            UIModule.updateStatus('Ready', 'online');
            throw new Error(result.error);
        }
    },

    async checkStatus(jobId) {
        const result = await this.makeRequest(`/api/status/${jobId}`);
        
        if (result.success) {
            return result.data;
        } else {
            throw new Error(result.error);
        }
    },

    startProgressMonitoring() {
        if (this.progressInterval) {
            clearInterval(this.progressInterval);
        }
        
        this.progressInterval = setInterval(() => {
            this.checkProgress();
        }, 3000);
        
        // Show stop button
        const stopButton = document.getElementById('stopScanBtn');
        if (stopButton) {
            stopButton.style.display = 'inline-block';
        }
    },
    
    stopProgressMonitoring() {
        if (this.progressInterval) {
            clearInterval(this.progressInterval);
            this.progressInterval = null;
        }
        
        // Hide stop button
        const stopButton = document.getElementById('stopScanBtn');
        if (stopButton) {
            stopButton.style.display = 'none';
        }
    },

    async stopScan() {
        if (!AppState.currentJobId) {
            UIModule.showToast('No active scan to stop', 'error');
            return;
        }
        
        try {
            const response = await fetch(`/api/stop/${AppState.currentJobId}`, {
                method: 'POST'
            });
            
            const result = await response.json();
            
            if (result.success) {
                AppState.isScanning = false;
                UIModule.updateStatus('Scan stopped - getting partial results...', 'warning');
                UIModule.showToast('Scan stop requested - collecting partial results', 'warning');
                
                // Continue monitoring for final results
                this.stopProgressMonitoring();
                setTimeout(() => {
                    this.checkFinalResults();
                }, 3000);
            } else {
                UIModule.showToast(result.error || 'Failed to stop scan', 'error');
            }
        } catch (error) {
            console.error('Stop scan error:', error);
            UIModule.showToast('Failed to stop scan', 'error');
        }
    },
    
    async checkFinalResults() {
        if (!AppState.currentJobId) return;
        
        try {
            const status = await this.checkStatus(AppState.currentJobId);
            
            if (status && status.status !== 'running') {
                this.handleScanComplete(status);
            }
        } catch (error) {
            console.error('Error checking final results:', error);
        }
    },

    async checkProgress() {
        if (!AppState.currentJobId) return;
        
        try {
            // Use the dedicated status helper which unwraps the API response
            const job = await this.checkStatus(AppState.currentJobId);
            
            if (job) {
                // Update duration display
                if (job.current_duration_formatted) {
                    UIModule.updateStatus(`Scanning... (${job.current_duration_formatted})`, 'pending');
                }
                
                if (job.status === 'finished' || job.status === 'completed' || job.status === 'error' || job.status === 'cancelled' || job.status === 'timeout') {
                    this.stopProgressMonitoring();
                    this.handleScanComplete(job);
                } else if (job.status === 'running') {
                    console.log(`Scan running for ${job.current_duration_formatted || 'unknown time'}...`);
                }
            }
        } catch (error) {
            console.error('Progress check error:', error);
        }
    },

    handleScanComplete(jobData) {
        AppState.isScanning = false;
        this.stopProgressMonitoring();
        
        if (jobData.status === 'error') {
            UIModule.updateStatus('Scan failed', 'offline');
            UIModule.showToast(jobData.error || 'Scan failed', 'error');
            return;
        }
        
        if (jobData.status === 'cancelled') {
            UIModule.updateStatus('Scan cancelled', 'warning');
            UIModule.showToast('Scan was cancelled - showing partial results', 'warning');
        } else if (jobData.status === 'timeout') {
            UIModule.updateStatus('Scan timed out', 'warning');
            UIModule.showToast('Scan timed out - showing partial results', 'warning');
        } else {
            UIModule.updateStatus('Scan completed successfully', 'online');
            UIModule.showToast('Reconnaissance completed!', 'success');
        }
        
        if (jobData.result) {
            AppState.lastResult = jobData.result;
            UIModule.showResults(jobData.result);
        }
    },

    startProgressMonitoring() {
        if (AppState.progressInterval) {
            clearInterval(AppState.progressInterval);
        }
        
        AppState.progressInterval = setInterval(async () => {
            if (!AppState.currentJobId || !AppState.isScanning) {
                this.stopProgressMonitoring();
                return;
            }
            
            try {
                const status = await this.checkStatus(AppState.currentJobId);
                UIModule.updateProgress(status);
                
                if (status.status === 'finished' || status.status === 'completed' || status.status === 'error' || status.status === 'cancelled' || status.status === 'timeout') {
                    this.handleScanComplete(status);
                }
                
            } catch (error) {
                console.error('Progress monitoring error:', error);
                UIModule.showToast('Failed to check scan status', 'error');
            }
        }, AppConfig.refreshInterval);
    },

    stopProgressMonitoring() {
        if (AppState.progressInterval) {
            clearInterval(AppState.progressInterval);
            AppState.progressInterval = null;
        }
    },

    async testTools() {
        const result = await this.makeRequest(`/api/tools/test`);
        
        if (result.success) {
            return result.data.test_results;
        } else {
            throw new Error(result.error);
        }
    },

    async enhanceWithSpiderFoot(jobId, services) {
        const requestData = {
            services: services
        };
        
        const requestOptions = {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(requestData)
        };
        
        const result = await this.makeRequest(`/api/enhance/${jobId}`, requestOptions);
        
        if (result.success) {
            return { success: true, enhanced: result.data };
        } else {
            return { success: false, error: result.error };
        }
    }
};

// ===========================================
// UI Management Module
// ===========================================
const UIModule = {
    elements: {},
    _initialized: false,
    _eventsBound: false,
    _activeToasts: new Set(),
    
    init() {
        if (this._initialized) return;
        this._initialized = true;
        console.log('🎨 UI Module initialized');
        this.cacheElements();
        this.bindEvents();
        this.setupTabs();
    },

    cacheElements() {
        this.elements = {
            // Input elements
            targetInput: document.getElementById('targetInput'),
            authInput: document.getElementById('authInput'),
            customWordlist: document.getElementById('customWordlist'),
            startReconBtn: document.getElementById('startReconBtn'),
            clearBtn: document.getElementById('clearBtn'),
            
            // Reconnaissance type elements
            quickRecon: document.getElementById('quickRecon'),
            normalRecon: document.getElementById('normalRecon'),
            deepRecon: document.getElementById('deepRecon'),
            
            // Service checkboxes
            domainSubdomainCheck: document.getElementById('domainSubdomainCheck'),
            techFingerprintCheck: document.getElementById('techFingerprintCheck'),
            portScanCheck: document.getElementById('portScanCheck'),
            employeeDataCheck: document.getElementById('employeeDataCheck'),
            cloudExposureCheck: document.getElementById('cloudExposureCheck'),
            cveMappingCheck: document.getElementById('cveMappingCheck'),
            
            // Status elements
            statusIndicator: document.getElementById('statusIndicator'),
            statusText: document.querySelector('.status-text'),
            statusDot: document.querySelector('.status-dot'),
            
            // Section elements
            inputSection: document.getElementById('inputSection'),
            progressSection: document.getElementById('progressSection'),
            resultsSection: document.getElementById('resultsSection'),
            
            // Progress elements
            progressFill: document.getElementById('progressFill'),
            progressText: document.getElementById('progressText'),
            progressTime: document.getElementById('progressTime'),
            stopBtn: document.getElementById('stopBtn'),
            
            // Results elements
            summaryGrid: document.getElementById('summaryGrid'),
            exportBtn: document.getElementById('exportBtn'),
            newScanBtn: document.getElementById('newScanBtn'),
            
            // Tab elements
            tabBtns: document.querySelectorAll('.tab-btn'),
            tabPanels: document.querySelectorAll('.tab-panel'),
            
            // Modal elements
            settingsModal: document.getElementById('settingsModal'),
            helpModal: document.getElementById('helpModal'),
            settingsBtn: document.getElementById('settingsBtn'),
            helpBtn: document.getElementById('helpBtn'),
            closeSettingsBtn: document.getElementById('closeSettingsBtn'),
            closeHelpBtn: document.getElementById('closeHelpBtn'),
            saveSettingsBtn: document.getElementById('saveSettingsBtn'),
            
            // Settings elements
            backendUrl: document.getElementById('backendUrl'),
            refreshInterval: document.getElementById('refreshInterval'),
            darkMode: document.getElementById('darkMode'),
            
            // Toast container
            toastContainer: document.getElementById('toastContainer')
        };
    },

    bindEvents() {
        if (this._eventsBound) return;
        this._eventsBound = true;
        // Initialize event listeners
        document.getElementById('startReconBtn').addEventListener('click', async () => {
            await this.handleStartRecon();
        });
        
        document.getElementById('stopScanBtn').addEventListener('click', async () => {
            await APIModule.stopScan();
        });
        
        this.elements.clearBtn?.addEventListener('click', this.handleClear.bind(this));
        this.elements.stopBtn?.addEventListener('click', this.handleStop.bind(this));
        
        // Export and new scan
        this.elements.exportBtn?.addEventListener('click', this.handleExport.bind(this));
        this.elements.newScanBtn?.addEventListener('click', this.handleNewScan.bind(this));
        
        // Enhancement button
        const enhanceBtn = document.getElementById('enhanceBtn');
        if (enhanceBtn) {
            enhanceBtn.addEventListener('click', this.handleEnhancement.bind(this));
        }
        
        // Modal events
        this.elements.settingsBtn?.addEventListener('click', () => this.showModal('settings'));
        this.elements.helpBtn?.addEventListener('click', () => this.showModal('help'));
        this.elements.closeSettingsBtn?.addEventListener('click', () => this.hideModal('settings'));
        this.elements.closeHelpBtn?.addEventListener('click', () => this.hideModal('help'));
        this.elements.saveSettingsBtn?.addEventListener('click', this.handleSaveSettings.bind(this));
        
        // Enter key support
        this.elements.targetInput?.addEventListener('keypress', (e) => {
            if (e.key === 'Enter' && !AppState.isScanning) {
                this.handleStartRecon();
            }
        });
        
        this.elements.authInput?.addEventListener('keypress', (e) => {
            if (e.key === 'Enter' && !AppState.isScanning) {
                this.handleStartRecon();
            }
        });
    },

    // Show/hide results tabs and panels based on selected services
    applyTabVisibility(services) {
        const sv = services || AppState.selectedServices || {};
        const setVisible = (key, visible) => {
            const btn = document.querySelector(`.tab-btn[data-tab="${key}"]`);
            const panel = document.getElementById(`${key}Tab`);
            if (btn) btn.style.display = visible ? '' : 'none';
            if (panel) panel.style.display = visible ? '' : 'none';
        };
        setVisible('subdomains', !!sv.domainSubdomain);
        setVisible('hosts', !!sv.portScan);
        setVisible('technology', !!sv.techFingerprint);
        setVisible('osint', !!sv.employeeData || !!sv.cloudExposure);
        setVisible('vulnerabilities', !!sv.cveMapping);
        // Overview and Raw tabs remain available
        setVisible('overview', true);
        setVisible('raw', true);

        // Ensure the currently active tab is visible, otherwise switch to Overview
        const activeBtn = document.querySelector('.tab-btn.active');
        const activeTabId = activeBtn?.getAttribute('data-tab');
        const activeVisible = activeBtn && activeBtn.style.display !== 'none';
        if (!activeVisible) {
            this.switchTab('overview');
        }
    },

    setupTabs() {
        this.elements.tabBtns.forEach(btn => {
            btn.addEventListener('click', () => {
                const tabId = btn.getAttribute('data-tab');
                this.switchTab(tabId);
            });
        });
    },

    switchTab(tabId) {
        // Remove active class from all tabs and panels
        this.elements.tabBtns.forEach(btn => btn.classList.remove('active'));
        this.elements.tabPanels.forEach(panel => panel.classList.remove('active'));
        
        // Add active class to selected tab and panel
        const activeBtn = document.querySelector(`[data-tab="${tabId}"]`);
        const activePanel = document.getElementById(`${tabId}Tab`);
        
        if (activeBtn && activePanel) {
            activeBtn.classList.add('active');
            activePanel.classList.add('active');
        }
    },

    async handleStartRecon() {
        const target = (this.elements.targetInput?.value || '').trim();
        
        if (!target) {
            this.showToast('Please enter a target domain', 'warning');
            this.elements.targetInput?.focus();
            return;
        }
        
        // Get selected reconnaissance type
        const reconType = this.getSelectedReconType();
        
        // Get selected services
        const services = this.getSelectedServices();
        // Persist user selection for strict UI-side filtering of progress/results
        AppState.selectedServices = services;
        
        const options = {
            reconType: reconType,
            services: services,
            useSpiderfoot: false,  // SpiderFoot now handled post-scan
            customWordlist: null
        };
        
        try {
            this.showProgressSection(services);
            await APIModule.startRecon(target, null, options);
            this.showToast('Reconnaissance started successfully', 'success');
        } catch (error) {
            this.showToast(`Failed to start reconnaissance: ${error.message}`, 'error');
            this.showInputSection();
        }
    },

    handleClear() {
        if (this.elements.targetInput) this.elements.targetInput.value = '';
        if (this.elements.authInput) this.elements.authInput.value = '';
        if (this.elements.customWordlist) this.elements.customWordlist.value = '';
        
        // Reset recon type to quick
        if (this.elements.quickRecon) this.elements.quickRecon.checked = true;
        
        // Reset service checkboxes to defaults
        if (this.elements.domainSubdomainCheck) this.elements.domainSubdomainCheck.checked = true;
        if (this.elements.techFingerprintCheck) this.elements.techFingerprintCheck.checked = true;
        if (this.elements.portScanCheck) this.elements.portScanCheck.checked = true;
        if (this.elements.employeeDataCheck) this.elements.employeeDataCheck.checked = false;
        if (this.elements.cloudExposureCheck) this.elements.cloudExposureCheck.checked = false;
        if (this.elements.cveMappingCheck) this.elements.cveMappingCheck.checked = false;
        if (this.elements.spiderfootCheck) this.elements.spiderfootCheck.checked = false;
    },

    handleStop() {
        if (AppState.isScanning) {
            AppState.isScanning = false;
            APIModule.stopProgressMonitoring();
            this.showToast('Scan stopped by user', 'info');
            this.showInputSection();
            this.updateStatus('Ready', 'online');
        }
    },

    handleExport(event) {
        if (!AppState.currentResults) {
            this.showToast('No results to export', 'warning');
            return;
        }
        this.toggleExportDropdown(event);
    },

    toggleExportDropdown(event) {
        let menu = document.getElementById('exportDropdown');
        if (menu && menu.classList.contains('open')) {
            this.hideExportDropdown();
            return;
        }
        this.showExportDropdown(event);
    },

    showExportDropdown(event) {
        const btn = this.elements.exportBtn;
        if (!btn) return;
        this.hideExportDropdown();

        const rect = btn.getBoundingClientRect();
        const menu = document.createElement('div');
        menu.id = 'exportDropdown';
        menu.className = 'dropdown-menu open';
        menu.setAttribute('role', 'menu');
        menu.setAttribute('aria-label', 'Export Results');
        menu.style.position = 'fixed';
        menu.style.top = `${rect.bottom + 6}px`;
        menu.style.left = `${rect.left}px`;
        menu.style.minWidth = `${Math.max(220, rect.width)}px`;
        menu.style.background = 'var(--bg-card)';
        menu.style.border = '1px solid var(--border-primary)';
        menu.style.borderRadius = '10px';
        menu.style.boxShadow = 'var(--shadow-lg)';
        menu.style.zIndex = '2000';
        menu.style.overflow = 'hidden';

        const itemStyle = 'padding:12px 14px; cursor:pointer; display:flex; align-items:center; gap:12px; color: var(--text-primary); background: transparent; border-bottom: 1px solid var(--border-primary); transition: background 0.15s ease, color 0.15s ease; outline: none;';
        const itemHover = 'this.style.background="var(--bg-hover)"; this.style.color="var(--text-primary)"';
        const itemLeave = 'this.style.background="transparent"; this.style.color="var(--text-primary)"';

        menu.innerHTML = `
            <div style="${itemStyle}" onmouseover="${itemHover}" onmouseout="${itemLeave}" onfocus="${itemHover}" onblur="${itemLeave}" tabindex="0" role="menuitem" data-type="json">
                <i class="fas fa-file-code"></i> Export as JSON
            </div>
            <div style="${itemStyle}" onmouseover="${itemHover}" onmouseout="${itemLeave}" onfocus="${itemHover}" onblur="${itemLeave}" tabindex="0" role="menuitem" data-type="csv">
                <i class="fas fa-file-csv"></i> Export as CSV
            </div>
            <div style="${itemStyle}" onmouseover="${itemHover}" onmouseout="${itemLeave}" onfocus="${itemHover}" onblur="${itemLeave}" tabindex="0" role="menuitem" data-type="html">
                <i class="fas fa-file-alt"></i> Export as HTML
            </div>
            <div style="${itemStyle}" onmouseover="${itemHover}" onmouseout="${itemLeave}" onfocus="${itemHover}" onblur="${itemLeave}" tabindex="0" role="menuitem" data-type="pdf">
                <i class="fas fa-file-pdf"></i> Export as PDF (enhanced)
            </div>
        `;

        menu.addEventListener('click', (e) => {
            const target = e.target.closest('[data-type]');
            if (!target) return;
            const type = target.getAttribute('data-type');
            this.handleExportChoice(type);
        });

        document.body.appendChild(menu);

        const close = (ev) => {
            const m = document.getElementById('exportDropdown');
            if (m && !m.contains(ev.target) && ev.target !== this.elements.exportBtn) {
                this.hideExportDropdown();
                document.removeEventListener('click', close);
                window.removeEventListener('resize', close);
                window.removeEventListener('scroll', close, true);
            }
        };
        setTimeout(() => {
            document.addEventListener('click', close);
            window.addEventListener('resize', close);
            window.addEventListener('scroll', close, true);
        }, 0);
    },

    hideExportDropdown() {
        const menu = document.getElementById('exportDropdown');
        if (menu && menu.parentNode) menu.parentNode.removeChild(menu);
    },

    async handleExportChoice(type) {
        this.hideExportDropdown();
        const results = AppState.currentResults;
        const target = AppState.currentTarget || results?.target || 'target';
        try {
            // Use UI-filtered results so exports adhere to user-selected services
            const services = AppState.selectedServices || this.getSelectedServices();
            const filtered = DataModule.filterResultsByServices(results, services);
            if (type === 'json') {
                DataModule.exportAsJSON(filtered, target);
            } else if (type === 'csv') {
                DataModule.exportAsCSV(filtered, target);
            } else if (type === 'html') {
                DataModule.exportAsHTML(filtered, target);
            } else if (type === 'pdf') {
                await DataModule.exportAsPDF(filtered, target, AppState.spiderfootEnhanced || null);
            }
        } catch (err) {
            console.error('Export error:', err);
            this.showToast('Export failed: ' + (err?.message || err), 'error');
        }
    },

    handleNewScan() {
        AppState.currentResults = null;
        AppState.currentJobId = null;
        AppState.currentTarget = null;
        this.showInputSection();
        this.updateStatus('Ready', 'online');
    },

    async handleEnhancement() {
        if (!AppState.currentJobId || !AppState.currentResults) {
            this.showToast('No scan results to enhance', 'warning');
            return;
        }
        // Run enhancement directly in results page
        await this.runSpiderFootEnhancement();
    },

    generateEnhancementOptions() {
        const services = this.getSelectedServices();
        let html = '<div class="service-options">';
        
        const serviceDescriptions = {
            domainSubdomain: 'Advanced subdomain discovery and DNS analysis',
            techFingerprint: 'Deep technology stack identification',
            portScan: 'Enhanced port scanning with service detection',
            employeeData: 'OSINT for employee and credential discovery',
            cloudExposure: 'Cloud storage and misconfiguration detection',
            cveMapping: 'Vulnerability assessment and CVE mapping'
        };

        for (const [service, enabled] of Object.entries(services)) {
            if (enabled) {
                html += `
                    <div class="enhancement-option">
                        <i class="fas fa-check-circle text-success"></i>
                        <span>${serviceDescriptions[service] || service}</span>
                    </div>
                `;
            }
        }
        
        html += '</div>';
        return html;
    },

    async runSpiderFootEnhancement() {
        this.updateStatus('Running SpiderFoot enhancement...', 'pending');
        this.showToast('Starting SpiderFoot enhancement with selective modules', 'info');

        // Disable enhance button while processing
        const enhanceBtn = document.getElementById('enhanceBtn');
        if (enhanceBtn) enhanceBtn.disabled = true;

        // Ensure tab and show loader content
        const services = this.getSelectedServices();
        const sfPanel = this.ensureSpiderFootTab();
        this.renderEnhancementLoader(sfPanel, services);

        const startTime = Date.now();
        let pct = 0;
        const stages = [
            { at: 5, msg: 'Preparing modules...' },
            { at: 20, msg: 'Injecting seed data (subdomains, IPs, emails)...' },
            { at: 45, msg: 'Launching SpiderFoot with selective modules...' },
            { at: 70, msg: 'Collecting events...' },
            { at: 90, msg: 'Parsing and formatting results...' }
        ];

        const tick = () => {
            // Ease up to 95% while waiting
            const elapsed = Math.floor((Date.now() - startTime) / 1000);
            pct = Math.min(95, Math.floor(elapsed * 8)); // ~12s to reach 95%
            const stage = stages.filter(s => pct >= s.at).pop();
            this.updateEnhancementProgress(sfPanel, pct, stage ? stage.msg : 'Initializing...');
        };
        tick();
        const enhInterval = setInterval(tick, 800);

        try {
            const response = await APIModule.enhanceWithSpiderFoot(
                AppState.currentJobId,
                services
            );

            clearInterval(enhInterval);
            // Jump to 100%
            this.updateEnhancementProgress(sfPanel, 100, 'Completed');

            if (response.success) {
                this.showToast('SpiderFoot enhancement completed!', 'success');
                if (response.enhanced) {
                    this.appendEnhancedResults(response.enhanced);
                }
            } else {
                this.showToast('Enhancement failed: ' + (response.error || 'Unknown error'), 'error');
                sfPanel.innerHTML = `
                    <div class="spiderfoot-results">
                        <h4>SpiderFoot Enhanced Analysis</h4>
                        <div class="enhancement-info">
                            <i class="fas fa-exclamation-triangle"></i>
                            <span>${response.error || 'Unknown error'}</span>
                        </div>
                    </div>
                `;
            }
        } catch (error) {
            clearInterval(enhInterval);
            this.showToast('Failed to run enhancement: ' + error.message, 'error');
            sfPanel.innerHTML = `
                <div class="spiderfoot-results">
                    <h4>SpiderFoot Enhanced Analysis</h4>
                    <div class="enhancement-info">
                        <i class="fas fa-exclamation-triangle"></i>
                        <span>${error.message}</span>
                    </div>
                </div>
            `;
        } finally {
            this.updateStatus('Ready', 'online');
            if (enhanceBtn) enhanceBtn.disabled = false;
        }
    },

    ensureSpiderFootTab() {
        // Ensure a SpiderFoot tab and panel exist, return the panel element
        const tabNav = document.querySelector('.tab-nav');
        if (tabNav && !document.querySelector('[data-tab="spiderfoot"]')) {
            const sfTab = document.createElement('button');
            sfTab.className = 'tab-btn';
            sfTab.setAttribute('data-tab', 'spiderfoot');
            sfTab.innerHTML = '<i class="fas fa-spider"></i> SpiderFoot';
            sfTab.onclick = () => this.switchTab('spiderfoot');
            tabNav.appendChild(sfTab);
        }

        let sfPanel = document.getElementById('spiderfootTab');
        if (!sfPanel) {
            const tabContent = document.querySelector('.tab-content');
            sfPanel = document.createElement('div');
            sfPanel.className = 'tab-panel';
            sfPanel.id = 'spiderfootTab';
            tabContent.appendChild(sfPanel);
        }

        // Switch to the SpiderFoot tab while running
        this.switchTab('spiderfoot');
        return sfPanel;
    },

    renderEnhancementLoader(sfPanel, services) {
        // Create a simple inline loader with a progress bar and selected services summary
        const enabledServices = Object.entries(services)
            .filter(([_, v]) => v)
            .map(([k]) => k)
            .join(', ') || 'default';

        sfPanel.innerHTML = `
            <div class="spiderfoot-results">
                <h4>SpiderFoot Enhanced Analysis</h4>
                <div class="enhancement-info" style="margin-bottom:12px;">
                    <i class="fas fa-info-circle"></i>
                    <span>Running selective modules for: ${enabledServices}</span>
                </div>
                <div class="progress-bar">
                    <div class="progress-fill" id="sfEnhProgress" style="width: 0%;"></div>
                </div>
                <div class="progress-info" style="display:flex; justify-content:space-between; margin-top:8px;">
                    <span id="sfEnhText">Initializing...</span>
                    <span id="sfEnhPct">0%</span>
                </div>
            </div>
        `;
    },

    updateEnhancementProgress(sfPanel, pct, text) {
        const fill = sfPanel.querySelector('#sfEnhProgress');
        const pctEl = sfPanel.querySelector('#sfEnhPct');
        const txtEl = sfPanel.querySelector('#sfEnhText');
        if (fill) fill.style.width = `${pct}%`;
        if (pctEl) pctEl.textContent = `${pct}%`;
        if (txtEl) txtEl.textContent = text || '';
    },

    appendEnhancedResults(enhancedData) {
        // Ensure a SpiderFoot tab exists and update its content in-place
        const tabNav = document.querySelector('.tab-nav');
        if (tabNav && !document.querySelector('[data-tab="spiderfoot"]')) {
            const sfTab = document.createElement('button');
            sfTab.className = 'tab-btn';
            sfTab.setAttribute('data-tab', 'spiderfoot');
            sfTab.innerHTML = '<i class="fas fa-spider"></i> SpiderFoot';
            sfTab.onclick = () => this.switchTab('spiderfoot');
            tabNav.appendChild(sfTab);
        }

        // Ensure panel exists
        let sfPanel = document.getElementById('spiderfootTab');
        if (!sfPanel) {
            const tabContent = document.querySelector('.tab-content');
            sfPanel = document.createElement('div');
            sfPanel.className = 'tab-panel';
            sfPanel.id = 'spiderfootTab';
            tabContent.appendChild(sfPanel);
        }

        // Update panel content
        sfPanel.innerHTML = `
            <div class="spiderfoot-results">
                <h4>SpiderFoot Enhanced Analysis</h4>
                <pre>${JSON.stringify(enhancedData, null, 2)}</pre>
            </div>
        `;

        // Switch to the SpiderFoot tab
        this.switchTab('spiderfoot');

        // Persist enhanced data for exporting (PDF consolidation)
        AppState.spiderfootEnhanced = enhancedData;
    },

    getAuthKey() {
        return (this.elements.authInput?.value || '').trim();
    },

    getSelectedReconType() {
        if (this.elements.quickRecon?.checked) return 'quick';
        if (this.elements.normalRecon?.checked) return 'normal';
        if (this.elements.deepRecon?.checked) return 'deep';
        return 'quick'; // default
    },

    getSelectedServices() {
        const services = {};
        services.domainSubdomain = this.elements.domainSubdomainCheck?.checked || false;
        services.techFingerprint = this.elements.techFingerprintCheck?.checked || false;
        services.portScan = this.elements.portScanCheck?.checked || false;
        services.employeeData = this.elements.employeeDataCheck?.checked || false;
        services.cloudExposure = this.elements.cloudExposureCheck?.checked || false;
        services.cveMapping = this.elements.cveMappingCheck?.checked || false;
        return services;
    },

    showInputSection() {
        if (this.elements.inputSection) this.elements.inputSection.style.display = 'block';
        if (this.elements.progressSection) this.elements.progressSection.style.display = 'none';
        if (this.elements.resultsSection) this.elements.resultsSection.style.display = 'none';
    },

    showProgressSection(services) {
        if (this.elements.inputSection) this.elements.inputSection.style.display = 'none';
        if (this.elements.progressSection) this.elements.progressSection.style.display = 'block';
        if (this.elements.resultsSection) this.elements.resultsSection.style.display = 'none';
        
        // Reset progress
        this.updateProgressBar(0);
        this.updateProgressText('Initializing scan...');
        this.updateProgressStages([]);

        // Determine and apply which progress stages to show, based on user selections
        const svc = services || AppState.selectedServices || this.getSelectedServices();
        AppState.progressStages = this.computeProgressStages(svc);
        this.filterProgressStageElements(AppState.progressStages);
    },

    showResults(results) {
        if (this.elements.inputSection) this.elements.inputSection.style.display = 'none';
        if (this.elements.progressSection) this.elements.progressSection.style.display = 'none';
        if (this.elements.resultsSection) this.elements.resultsSection.style.display = 'block';
        
        // Render results
        AppState.currentResults = results;
        const services = AppState.selectedServices || this.getSelectedServices();
        // Apply tab visibility strictly based on selected services
        this.applyTabVisibility(services);
        // Create a UI-filtered copy of results strictly limited to selected services
        const filtered = DataModule.filterResultsByServices(results, services);
        DataModule.renderResults(filtered);
        this.showToast('Scan completed successfully!', 'success');
    },

    updateStatus(text, status) {
        if (this.elements.statusText) {
            this.elements.statusText.textContent = text;
        }
        
        if (this.elements.statusDot) {
            this.elements.statusDot.className = `status-dot status-${status}`;
        }
    },

    updateProgress(status) {
        // Calculate progress based on status
        let progress = 0;
        const stageList = Array.isArray(AppState.progressStages) ? AppState.progressStages : [];
        
        if (status.status === 'running') {
            progress = Math.min(90, (Date.now() - AppState.startTime) / 1000 / 2); // Rough estimate
        } else {
            // For completed/cancelled/timeout/error/finished, mark as 100%
            progress = 100;
        }
        
        this.updateProgressBar(progress);
        this.updateProgressText(`Processing ${AppState.currentTarget}...`);
        this.updateProgressTime();
        // Determine how many stages to mark as completed based on percentage
        const completeCount = stageList.length > 0 
            ? Math.min(stageList.length, Math.floor((progress / 100) * stageList.length))
            : 0;
        this.updateProgressStages(stageList.slice(0, completeCount));
    },

    updateProgressBar(percentage) {
        if (this.elements.progressFill) {
            this.elements.progressFill.style.width = `${percentage}%`;
        }
    },

    updateProgressText(text) {
        if (this.elements.progressText) {
            this.elements.progressText.textContent = text;
        }
    },

    updateProgressTime() {
        if (!AppState.startTime) return;
        
        const elapsed = Math.floor((Date.now() - AppState.startTime) / 1000);
        const minutes = Math.floor(elapsed / 60);
        const seconds = elapsed % 60;
        const timeStr = `${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
        
        if (this.elements.progressTime) {
            this.elements.progressTime.textContent = timeStr;
        }
    },

    updateProgressStages(completedStages) {
        // Consider only visible stage elements when calculating active/completed
        const allStages = Array.from(document.querySelectorAll('.stage'));
        const stages = allStages.filter(el => el.style.display !== 'none');
        stages.forEach((stage, index) => {
            const stageType = stage.getAttribute('data-stage');
            stage.classList.remove('active', 'completed');
            if (completedStages.includes(stageType)) {
                stage.classList.add('completed');
            } else if (index === completedStages.length) {
                stage.classList.add('active');
            }
        });
        // Clear any state on hidden stages
        allStages.filter(el => el.style.display === 'none').forEach(el => el.classList.remove('active', 'completed'));
    },

    // Compute which visual progress stages should be displayed from selected services
    computeProgressStages(services) {
        const sv = services || {};
        const stages = [];
        if (sv.domainSubdomain) {
            stages.push('dns', 'subdomains');
        }
        if (sv.portScan) {
            stages.push('ports');
        }
        if (sv.techFingerprint) {
            stages.push('tech');
        }
        if (sv.employeeData || sv.cloudExposure) {
            stages.push('osint');
        }
        return stages;
    },

    // Show/hide stage elements to strictly adhere to selected services
    filterProgressStageElements(visibleStages) {
        const stages = document.querySelectorAll('.progress-stages .stage');
        const setVisible = new Set(visibleStages || []);
        stages.forEach(stage => {
            const type = stage.getAttribute('data-stage');
            if (setVisible.has(type)) {
                stage.style.display = '';
            } else {
                stage.style.display = 'none';
                stage.classList.remove('active', 'completed');
            }
        });
    },

    showModal(type) {
        const modal = type === 'settings' ? this.elements.settingsModal : this.elements.helpModal;
        if (modal) {
            modal.classList.add('active');
        }
    },

    hideModal(type) {
        const modal = type === 'settings' ? this.elements.settingsModal : this.elements.helpModal;
        if (modal) {
            modal.classList.remove('active');
        }
    },

    handleSaveSettings() {
        if (this.elements.backendUrl) {
            AppConfig.backendUrl = this.elements.backendUrl.value;
            AppState.settings.backendUrl = this.elements.backendUrl.value;
        }
        
        if (this.elements.refreshInterval) {
            AppConfig.refreshInterval = parseInt(this.elements.refreshInterval.value);
            AppState.settings.refreshInterval = parseInt(this.elements.refreshInterval.value);
        }
        
        if (this.elements.darkMode) {
            AppState.settings.darkMode = this.elements.darkMode.checked;
        }
        
        saveSettings();
        this.hideModal('settings');
    },

    showToast(message, type = 'info') {
        const key = `${type}|${message}`;
        if (!this._activeToasts) this._activeToasts = new Set();
        if (this._activeToasts.has(key)) {
            return; // suppress duplicate toasts while one is visible
        }
        this._activeToasts.add(key);

        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.textContent = message;
        
        if (this.elements.toastContainer) {
            this.elements.toastContainer.appendChild(toast);
            
            // Auto remove after 5 seconds
            setTimeout(() => {
                this._activeToasts.delete(key);
                if (toast.parentNode) {
                    toast.parentNode.removeChild(toast);
                }
            }, 5000);
        }
    }
};

// ===========================================
// Data Visualization & Results Module
// ===========================================
const DataModule = {
    init() {
        console.log('📊 Data Module initialized');
    },

    // Create a UI-filtered copy of backend results strictly limited to selected services
    filterResultsByServices(results, services) {
        const sv = services || AppState.selectedServices || {};
        const r = results || {};
        const filtered = { ...r };

        // Shallow-clone complex fields to avoid mutating originals
        filtered.subdomains = sv.domainSubdomain ? (r.subdomains ? [...r.subdomains] : []) : [];
        filtered.hosts = sv.portScan ? (r.hosts ? r.hosts.map(h => ({ ...h, ips: h.ips ? [...h.ips] : [], open_ports: h.open_ports ? [...h.open_ports] : [], services: h.services ? [...h.services] : [] })) : []) : [];
        filtered.tech = sv.techFingerprint ? (r.tech ? JSON.parse(JSON.stringify(r.tech)) : {}) : {};

        // OSINT-related
        if (sv.employeeData) {
            filtered.harvester = r.harvester ? { ...r.harvester, emails: r.harvester.emails ? [...r.harvester.emails] : [] } : { emails: [] };
            filtered.github_hits = r.github_hits ? [...r.github_hits] : [];
            filtered.paste_hits = r.paste_hits ? [...r.paste_hits] : [];
        } else {
            filtered.harvester = { emails: [] };
            filtered.github_hits = [];
            filtered.paste_hits = [];
        }

        // Cloud Exposure
        filtered.s3_buckets = sv.cloudExposure ? (r.s3_buckets ? [...r.s3_buckets] : []) : [];

        // Vulnerabilities
        filtered.cves = sv.cveMapping ? (r.cves ? JSON.parse(JSON.stringify(r.cves)) : {}) : {};

        return filtered;
    },

    renderResults(results) {
        this.renderSummaryCards(results);
        this.renderOverview(results);
        this.renderSubdomains(results);
        this.renderHosts(results);
        this.renderTechnology(results);
        this.renderOSINT(results);
        this.renderVulnerabilities(results);
        this.renderRawData(results);
    },

    renderSummaryCards(results) {
        const summaryGrid = document.getElementById('summaryGrid');
        if (!summaryGrid) return;

        const sv = AppState.selectedServices || {};
        const cards = [];
        if (sv.domainSubdomain) {
            cards.push({ icon: 'fas fa-sitemap', value: results.subdomains?.length || 0, label: 'Subdomains Found' });
        }
        if (sv.portScan) {
            cards.push({ icon: 'fas fa-server', value: results.hosts?.length || 0, label: 'Hosts Discovered' });
            cards.push({ icon: 'fas fa-door-open', value: this.getTotalOpenPorts(results.hosts), label: 'Open Ports' });
        }
        if (sv.employeeData) {
            cards.push({ icon: 'fab fa-github', value: results.github_hits?.length || 0, label: 'GitHub References' });
            cards.push({ icon: 'fas fa-envelope', value: results.harvester?.emails?.length || 0, label: 'Email Addresses' });
        }
        if (sv.cveMapping) {
            cards.push({ icon: 'fas fa-exclamation-triangle', value: this.getTotalCVEs(results.cves), label: 'Potential CVEs' });
        }

        summaryGrid.innerHTML = cards.map(card => `
            <div class="summary-card">
                <div class="summary-card-icon">
                    <i class="${card.icon}"></i>
                </div>
                <div class="summary-card-value">${card.value}</div>
                <div class="summary-card-label">${card.label}</div>
            </div>
        `).join('');
    },

    renderOverview(results) {
        // Target Information
        const targetInfo = document.getElementById('targetInfo');
        if (targetInfo) {
            targetInfo.innerHTML = `
                <div class="mb-2"><strong>Domain:</strong> ${results.target}</div>
                <div class="mb-2"><strong>Scan Date:</strong> ${new Date(results.timestamp).toLocaleString()}</div>
                <div class="mb-2"><strong>Duration:</strong> ${this.calculateDuration()}</div>
                <div class="mb-2"><strong>Status:</strong> <span class="badge success">Completed</span></div>
            `;
        }

        // Scan Statistics
        const scanStats = document.getElementById('scanStats');
        if (scanStats) {
            const sv = AppState.selectedServices || {};
            const parts = [];
            if (sv.domainSubdomain) parts.push(`<div class="mb-2"><strong>Subdomains:</strong> ${results.subdomains?.length || 0}</div>`);
            if (sv.portScan) {
                parts.push(`<div class=\"mb-2\"><strong>Live Hosts:</strong> ${results.hosts?.length || 0}</div>`);
                parts.push(`<div class=\"mb-2\"><strong>Services:</strong> ${this.getTotalServices(results.hosts)}</div>`);
            }
            if (sv.techFingerprint) parts.push(`<div class=\"mb-2\"><strong>Technologies:</strong> ${Object.keys(results.tech || {}).length}</div>`);
            // SpiderFoot status (if present) can be shown regardless as it's an enhancement step
            parts.push(`<div class=\"mb-2\"><strong>SpiderFoot:</strong> ${
                (results.summary && results.summary.spiderfoot_status)
                    ? results.summary.spiderfoot_status
                    : ((Array.isArray(results.spiderfoot_events) && results.spiderfoot_events.length && results.spiderfoot_events[0].status)
                        ? results.spiderfoot_events[0].status
                        : 'not_run')
            }</div>`);
            scanStats.innerHTML = parts.join('');
        }

        // Risk Assessment
        const riskAssessment = document.getElementById('riskAssessment');
        if (riskAssessment) {
            const risk = this.calculateRiskLevel(results);
            riskAssessment.innerHTML = `
                <div class="mb-2">
                    <strong>Overall Risk:</strong> 
                    <span class="badge ${risk.class}">${risk.level}</span>
                </div>
                <div class="text-secondary" style="font-size: 0.875rem;">
                    ${risk.description}
                </div>
            `;
        }
    },

    renderSubdomains(results) {
        const tableBody = document.querySelector('#subdomainsTable tbody');
        if (!tableBody) return;

        const subdomains = results.subdomains || [];
        const hosts = results.hosts || [];

        tableBody.innerHTML = subdomains.map(subdomain => {
            const hostInfo = hosts.find(h => h.hostname === subdomain);
            const ips = hostInfo?.ips || [];
            const status = ips.length > 0 ? 'Online' : 'Unknown';
            
            return `
                <tr>
                    <td class="text-mono">${subdomain}</td>
                    <td>
                        <span class="badge ${status === 'Online' ? 'success' : 'warning'}">
                            ${status}
                        </span>
                    </td>
                    <td class="text-mono">${ips.join(', ') || 'N/A'}</td>
                    <td>${this.detectTechFromHost(hostInfo) || 'Unknown'}</td>
                    <td>
                        <button class="btn-icon" onclick="UtilsModule.copyToClipboard('${subdomain}')" title="Copy">
                            <i class="fas fa-copy"></i>
                        </button>
                    </td>
                </tr>
            `;
        }).join('');
    },

    renderHosts(results) {
        const hostsContainer = document.getElementById('hostsContainer');
        if (!hostsContainer) return;

        const hosts = results.hosts || [];

        hostsContainer.innerHTML = hosts.map(host => `
            <div class="overview-card mb-3">
                <h4><i class="fas fa-server"></i> ${host.hostname}</h4>
                <div class="mb-2">
                    <strong>IP Addresses:</strong> 
                    <span class="text-mono">${host.ips?.join(', ') || 'None'}</span>
                </div>
                <div class="mb-2">
                    <strong>Open Ports:</strong> 
                    <span class="text-mono">${host.open_ports?.join(', ') || 'None detected'}</span>
                </div>
                ${host.services?.length > 0 ? `
                    <div class="mb-2">
                        <strong>Services:</strong>
                        <div class="mt-1">
                            ${host.services.map(service => `
                                <div class="text-mono text-secondary" style="font-size: 0.8rem;">
                                    ${service}
                                </div>
                            `).join('')}
                        </div>
                    </div>
                ` : ''}
            </div>
        `).join('');
    },

    renderTechnology(results) {
        const technologyContainer = document.getElementById('technologyContainer');
        if (!technologyContainer) return;

        const tech = results.tech || {};
        
        if (Object.keys(tech).length === 0) {
            technologyContainer.innerHTML = '<div class="text-center text-muted">No technology stack detected</div>';
            return;
        }

        technologyContainer.innerHTML = `
            <div class="overview-grid">
                ${Object.entries(tech).map(([category, technologies]) => `
                    <div class="overview-card">
                        <h4>${this.formatTechCategory(category)}</h4>
                        <div>
                            ${Array.isArray(technologies) 
                                ? technologies.map(tech => `<span class="badge info mr-1 mb-1">${tech}</span>`).join('')
                                : typeof technologies === 'object'
                                    ? Object.entries(technologies).map(([key, value]) => `
                                        <div class="mb-1 text-secondary">
                                            <strong>${key}:</strong> ${value}
                                        </div>
                                    `).join('')
                                    : `<span class="badge info">${technologies}</span>`
                            }
                        </div>
                    </div>
                `).join('')}
            </div>
        `;
    },

    renderOSINT(results) {
        // GitHub Results
        const githubResults = document.getElementById('githubResults');
        if (githubResults) {
            const sv = AppState.selectedServices || {};
            // Toggle GitHub card visibility
            if (githubResults.parentElement) githubResults.parentElement.style.display = sv.employeeData ? '' : 'none';
            const github = results.github_hits || [];
            githubResults.innerHTML = github.length > 0 
                ? github.map(hit => `
                    <div class="mb-2 p-2" style="background: var(--bg-secondary); border-radius: var(--radius-sm);">
                        <div class="text-mono" style="font-size: 0.8rem;">${hit.path || 'N/A'}</div>
                        <div class="text-secondary" style="font-size: 0.75rem;">
                            ${hit.repository || 'Unknown Repository'}
                        </div>
                        ${hit.url ? `
                            <a href="${hit.url}" target="_blank" class="text-primary" style="font-size: 0.75rem;">
                                View on GitHub <i class="fas fa-external-link-alt"></i>
                            </a>
                        ` : ''}
                    </div>
                `).join('')
                : '<div class="text-muted">No GitHub references found</div>';
        }

        // Paste Results
        const pasteResults = document.getElementById('pasteResults');
        if (pasteResults) {
            const sv = AppState.selectedServices || {};
            if (pasteResults.parentElement) pasteResults.parentElement.style.display = sv.employeeData ? '' : 'none';
            const pastes = results.paste_hits || [];
            pasteResults.innerHTML = pastes.length > 0 
                ? pastes.map(paste => `
                    <div class="mb-2 p-2" style="background: var(--bg-secondary); border-radius: var(--radius-sm);">
                        <a href="${paste.url}" target="_blank" class="text-primary">
                            ${paste.url} <i class="fas fa-external-link-alt"></i>
                        </a>
                        <div class="text-secondary mt-1" style="font-size: 0.75rem;">
                            ${paste.snippet ? paste.snippet.substring(0, 100) + '...' : 'No preview available'}
                        </div>
                    </div>
                `).join('')
                : '<div class="text-muted">No paste site references found</div>';
        }

        // Cloud Storage Results
        const cloudResults = document.getElementById('cloudResults');
        if (cloudResults) {
            const sv = AppState.selectedServices || {};
            if (cloudResults.parentElement) cloudResults.parentElement.style.display = sv.cloudExposure ? '' : 'none';
            const s3buckets = results.s3_buckets || [];
            cloudResults.innerHTML = s3buckets.length > 0 
                ? s3buckets.map(bucket => `
                    <div class="mb-2 p-2" style="background: var(--bg-secondary); border-radius: var(--radius-sm);">
                        <div class="text-mono">${bucket.bucket}</div>
                        <div class="text-secondary" style="font-size: 0.8rem;">
                            <span class="badge ${bucket.status === 200 ? 'success' : 'warning'}">
                                HTTP ${bucket.status}
                            </span>
                            <a href="${bucket.url}" target="_blank" class="text-primary ml-2">
                                ${bucket.url} <i class="fas fa-external-link-alt"></i>
                            </a>
                        </div>
                    </div>
                `).join('')
                : '<div class="text-muted">No S3 buckets discovered</div>';
        }

        // Email Intelligence
        const emailResults = document.getElementById('emailResults');
        if (emailResults) {
            const sv = AppState.selectedServices || {};
            if (emailResults.parentElement) emailResults.parentElement.style.display = sv.employeeData ? '' : 'none';
            const emails = results.harvester?.emails || [];
            emailResults.innerHTML = emails.length > 0 
                ? emails.map(email => `
                    <div class="mb-1 text-mono" style="font-size: 0.9rem;">
                        ${email}
                        <button class="btn-icon ml-2" onclick="UtilsModule.copyToClipboard('${email}')" title="Copy">
                            <i class="fas fa-copy"></i>
                        </button>
                    </div>
                `).join('')
                : '<div class="text-muted">No email addresses found</div>';
        }
    },

    renderVulnerabilities(results) {
        const vulnerabilitiesContainer = document.getElementById('vulnerabilitiesContainer');
        if (!vulnerabilitiesContainer) return;

        const cves = results.cves || {};
        
        if (Object.keys(cves).length === 0) {
            vulnerabilitiesContainer.innerHTML = '<div class="text-center text-muted">No vulnerabilities identified</div>';
            return;
        }

        vulnerabilitiesContainer.innerHTML = Object.entries(cves).map(([software, vulnerabilities]) => `
            <div class="overview-card mb-3">
                <h4><i class="fas fa-bug"></i> ${software}</h4>
                ${vulnerabilities.map(cve => `
                    <div class="mb-3 p-3" style="background: var(--bg-secondary); border-radius: var(--radius-sm);">
                        <div class="mb-2">
                            <strong class="text-primary">${cve.id}</strong>
                            ${cve.cvss ? `<span class="badge ${this.getCVSSClass(cve.cvss)} ml-2">CVSS: ${cve.cvss}</span>` : ''}
                        </div>
                        <div class="text-secondary mb-2" style="font-size: 0.9rem;">
                            ${cve.summary || 'No description available'}
                        </div>
                        ${cve.references?.length > 0 ? `
                            <div style="font-size: 0.8rem;">
                                <strong>References:</strong>
                                ${cve.references.slice(0, 3).map(ref => `
                                    <a href="${ref}" target="_blank" class="text-primary d-block">
                                        ${ref} <i class="fas fa-external-link-alt"></i>
                                    </a>
                                `).join('')}
                            </div>
                        ` : ''}
                    </div>
                `).join('')}
            </div>
        `).join('');
    },

    renderRawData(results) {
        const rawData = document.getElementById('rawData');
        if (rawData) {
            rawData.textContent = JSON.stringify(results, null, 2);
        }

        // Copy button functionality
        const copyRawBtn = document.getElementById('copyRawBtn');
        if (copyRawBtn) {
            copyRawBtn.onclick = () => {
                UtilsModule.copyToClipboard(JSON.stringify(results, null, 2));
                UIModule.showToast('Raw data copied to clipboard', 'success');
            };
        }
    },

    exportResults(results, target) {
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        
        // Export JSON
        const jsonBlob = new Blob([JSON.stringify(results, null, 2)], { type: 'application/json' });
        UtilsModule.downloadBlob(jsonBlob, `${target}_recon_${timestamp}.json`);
        
        // Export CSV
        const csvData = this.convertToCSV(results);
        const csvBlob = new Blob([csvData], { type: 'text/csv' });
        UtilsModule.downloadBlob(csvBlob, `${target}_recon_${timestamp}.csv`);
        
        UIModule.showToast('Results exported successfully', 'success');
    },

    // New export variants used by the dropdown
    exportAsJSON(results, target) {
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const jsonBlob = new Blob([JSON.stringify(results, null, 2)], { type: 'application/json' });
        UtilsModule.downloadBlob(jsonBlob, `${target}_recon_${timestamp}.json`);
        UIModule.showToast('JSON exported', 'success');
    },

    exportAsCSV(results, target) {
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const csvData = this.convertToCSV(results);
        const csvBlob = new Blob([csvData], { type: 'text/csv' });
        UtilsModule.downloadBlob(csvBlob, `${target}_recon_${timestamp}.csv`);
        UIModule.showToast('CSV exported', 'success');
    },

    exportAsHTML(results, target) {
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const sfEnhanced = AppState.spiderfootEnhanced || null;
        const html = this.buildHTMLReport(results, sfEnhanced);
        UtilsModule.downloadText(html, `${target}_recon_${timestamp}.html`, 'text/html');
        UIModule.showToast('HTML report exported', 'success');
    },

    async exportAsPDF(results, target, sfEnhanced) {
        try {
            UIModule.showToast('Generating PDF report...', 'info');
            const res = await fetch(`${AppConfig.backendUrl}/api/export/pdf`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ results, target, sf_enhanced: sfEnhanced || null })
            });
            if (!res.ok) {
                let msg = `HTTP ${res.status}`;
                try {
                    const err = await res.json();
                    if (err && err.error) msg = err.error;
                } catch {}
                throw new Error(msg);
            }
            const blob = await res.blob();
            const cd = res.headers.get('Content-Disposition') || '';
            let filename = `${(target || 'target').replace(/[^a-zA-Z0-9_.-]/g,'_')}_recon_${new Date().toISOString().replace(/[:.]/g,'-')}.pdf`;
            const m = cd.match(/filename\*=UTF-8''([^;]+)|filename="?([^";]+)"?/i);
            if (m) filename = decodeURIComponent(m[1] || m[2]);
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            URL.revokeObjectURL(url);
            a.remove();
            UIModule.showToast('PDF report exported', 'success');
        } catch (err) {
            console.error('PDF export failed:', err);
            UIModule.showToast('PDF export failed: ' + (err?.message || err), 'error');
        }
    },

    // Helper Methods
    getTotalOpenPorts(hosts) {
        if (!hosts) return 0;
        return hosts.reduce((total, host) => total + (host.open_ports?.length || 0), 0);
    },

    getSummaryStats(results) {
        return {
            subdomains: results.subdomains?.length || 0,
            hosts: results.hosts?.length || 0,
            openPorts: this.getTotalOpenPorts(results.hosts),
            emails: results.harvester?.emails?.length || 0,
            github: results.github_hits?.length || 0,
            pastes: results.paste_hits?.length || 0,
            cves: this.getTotalCVEs(results.cves)
        };
    },

    getTopPortsData(results, topN = 10) {
        const counts = {};
        (results.hosts || []).forEach(h => (h.open_ports || []).forEach(p => { counts[p] = (counts[p] || 0) + 1; }));
        const sorted = Object.entries(counts).sort((a,b) => b[1]-a[1]).slice(0, topN);
        return { labels: sorted.map(([p]) => p), data: sorted.map(([,c]) => c) };
    },

    buildHTMLReport(results, sfEnhanced) {
        const s = this.getSummaryStats(results);
        const esc = (str) => (str || '').toString().replace(/[&<>]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
        const subRows = (results.subdomains||[]).map(sd => {
            const host = (results.hosts||[]).find(h => h.hostname === sd);
            const ips = host?.ips?.join(', ') || 'N/A';
            return `<tr><td>${esc(sd)}</td><td>${esc(ips)}</td></tr>`;
        }).join('');
        const hostBlocks = (results.hosts||[]).map(h => `
            <div class='card'>
                <div class='h'>${esc(h.hostname)}</div>
                <div><b>IPs:</b> ${esc(h.ips?.join(', ') || 'None')}</div>
                <div><b>Open Ports:</b> ${esc(h.open_ports?.join(', ') || 'None')}</div>
                ${h.services?.length ? `<div><b>Services:</b> ${esc(h.services.join(' | '))}</div>` : ''}
            </div>`).join('');
        const style = `
            <style>
            body{font-family:Inter,Arial,sans-serif;background:#0f0f0f;color:#eaeaea;padding:24px}
            .grid{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:16px}
            .kpi{flex:1 1 160px;border:1px solid #2a2a2a;border-radius:8px;padding:12px}
            .kpi .l{font-size:12px;color:#aaa}.kpi .v{font-size:20px;font-weight:700}
            h1{margin:0 0 8px 0} h2{margin:16px 0 8px 0}
            table{width:100%;border-collapse:collapse;font-size:12px}
            th,td{border-bottom:1px solid #2a2a2a;padding:6px;text-align:left}
            .card{border:1px solid #2a2a2a;border-radius:8px;padding:12px;margin-bottom:10px}
            .card .h{font-weight:600;margin-bottom:6px}
            .muted{color:#aaa}
            </style>`;
        const html = `<!DOCTYPE html><html><head><meta charset='utf-8'><title>Recon Report</title>${style}</head><body>
            <h1>Red Team Recon Report</h1>
            <div class='muted'>Target: <b>${esc(results.target)}</b> · Generated: ${new Date().toLocaleString()}</div>
            <h2>Executive Summary</h2>
            <div class='grid'>
                <div class='kpi'><div class='l'>Subdomains</div><div class='v'>${s.subdomains}</div></div>
                <div class='kpi'><div class='l'>Hosts</div><div class='v'>${s.hosts}</div></div>
                <div class='kpi'><div class='l'>Open Ports</div><div class='v'>${s.openPorts}</div></div>
                <div class='kpi'><div class='l'>Emails</div><div class='v'>${s.emails}</div></div>
                <div class='kpi'><div class='l'>GitHub Hits</div><div class='v'>${s.github}</div></div>
                <div class='kpi'><div class='l'>Pastes</div><div class='v'>${s.pastes}</div></div>
                <div class='kpi'><div class='l'>CVEs</div><div class='v'>${s.cves}</div></div>
            </div>
            <h2>Subdomains</h2>
            ${subRows ? `<table><thead><tr><th>Subdomain</th><th>IP(s)</th></tr></thead><tbody>${subRows}</tbody></table>` : `<div class='muted'>No subdomains found</div>`}
            <h2>Hosts & Ports</h2>
            ${hostBlocks || `<div class='muted'>No hosts detected</div>`}
            ${sfEnhanced ? `
            <h2>SpiderFoot Enrichment</h2>
            <div class='card'>
                <div><b>Modules Used:</b> ${(sfEnhanced.modules_used || sfEnhanced.results?.modules_run || []).join(', ') || 'N/A'}</div>
                <div><b>Events Found:</b> ${sfEnhanced.results?.events_found ?? 'N/A'}</div>
            </div>` : ''}
        </body></html>`;
        return html;
    },

    getTotalServices(hosts) {
        if (!hosts) return 0;
        return hosts.reduce((total, host) => total + (host.services?.length || 0), 0);
    },

    getTotalCVEs(cves) {
        if (!cves) return 0;
        return Object.values(cves).reduce((total, cvelist) => total + cvelist.length, 0);
    },

    calculateDuration() {
        if (!AppState.startTime) return 'Unknown';
        const duration = Math.floor((Date.now() - AppState.startTime) / 1000);
        const minutes = Math.floor(duration / 60);
        const seconds = duration % 60;
        return `${minutes}m ${seconds}s`;
    },

    calculateRiskLevel(results) {
        let score = 0;
        
        // Factor in open ports
        const openPorts = this.getTotalOpenPorts(results.hosts);
        if (openPorts > 10) score += 3;
        else if (openPorts > 5) score += 2;
        else if (openPorts > 0) score += 1;
        
        // Factor in CVEs
        const cves = this.getTotalCVEs(results.cves);
        if (cves > 10) score += 4;
        else if (cves > 5) score += 3;
        else if (cves > 0) score += 2;
        
        // Factor in exposed information
        const github = results.github_hits?.length || 0;
        const pastes = results.paste_hits?.length || 0;
        if (github > 5 || pastes > 0) score += 2;
        else if (github > 0) score += 1;
        
        if (score >= 7) return { level: 'Critical', class: 'error', description: 'Multiple high-risk issues identified' };
        if (score >= 5) return { level: 'High', class: 'warning', description: 'Several security concerns detected' };
        if (score >= 3) return { level: 'Medium', class: 'info', description: 'Some security issues present' };
        return { level: 'Low', class: 'success', description: 'Minimal security concerns detected' };
    },

    detectTechFromHost(hostInfo) {
        if (!hostInfo?.services) return null;
        const services = hostInfo.services.join(' ').toLowerCase();
        if (services.includes('apache')) return 'Apache';
        if (services.includes('nginx')) return 'Nginx';
        if (services.includes('ssh')) return 'SSH';
        return null;
    },

    formatTechCategory(category) {
        return category.replace(/-/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
    },

    getCVSSClass(cvss) {
        const score = parseFloat(cvss);
        if (score >= 9.0) return 'error';
        if (score >= 7.0) return 'warning';
        if (score >= 4.0) return 'info';
        return 'success';
    },

    convertToCSV(results) {
        const headers = ['Type', 'Value', 'Details'];
        const rows = [headers.join(',')];
        
        // Add subdomains
        if (results.subdomains) {
            results.subdomains.forEach(sub => {
                const host = results.hosts?.find(h => h.hostname === sub);
                rows.push(`"Subdomain","${sub}","${host?.ips?.join(';') || 'N/A'}"`);
            });
        }
        
        // Add emails
        if (results.harvester?.emails) {
            results.harvester.emails.forEach(email => {
                rows.push(`"Email","${email}","From harvester"`);
            });
        }
        
        return rows.join('\n');
    }
};

// ===========================================
// Utilities Module
// ===========================================
const UtilsModule = {
    init() {
        console.log('🔧 Utils Module initialized');
    },

    // Clipboard Operations
    async copyToClipboard(text) {
        try {
            if (navigator.clipboard && window.isSecureContext) {
                await navigator.clipboard.writeText(text);
                UIModule.showToast('Copied to clipboard', 'success');
            } else {
                // Fallback for older browsers
                this.fallbackCopyToClipboard(text);
            }
        } catch (error) {
            console.error('Copy to clipboard failed:', error);
            UIModule.showToast('Failed to copy to clipboard', 'error');
        }
    },

    fallbackCopyToClipboard(text) {
        const textArea = document.createElement('textarea');
        textArea.value = text;
        textArea.style.position = 'fixed';
        textArea.style.left = '-999999px';
        textArea.style.top = '-999999px';
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        
        try {
            document.execCommand('copy');
            UIModule.showToast('Copied to clipboard', 'success');
        } catch (error) {
            console.error('Fallback copy failed:', error);
            UIModule.showToast('Failed to copy to clipboard', 'error');
        } finally {
            document.body.removeChild(textArea);
        }
    },

    // File Download Operations
    downloadBlob(blob, filename) {
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.style.display = 'none';
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
    },

    downloadText(text, filename, mimeType = 'text/plain') {
        const blob = new Blob([text], { type: mimeType });
        this.downloadBlob(blob, filename);
    },

    downloadJSON(object, filename) {
        const json = JSON.stringify(object, null, 2);
        this.downloadText(json, filename, 'application/json');
    },

    // Dynamic script loader (prevents duplicate loads)
    _loadedScripts: new Set(),
    loadScript(src) {
        return new Promise((resolve, reject) => {
            try {
                if (this._loadedScripts.has(src)) {
                    return resolve();
                }
                // If a matching script tag already exists, resolve when it loads
                const existing = Array.from(document.getElementsByTagName('script')).find(s => s.src === src);
                if (existing) {
                    if (existing.getAttribute('data-loaded') === 'true') {
                        this._loadedScripts.add(src);
                        return resolve();
                    }
                    existing.addEventListener('load', () => {
                        existing.setAttribute('data-loaded', 'true');
                        this._loadedScripts.add(src);
                        resolve();
                    });
                    existing.addEventListener('error', () => reject(new Error('Failed to load script: ' + src)));
                    return;
                }

                const script = document.createElement('script');
                script.src = src;
                script.async = true;
                script.onload = () => {
                    script.setAttribute('data-loaded', 'true');
                    this._loadedScripts.add(src);
                    resolve();
                };
                script.onerror = () => reject(new Error('Failed to load script: ' + src));
                document.head.appendChild(script);
            } catch (err) {
                reject(err);
            }
        });
    },

    // Validation Utilities
    isValidDomain(domain) {
        const domainRegex = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/;
        return domainRegex.test(domain) && domain.length <= 253;
    },

    isValidEmail(email) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
    },

    isValidIP(ip) {
        const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        const ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
        return ipv4Regex.test(ip) || ipv6Regex.test(ip);
    },

    // Formatting Utilities
    formatBytes(bytes, decimals = 2) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const dm = decimals < 0 ? 0 : decimals;
        const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
    },

    formatDuration(seconds) {
        const days = Math.floor(seconds / 86400);
        const hours = Math.floor((seconds % 86400) / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);
        const remainingSeconds = seconds % 60;

        const parts = [];
        if (days > 0) parts.push(`${days}d`);
        if (hours > 0) parts.push(`${hours}h`);
        if (minutes > 0) parts.push(`${minutes}m`);
        if (remainingSeconds > 0 || parts.length === 0) parts.push(`${remainingSeconds}s`);

        return parts.join(' ');
    },

    formatDate(date, options = {}) {
        const defaultOptions = {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        };
        return new Date(date).toLocaleDateString(undefined, { ...defaultOptions, ...options });
    },

    // String Utilities
    capitalize(str) {
        return str.charAt(0).toUpperCase() + str.slice(1).toLowerCase();
    },

    slugify(str) {
        return str
            .toLowerCase()
            .trim()
            .replace(/[^\w\s-]/g, '')
            .replace(/[\s_-]+/g, '-')
            .replace(/^-+|-+$/g, '');
    },

    truncate(str, length = 100, suffix = '...') {
        if (str.length <= length) return str;
        return str.substring(0, length - suffix.length) + suffix;
    },

    // URL Utilities
    buildUrl(base, params = {}) {
        const url = new URL(base);
        Object.entries(params).forEach(([key, value]) => {
            if (value !== null && value !== undefined) {
                url.searchParams.set(key, value);
            }
        });
        return url.toString();
    },

    extractDomain(url) {
        try {
            return new URL(url).hostname;
        } catch {
            return url.replace(/^https?:\/\//, '').split('/')[0];
        }
    },

    // Array Utilities
    unique(array) {
        return [...new Set(array)];
    },

    groupBy(array, key) {
        return array.reduce((groups, item) => {
            const group = item[key];
            groups[group] = groups[group] || [];
            groups[group].push(item);
            return groups;
        }, {});
    },

    sortBy(array, key, direction = 'asc') {
        return array.sort((a, b) => {
            const aVal = a[key];
            const bVal = b[key];
            if (direction === 'desc') {
                return bVal > aVal ? 1 : bVal < aVal ? -1 : 0;
            }
            return aVal > bVal ? 1 : aVal < bVal ? -1 : 0;
        });
    },

    // Security Utilities
    sanitizeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    },

    generateId(length = 8) {
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        let result = '';
        for (let i = 0; i < length; i++) {
            result += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        return result;
    },

    // Theme and UI Utilities
    setTheme(theme) {
        document.documentElement.setAttribute('data-theme', theme);
        AppState.settings.theme = theme;
        saveSettings();
    },

    toggleDarkMode() {
        const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
        this.setTheme(isDark ? 'light' : 'dark');
    },

    // Browser Utilities
    getBrowserInfo() {
        const ua = navigator.userAgent;
        const browsers = [
            { name: 'Chrome', regex: /Chrome\/([0-9.]+)/ },
            { name: 'Firefox', regex: /Firefox\/([0-9.]+)/ },
            { name: 'Safari', regex: /Safari\/([0-9.]+)/ },
            { name: 'Edge', regex: /Edg\/([0-9.]+)/ }
        ];
        
        for (const browser of browsers) {
            const match = ua.match(browser.regex);
            if (match) {
                return { name: browser.name, version: match[1] };
            }
        }
        return { name: 'Unknown', version: 'Unknown' };
    },

    isMobile() {
        return /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent);
    },

    // Performance Utilities
    debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    },

    throttle(func, limit) {
        let inThrottle;
        return function() {
            const args = arguments;
            const context = this;
            if (!inThrottle) {
                func.apply(context, args);
                inThrottle = true;
                setTimeout(() => inThrottle = false, limit);
            }
        };
    },

    // Storage Utilities
    storage: {
        set(key, value, expiry = null) {
            const item = {
                value: value,
                expiry: expiry ? Date.now() + expiry : null
            };
            localStorage.setItem(key, JSON.stringify(item));
        },

        get(key) {
            const itemStr = localStorage.getItem(key);
            if (!itemStr) return null;

            try {
                const item = JSON.parse(itemStr);
                if (item.expiry && Date.now() > item.expiry) {
                    localStorage.removeItem(key);
                    return null;
                }
                return item.value;
            } catch {
                return null;
            }
        },

        remove(key) {
            localStorage.removeItem(key);
        },

        clear() {
            localStorage.clear();
        }
    },

    // Error Handling Utilities
    handleError(error, context = 'Application') {
        console.error(`${context} Error:`, error);
        
        let message = 'An unexpected error occurred';
        if (error.message) {
            message = error.message;
        } else if (typeof error === 'string') {
            message = error;
        }
        
        UIModule.showToast(message, 'error');
        
        // Log to external service in production
        if (AppConfig.environment === 'production') {
            // Send to error tracking service
        }
    },

    // Network Utilities
    async checkOnlineStatus() {
        if (!navigator.onLine) return false;
        
        try {
            const response = await fetch('/api/health', {
                method: 'HEAD',
                mode: 'no-cors',
                cache: 'no-store'
            });
            return true;
        } catch {
            return false;
        }
    }
};

// Initialize the application when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    console.log('🚀 Initializing Red Team Recon Toolkit...');
    
    try {
        // Initialize UI Module (idempotent)
        UIModule.init();
        UIModule.bindEvents();
        
        console.log('✅ Application initialized successfully');
        
        // Start button availability check (no additional bindings here)
        const startBtn = document.getElementById('startReconBtn');
        if (startBtn) {
            console.log('✅ Start button found');
        } else {
            console.error('❌ Start button not found');
        }
        
        // Do not override status set by health check in the primary initializer
        
    } catch (error) {
        console.error('❌ Failed to initialize application:', error);
        Utils.handleError(error, 'Initialization');
    }
});