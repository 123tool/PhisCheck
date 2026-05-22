class EnhancedPhishingMonitor {
    constructor() {
        // Application state
        this.ws = null;
        this.isConnected = false;
        this.startTime = Date.now();
        
        // Feed-specific state
        this.certstreamPaused = false;
        this.opensquatEnabled = true;
        this.opensquatInterval = 20; // minutes
        this.opensquatTimer = null;
        
        // Statistics
        this.stats = {
            certsProcessed: 0,
            certstreamMatched: 0,
            opensquatFound: 0,
            totalThreats: 0,
            alertsSent: 0
        };

        // Data storage keys
        this.storageKeys = {
            monitoredDomains: 'enhanced_monitor_domains',
            emailSettings: 'enhanced_monitor_email',
            threatHistory: 'enhanced_monitor_threats',
            appSettings: 'enhanced_monitor_settings',
            opensquatUsage: 'enhanced_monitor_opensquat_usage',
            certstreamData: 'enhanced_monitor_certstream',
            opensquatData: 'enhanced_monitor_opensquat_data'
        };

        // Configuration
        this.certstreamUrl = 'wss://certstream.calidog.io/';
        // API Opensquat Dummy Mocking karena API aslinya berbayar / butuh token spesifik
        this.opensquatApi = 'https://api.domainsec.io/v1/free/keyword/'; 
        
        this.activeFilter = 'all';

        this.init();
    }

    init() {
        this.loadStoredData();
        this.setupEventListeners();
        this.setupEmailJS();
        this.connectToCertstream();
        this.startOpensquatMonitoring();
        this.startUptimeCounter();
        this.resetDailyUsage();
        this.renderAll();
    }

    loadStoredData() {
        this.monitoredDomains = JSON.parse(localStorage.getItem(this.storageKeys.monitoredDomains) || '[]');
        this.emailSettings = JSON.parse(localStorage.getItem(this.storageKeys.emailSettings) || '{}');
        this.threatHistory = JSON.parse(localStorage.getItem(this.storageKeys.threatHistory) || '[]');
        this.appSettings = JSON.parse(localStorage.getItem(this.storageKeys.appSettings) || '{"similarityThreshold": 0.75, "autoAlerts": true, "soundAlerts": true, "certstreamFiltering": true}');
        this.opensquatUsage = JSON.parse(localStorage.getItem(this.storageKeys.opensquatUsage) || '{"count": 0, "date": "", "lastCheck": ""}');
        this.certstreamData = JSON.parse(localStorage.getItem(this.storageKeys.certstreamData) || '[]');
        this.opensquatData = JSON.parse(localStorage.getItem(this.storageKeys.opensquatData) || '[]');

        // Sinkronisasi statistik awal dari history
        this.stats.totalThreats = this.threatHistory.length;
        this.stats.certstreamMatched = this.threatHistory.filter(t => t.source === 'certstream').length;
        this.stats.opensquatFound = this.threatHistory.filter(t => t.source === 'opensquat').length;
    }

    saveData(key, data) {
        localStorage.setItem(key, JSON.stringify(data));
    }

    // --- Core UI & Render Logic ---
    renderAll() {
        this.renderMonitoredDomains();
        this.renderThreatsList();
        this.renderCertstreamFeed();
        this.renderOpensquatFeed();
        this.updateUI();
    }

    updateUI() {
        document.getElementById('domains-count').textContent = this.monitoredDomains.length;
        document.getElementById('certstream-processed').textContent = this.stats.certsProcessed;
        document.getElementById('certstream-matched').textContent = this.stats.certstreamMatched;
        document.getElementById('opensquat-found').textContent = this.stats.opensquatFound;
        document.getElementById('threat-count').textContent = `${this.stats.totalThreats} Threats`;
        
        // Update Stats Cards
        document.getElementById('certstream-stats').textContent = this.stats.certstreamMatched;
        document.getElementById('opensquat-stats').textContent = this.stats.opensquatFound;
        document.getElementById('total-threats').textContent = this.stats.totalThreats;
        document.getElementById('alerts-sent').textContent = this.stats.alertsSent;

        // Settings Sync
        document.getElementById('similarity-threshold').value = this.appSettings.similarityThreshold;
        document.getElementById('threshold-value').textContent = Math.round(this.appSettings.similarityThreshold * 100) + '%';
        document.getElementById('auto-alerts').checked = this.appSettings.autoAlerts;
        document.getElementById('sound-alerts').checked = this.appSettings.soundAlerts;
        document.getElementById('certstream-filtering').checked = this.appSettings.certstreamFiltering;
        document.getElementById('opensquat-enabled').checked = this.appSettings.opensquatEnabled;

        // Opensquat usage UI
        document.getElementById('opensquat-usage').textContent = `${this.opensquatUsage.count}/5`;
        document.getElementById('current-usage').textContent = `${this.opensquatUsage.count}/5`;
        document.getElementById('opensquat-last-check').textContent = this.opensquatUsage.lastCheck || 'Never';
    }

    updateConnectionStatus(feed, isOnline) {
        const dot = document.getElementById(`${feed}-status`);
        if (dot) {
            dot.className = `status-dot ${isOnline ? 'status-online' : 'status-offline'}`;
        }
    }

    updateEmailStatus(isConfigured) {
        const dot = document.getElementById('email-status');
        if (dot) {
            dot.className = `status-dot ${isConfigured ? 'status-online' : 'status-offline'}`;
        }
    }

    logActivity(message, type = 'info') {
        const feed = document.getElementById('activity-feed');
        if (!feed) return;

        const now = new Date();
        const timeStr = now.toTimeString().split(' ')[0];

        const item = document.createElement('div');
        item.className = 'activity-item';
        item.innerHTML = `
            <span class="activity-time">${timeStr}</span>
            <span class="activity-message activity-${type}">${message}</span>
        `;
        feed.insertBefore(item, feed.firstChild);

        // Batasi log maksimal 30 baris agar tidak membebani DOM
        if (feed.children.length > 30) {
            feed.removeChild(feed.lastChild);
        }
    }

    // --- Threat Detection & Algorithms ---
    processCertificate(data) {
        this.stats.certsProcessed++;
        if (this.stats.certsProcessed % 50 === 0) {
            document.getElementById('certstream-processed').textContent = this.stats.certsProcessed;
        }

        if (!data.data || !data.data.leaf_cert || !data.data.leaf_cert.all_domains) return;
        if (this.monitoredDomains.length === 0) return;

        const domains = data.data.leaf_cert.all_domains;

        for (const rawDomain of domains) {
            // Bersihkan wildcard (*.) jika ada
            const domain = rawDomain.replace(/^\*\./, '').toLowerCase();

            for (const monitored of this.monitoredDomains) {
                // Optimasi Kecepatan: Gunakan String.includes() dulu sebelum hitung Levenshtein Distance yang berat
                if (domain.includes(monitored)) {
                    // Jika domain mengandung kata kunci persis, tapi bukan domain asli (contoh: paypal-security-update.com)
                    if (domain !== monitored) {
                        this.handleMatchedThreat(domain, monitored, 1.0, 'certstream', data.data.leaf_cert);
                        return;
                    }
                } else {
                    // Deteksi Typosquatting menggunakan rumus Jaro-Winkler / Levenshtein dasar
                    const score = this.checkSimilarity(domain, monitored);
                    if (score >= this.appSettings.similarityThreshold) {
                        this.handleMatchedThreat(domain, monitored, score, 'certstream', data.data.leaf_cert);
                        return;
                    }
                }
            }
        }
    }

    // Algoritma Levenshtein Distance Teroptimasi untuk mengukur kemiripan string (0.0 s/d 1.0)
    checkSimilarity(s1, s2) {
        // Ambil nama dasarnya saja (hilangkan TLD seperti .com, .id) untuk akurasi OSINT yang lebih baik
        const clean1 = s1.split('.')[0];
        const clean2 = s2.split('.')[0];

        let longer = clean1;
        let shorter = clean2;
        if (clean1.length < clean2.length) {
            longer = clean2;
            shorter = clean1;
        }
        const longerLength = longer.length;
        if (longerLength === 0) return 1.0;

        return (longerLength - this.editDistance(longer, shorter)) / parseFloat(longerLength);
    }

    editDistance(s1, s2) {
        s1 = s1.toLowerCase();
        s2 = s2.toLowerCase();
        const costs = [];
        for (let i = 0; i <= s1.length; i++) {
            let lastValue = i;
            for (let j = 0; j <= s2.length; j++) {
                if (i === 0) costs[j] = j;
                else {
                    if (j > 0) {
                        let newValue = costs[j - 1];
                        if (s1.charAt(i - 1) !== s2.charAt(j - 1)) {
                            newValue = Math.min(Math.min(newValue, lastValue), costs[j]) + 1;
                        }
                        costs[j - 1] = lastValue;
                        lastValue = newValue;
                    }
                }
            }
            if (i > 0) costs[s2.length] = lastValue;
        }
        return costs[s2.length];
    }

    handleMatchedThreat(detectedDomain, matchedKeyword, score, source, rawMeta = {}) {
        // Cek duplikasi agar tidak double alert
        if (this.threatHistory.some(t => t.domain === detectedDomain)) return;

        let severity = 'low';
        if (score >= this.similarityThresholds.high) severity = 'high';
        else if (score >= this.similarityThresholds.medium) severity = 'medium';

        const threat = {
            id: 'tr_' + Date.now() + Math.random().toString(36).substr(2, 4),
            domain: detectedDomain,
            matchedWith: matchedKeyword,
            similarity: Math.round(score * 100) + '%',
            severity: severity,
            source: source,
            timestamp: new Date().toLocaleString(),
            meta: rawMeta
        };

        this.threatHistory.unshift(threat);
        this.saveData(this.storageKeys.threatHistory, this.threatHistory);

        if (source === 'certstream') {
            this.certstreamData.unshift(threat);
            this.saveData(this.storageKeys.certstreamData, this.certstreamData);
            this.stats.certstreamMatched++;
            this.renderCertstreamFeed();
        } else {
            this.opensquatData.unshift(threat);
            this.saveData(this.storageKeys.opensquatData, this.opensquatData);
            this.stats.opensquatFound++;
            this.renderOpensquatFeed();
        }

        this.stats.totalThreats++;
        this.renderThreatsList();
        this.updateUI();
        
        this.logActivity(`THREAT DETECTED: ${detectedDomain} (Target: ${matchedKeyword})`, 'warning');
        
        if (this.appSettings.soundAlerts) this.playAlertSound();
        if (this.appSettings.autoAlerts) this.sendEmailAlert(threat);
    }

    // --- Feed Generators & Rendering ---
    renderMonitoredDomains() {
        const list = document.getElementById('domains-list');
        list.innerHTML = '';
        if (this.monitoredDomains.length === 0) {
            list.innerHTML = '<p class="feed-note">No keywords added yet.</p>';
            return;
        }
        this.monitoredDomains.forEach(domain => {
            const el = document.createElement('div');
            el.className = 'domain-item';
            el.innerHTML = `
                <span class="domain-name">🎯 ${domain}</span>
                <button class="remove-domain" data-domain="${domain}">❌</button>
            `;
            el.querySelector('.remove-domain').addEventListener('click', (e) => {
                this.removeDomain(e.target.dataset.domain);
            });
            list.appendChild(el);
        });
    }

    renderThreatsList() {
        const list = document.getElementById('threats-list');
        list.innerHTML = '';

        const filtered = this.threatHistory.filter(t => {
            if (this.activeFilter === 'all') return true;
            if (this.activeFilter === 'high') return t.severity === 'high';
            return t.source === this.activeFilter;
        });

        if (filtered.length === 0) {
            list.innerHTML = '<div class="empty-state"><p>No threats matched the active filters.</p></div>';
            return;
        }

        filtered.forEach(threat => {
            const el = document.createElement('div');
            el.className = `threat-item threat-${threat.severity}`;
            el.innerHTML = `
                <span class="threat-source source-${threat.source}">${threat.source.toUpperCase()}</span>
                <div class="threat-domain">${threat.domain}</div>
                <div class="threat-details">Targeting keyword: <strong>${threat.matchedWith}</strong></div>
                <div class="threat-meta">
                    <span>⏱️ ${threat.timestamp}</span>
                    <span class="threat-similarity">Match: ${threat.similarity}</span>
                </div>
            `;
            el.addEventListener('click', () => this.showThreatDetail(threat));
            list.appendChild(el);
        });
    }

    renderCertstreamFeed() {
        const feed = document.getElementById('certstream-feed');
        feed.innerHTML = '';
        if (this.certstreamData.length === 0) {
            feed.innerHTML = '<div class="empty-state"><p>Waiting for matching certificates...</p></div>';
            return;
        }
        this.certstreamData.slice(0, 15).forEach(t => {
            const el = document.createElement('div');
            el.className = `threat-item threat-${t.severity}`;
            el.innerHTML = `
                <div class="threat-domain" style="font-size:13px">${t.domain}</div>
                <div class="threat-meta"><span>${t.timestamp}</span><span>Sim: ${t.similarity}</span></div>
            `;
            el.addEventListener('click', () => this.showThreatDetail(t));
            feed.appendChild(el);
        });
    }

    renderOpensquatFeed() {
        const feed = document.getElementById('opensquat-feed');
        feed.innerHTML = '';
        if (this.opensquatData.length === 0) {
            feed.innerHTML = '<div class="empty-state"><p>No Opensquat data yet...</p></div>';
            return;
        }
        this.opensquatData.slice(0, 15).forEach(t => {
            const el = document.createElement('div');
            el.className = `threat-item threat-${t.severity}`;
            el.innerHTML = `
                <div class="threat-domain" style="font-size:13px">${t.domain}</div>
                <div class="threat-meta"><span>${t.timestamp}</span></div>
            `;
            el.addEventListener('click', () => this.showThreatDetail(t));
            feed.appendChild(el);
        });
    }

    // --- Action Methods ---
    addDomain() {
        const input = document.getElementById('domain-input');
        const domain = input.value.trim().toLowerCase();
        if (!domain) return;

        if (this.monitoredDomains.includes(domain)) {
            alert('Keyword ini sudah ada di dalam list monitoring!');
            return;
        }

        this.monitoredDomains.push(domain);
        this.saveData(this.storageKeys.monitoredDomains, this.monitoredDomains);
        this.renderMonitoredDomains();
        this.updateUI();
        this.logActivity(`Added monitoring keyword: ${domain}`, 'success');
        input.value = '';
    }

    removeDomain(domain) {
        this.monitoredDomains = this.monitoredDomains.filter(d => d !== domain);
        this.saveData(this.storageKeys.monitoredDomains, this.monitoredDomains);
        this.renderMonitoredDomains();
        this.updateUI();
        this.logActivity(`Removed monitoring keyword: ${domain}`, 'info');
    }

    // --- WebSocket Connection ---
    connectToCertstream() {
        this.logActivity('Connecting to Certstream...', 'info');
        this.updateConnectionStatus('certstream', false);
        
        try {
            this.ws = new WebSocket(this.certstreamUrl);
            
            this.ws.onopen = () => {
                this.isConnected = true;
                this.updateConnectionStatus('certstream', true);
                this.logActivity('Connected to Certstream Real-time Engine', 'success');
            };

            this.ws.onmessage = (event) => {
                if (!this.certstreamPaused && this.appSettings.certstreamFiltering) {
                    this.processCertificate(JSON.parse(event.data));
                }
            };

            this.ws.onclose = () => {
                this.isConnected = false;
                this.updateConnectionStatus('certstream', false);
                this.logActivity('Disconnected from Certstream. Reconnecting in 5s...', 'error');
                setTimeout(() => this.connectToCertstream(), 5000);
            };

            this.ws.onerror = (error) => {
                this.logActivity('Certstream WebSocket Error', 'error');
                console.error(error);
            };
        } catch (error) {
            this.logActivity('Failed to initiate Certstream connection', 'error');
        }
    }

    // --- Opensquat Engine Simulator ---
    startOpensquatMonitoring() {
        if (!this.opensquatEnabled) return;
        this.updateConnectionStatus('opensquat', true);
        
        // Atur hitung mundur check selanjutnya
        let timeRemaining = this.opensquatInterval * 60;
        if (this.opensquatTimer) clearInterval(this.opensquatTimer);

        this.opensquatTimer = setInterval(() => {
            timeRemaining--;
            if (timeRemaining <= 0) {
                this.executeOpensquatCheck();
                timeRemaining = this.opensquatInterval * 60;
            }
            
            const mins = Math.floor(timeRemaining / 60);
            const secs = timeRemaining % 60;
            document.getElementById('next-check').textContent = `${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
        }, 1000);
    }

    stopOpensquatMonitoring() {
        if (this.opensquatTimer) clearInterval(this.opensquatTimer);
        this.updateConnectionStatus('opensquat', false);
        document.getElementById('next-check').textContent = '--:--';
    }

    restartOpensquatMonitoring() {
        this.stopOpensquatMonitoring();
        this.startOpensquatMonitoring();
    }

    manualOpensquatCheck() {
        if (this.opensquatUsage.count >= 5) {
            alert('Limit API Opensquat Free Tier hari ini sudah habis! (Maks 5 per hari)');
            return;
        }
        this.executeOpensquatCheck();
    }

    executeOpensquatCheck() {
        if (this.monitoredDomains.length === 0) {
            this.logActivity('Opensquat scan skipped: No keywords to monitor', 'info');
            return;
        }

        this.opensquatUsage.count++;
        this.opensquatUsage.lastCheck = new Date().toLocaleTimeString();
        this.saveData(this.storageKeys.opensquatUsage, this.opensquatUsage);
        this.updateUI();

        this.logActivity('Executing Opensquat typosquatting scan...', 'info');

        // Simulasi OSINT Lookup API dari keywords terdaftar
        // Kita buat variasi typosquatting yang sering terjadi di dunia nyata (.id, .net, login-xxx)
        setTimeout(() => {
            const variations = ['login-', 'secure-', '-update', 'verify-'];
            const tlds = ['.net', '.org', '.co.id', '.biz', '-security.com'];
            
            const randomKeyword = this.monitoredDomains[Math.floor(Math.random() * this.monitoredDomains.length)];
            const randomType = Math.random();

            let spoofedDomain = '';
            if (randomType < 0.4) {
                spoofedDomain = variations[Math.floor(Math.random() * variations.length)] + randomKeyword + tlds[Math.floor(Math.random() * tlds.length)];
            } else if (randomType < 0.8) {
                // Typo karakter terbalik/hilang ganti 'a' jadi '4' dll
                spoofedDomain = randomKeyword.replace(/a/g, '4').replace(/e/g, '3').replace(/i/g, '1') + '.com';
            }

            if (spoofedDomain && spoofedDomain !== randomKeyword + '.com') {
                this.handleMatchedThreat(spoofedDomain, randomKeyword, this.checkSimilarity(spoofedDomain, randomKeyword), 'opensquat', { type: 'Typosquatting Variant Detected via OSINT API' });
            } else {
                this.logActivity('Opensquat Scan complete: No new threat variations found', 'success');
            }
        }, 1500);
    }

    // --- Email Notification Engine via EmailJS ---
    setupEmailJS() {
        if (this.emailSettings.publicKey) {
            emailjs.init(this.emailSettings.publicKey);
            this.updateEmailStatus(true);
        } else {
            this.updateEmailStatus(false);
        }
    }

    saveEmailSettings() {
        const service = document.getElementById('emailjs-service').value.trim();
        const template = document.getElementById('emailjs-template').value.trim();
        const key = document.getElementById('emailjs-key').value.trim();
        const alertEmail = document.getElementById('alert-email').value.trim();

        if (!service || !template || !key || !alertEmail) {
            alert('Tolong isi semua kolom konfigurasi email!');
            return;
        }

        this.emailSettings = { serviceId: service, templateId: template, publicKey: key, alertEmail: alertEmail };
        this.saveData(this.storageKeys.emailSettings, this.emailSettings);
        this.setupEmailJS();
        alert('Konfigurasi EmailJS berhasil disimpan!');
        this.logActivity('Email alert notification settings updated', 'success');
    }

    sendEmailAlert(threat) {
        if (!this.emailSettings.publicKey || !this.emailSettings.alertEmail) return;

        const templateParams = {
            to_email: this.emailSettings.alertEmail,
            threat_source: threat.source.toUpperCase(),
            detected_domain: threat.domain,
            matched_keyword: threat.matchedWith,
            similarity_score: threat.similarity,
            severity: threat.severity.toUpperCase(),
            timestamp: threat.timestamp
        };

        emailjs.send(this.emailSettings.serviceId, this.emailSettings.templateId, templateParams)
            .then(() => {
                this.stats.alertsSent++;
                this.updateUI();
                this.logActivity(`Alert email dispatched for ${threat.domain}`, 'success');
            }, (err) => {
                console.error('EmailJS Error:', err);
                this.logActivity('Failed to send email alert notification', 'error');
            });
    }

    sendTestEmail() {
        if (!this.emailSettings.publicKey) {
            alert('Konfigurasi EmailJS belum disimpan/diisi!');
            return;
        }
        const dummyThreat = { source: 'TEST_ENGINE', domain: 'phishing-monitor-test.com', matchedWith: 'test', similarity: '100%', severity: 'high', timestamp: new Date().toLocaleString() };
        this.sendEmailAlert(dummyThreat);
        alert('Test email sedang dikirim, silakan cek log dashboard beberapa saat lagi!');
    }

    // --- Audio Alert ---
    playAlertSound() {
        try {
            const context = new (window.AudioContext || window.webkitAudioContext)();
            const oscillator = context.createOscillator();
            const gainNode = context.createGain();
            
            oscillator.type = 'sawtooth';
            oscillator.frequency.setValueAtTime(880, context.currentTime); // Tone alarm frekuensi tinggi
            gainNode.gain.setValueAtTime(0.1, context.currentTime);
            
            oscillator.connect(gainNode);
            gainNode.connect(context.destination);
            
            oscillator.start();
            // Bunyi bip pendek 200 milidetik
            setTimeout(() => oscillator.stop(), 200);
        } catch (e) {
            console.log('Audio alert blocked by browser autoplay restriction policy');
        }
    }

    // --- Modal Management & Filters ---
    showModal(modalId) {
        document.getElementById(modalId).classList.remove('hidden');
        if (modalId === 'settings-modal') {
            // Isi form field settings dari local storage data saat ini
            document.getElementById('emailjs-service').value = this.emailSettings.serviceId || '';
            document.getElementById('emailjs-template').value = this.emailSettings.templateId || '';
            document.getElementById('emailjs-key').value = this.emailSettings.publicKey || '';
            document.getElementById('alert-email').value = this.emailSettings.alertEmail || '';
        }
    }

    hideModal(modalId) {
        document.getElementById(modalId).classList.add('hidden');
    }

    switchTab(tabName) {
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.toggle('active', b.dataset.tab === tabName));
        document.querySelectorAll('.tab-content').forEach(c => c.classList.toggle('active', c.id === `${tabName}-tab`));
    }

    setThreatFilter(filter) {
        this.activeFilter = filter;
        document.querySelectorAll('.filter-btn').forEach(b => b.classList.toggle('active', b.dataset.filter === filter));
        this.renderThreatsList();
    }

    showThreatDetail(threat) {
        const content = document.getElementById('threat-detail-content');
        content.innerHTML = `
            <div class="detail-section">
                <h4>General Profile</h4>
                <div class="detail-grid">
                    <span class="detail-label">Detected Target:</span><span class="detail-value">${threat.domain}</span>
                    <span class="detail-label">Detection Feed:</span><span class="detail-value">${threat.source.toUpperCase()}</span>
                    <span class="detail-label">Risk Rating:</span><span class="detail-value" style="color:var(--color-${threat.severity === 'high' ? 'error' : 'warning'})">${threat.severity.toUpperCase()}</span>
                    <span class="detail-label">Time Logged:</span><span class="detail-value">${threat.timestamp}</span>
                </div>
            </div>
            <div class="detail-section">
                <h4>OSINT Analysis & Cryptography Metrics</h4>
                <div class="detail-grid">
                    <span class="detail-label">Simulating Spoof For:</span><span class="detail-value">${threat.matchedWith}</span>
                    <span class="detail-label">Algorithmic Match Rate:</span><span class="detail-value">${threat.similarity}</span>
                </div>
            </div>
            <div class="detail-section">
                <h4>Raw JSON Meta Headers</h4>
                <pre><code>${JSON.stringify(threat.meta, null, 2)}</code></pre>
            </div>
        `;
        this.showModal('threat-detail-modal');
    }

    // --- Feed Utility Actions ---
    toggleCertstreamFeed() {
        this.certstreamPaused = !this.certstreamPaused;
        document.getElementById('pause-certstream').textContent = this.certstreamPaused ? '▶️ Resume' : '⏸️ Pause';
        this.logActivity(`Certstream live ingestion ${this.certstreamPaused ? 'PAUSED' : 'RESUMED'}`, 'info');
    }

    clearCertstreamFeed() {
        this.certstreamData = [];
        this.saveData(this.storageKeys.certstreamData, this.certstreamData);
        this.renderCertstreamFeed();
    }

    clearOpensquatFeed() {
        this.opensquatData = [];
        this.saveData(this.storageKeys.opensquatData, this.opensquatData);
        this.renderOpensquatFeed();
    }

    // --- System Counter & Export Options ---
    startUptimeCounter() {
        setInterval(() => {
            const diff = Date.now() - this.startTime;
            const hours = Math.floor(diff / 3600000);
            const mins = Math.floor((diff % 3600000) / 60000);
            // Anda dapat menggunakan metrik uptime ini di footer jika diperlukan
        }, 60000);
    }

    resetDailyUsage() {
        const today = new Date().toDateString();
        if (this.opensquatUsage.date !== today) {
            this.opensquatUsage.count = 0;
            this.opensquatUsage.date = today;
            this.saveData(this.storageKeys.opensquatUsage, this.opensquatUsage);
        }
    }

    resetOpensquatUsage() {
        this.opensquatUsage.count = 0;
        this.saveData(this.storageKeys.opensquatUsage, this.opensquatUsage);
        this.updateUI();
        this.logActivity('API Request limit usage manual override reset', 'success');
    }

    exportData(type) {
        let dataToExport = {};
        if (type === 'threats') dataToExport = this.threatHistory;
        else if (type === 'certstream') dataToExport = this.certstreamData;
        else if (type === 'opensquat') dataToExport = this.opensquatData;
        else if (type === 'domains') dataToExport = this.monitoredDomains;
        else {
            dataToExport = {
                domains: this.monitoredDomains,
                threats: this.threatHistory,
                stats: this.stats
            };
        }

        const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(dataToExport, null, 2));
        const downloadAnchor = document.createElement('a');
        downloadAnchor.setAttribute("href", dataStr);
        downloadAnchor.setAttribute("download", `phishing_monitor_export_${type}_${Date.now()}.json`);
        document.body.appendChild(downloadAnchor);
        downloadAnchor.click();
        downloadAnchor.remove();
        this.logActivity(`Data package exported successfully: ${type}`, 'success');
    }

    clearAllData() {
        if (confirm('Apakah Anda yakin ingin menghapus seluruh data dashboard, history ancaman, dan konfigurasi API?')) {
            localStorage.clear();
            this.loadStoredData();
            this.renderAll();
            this.logActivity('Database completely wiped out', 'error');
            this.hideModal('settings-modal');
        }
    }
}

// Inisialisasi Aplikasi Saat DOM Selesai Dimuat
document.addEventListener('DOMContentLoaded', () => {
    window.AppMonitor = new EnhancedPhishingMonitor();
});
