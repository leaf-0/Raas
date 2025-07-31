/**
 * Dashboard JavaScript for FME-ABT Detector
 * Handles real-time updates, chart interactions, and UI controls
 */

class FMEABTDashboard {
    constructor() {
        this.socket = null;
        this.charts = {};
        this.darkMode = false;
        this.autoRefresh = true;
        this.refreshInterval = 30000; // 30 seconds
        
        this.init();
    }
    
    init() {
        this.initWebSocket();
        this.initEventListeners();
        this.loadInitialData();
        this.startAutoRefresh();
    }
    
    initWebSocket() {
        this.socket = io();
        
        this.socket.on('connect', () => {
            console.log('Connected to WebSocket');
            this.updateConnectionStatus(true);
        });
        
        this.socket.on('disconnect', () => {
            console.log('Disconnected from WebSocket');
            this.updateConnectionStatus(false);
        });
        
        this.socket.on('data_update', (data) => {
            this.handleDataUpdate(data);
        });
        
        this.socket.on('error', (error) => {
            console.error('WebSocket error:', error);
            this.showNotification('WebSocket error: ' + error.message, 'error');
        });
        
        this.socket.on('status', (status) => {
            this.showNotification(status.message, 'info');
        });
    }
    
    initEventListeners() {
        // Theme toggle
        document.getElementById('theme-toggle')?.addEventListener('click', () => {
            this.toggleTheme();
        });
        
        // Auto-refresh toggle
        document.getElementById('auto-refresh-toggle')?.addEventListener('change', (e) => {
            this.autoRefresh = e.target.checked;
            if (this.autoRefresh) {
                this.startAutoRefresh();
            } else {
                this.stopAutoRefresh();
            }
        });
        
        // Manual refresh button
        document.getElementById('refresh-btn')?.addEventListener('click', () => {
            this.loadInitialData();
        });
        
        // Threshold tuning form
        document.getElementById('threshold-form')?.addEventListener('submit', (e) => {
            e.preventDefault();
            this.updateThresholds();
        });
        
        // Whitelist forms
        document.getElementById('process-whitelist-form')?.addEventListener('submit', (e) => {
            e.preventDefault();
            this.manageWhitelist('process');
        });
        
        document.getElementById('directory-whitelist-form')?.addEventListener('submit', (e) => {
            e.preventDefault();
            this.manageWhitelist('directory');
        });
        
        // Export button
        document.getElementById('export-btn')?.addEventListener('click', () => {
            this.exportDataset();
        });
        
        // Severity filter
        document.getElementById('severity-filter')?.addEventListener('change', (e) => {
            this.loadAlerts(e.target.value);
        });
    }
    
    loadInitialData() {
        this.loadEvents();
        this.loadAlerts();
        this.loadMetrics();
        this.loadCharts();
        this.loadConfig();
    }
    
    async loadEvents() {
        try {
            const response = await fetch('/api/events?hours=24&limit=100');
            const data = await response.json();
            
            if (data.success) {
                this.updateEventsTable(data.data);
            } else {
                this.showNotification('Error loading events: ' + data.error, 'error');
            }
        } catch (error) {
            console.error('Error loading events:', error);
            this.showNotification('Error loading events', 'error');
        }
    }
    
    async loadAlerts(severity = null) {
        try {
            let url = '/api/alerts?hours=24';
            if (severity && severity !== 'all') {
                url += `&severity=${severity}`;
            }
            
            const response = await fetch(url);
            const data = await response.json();
            
            if (data.success) {
                this.updateAlertsTable(data.data);
            } else {
                this.showNotification('Error loading alerts: ' + data.error, 'error');
            }
        } catch (error) {
            console.error('Error loading alerts:', error);
            this.showNotification('Error loading alerts', 'error');
        }
    }
    
    async loadMetrics() {
        try {
            const response = await fetch('/api/metrics?hours=24');
            const data = await response.json();
            
            if (data.success) {
                this.updateMetricsDisplay(data.data);
            } else {
                this.showNotification('Error loading metrics: ' + data.error, 'error');
            }
        } catch (error) {
            console.error('Error loading metrics:', error);
            this.showNotification('Error loading metrics', 'error');
        }
    }
    
    async loadCharts() {
        await this.loadEntropyTrendChart();
        await this.loadBurstHeatmap();
    }
    
    async loadEntropyTrendChart() {
        try {
            const response = await fetch('/api/charts/entropy-trend?hours=24');
            const data = await response.json();
            
            if (data.success && data.chart) {
                Plotly.newPlot('entropy-trend-chart', data.chart.data, data.chart.layout, {
                    responsive: true,
                    displayModeBar: true
                });
                this.charts.entropyTrend = data.chart;
            }
        } catch (error) {
            console.error('Error loading entropy trend chart:', error);
        }
    }
    
    async loadBurstHeatmap() {
        try {
            const response = await fetch('/api/charts/burst-heatmap?hours=24');
            const data = await response.json();
            
            if (data.success && data.chart) {
                Plotly.newPlot('burst-heatmap-chart', data.chart.data, data.chart.layout, {
                    responsive: true,
                    displayModeBar: true
                });
                this.charts.burstHeatmap = data.chart;
            }
        } catch (error) {
            console.error('Error loading burst heatmap:', error);
        }
    }
    
    async loadConfig() {
        try {
            const response = await fetch('/api/config');
            const data = await response.json();
            
            if (data.success) {
                this.updateConfigForm(data.config);
            }
        } catch (error) {
            console.error('Error loading config:', error);
        }
    }
    
    updateEventsTable(events) {
        const tbody = document.querySelector('#events-table tbody');
        if (!tbody) return;
        
        tbody.innerHTML = '';
        
        events.forEach(event => {
            const row = document.createElement('tr');
            row.className = 'hover:bg-gray-50 dark:hover:bg-gray-700';
            
            row.innerHTML = `
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-gray-100">
                    ${this.truncatePath(event.path || 'N/A')}
                </td>
                <td class="px-6 py-4 whitespace-nowrap">
                    <span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full 
                           ${this.getEventTypeClass(event.event_type)}">
                        ${event.event_type || 'N/A'}
                    </span>
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-gray-100">
                    ${event.formatted_time || 'N/A'}
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-gray-100">
                    ${event.process_name || 'N/A'}
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-gray-100">
                    ${this.formatFileSize(event.size)}
                </td>
            `;
            
            tbody.appendChild(row);
        });
    }
    
    updateAlertsTable(alerts) {
        const tbody = document.querySelector('#alerts-table tbody');
        if (!tbody) return;
        
        tbody.innerHTML = '';
        
        alerts.forEach(alert => {
            const row = document.createElement('tr');
            row.className = 'hover:bg-gray-50 dark:hover:bg-gray-700';
            
            row.innerHTML = `
                <td class="px-6 py-4 whitespace-nowrap">
                    <span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full 
                           ${this.getSeverityClass(alert.severity)}">
                        ${alert.severity || 'N/A'}
                    </span>
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-gray-100">
                    ${alert.alert_type || 'N/A'}
                </td>
                <td class="px-6 py-4 text-sm text-gray-900 dark:text-gray-100">
                    ${alert.message || 'N/A'}
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-gray-100">
                    ${alert.formatted_time || 'N/A'}
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-gray-100">
                    ${alert.action_taken || 'None'}
                </td>
            `;
            
            tbody.appendChild(row);
        });
    }
    
    updateMetricsDisplay(metrics) {
        // Update metric cards
        document.getElementById('total-events')?.textContent = metrics.total_events || 0;
        document.getElementById('total-alerts')?.textContent = metrics.total_alerts || 0;
        
        // Update event types breakdown
        const eventTypesContainer = document.getElementById('event-types');
        if (eventTypesContainer && metrics.event_types) {
            eventTypesContainer.innerHTML = '';
            Object.entries(metrics.event_types).forEach(([type, count]) => {
                const item = document.createElement('div');
                item.className = 'flex justify-between';
                item.innerHTML = `
                    <span class="text-gray-600 dark:text-gray-400">${type}:</span>
                    <span class="font-semibold">${count}</span>
                `;
                eventTypesContainer.appendChild(item);
            });
        }
        
        // Update top processes
        const processesContainer = document.getElementById('top-processes');
        if (processesContainer && metrics.top_processes) {
            processesContainer.innerHTML = '';
            Object.entries(metrics.top_processes).forEach(([process, count]) => {
                const item = document.createElement('div');
                item.className = 'flex justify-between';
                item.innerHTML = `
                    <span class="text-gray-600 dark:text-gray-400">${process}:</span>
                    <span class="font-semibold">${count}</span>
                `;
                processesContainer.appendChild(item);
            });
        }
    }
    
    updateConfigForm(config) {
        document.getElementById('entropy-threshold')?.setAttribute('value', config.entropy_threshold || 7.0);
        document.getElementById('variance-threshold')?.setAttribute('value', config.variance_threshold || 0.5);
        document.getElementById('chi-square-threshold')?.setAttribute('value', config.chi_square_threshold || 1000);
        document.getElementById('burst-multiplier')?.setAttribute('value', config.burst_multiplier || 3.0);
        document.getElementById('baseline-days')?.setAttribute('value', config.baseline_days || 7);
    }
    
    async updateThresholds() {
        try {
            const formData = new FormData(document.getElementById('threshold-form'));
            const data = Object.fromEntries(formData.entries());
            
            const response = await fetch('/api/tune', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(data)
            });
            
            const result = await response.json();
            
            if (result.success) {
                this.showNotification('Thresholds updated successfully', 'success');
            } else {
                this.showNotification('Error updating thresholds: ' + result.error, 'error');
            }
        } catch (error) {
            console.error('Error updating thresholds:', error);
            this.showNotification('Error updating thresholds', 'error');
        }
    }
    
    async manageWhitelist(type) {
        try {
            const form = document.getElementById(`${type}-whitelist-form`);
            const formData = new FormData(form);
            
            const data = {
                action: formData.get('action'),
                type: type,
                value: formData.get('value')
            };
            
            const response = await fetch('/api/whitelist', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(data)
            });
            
            const result = await response.json();
            
            if (result.success) {
                this.showNotification(result.message, 'success');
                form.reset();
            } else {
                this.showNotification('Error managing whitelist: ' + result.error, 'error');
            }
        } catch (error) {
            console.error('Error managing whitelist:', error);
            this.showNotification('Error managing whitelist', 'error');
        }
    }
    
    async exportDataset() {
        try {
            const response = await fetch('/api/export');
            
            if (response.ok) {
                const blob = await response.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `fme_abt_dataset_${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.csv`;
                document.body.appendChild(a);
                a.click();
                window.URL.revokeObjectURL(url);
                document.body.removeChild(a);
                
                this.showNotification('Dataset exported successfully', 'success');
            } else {
                this.showNotification('Error exporting dataset', 'error');
            }
        } catch (error) {
            console.error('Error exporting dataset:', error);
            this.showNotification('Error exporting dataset', 'error');
        }
    }
    
    handleDataUpdate(data) {
        if (data.events) {
            this.updateEventsTable(data.events);
        }
        if (data.alerts) {
            this.updateAlertsTable(data.alerts);
        }
        if (data.metrics) {
            this.updateMetricsDisplay(data.metrics);
        }
        
        // Update last refresh time
        document.getElementById('last-refresh')?.textContent = 
            new Date().toLocaleTimeString();
    }
    
    startAutoRefresh() {
        if (this.refreshTimer) {
            clearInterval(this.refreshTimer);
        }
        
        this.refreshTimer = setInterval(() => {
            if (this.autoRefresh) {
                this.socket.emit('request_update');
            }
        }, this.refreshInterval);
    }
    
    stopAutoRefresh() {
        if (this.refreshTimer) {
            clearInterval(this.refreshTimer);
            this.refreshTimer = null;
        }
    }
    
    toggleTheme() {
        this.darkMode = !this.darkMode;
        document.documentElement.classList.toggle('dark', this.darkMode);
        
        // Update charts for theme
        if (this.charts.entropyTrend) {
            this.updateChartTheme('entropy-trend-chart', this.charts.entropyTrend);
        }
        if (this.charts.burstHeatmap) {
            this.updateChartTheme('burst-heatmap-chart', this.charts.burstHeatmap);
        }
    }
    
    updateChartTheme(elementId, chartData) {
        const template = this.darkMode ? 'plotly_dark' : 'plotly_white';
        const layout = { ...chartData.layout, template: template };
        Plotly.relayout(elementId, layout);
    }
    
    updateConnectionStatus(connected) {
        const indicator = document.getElementById('connection-status');
        if (indicator) {
            indicator.className = connected 
                ? 'h-3 w-3 bg-green-400 rounded-full'
                : 'h-3 w-3 bg-red-400 rounded-full';
        }
    }
    
    showNotification(message, type = 'info') {
        // Simple notification system
        const notification = document.createElement('div');
        notification.className = `fixed top-4 right-4 p-4 rounded-md shadow-lg z-50 ${this.getNotificationClass(type)}`;
        notification.textContent = message;
        
        document.body.appendChild(notification);
        
        setTimeout(() => {
            notification.remove();
        }, 5000);
    }
    
    getNotificationClass(type) {
        const classes = {
            'success': 'bg-green-500 text-white',
            'error': 'bg-red-500 text-white',
            'warning': 'bg-yellow-500 text-white',
            'info': 'bg-blue-500 text-white'
        };
        return classes[type] || classes.info;
    }
    
    getEventTypeClass(eventType) {
        const classes = {
            'created': 'bg-green-100 text-green-800',
            'modified': 'bg-yellow-100 text-yellow-800',
            'deleted': 'bg-red-100 text-red-800'
        };
        return classes[eventType] || 'bg-gray-100 text-gray-800';
    }
    
    getSeverityClass(severity) {
        const classes = {
            'low': 'bg-blue-100 text-blue-800',
            'medium': 'bg-yellow-100 text-yellow-800',
            'high': 'bg-orange-100 text-orange-800',
            'critical': 'bg-red-100 text-red-800'
        };
        return classes[severity] || 'bg-gray-100 text-gray-800';
    }
    
    truncatePath(path, maxLength = 50) {
        if (path.length <= maxLength) return path;
        return '...' + path.slice(-(maxLength - 3));
    }
    
    formatFileSize(bytes) {
        if (!bytes) return 'N/A';
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(1024));
        return Math.round(bytes / Math.pow(1024, i) * 100) / 100 + ' ' + sizes[i];
    }
}

// Initialize dashboard when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.dashboard = new FMEABTDashboard();
});
