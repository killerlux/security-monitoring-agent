// Utility functions
function humanBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

function setBadge(elementId, text, type = 'neutral') {
    const element = document.getElementById(elementId);
    if (!element) return;
    
    element.textContent = text;
    element.className = element.className.replace(/bg-\w+-\d+|text-\w+-\d+/g, '');
    
    switch (type) {
        case 'success':
            element.classList.add('bg-green-100', 'text-green-800', 'dark:bg-green-900', 'dark:text-green-200');
            break;
        case 'warning':
            element.classList.add('bg-yellow-100', 'text-yellow-800', 'dark:bg-yellow-900', 'dark:text-yellow-200');
            break;
        case 'error':
            element.classList.add('bg-red-100', 'text-red-800', 'dark:bg-red-900', 'dark:text-red-200');
            break;
        default:
            element.classList.add('bg-neutral-100', 'text-neutral-800', 'dark:bg-neutral-700', 'dark:text-neutral-200');
    }
}

function showToast(message, type = 'success') {
    const toast = document.getElementById('toast');
    const messageEl = document.getElementById('toast-message');
    
    messageEl.textContent = message;
    toast.classList.add('show');
    
    setTimeout(() => {
        toast.classList.remove('show');
    }, 3000);
}

function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// Dark Mode Toggle
const darkModeBtn = document.getElementById('dark-mode-btn');
const toggleDarkMode = () => {
    if (document.documentElement.classList.contains('dark')) {
        document.documentElement.classList.remove('dark');
        localStorage.setItem('theme', 'light');
    } else {
        document.documentElement.classList.add('dark');
        localStorage.setItem('theme', 'dark');
    }
};
darkModeBtn.addEventListener('click', toggleDarkMode);

// Initial theme setup
if (localStorage.getItem('theme') === 'dark' || (!localStorage.getItem('theme') && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
    document.documentElement.classList.add('dark');
}

// Chart instances
let cpuChart;

// Initialize Charts
const initCharts = () => {
    const cpuCtx = document.getElementById('cpu-chart').getContext('2d');
    cpuChart = new Chart(cpuCtx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'CPU Load (1m)',
                data: [],
                borderColor: 'rgb(75, 192, 192)',
                tension: 0.1,
                fill: false
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: { type: 'time', time: { unit: 'minute' } },
                y: { beginAtZero: true }
            }
        }
    });
};

// Update Charts
const updateCharts = (historyData) => {
    if (!cpuChart) return;
    
    const cpuLabels = [];
    const cpuLoads = [];
    
    historyData.forEach(item => {
        cpuLabels.push(new Date(item.ts));
        cpuLoads.push(item.cpu.load1);
    });
    
    cpuChart.data.labels = cpuLabels;
    cpuChart.data.datasets[0].data = cpuLoads;
    cpuChart.update();
};

// Update KPIs
const updateKPIs = (data) => {
    // CPU
    const cpuLoad = data.cpu.load1;
    const cpuProgress = document.getElementById('cpu-progress');
    const cpuLoadEl = document.getElementById('cpu-load');
    const cpuUsageEl = document.getElementById('cpu-usage');
    
    if (cpuProgress) {
        const percentage = Math.min(cpuLoad / 4, 1); // Assume 4.0 is 100%
        const circumference = 2 * Math.PI * 24;
        cpuProgress.style.strokeDasharray = `${circumference * percentage} ${circumference}`;
    }
    
    if (cpuLoadEl) {
        cpuLoadEl.textContent = cpuLoad.toFixed(2);
        cpuLoadEl.className = cpuLoadEl.className.replace(/skeleton|h-\d+|w-\d+/g, '');
        cpuLoadEl.classList.add('font-mono', 'text-lg', 'font-semibold');
    }
    
    if (cpuUsageEl) {
        cpuUsageEl.textContent = `Load 1m (${cpuLoad < 1 ? 'OK' : cpuLoad < 2 ? 'WARN' : 'HIGH'})`;
    }

    // RAM
    const ramUsed = data.mem.used_mb;
    const ramTotal = data.mem.total_mb;
    const ramPercentage = ramUsed / ramTotal;
    const ramProgress = document.getElementById('ram-progress');
    const ramUsageEl = document.getElementById('ram-usage');
    const ramTotalEl = document.getElementById('ram-total');
    
    if (ramProgress) {
        const circumference = 2 * Math.PI * 24;
        ramProgress.style.strokeDasharray = `${circumference * ramPercentage} ${circumference}`;
    }
    
    if (ramUsageEl) {
        ramUsageEl.textContent = `${humanBytes(ramUsed * 1024 * 1024)} / ${humanBytes(ramTotal * 1024 * 1024)}`;
        ramUsageEl.className = ramUsageEl.className.replace(/skeleton|h-\d+|w-\d+/g, '');
        ramUsageEl.classList.add('font-mono', 'text-sm');
    }
    
    if (ramTotalEl) {
        ramTotalEl.textContent = `Used / Total (${(ramPercentage * 100).toFixed(0)}%)`;
    }

    // Disk
    const diskUsage = data.disk[0]?.used_pct || 0;
    const diskProgress = document.getElementById('disk-progress');
    const diskUsageEl = document.getElementById('disk-usage');
    const diskMountEl = document.getElementById('disk-mount');
    
    if (diskProgress) {
        const circumference = 2 * Math.PI * 24;
        diskProgress.style.strokeDasharray = `${circumference * diskUsage / 100} ${circumference}`;
    }
    
    if (diskUsageEl) {
        diskUsageEl.textContent = `${diskUsage.toFixed(1)}%`;
        diskUsageEl.className = diskUsageEl.className.replace(/skeleton|h-\d+|w-\d+/g, '');
        diskUsageEl.classList.add('font-mono', 'text-lg', 'font-semibold');
    }
    
    if (diskMountEl) {
        diskMountEl.textContent = `Root (/) (${diskUsage < 80 ? 'OK' : diskUsage < 90 ? 'WARN' : 'HIGH'})`;
    }

    // Network
    const defaultIface = data.net.default_iface || 'N/A';
    const networkInterfaceEl = document.getElementById('network-interface');
    const networkTrafficEl = document.getElementById('network-traffic');
    
    if (networkInterfaceEl) {
        networkInterfaceEl.textContent = defaultIface;
        networkInterfaceEl.className = networkInterfaceEl.className.replace(/skeleton|h-\d+|w-\d+/g, '');
        networkInterfaceEl.classList.add('font-mono', 'text-sm');
    }
    
    if (networkTrafficEl) {
        networkTrafficEl.textContent = 'Default Interface';
    }
};

// Render Alerts
const renderAlerts = (alerts) => {
    const alertsList = document.getElementById('alerts-list');
    const alertsCount = document.getElementById('alerts-count');
    
    if (!alertsList || !alertsCount) return;
    
    alertsCount.textContent = alerts.length;
    
    if (alerts.length === 0) {
        alertsList.innerHTML = `
            <div class="text-center py-8 text-neutral-500 dark:text-neutral-400">
                <svg class="w-12 h-12 mx-auto mb-2 opacity-50" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                </svg>
                <p>Aucune alerte active</p>
            </div>
        `;
        return;
    }
    
    alertsList.innerHTML = alerts.map(alert => {
        const severityColors = {
            'info': 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200',
            'warn': 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200',
            'high': 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200'
        };
        
        return `
            <div class="flex items-center justify-between p-3 bg-neutral-50 dark:bg-neutral-700 rounded-lg">
                <div class="flex items-center space-x-3">
                    <span class="px-2 py-1 text-xs rounded-full ${severityColors[alert.severity] || severityColors.info}">
                        ${alert.severity.toUpperCase()}
                    </span>
                    <span class="font-mono text-sm">${alert.code}</span>
                </div>
            </div>
        `;
    }).join('');
};

// Render Ports
const renderPorts = (ports) => {
    const portsTable = document.getElementById('ports-table');
    if (!portsTable) return;
    
    if (!ports || ports.length === 0) {
        portsTable.innerHTML = `
            <tr>
                <td colspan="3" class="text-center py-4 text-neutral-500 dark:text-neutral-400">
                    Aucun port ouvert détecté
                </td>
            </tr>
        `;
        return;
    }
    
    portsTable.innerHTML = ports.map(port => `
        <tr class="border-b border-neutral-200 dark:border-neutral-700">
            <td class="py-2 font-mono">${port.port}</td>
            <td class="py-2">
                <span class="px-2 py-1 text-xs rounded ${port.proto === 'tcp' ? 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200' : 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200'}">
                    ${port.proto.toUpperCase()}
                </span>
            </td>
            <td class="py-2 font-mono text-sm">${port.proc || 'N/A'}</td>
        </tr>
    `).join('');
};

// Filter Ports
const filterPorts = () => {
    const searchTerm = document.getElementById('ports-search').value.toLowerCase();
    const rows = document.querySelectorAll('#ports-table tr');
    
    rows.forEach(row => {
        const text = row.textContent.toLowerCase();
        row.style.display = text.includes(searchTerm) ? '' : 'none';
    });
};

// Render Interfaces
const renderInterfaces = (interfaces) => {
    const interfacesList = document.getElementById('interfaces-list');
    if (!interfacesList) return;
    
    if (!interfaces || interfaces.length === 0) {
        interfacesList.innerHTML = `
            <div class="text-center py-4 text-neutral-500 dark:text-neutral-400">
                <p class="text-sm">Aucune interface détectée</p>
            </div>
        `;
        return;
    }
    
    interfacesList.innerHTML = interfaces.map(iface => {
        const stateColors = {
            'up': 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200',
            'down': 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200',
            'unknown': 'bg-gray-100 text-gray-800 dark:bg-gray-900 dark:text-gray-200'
        };
        
        return `
            <div class="flex items-center justify-between p-3 bg-neutral-50 dark:bg-neutral-700 rounded-lg">
                <div class="flex items-center space-x-3">
                    <span class="font-mono text-sm">${iface.name}</span>
                    <span class="px-2 py-1 text-xs rounded-full ${stateColors[iface.state] || stateColors.unknown}">
                        ${iface.state.toUpperCase()}
                    </span>
                </div>
                <div class="text-xs text-neutral-500 dark:text-neutral-400">
                    RX: ${humanBytes(iface.rx_delta || 0)} | TX: ${humanBytes(iface.tx_delta || 0)}
                </div>
            </div>
        `;
    }).join('');
};

// Render USB Events
const renderUSBEvents = (events) => {
    const usbEventsList = document.getElementById('usb-events-list');
    if (!usbEventsList) return;
    
    if (!events || events.length === 0) {
        usbEventsList.innerHTML = `
            <div class="text-center py-4 text-neutral-500 dark:text-neutral-400">
                <svg class="w-8 h-8 mx-auto mb-2 opacity-50" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6v6m0 0v6m0-6h6m-6 0H6"></path>
                </svg>
                <p class="text-sm">Aucun événement USB récent</p>
            </div>
        `;
        return;
    }
    
    usbEventsList.innerHTML = events.slice(0, 5).map(event => `
        <div class="p-3 bg-neutral-50 dark:bg-neutral-700 rounded-lg">
            <div class="flex items-center justify-between mb-1">
                <span class="font-mono text-sm">${event.device}</span>
                <span class="px-2 py-1 text-xs rounded-full ${event.action === 'add' ? 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200' : 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200'}">
                    ${event.action.toUpperCase()}
                </span>
            </div>
            <div class="text-xs text-neutral-500 dark:text-neutral-400">
                ${event.vendor_id}:${event.product_id} - ${event.class_name}
            </div>
        </div>
    `).join('');
};

// Main refresh function
async function refresh() {
    const host = document.getElementById('host-select').value;
    if (!host) return;
    
    try {
        // Show loading states
        const loadingElements = document.querySelectorAll('.skeleton');
        loadingElements.forEach(el => el.style.display = 'block');
        
        // Fetch latest data
        const latestResponse = await fetch(`/api/latest?host=${host}`);
        if (!latestResponse.ok) throw new Error(`HTTP ${latestResponse.status}`);
        const latestData = await latestResponse.json();
        
        // Update header
        document.title = `Security Monitor - ${latestData.host}`;
        
        // Update status badge
        const alertCount = latestData.alerts?.length || 0;
        if (alertCount === 0) {
            setBadge('status-badge', '● OK', 'success');
        } else if (alertCount < 3) {
            setBadge('status-badge', '⚠ WARN', 'warning');
        } else {
            setBadge('status-badge', '🚨 HIGH', 'error');
        }
        
        // Update KPIs
        updateKPIs(latestData);
        
        // Update sections
        renderAlerts(latestData.alerts || []);
        renderPorts(latestData.net?.open_ports || []);
        renderInterfaces(latestData.net?.ifaces || []);
        
        // Hide loading states
        loadingElements.forEach(el => el.style.display = 'none');
        
        // Fetch history for charts
        const historyResponse = await fetch(`/api/history?host=${host}&from=${new Date(Date.now() - 60 * 60 * 1000).toISOString()}`);
        if (historyResponse.ok) {
            const historyData = await historyResponse.json();
            updateCharts(historyData);
        }
        
        showToast('Données mises à jour');
        
    } catch (error) {
        console.error('Error refreshing data:', error);
        showToast('Erreur lors de la mise à jour', 'error');
        
        // Hide loading states on error
        const loadingElements = document.querySelectorAll('.skeleton');
        loadingElements.forEach(el => el.style.display = 'none');
    }
}

// Trigger Scan Function
async function triggerScan() {
    const scanBtn = document.getElementById('trigger-scan-btn');
    const scanBtnText = document.getElementById('scan-btn-text');
    
    if (scanBtn.disabled) return; // Prevent multiple clicks
    
    try {
        // Update button state
        scanBtn.disabled = true;
        scanBtn.classList.remove('bg-blue-600', 'hover:bg-blue-700');
        scanBtn.classList.add('bg-blue-400', 'cursor-not-allowed');
        scanBtnText.textContent = 'Scan en cours...';
        
        // Show loading indicator
        const icon = scanBtn.querySelector('svg');
        icon.innerHTML = '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path>';
        icon.classList.add('animate-spin');
        
        // Trigger the scan
        const response = await fetch('/api/trigger-scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        });
        
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }
        
        const result = await response.json();
        showToast('Scan de sécurité lancé !', 'success');
        
        // Wait a bit then check for completion
        setTimeout(async () => {
            await checkScanCompletion();
        }, 2000);
        
    } catch (error) {
        console.error('Error triggering scan:', error);
        showToast('Erreur lors du lancement du scan', 'error');
        
        // Reset button state
        resetScanButton();
    }
}

async function checkScanCompletion() {
    const scanBtn = document.getElementById('trigger-scan-btn');
    const scanBtnText = document.getElementById('scan-btn-text');
    
    try {
        // Check scan status
        const response = await fetch('/api/scan-status');
        if (response.ok) {
            const status = await response.json();
            
            if (status.status === 'completed') {
                showToast('Scan terminé avec succès !', 'success');
                resetScanButton();
                
                // Refresh data after scan completion
                setTimeout(refresh, 1000);
            } else {
                // Check again in 2 seconds
                setTimeout(checkScanCompletion, 2000);
            }
        } else {
            // Reset button after timeout
            setTimeout(resetScanButton, 5000);
        }
    } catch (error) {
        console.error('Error checking scan status:', error);
        setTimeout(resetScanButton, 5000);
    }
}

function resetScanButton() {
    const scanBtn = document.getElementById('trigger-scan-btn');
    const scanBtnText = document.getElementById('scan-btn-text');
    
    scanBtn.disabled = false;
    scanBtn.classList.remove('bg-blue-400', 'cursor-not-allowed');
    scanBtn.classList.add('bg-blue-600', 'hover:bg-blue-700');
    scanBtnText.textContent = 'Scanner';
    
    const icon = scanBtn.querySelector('svg');
    icon.innerHTML = '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>';
    icon.classList.remove('animate-spin');
}

// Event Listeners
document.getElementById('refresh-btn').addEventListener('click', debounce(refresh, 300));
document.getElementById('trigger-scan-btn').addEventListener('click', debounce(triggerScan, 300));
document.getElementById('host-select').addEventListener('change', refresh);
document.getElementById('ports-search').addEventListener('input', debounce(filterPorts, 300));

// Initialize
window.addEventListener('load', () => {
    initCharts();
    refresh();
    
    // Auto-refresh every 30 seconds
    setInterval(refresh, 30000);
});
