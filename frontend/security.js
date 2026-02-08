// Security Dashboard JavaScript

// Configuration
const SENTINEL_API_URL = "http://localhost:8000/api";

// Load alerts on page load
document.addEventListener('DOMContentLoaded', function() {
  loadAlerts();
  loadStats();
  setInterval(loadAlerts, 5000); // Refresh every 5 seconds
});

// Load alerts from SentinelAI
async function loadAlerts() {
  try {
    const response = await fetch(`${SENTINEL_API_URL}/alerts?limit=50`);
    const data = await response.json();
    
    updateDashboard(data.alerts);
    updateStats(data.alerts);
    
  } catch (error) {
    console.error("Failed to load alerts:", error);
    document.getElementById('alertLog').innerHTML = 
      '<div class="alert-item">❌ Failed to load alerts. Make sure SentinelAI is running.</div>';
  }
}

// Update dashboard with alerts
function updateDashboard(alerts) {
  const alertLog = document.getElementById('alertLog');
  const criticalList = document.getElementById('criticalList');
  const highList = document.getElementById('highList');
  const mediumList = document.getElementById('mediumList');
  const lowList = document.getElementById('lowList');
  
  // Clear lists
  criticalList.innerHTML = '';
  highList.innerHTML = '';
  mediumList.innerHTML = '';
  lowList.innerHTML = '';
  
  // Categorize alerts by severity
  let criticalAlerts = [];
  let highAlerts = [];
  let mediumAlerts = [];
  let lowAlerts = [];
  
  // Process alerts
  alertLog.innerHTML = '';
  
  alerts.forEach(alert => {
    const severity = alert.severity || 'medium';
    const threatClass = getThreatClass(severity);
    
    // Add to alert log
    const alertItem = document.createElement('div');
    alertItem.className = `alert-item ${threatClass}`;
    alertItem.innerHTML = `
      <strong>${alert.attack_type || 'Unknown'}</strong>
      <br>
      ${alert.payload || ''}
      <br>
      <span class="timestamp">${alert.timestamp}</span>
      <span class="ip-address"> • IP: ${alert.ip || 'Unknown'}</span>
      <span class="confidence"> • Confidence: ${alert.confidence || 'N/A'}</span>
    `;
    alertLog.prepend(alertItem);
    
    // Categorize
    if (severity.toLowerCase() === 'critical') {
      criticalAlerts.push(alert);
    } else if (severity.toLowerCase() === 'high') {
      highAlerts.push(alert);
    } else if (severity.toLowerCase() === 'medium') {
      mediumAlerts.push(alert);
    } else {
      lowAlerts.push(alert);
    }
  });
  
  // Update category lists
  updateCategoryList(criticalList, criticalAlerts, 'critical');
  updateCategoryList(highList, highAlerts, 'high');
  updateCategoryList(mediumList, mediumAlerts, 'medium');
  updateCategoryList(lowList, lowAlerts, 'low');
  
  // Show message if no alerts
  if (alerts.length === 0) {
    alertLog.innerHTML = '<div class="alert-item">No attacks detected yet.</div>';
  }
}

// Update category list
function updateCategoryList(element, alerts, type) {
  if (alerts.length === 0) {
    element.innerHTML = `No ${type} threats detected`;
    return;
  }
  
  let html = '';
  alerts.slice(0, 5).forEach(alert => {
    const time = new Date(alert.timestamp).toLocaleTimeString();
    html += `
      <div style="margin: 5px 0; padding: 5px; background: rgba(255,255,255,0.05); border-radius: 3px;">
        <strong>${alert.attack_type}</strong><br>
        <small>${time} • ${alert.ip || 'Unknown IP'}</small>
      </div>
    `;
  });
  
  if (alerts.length > 5) {
    html += `<small>...and ${alerts.length - 5} more</small>`;
  }
  
  element.innerHTML = html;
}

// Update statistics
function updateStats(alerts) {
  const today = new Date().toDateString();
  const todayAlerts = alerts.filter(alert => {
    const alertDate = new Date(alert.timestamp).toDateString();
    return alertDate === today;
  });
  
  // Count by severity
  let critical = 0, high = 0, medium = 0, low = 0;
  alerts.forEach(alert => {
    const severity = (alert.severity || 'medium').toLowerCase();
    if (severity === 'critical') critical++;
    else if (severity === 'high') high++;
    else if (severity === 'medium') medium++;
    else low++;
  });
  
  // Load from localStorage for additional stats
  const todayStats = JSON.parse(localStorage.getItem(`sentinel_attacks_${today}`)) || { total: 0 };
  const globalStats = JSON.parse(localStorage.getItem('sentinel_global_stats')) || { total: 0 };
  
  // Update display
  document.getElementById('totalAttacks').textContent = globalStats.total;
  document.getElementById('todayAttacks').textContent = todayStats.total;
  document.getElementById('activeThreats').textContent = critical + high;
  
  // Load blocked IPs
  loadBlockedIPs();
}

// Load blocked IPs
async function loadBlockedIPs() {
  try {
    const response = await fetch(`${SENTINEL_API_URL}/blocked-ips`);
    const data = await response.json();
    document.getElementById('blockedIPs').textContent = data.blocked_ips?.length || 0;
  } catch (error) {
    console.error("Failed to load blocked IPs:", error);
  }
}

// Clear alerts
async function clearAlerts() {
  if (confirm("Are you sure you want to clear all alert logs?")) {
    try {
      const response = await fetch(`${SENTINEL_API_URL}/clear-alerts`, {
        method: 'POST'
      });
      const data = await response.json();
      alert(data.message || "Alerts cleared");
      loadAlerts();
    } catch (error) {
      alert("Failed to clear alerts: " + error);
    }
  }
}

// Show blocked IPs
async function showBlockedIPs() {
  try {
    const response = await fetch(`${SENTINEL_API_URL}/blocked-ips`);
    const data = await response.json();
    
    let message = "Blocked IPs:\n\n";
    data.blocked_ips?.forEach(ip => {
      const time = new Date(ip.blocked_until * 1000).toLocaleString();
      message += `• ${ip.ip} (until: ${time})\n`;
    });
    
    if (data.blocked_ips?.length === 0) {
      message = "No IPs are currently blocked.";
    }
    
    alert(message);
  } catch (error) {
    alert("Failed to load blocked IPs: " + error);
  }
}

// Get threat class
function getThreatClass(severity) {
  severity = severity.toLowerCase();
  if (severity === 'critical') return 'critical';
  if (severity === 'high') return 'high';
  if (severity === 'medium') return 'medium';
  return 'low';
}
