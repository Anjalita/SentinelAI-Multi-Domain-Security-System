from datetime import datetime
import os
import json

ALERT_DIR = "alerts"
ALERT_FILE = os.path.join(ALERT_DIR, "alerts.log")
ALERT_JSON = os.path.join(ALERT_DIR, "alerts.json")  # For dashboard

# Create alerts folder
os.makedirs(ALERT_DIR, exist_ok=True)

SEVERITY_MAP = {
    "SQL": "CRITICAL",
    "XSS": "HIGH",
    "TRAVERSAL": "MEDIUM",
    "CMDINJ": "CRITICAL",
    "SSTI": "CRITICAL",
    "MALWARE": "CRITICAL",
    "IP_BLOCKED": "HIGH",
    "BLOCKED_IP_ATTEMPT": "MEDIUM",
    "SUCCESSFUL_LOGIN": "INFO"
}

def log_alert(module, attack_type, payload, confidence, client_ip="Unknown"):
    """Enhanced logging with IP tracking"""
    
    # Don't log benign web requests (too noisy)
    if attack_type == "BENIGN" and module == "WEB":
        return
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    severity = SEVERITY_MAP.get(attack_type, "MEDIUM")
    
    # Format for log file
    log_entry = (
        f"{timestamp} | {module} | {attack_type} | "
        f"{severity} | {confidence:.2f} | {payload} | {client_ip}\n"
    )
    
    # Format for JSON (dashboard)
    json_entry = {
        "timestamp": timestamp,
        "module": module,
        "attack_type": attack_type,
        "severity": severity,
        "confidence": float(f"{confidence:.2f}"),
        "payload": payload,
        "ip": client_ip
    }
    
    # Write to log file
    with open(ALERT_FILE, "a", encoding="utf-8") as f:
        f.write(log_entry)
    
    # Update JSON file (append)
    try:
        if os.path.exists(ALERT_JSON):
            with open(ALERT_JSON, "r", encoding="utf-8") as f:
                data = json.load(f)
        else:
            data = {"alerts": []}
        
        data["alerts"].append(json_entry)
        # Keep only last 1000 alerts
        if len(data["alerts"]) > 1000:
            data["alerts"] = data["alerts"][-1000:]
        
        with open(ALERT_JSON, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        print(f"⚠️ JSON logging failed: {e}")
    
    # Console output for important alerts
    if severity in ["CRITICAL", "HIGH"]:
        print(f"🚨 {timestamp} | {client_ip} | {attack_type} | {payload[:50]}...")
