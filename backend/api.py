from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel
import joblib
import numpy as np
from alert_logger import log_alert
from fastapi.middleware.cors import CORSMiddleware
import time
import os

app = FastAPI(title="SentinelAI: Multi-Domain Security System")

# Allow frontend → backend calls
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# --------------------
# Rate limiting storage
# --------------------
RATE_LIMIT = {}
FAILED_ATTEMPTS = {}
blocked_ips = {}

# --------------------
# Load ML models once
# --------------------
print("🔧 Loading ML models...")

# Initialize variables
vectorizer = None
web_model = None
ids_model = None
android_model = None
ids_expected_features = 78  # Default, will update

try:
    vectorizer = joblib.load("models/web_tfidf_vectorizer.pkl")
    web_model = joblib.load("models/web_attack_classifier.pkl")
    print("✅ Web attack model loaded")
except Exception as e:
    print(f"❌ Failed to load web models: {e}")

try:
    ids_model = joblib.load("models/ids_random_forest.pkl")
    print("✅ Network IDS model loaded")
    
    # Get expected features
    if hasattr(ids_model, 'n_features_in_'):
        ids_expected_features = ids_model.n_features_in_
        print(f"   Expected features: {ids_expected_features}")
    
    if hasattr(ids_model, 'classes_'):
        print(f"   Classes: {ids_model.classes_}")
        
except Exception as e:
    print(f"⚠️ Network IDS model not loaded: {e}")

try:
    android_model = joblib.load("models/android_random_forest.pkl")
    print("✅ Android malware model loaded")
except Exception as e:
    print(f"⚠️ Android malware model not loaded: {e}")

# --------------------
# Request models
# --------------------
class WebRequest(BaseModel):
    payload: str

class LoginRequest(BaseModel):
    username: str
    password: str

class NetworkRequest(BaseModel):
    # Extended features for IDS (78 features)
    features: list

class AndroidRequest(BaseModel):
    permissions: list

# --------------------
# HELPER FUNCTIONS
# --------------------
def get_threat_level(detected_attack, confidence):
    """Determine threat level based on attack type and confidence"""
    critical_attacks = ["SQL", "XSS", "COMMAND", "FTP-BruteForce", "SSH-Bruteforce", "MALWARE"]
    high_attacks = ["SQL", "XSS", "LDAP"]
    medium_attacks = ["TRAVERSAL", "CMS", "RFI"]
    
    if detected_attack in critical_attacks and confidence > 0.8:
        return "critical"
    elif detected_attack in high_attacks and confidence > 0.6:
        return "high"
    elif detected_attack in medium_attacks:
        return "medium"
    else:
        return "low"

def rule_based_detection(text):
    """Simple rule-based detection as fallback"""
    text_lower = text.lower()
    
    rules = [
        ("or '1'='1'", "SQL"),
        ("' or '1'='1", "SQL"),
        ("1=1", "SQL"),
        ("union select", "SQL"),
        ("<script>", "XSS"),
        ("javascript:", "XSS"),
        ("alert(", "XSS"),
        ("../", "TRAVERSAL"),
        ("/etc/passwd", "TRAVERSAL"),
        (";", "CMDINJ"),
        ("&&", "CMDINJ"),
        ("|", "CMDINJ")
    ]
    
    for pattern, attack_type in rules:
        if pattern in text_lower:
            return attack_type, 0.95
    
    return "BENIGN", 0.0

def prepare_ids_features(input_features):
    """Prepare features for IDS model (pad or truncate to expected size)"""
    if not isinstance(input_features, list):
        return np.zeros((1, ids_expected_features))
    
    features_array = np.array(input_features, dtype=float)
    
    if len(features_array) < ids_expected_features:
        # Pad with zeros
        padding = ids_expected_features - len(features_array)
        features_array = np.pad(features_array, (0, padding), mode='constant')
    elif len(features_array) > ids_expected_features:
        # Truncate
        features_array = features_array[:ids_expected_features]
    
    return features_array.reshape(1, -1)

# --------------------
# RATE LIMIT MIDDLEWARE
# --------------------
@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    client_ip = request.client.host or "127.0.0.1"
    path = request.url.path
    
    if "/api/login-check" in path or "/api/detect" in path:
        current_time = time.time()
        
        if client_ip in RATE_LIMIT:
            last_request, count = RATE_LIMIT[client_ip]
            if current_time - last_request < 1:
                if count > 10:
                    log_alert(
                        module="RATE_LIMIT",
                        attack_type="RATE_LIMIT_EXCEEDED",
                        payload=f"Too many requests: {count}/sec",
                        confidence=1.0,
                        client_ip=client_ip
                    )
                    raise HTTPException(status_code=429, detail="Too many requests")
                RATE_LIMIT[client_ip] = (last_request, count + 1)
            else:
                RATE_LIMIT[client_ip] = (current_time, 1)
        else:
            RATE_LIMIT[client_ip] = (current_time, 1)
    
    response = await call_next(request)
    return response

# ==================== WEB DETECTION ====================
@app.post("/api/login-check")
async def login_check(data: LoginRequest, request: Request):
    client_ip = request.client.host or "127.0.0.1"
    combined_input = f"{data.username} {data.password}"
    silent_mode = request.headers.get("X-Silent-Mode", "false").lower() == "true"
    
    current_time = time.time()
    if client_ip in blocked_ips:
        if current_time < blocked_ips[client_ip]:
            log_alert(
                module="LOGIN",
                attack_type="BLOCKED_IP_ATTEMPT",
                payload=f"Blocked IP tried login",
                confidence=1.0,
                client_ip=client_ip
            )
            return {
                "allow": False, 
                "reason": "Invalid credentials",
                "blocked": True,
                "threat_level": "critical",
                "timestamp": current_time
            }
        else:
            del blocked_ips[client_ip]
    
    detected_attack = "BENIGN"
    confidence = 0.0
    
    if web_model and vectorizer:
        try:
            X = vectorizer.transform([combined_input])
            ml_prediction = web_model.predict(X)[0]
            ml_confidence = float(np.max(web_model.predict_proba(X)))
            
            if ml_prediction != "BENIGN":
                detected_attack = ml_prediction
                confidence = ml_confidence
        except Exception as e:
            print(f"ML detection error: {e}")
    
    if detected_attack == "BENIGN":
        rule_attack, rule_conf = rule_based_detection(combined_input)
        if rule_attack != "BENIGN":
            detected_attack = rule_attack
            confidence = rule_conf
    
    if detected_attack != "BENIGN":
        FAILED_ATTEMPTS[client_ip] = FAILED_ATTEMPTS.get(client_ip, 0) + 1
        threat_level = get_threat_level(detected_attack, confidence)
        
        if FAILED_ATTEMPTS[client_ip] >= 3:
            blocked_ips[client_ip] = current_time + 3600
            log_alert(
                module="LOGIN",
                attack_type="IP_BLOCKED",
                payload=f"IP blocked after 3 attacks",
                confidence=1.0,
                client_ip=client_ip
            )
        
        log_alert(
            module="LOGIN",
            attack_type=detected_attack,
            payload=combined_input[:80],
            confidence=confidence,
            client_ip=client_ip
        )
        
        if silent_mode:
            return {
                "allow": False,
                "reason": "Invalid credentials",
                "blocked": False,
                "threat_level": "low",
                "silent": True
            }
        else:
            return {
                "allow": False,
                "reason": f"Security violation: {detected_attack}",
                "blocked": True if FAILED_ATTEMPTS.get(client_ip, 0) >= 3 else False,
                "threat_level": threat_level,
                "attack_type": detected_attack,
                "confidence": confidence,
                "timestamp": current_time
            }
    
    log_alert(
        module="LOGIN",
        attack_type="SUCCESSFUL_LOGIN",
        payload=f"User: {data.username[:15]}",
        confidence=0.0,
        client_ip=client_ip
    )
    
    return {
        "allow": True, 
        "reason": "Security check passed",
        "timestamp": current_time
    }

@app.post("/api/detect/web")
async def detect_web(data: WebRequest, request: Request):
    client_ip = request.client.host or "127.0.0.1"
    
    if not web_model or not vectorizer:
        attack_type, confidence = rule_based_detection(data.payload)
        threat_level = get_threat_level(attack_type, confidence)
        
        if attack_type != "BENIGN":
            log_alert(
                module="WEB",
                attack_type=attack_type,
                payload=data.payload[:80],
                confidence=confidence,
                client_ip=client_ip
            )
        
        return {
            "is_malicious": attack_type != "BENIGN",
            "attack_type": attack_type,
            "threat_level": threat_level,
            "confidence": confidence,
            "client_ip": client_ip,
            "method": "rule-based"
        }
    
    try:
        X = vectorizer.transform([data.payload])
        prediction = web_model.predict(X)[0]
        confidence = float(np.max(web_model.predict_proba(X)))
        threat_level = get_threat_level(prediction, confidence)
        
        if prediction != "BENIGN":
            log_alert(
                module="WEB",
                attack_type=prediction,
                payload=data.payload[:80],
                confidence=confidence,
                client_ip=client_ip
            )
        
        return {
            "is_malicious": prediction != "BENIGN",
            "attack_type": prediction,
            "threat_level": threat_level,
            "confidence": confidence,
            "client_ip": client_ip,
            "method": "ML"
        }
    except Exception as e:
        print(f"Web detection error: {e}")
        attack_type, confidence = rule_based_detection(data.payload)
        threat_level = get_threat_level(attack_type, confidence)
        
        return {
            "is_malicious": attack_type != "BENIGN",
            "attack_type": attack_type,
            "threat_level": threat_level,
            "confidence": confidence,
            "client_ip": client_ip,
            "method": "rule-based"
        }

# ==================== NETWORK IDS DETECTION ====================
@app.post("/api/detect/network")
async def detect_network(data: NetworkRequest, request: Request):
    """Detect network intrusions"""
    client_ip = request.client.host or "127.0.0.1"
    
    if not ids_model:
        return {"error": "IDS model not loaded", "status": "unavailable"}
    
    try:
        # Prepare features (pad/truncate to expected size)
        features = prepare_ids_features(data.features)
        
        # Make prediction
        prediction = ids_model.predict(features)[0]
        
        # Get probability if available
        if hasattr(ids_model, 'predict_proba'):
            probabilities = ids_model.predict_proba(features)[0]
            confidence = float(np.max(probabilities))
            predicted_class = ids_model.classes_[np.argmax(probabilities)] if hasattr(ids_model, 'classes_') else prediction
        else:
            confidence = 1.0
            predicted_class = prediction
        
        # Log if attack detected
        if predicted_class != "BENIGN":
            log_alert(
                module="NETWORK",
                attack_type=predicted_class,
                payload=f"Network attack: {predicted_class}",
                confidence=confidence,
                client_ip=client_ip
            )
        
        threat_level = get_threat_level(predicted_class, confidence)
        
        return {
            "is_malicious": predicted_class != "BENIGN",
            "attack_type": predicted_class,
            "threat_level": threat_level,
            "confidence": confidence,
            "client_ip": client_ip,
            "features_received": len(data.features) if isinstance(data.features, list) else 0,
            "features_used": ids_expected_features,
            "method": "ML"
        }
        
    except Exception as e:
        return {"error": str(e), "status": "error"}

@app.post("/api/simulate/network-attack")
async def simulate_network_attack(attack_type: str = "normal"):
    """Simulate network attacks with correct feature count"""
    
    # Create sample features (78 zeros with some patterns for attacks)
    normal_traffic = [0] * ids_expected_features
    ssh_bruteforce = [0] * ids_expected_features
    ftp_bruteforce = [0] * ids_expected_features
    
    # Set some features for attacks (simplified)
    if ids_expected_features > 10:
        # SSH Brute Force pattern
        ssh_bruteforce[5] = 120.5  # duration
        ssh_bruteforce[6] = 25     # failed logins
        ssh_bruteforce[7] = 100    # count
        
        # FTP Brute Force pattern
        ftp_bruteforce[5] = 85.2   # duration
        ftp_bruteforce[6] = 35     # failed logins
        ftp_bruteforce[7] = 150    # count
    
    attack_types = {
        "ssh_bruteforce": ssh_bruteforce,
        "ftp_bruteforce": ftp_bruteforce,
        "normal": normal_traffic
    }
    
    if attack_type not in attack_types:
        return {"error": f"Unknown attack type. Choose from: {list(attack_types.keys())}"}
    
    features = attack_types[attack_type]
    
    # Create mock request
    class MockRequest:
        def __init__(self):
            self.client = type('obj', (object,), {'host': '127.0.0.1'})()
    
    mock_request = MockRequest()
    network_data = NetworkRequest(features=features)
    
    # Call detection
    return await detect_network(network_data, mock_request)

# ==================== ANDROID MALWARE DETECTION ====================
@app.post("/api/detect/android")
async def detect_android(data: AndroidRequest, request: Request):
    """Detect Android malware based on permissions"""
    client_ip = request.client.host or "127.0.0.1"
    
    if not android_model:
        return {"error": "Android model not loaded", "status": "unavailable"}
    
    try:
        if len(data.permissions) == 0:
            return {"error": "No permissions provided"}
        
        # Convert permission list to feature vector
        features = np.array([data.permissions]).astype(float)
        
        prediction = android_model.predict(features)[0]
        
        if hasattr(android_model, 'predict_proba'):
            probabilities = android_model.predict_proba(features)[0]
            confidence = float(np.max(probabilities))
            predicted_class = android_model.classes_[np.argmax(probabilities)] if hasattr(android_model, 'classes_') else prediction
        else:
            confidence = 1.0
            predicted_class = prediction
        
        is_malicious = str(predicted_class).upper() in ["MALWARE", "1"]
        
        if is_malicious:
            log_alert(
                module="ANDROID",
                attack_type="MALWARE",
                payload=f"Android malware detected with {len(data.permissions)} suspicious permissions",
                confidence=confidence,
                client_ip=client_ip
            )
        
        threat_level = "critical" if is_malicious and confidence > 0.8 else "high" if is_malicious else "low"
        
        return {
            "is_malicious": is_malicious,
            "malware_type": str(predicted_class),
            "threat_level": threat_level,
            "confidence": confidence,
            "client_ip": client_ip,
            "permissions_analyzed": len(data.permissions),
            "method": "ML"
        }
        
    except Exception as e:
        return {"error": str(e), "status": "error"}

# ==================== UTILITY ENDPOINTS ====================
@app.get("/api/status")
async def api_status():
    return {
        "status": "online",
        "timestamp": time.time(),
        "models": {
            "web_attack": web_model is not None,
            "network_ids": ids_model is not None,
            "android_malware": android_model is not None,
            "vectorizer": vectorizer is not None,
            "ids_expected_features": ids_expected_features if ids_model else None
        },
        "security": {
            "blocked_ips_count": len(blocked_ips),
            "failed_attempts_count": len(FAILED_ATTEMPTS)
        }
    }

@app.get("/api/stats")
async def get_stats():
    try:
        alert_file = "alerts/alerts.log"
        total_alerts = 0
        if os.path.exists(alert_file):
            with open(alert_file, "r", encoding="utf-8") as f:
                total_alerts = len(f.readlines())
        
        return {
            "total_alerts": total_alerts,
            "blocked_ips": len(blocked_ips),
            "failed_attempts": len(FAILED_ATTEMPTS),
            "models_loaded": {
                "web": web_model is not None,
                "ids": ids_model is not None,
                "android": android_model is not None
            },
            "ids_features": ids_expected_features if ids_model else "N/A",
            "timestamp": time.time()
        }
    except Exception as e:
        print(f"Error getting stats: {e}")
        return {
            "total_alerts": 0,
            "blocked_ips": 0,
            "failed_attempts": 0,
            "models_loaded": {},
            "error": str(e)
        }

@app.get("/api/alerts")
async def get_alerts(limit: int = 50):
    try:
        alert_file = "alerts/alerts.log"
        if not os.path.exists(alert_file):
            return {"alerts": []}
        
        with open(alert_file, "r", encoding="utf-8") as f:
            lines = f.readlines()[-limit:]
        
        alerts = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
                
            parts = line.split(" | ")
            if len(parts) >= 6:
                alert = {
                    "timestamp": parts[0],
                    "module": parts[1],
                    "attack_type": parts[2],
                    "severity": parts[3],
                    "confidence": parts[4],
                    "payload": parts[5]
                }
                if len(parts) > 6:
                    alert["ip"] = parts[6]
                else:
                    alert["ip"] = "Unknown"
                
                alerts.append(alert)
        
        return {"alerts": alerts[::-1]}
    except Exception as e:
        print(f"Error reading alerts: {e}")
        return {"alerts": []}

@app.post("/api/clear-alerts")
async def clear_alerts():
    try:
        alert_file = "alerts/alerts.log"
        if os.path.exists(alert_file):
            with open(alert_file, "w", encoding="utf-8") as f:
                f.write("")
        return {"message": "All alerts cleared"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to clear alerts: {e}")

@app.get("/api/blocked-ips")
async def get_blocked_ips():
    current_time = time.time()
    expired = [ip for ip, expiry in blocked_ips.items() if expiry < current_time]
    for ip in expired:
        del blocked_ips[ip]
        if ip in FAILED_ATTEMPTS:
            del FAILED_ATTEMPTS[ip]
    
    return {
        "blocked_ips": [
            {"ip": ip, "blocked_until": blocked_ips[ip]}
            for ip in blocked_ips.keys()
        ]
    }

@app.post("/api/unblock-ip/{ip}")
async def unblock_ip(ip: str):
    if ip in blocked_ips:
        del blocked_ips[ip]
    if ip in FAILED_ATTEMPTS:
        del FAILED_ATTEMPTS[ip]
    return {"message": f"IP {ip} unblocked"}

@app.get("/")
async def root():
    current_time = time.time()
    blocked_count = len([ip for ip, expiry in blocked_ips.items() if expiry > current_time])
    
    return {
        "message": "🚀 SentinelAI Multi-Domain Security System",
        "status": "Running",
        "capabilities": ["Web Attack Detection", "Network IDS", "Android Malware Detection"],
        "models_loaded": {
            "web_attack": web_model is not None,
            "network_ids": ids_model is not None,
            "android_malware": android_model is not None
        },
        "security": {
            "currently_blocked_ips": blocked_count,
            "active_failed_attempts": len(FAILED_ATTEMPTS)
        },
        "version": "2.1.0",
        "timestamp": current_time,
        "endpoints": {
            "login_check": "POST /api/login-check",
            "detect_web": "POST /api/detect/web",
            "detect_network": "POST /api/detect/network",
            "detect_android": "POST /api/detect/android",
            "simulate_network": "POST /api/simulate/network-attack",
            "get_alerts": "GET /api/alerts",
            "get_stats": "GET /api/stats",
            "get_status": "GET /api/status",
            "get_blocked_ips": "GET /api/blocked-ips",
            "clear_alerts": "POST /api/clear-alerts",
            "unblock_ip": "POST /api/unblock-ip/{ip}"
        }
    }

# --------------------
# START SERVER
# --------------------
if __name__ == "__main__":
    import uvicorn
    print("\n" + "="*60)
    print("🚀 SentinelAI Multi-Domain Security System")
    print("="*60)
    print("🌐 Web Attack Detection: Active")
    print("📡 Network IDS: Active")
    print("📱 Android Malware Detection: Active")
    print(f"📊 IDS Features: {ids_expected_features}")
    print("🛡️  IP Blocking: Enabled")
    print("📋 API Docs: http://localhost:8000/docs")
    print("="*60 + "\n")
    
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=False)
