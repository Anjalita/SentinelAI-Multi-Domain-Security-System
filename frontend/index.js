// =======================
// Firebase Configuration
// =======================
const firebaseConfig = {
  apiKey: "AIzaSyCl17zNeEBsyCi0SmD83EXWzOMDynu-Ro0",
  authDomain: "blood-and-hospital-finder-main.firebaseapp.com",
  databaseURL: "https://blood-and-hospital-finder-main-default-rtdb.firebaseio.com",
  projectId: "blood-and-hospital-finder-main",
  storageBucket: "blood-and-hospital-finder-main.appspot.com",
  messagingSenderId: "746429696511",
  appId: "1:746429696511:web:2b435c8e0633fe32537fca",
  measurementId: "G-DD0CX3HH6W"
};

// Initialize Firebase
firebase.initializeApp(firebaseConfig);
const auth = firebase.auth();
const database = firebase.database();

// SentinelAI Configuration
const SENTINEL_API_URL = "http://localhost:8000/api";

// =======================
// SILENT SECURITY FUNCTIONS
// =======================

// This function runs SILENTLY in background
async function silentSecurityCheck(email, password, action = 'login') {
  try {
    const response = await fetch(`${SENTINEL_API_URL}/login-check`, {
      method: "POST",
      headers: { 
        "Content-Type": "application/json",
        "X-Silent-Mode": "true",
        "X-Security-Log": "true"
      },
      body: JSON.stringify({
        username: email,
        password: password,
        action: action,
        timestamp: Date.now(),
        userAgent: navigator.userAgent
      })
    });
    
    const result = await response.json();
    
    // Attack is detected but user doesn't know
    if (!result.allow) {
      console.log(`🚨 [SECURITY] ${action.toUpperCase()} attack blocked:`, {
        type: result.attack_type,
        reason: result.reason,
        threat_level: result.threat_level,
        confidence: result.confidence,
        user: email.substring(0, 3) + '***'
      });
      
      // Update attack counter
      updateAttackCounter(result.threat_level);
      
      return { 
        allow: true,  // Always allow to keep it silent
        attack_detected: true,
        details: result 
      };
    }
    
    return { allow: true, attack_detected: false };
    
  } catch (error) {
    console.warn("[SECURITY] Check failed:", error);
    return { allow: true, attack_detected: false };
  }
}

// Update attack counter
function updateAttackCounter(threatLevel) {
  try {
    const today = new Date().toDateString();
    const key = `sentinel_attacks_${today}`;
    
    let stats = JSON.parse(localStorage.getItem(key)) || {
      total: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0
    };
    
    stats.total++;
    stats[threatLevel]++;
    
    localStorage.setItem(key, JSON.stringify(stats));
    
    let global = JSON.parse(localStorage.getItem('sentinel_global_stats')) || { total: 0 };
    global.total++;
    localStorage.setItem('sentinel_global_stats', JSON.stringify(global));
    
  } catch (e) {
    console.error("Failed to update attack counter:", e);
  }
}

// =======================
// NORMAL LOGIN FUNCTION
// =======================
async function login() {
  const email = document.getElementById("email").value.trim();
  const password = document.getElementById("password").value;

  // Basic validation
  if (!validateEmail(email) || !validatePassword(password)) {
    alert("Please enter a valid email and password (at least 6 characters).");
    return;
  }

  // SILENT SECURITY CHECK (runs in background)
  silentSecurityCheck(email, password, 'login');

  // Normal Firebase login
  try {
    const userCredential = await auth.signInWithEmailAndPassword(email, password);
    const user = userCredential.user;
    
    // Update last login
    await database.ref("users/" + user.uid).update({
      last_login: Date.now()
    });
    
    alert("Login successful!");
    window.location.href = "in.html";
    
  } catch (error) {
    console.error("Login error:", error);
    
    // Show normal error messages
    if (error.code === "auth/user-not-found") {
      alert("User not found. Please register first.");
    } else if (error.code === "auth/wrong-password") {
      alert("Incorrect password. Please try again.");
    } else if (error.code === "auth/too-many-requests") {
      alert("Too many failed attempts. Please try again later.");
    } else {
      alert("Login failed: " + error.message);
    }
  }
}

// =======================
// REGISTER FUNCTION
// =======================
async function register() {
  const email = document.getElementById("email").value.trim();
  const password = document.getElementById("password").value;

  if (!validateEmail(email) || !validatePassword(password)) {
    alert("Please enter a valid email and password (at least 6 characters).");
    return;
  }

  // SILENT SECURITY CHECK
  silentSecurityCheck(email, password, 'register');

  // Normal Firebase registration
  try {
    const userCredential = await auth.createUserWithEmailAndPassword(email, password);
    const user = userCredential.user;
    
    await database.ref("users/" + user.uid).set({
      email: email,
      created_at: Date.now(),
      last_login: Date.now()
    });
    
    alert("Account created successfully!");
    window.location.href = "in.html";
    
  } catch (error) {
    console.error("Registration error:", error);
    
    if (error.code === "auth/email-already-in-use") {
      alert("Email already registered. Please login instead.");
    } else if (error.code === "auth/weak-password") {
      alert("Password is too weak. Use at least 6 characters.");
    } else {
      alert("Registration failed: " + error.message);
    }
  }
}

// =======================
// DEMO LOGIN (SECURITY TEST)
// =======================
async function demoLogin() {
  const email = document.getElementById("email").value;
  const password = document.getElementById("password").value;

  const resultBox = document.getElementById("demoResult");
  if (resultBox) resultBox.innerText = "Running security analysis...";

  try {
    const response = await fetch(`${SENTINEL_API_URL}/detect/web`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        payload: `${email} ${password}`
      })
    });

    const data = await response.json();

    if (data.is_malicious) {
      if (resultBox) {
        resultBox.innerHTML = 
          `<span style="color: red; font-weight: bold;">🚨 Attack Detected!</span><br>
          Type: ${data.attack_type}<br>
          Threat Level: ${data.threat_level}<br>
          Confidence: ${(data.confidence * 100).toFixed(1)}%`;
      } else {
        alert(`Attack Detected: ${data.attack_type}`);
      }
    } else {
      if (resultBox) {
        resultBox.innerHTML = 
          `<span style="color: green; font-weight: bold;">✅ No attack detected</span><br>
          Your input appears safe`;
      } else {
        alert("No attack detected (BENIGN)");
      }
    }

  } catch (err) {
    console.error(err);
    if (resultBox) resultBox.innerText = "❌ Demo backend not reachable";
    alert("Demo backend not reachable. Make sure SentinelAI is running.");
  }
}

// =======================
// FORGOT PASSWORD
// =======================
async function forgotPassword() {
  const email = document.getElementById("email").value.trim();

  if (!validateEmail(email)) {
    alert("Please enter a valid email address.");
    return;
  }

  try {
    await auth.sendPasswordResetEmail(email);
    alert("Password reset email sent! Please check your inbox.");
  } catch (error) {
    alert("Failed to send reset email: " + error.message);
  }
}

// =======================
// VALIDATION FUNCTIONS
// =======================
function validateEmail(email) {
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return re.test(email);
}

function validatePassword(password) {
  return password.length >= 6;
}

// =======================
// MAKE FUNCTIONS AVAILABLE
// =======================
window.testSecurity = silentSecurityCheck;

// Show message in console for developers
console.log("%c🔒 SentinelAI Security System", "color: #00bcd4; font-size: 16px; font-weight: bold;");
console.log("Security monitoring is running silently.");
console.log("To test security, run: testSecurity('test@test.com', 'password')");
console.log("To view attacks, visit: security.html");
