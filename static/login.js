const API_BASE = '/api';

// Check System Setup on Load
document.addEventListener('DOMContentLoaded', async () => {
    try {
        const res = await fetch(`${API_BASE}/check-setup`);
        const data = await res.json();
        
        // If not setup, redirect to register immediately
        if (!data.isSetup) {
            window.location.href = '/register.html';
        }
    } catch (e) { 
        console.error("Setup check failed", e);
        showError("Cannot connect to server. Please try again.");
    }
});

function showError(message) {
    const errorMsg = document.getElementById('errorMsg');
    if (errorMsg) {
        errorMsg.textContent = message;
        errorMsg.style.display = 'block';
        
        // Auto-hide after 5 seconds
        setTimeout(() => {
            errorMsg.style.display = 'none';
        }, 5000);
    }
}

document.getElementById('loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const errorMsg = document.getElementById('errorMsg');
    
    // Clear previous errors
    errorMsg.style.display = 'none';

    // Validate inputs
    if (!username || !password) {
        showError("Please enter both username and password");
        return;
    }

    try {
        const res = await fetch(`${API_BASE}/login`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({username, password})
        });

        if (res.status === 401) {
            showError("Invalid username or password. Please try again.");
            return;
        }

        if (!res.ok) {
            const errorText = await res.text();
            showError(errorText || "Login failed. Please try again.");
            return;
        }

        const data = await res.json();

        if (data.status === '2fa_required') {
            document.getElementById('loginForm').style.display = 'none';
            document.getElementById('otpForm').style.display = 'block';
            window.tempToken = data.tempToken;
        } else if (data.status === 'success') {
            window.location.href = '/index.html';
        } else {
            showError("Unexpected response from server");
        }
    } catch (err) {
        console.error("Login error:", err);
        showError("Cannot connect to server. Please check your connection.");
    }
});

document.getElementById('otpForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const code = document.getElementById('otpCode').value;
    const errorMsg = document.getElementById('errorMsg');
    
    // Validate code
    if (!code || code.length !== 6) {
        showError("Please enter a 6-digit code");
        return;
    }

    try {
        const res = await fetch(`${API_BASE}/verify-2fa`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({tempToken: window.tempToken, code})
        });

        if (res.status === 401) {
            showError("Invalid verification code. Please try again.");
            document.getElementById('otpCode').value = '';
            document.getElementById('otpCode').focus();
            return;
        }

        if (!res.ok) {
            const errorText = await res.text();
            showError(errorText || "Verification failed");
            return;
        }

        const data = await res.json();
        if (data.status === 'success') {
            window.location.href = '/index.html';
        } else {
            showError("Verification failed. Please try again.");
        }
    } catch (err) {
        console.error("2FA error:", err);
        showError("Cannot connect to server. Please check your connection.");
    }
});