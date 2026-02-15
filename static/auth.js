async function checkAuth() {
    try {
        const response = await fetch(`${API_BASE}/auth-status`);
        if (!response.ok) throw new Error("Auth check failed");
        const data = await response.json();
        if (!data.loggedIn) {
            window.location.href = '/login.html';
        } else {
            const userStatus = document.getElementById('userStatus');
            if(userStatus) userStatus.textContent = `👤 ${data.username} ▼`;
        }
    } catch (e) {
        console.error("Auth error:", e);
        window.location.href = '/login.html';
    }
}

async function logout() {
    try {
        await fetch(`${API_BASE}/logout`);
        window.location.href = '/login.html';
    } catch (e) {
        console.error("Logout error:", e);
        window.location.href = '/login.html';
    }
}

function showAddUserModal() {
    document.getElementById('addUserModal').style.display = 'block';
}

function closeAddUserModal() {
    document.getElementById('addUserModal').style.display = 'none';
}

// Add User Form Submission
document.addEventListener('DOMContentLoaded', () => {
    checkAuth(); // Check login on load

    const addUserForm = document.getElementById('addUserForm');
    if(addUserForm) {
        addUserForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const username = document.getElementById('newUsername').value;
            const password = document.getElementById('newPassword').value;
            
            if (!username || !password) {
                showMessage(currentLanguage === 'ar' ? 'الرجاء إدخال اسم المستخدم وكلمة المرور' : 'Please enter username and password', 'error');
                return;
            }
            
            if (password.length < 6) {
                showMessage(currentLanguage === 'ar' ? 'كلمة المرور يجب أن تكون 6 أحرف على الأقل' : 'Password must be at least 6 characters', 'error');
                return;
            }
            
            try {
                const res = await fetch(`${API_BASE}/users/add`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({username, password})
                });
                
                if(res.status === 409) {
                    showMessage(currentLanguage === 'ar' ? 'اسم المستخدم موجود بالفعل' : 'Username already exists', 'error');
                    return;
                }
                
                if(res.ok) {
                    showMessage(currentLanguage === 'ar' ? 'تم إنشاء المستخدم' : 'User Created', 'success');
                    closeAddUserModal();
                    document.getElementById('addUserForm').reset();
                } else {
                    const errorText = await res.text();
                    showMessage(errorText || 'Error creating user', 'error');
                }
            } catch(e) { 
                console.error(e);
                showMessage(currentLanguage === 'ar' ? 'خطأ في الاتصال بالخادم' : 'Server connection error', 'error');
            }
        });
    }
});

// 2FA Functions
async function show2FAModal() {
    const modal = document.getElementById('setup2FAModal');
    const container = document.getElementById('qrContainer');
    modal.style.display = 'block';
    
    try {
        const res = await fetch(`${API_BASE}/2fa/generate`);
        if (!res.ok) throw new Error('Failed to generate 2FA');
        
        const data = await res.json();
        
        document.getElementById('secret2FA').value = data.secret;
        container.innerHTML = `<img src="data:image/png;base64,${data.qr}" alt="QR Code" style="border:5px solid white">`;
    } catch (e) {
        console.error(e);
        showMessage('Error generating 2FA code', 'error');
        modal.style.display = 'none';
    }
}

async function confirm2FASetup() {
    const secret = document.getElementById('secret2FA').value;
    const code = document.getElementById('verify2FACode').value;
    
    if (!code || code.length !== 6) {
        showMessage(currentLanguage === 'ar' ? 'الرجاء إدخال رمز مكون من 6 أرقام' : 'Please enter a 6-digit code', 'error');
        return;
    }
    
    try {
        const res = await fetch(`${API_BASE}/2fa/enable`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({secret, code})
        });
        
        if(res.ok) {
            showMessage(currentLanguage === 'ar' ? 'تم تفعيل المصادقة الثنائية' : '2FA Enabled Successfully', 'success');
            document.getElementById('setup2FAModal').style.display = 'none';
            document.getElementById('verify2FACode').value = '';
        } else {
            showMessage(currentLanguage === 'ar' ? 'رمز غير صحيح' : 'Invalid Code', 'error');
        }
    } catch (e) {
        console.error(e);
        showMessage('Server error', 'error');
    }
}

async function changePassword() {
    const oldPass = prompt(currentLanguage === 'ar' ? "كلمة المرور القديمة:" : "Enter Old Password:");
    if(!oldPass) return;
    
    const newPass = prompt(currentLanguage === 'ar' ? "كلمة المرور الجديدة:" : "Enter New Password:");
    if(!newPass) return;
    
    if (newPass.length < 6) {
        showMessage(currentLanguage === 'ar' ? 'كلمة المرور يجب أن تكون 6 أحرف على الأقل' : 'Password must be at least 6 characters', 'error');
        return;
    }
    
    const code = prompt(currentLanguage === 'ar' ? "رمز 2FA (اتركه فارغاً إذا لم يكن مفعلاً):" : "2FA Code (Leave empty if disabled):");

    try {
        const res = await fetch(`${API_BASE}/user/change-password`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({oldPassword: oldPass, newPassword: newPass, twoFaCode: code || ""})
        });
        
        if(res.status === 401) {
            showMessage(currentLanguage === 'ar' ? 'كلمة المرور القديمة غير صحيحة أو رمز 2FA خاطئ' : 'Incorrect old password or invalid 2FA code', 'error');
            return;
        }
        
        if(res.ok) {
            showMessage(currentLanguage === 'ar' ? 'تم تغيير كلمة المرور' : 'Password Changed', 'success');
        } else {
            const errorText = await res.text();
            showMessage(errorText || 'Error changing password', 'error');
        }
    } catch (e) {
        console.error(e);
        showMessage('Server error', 'error');
    }
}

async function deleteMyAccount() {
    if(!confirm(currentLanguage === 'ar' ? 'هل أنت متأكد؟ سيتم حذفك وتسجيل الخروج.' : 'Are you sure? This will delete your account.')) return;
    
    try {
        await fetch(`${API_BASE}/user/delete-account`, {method: 'POST'});
        window.location.href = '/login.html';
    } catch (e) {
        console.error(e);
        showMessage('Error deleting account', 'error');
    }
}