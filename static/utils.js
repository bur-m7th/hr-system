// ============ CORE UTILITIES ============

function setDefaultPayPeriod() {
    const now = new Date();
    const year = now.getFullYear();
    const month = String(now.getMonth() + 1).padStart(2, '0');
    const period = `${year}-${month}`;
    
    const payPeriodElem = document.getElementById('payPeriod');
    if(payPeriodElem) payPeriodElem.value = period;
    
    const paymentPeriodElem = document.getElementById('paymentPeriod');
    if(paymentPeriodElem) paymentPeriodElem.value = period;
}

function calculateNetSalary() {
    const base = parseFloat(document.getElementById('paymentBaseSalary').value) || 0;
    const bonus = parseFloat(document.getElementById('paymentBonus').value) || 0;
    const deductions = parseFloat(document.getElementById('paymentDeductions').value) || 0;
    const net = base + bonus - deductions;
    
    // Bahraini Dinar usually uses 3 decimal places
    const netField = document.getElementById('paymentNetSalary');
    if(netField) netField.value = net.toFixed(3); 
}

function showTab(tabName) {
    document.querySelectorAll('.tab-content').forEach(tab => tab.classList.remove('active'));
    document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));

    const tab = document.getElementById(tabName + '-tab');
    if(tab) tab.classList.add('active');
    
    if(window.event && window.event.target) {
        window.event.target.classList.add('active');
    }

    if (tabName === 'history') loadHistoryTab();
    else if (tabName === 'generate') loadGenerateTab();
}

// Formats number only (e.g., 1,000.000)
function formatCurrency(amount) { 
    if(amount === undefined || amount === null) return "0.000";
    return parseFloat(amount).toFixed(3).replace(/\B(?=(\d{3})+(?!\d))/g, ","); 
}

// Formats with Currency Symbol (BHD 100.000 or 100.000 دينار)
function formatMoney(amount) {
    const val = parseFloat(amount) || 0;
    const formatted = val.toFixed(3).replace(/\B(?=(\d{3})+(?!\d))/g, ",");
    
    if (currentLanguage === 'ar') {
        return `${formatted} دينار`;
    }
    return `BHD ${formatted}`;
}

function formatPayPeriod(period) {
    if (!period) return "";
    const [year, month] = period.split('-');
    if (currentLanguage === 'ar') {
        const months = ['يناير', 'فبراير', 'مارس', 'أبريل', 'مايو', 'يونيو', 'يوليو', 'أغسطس', 'سبتمبر', 'أكتوبر', 'نوفمبر', 'ديسمبر'];
        return `${months[parseInt(month) - 1]} ${year}`;
    }
    const date = new Date(year, month - 1);
    return date.toLocaleDateString('en-US', { year: 'numeric', month: 'long' });
}

function showMessage(text, type, targetId = 'generateMessage') {
    const messageDiv = document.getElementById(targetId);
    if (messageDiv) {
        messageDiv.innerHTML = `<div class="message ${type}">${text}</div>`;
        setTimeout(() => { messageDiv.innerHTML = ''; }, 5000);
    } else { 
        alert(text); 
    }
}

// Close modals when clicking outside
window.onclick = function(event) { 
    if (event.target.classList.contains('modal')) { 
        event.target.style.display = 'none'; 
    } 
}