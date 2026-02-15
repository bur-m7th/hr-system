// ============ INITIALIZATION ============

document.addEventListener('DOMContentLoaded', () => {
    // 1. Apply Language Settings
    if (typeof switchLanguage === 'function') {
        switchLanguage(currentLanguage);
    }

    // 2. Load Initial Data
    if (typeof loadEmployees === 'function') loadEmployees(); 
    if (typeof loadFilterOptions === 'function') loadFilterOptions();
    if (typeof loadTemplateInfo === 'function') loadTemplateInfo();

    // 3. Setup Global Event Listeners
    setupEventListeners();
    if (typeof setDefaultPayPeriod === 'function') setDefaultPayPeriod();
});

function setupEventListeners() {
    // Payslip Generation
    const payslipForm = document.getElementById('payslipForm');
    if(payslipForm && typeof generatePayslips === 'function') {
        payslipForm.addEventListener('submit', generatePayslips);
    }

    // Employee Add/Edit
    const employeeForm = document.getElementById('employeeForm');
    if(employeeForm && typeof saveEmployee === 'function') {
        employeeForm.addEventListener('submit', saveEmployee);
    }

    // Payment Record
    const paymentRecordForm = document.getElementById('paymentRecordForm');
    if(paymentRecordForm && typeof addPaymentRecord === 'function') {
        paymentRecordForm.addEventListener('submit', addPaymentRecord);
    }

    // Export
    const exportForm = document.getElementById('exportForm');
    if(exportForm) {
        exportForm.addEventListener('submit', (e) => {
            e.preventDefault();
            const dept = document.getElementById('exportDepartment').value;
            if(dept) window.location.href = `${API_BASE}/export/department?department=${encodeURIComponent(dept)}`;
        });
    }

    // Template Upload
    const templateFile = document.getElementById('templateFile');
    if(templateFile && typeof handleFileSelect === 'function') {
        templateFile.addEventListener('change', handleFileSelect);
    }
    
    // Auto-calculate Net Salary
    const salaryInputs = ['paymentBaseSalary', 'paymentBonus', 'paymentDeductions'];
    salaryInputs.forEach(id => {
        const element = document.getElementById(id);
        if (element && typeof calculateNetSalary === 'function') {
            element.addEventListener('input', calculateNetSalary);
        }
    });
}