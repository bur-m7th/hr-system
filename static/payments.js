async function showAddPaymentModal() {
    if (typeof employees === 'undefined' || employees.length === 0) {
        try {
            const response = await fetch(`${API_BASE}/employees`);
            if (response.ok) {
                employees = await response.json();
            }
        } catch (e) { console.error("Could not load employees for modal"); }
    }

    filterPaymentModalEmployees();
    document.getElementById('paymentRecordForm').reset();
    setDefaultPayPeriod();
    document.getElementById('paymentModal').style.display = 'block';
}

function filterPaymentModalEmployees() {
    const select = document.getElementById('paymentEmployee');
    if(!select) return;

    select.innerHTML = `<option value="">${translations[currentLanguage].select_employee_option || "-- Select --"}</option>`;
    
    if (typeof employees !== 'undefined') {
        employees.forEach(emp => {
            const option = document.createElement('option');
            option.value = emp.id;
            option.textContent = emp.name;
            select.appendChild(option);
        });
    }
}

function updatePaymentModalSalary() {
    const empId = parseInt(document.getElementById('paymentEmployee').value);
    const employee = employees.find(e => e.id === empId);
    if (employee) { 
        document.getElementById('paymentBaseSalary').value = employee.baseSalary; 
        calculateNetSalary(); 
    }
}

async function addPaymentRecord(e) {
    e.preventDefault();
    const employeeId = parseInt(document.getElementById('paymentEmployee').value);
    const payPeriod = document.getElementById('paymentPeriod').value;
    const baseSalary = parseFloat(document.getElementById('paymentBaseSalary').value);
    const bonus = parseFloat(document.getElementById('paymentBonus').value) || 0;
    const deductions = parseFloat(document.getElementById('paymentDeductions').value) || 0;
    
    const netSalary = baseSalary + bonus - deductions;
    document.getElementById('paymentNetSalary').value = netSalary.toFixed(3);

    const paymentData = { employeeId, payPeriod, baseSalary, bonus, deductions, netSalary };
    
    try {
        const response = await fetch(`${API_BASE}/payments/add`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(paymentData)
        });
        if (!response.ok) throw new Error('Failed');
        closePaymentModal();
        
        // Refresh history if active
        if(typeof currentHistoryEmpId !== 'undefined' && currentHistoryEmpId) {
             const name = document.getElementById('historySelectedEmpName').textContent;
             viewEmployeeHistory(currentHistoryEmpId, name, baseSalary);
        }
        
        alert(currentLanguage === 'ar' ? 'تمت الإضافة!' : 'Record added!');
    } catch (error) { alert('Error: ' + error.message); }
}

function closePaymentModal() { document.getElementById('paymentModal').style.display = 'none'; }