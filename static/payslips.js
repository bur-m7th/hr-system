async function loadGenerateFilterOptions() {
    if (typeof loadFilterOptions === 'function') {
        await loadFilterOptions();
    }
}

async function loadEmployeesForGenerate() {
    try {
        const response = await fetch(`${API_BASE}/employees`);
        if (response.ok) {
            filteredEmployeesForGenerate = await response.json();
            displaySelectableEmployees();
        }
    } catch (error) { 
        console.error("Error loading generate employees", error);
        showMessage('Error loading employees', 'error');
    }
}

async function applyGenerateFilters() {
    const dept = document.getElementById('genFilterDepartment').value;
    const pos = document.getElementById('genFilterPosition').value;
    const search = document.getElementById('genSearchEmployee').value;
    
    let url = `${API_BASE}/employees?`;
    const params = [];
    if (dept) params.push(`department=${encodeURIComponent(dept)}`);
    if (pos) params.push(`position=${encodeURIComponent(pos)}`);
    if (search) params.push(`search=${encodeURIComponent(search)}`);
    url += params.join('&');

    try {
        const response = await fetch(url);
        if (response.ok) {
            filteredEmployeesForGenerate = await response.json();
            displaySelectableEmployees();
        }
    } catch (error) { 
        console.error(error);
        showMessage('Error applying filters', 'error');
    }
}

function clearGenerateFilters() {
    document.getElementById('genFilterDepartment').value = '';
    document.getElementById('genFilterPosition').value = '';
    document.getElementById('genSearchEmployee').value = '';
    loadEmployeesForGenerate();
}

function displaySelectableEmployees() {
    const container = document.getElementById('employeeSelectList');
    if (!container) return;
    
    if (!filteredEmployeesForGenerate || filteredEmployeesForGenerate.length === 0) {
        container.innerHTML = `<p style="padding:10px; color:#666;">${translations[currentLanguage].no_history || 'No employees found.'}</p>`;
        return;
    }
    
    container.innerHTML = '';
    filteredEmployeesForGenerate.forEach(employee => {
        const card = document.createElement('div');
        card.className = 'selectable-card';
        card.onclick = () => toggleEmployeeSelection(employee.id);
        
        if (selectedEmployeeIds.has(employee.id)) {
            card.classList.add('selected');
        }
        
        card.innerHTML = `
            <span class="checkbox"></span>
            <strong>${employee.name}</strong><br>
            <small>${employee.position} - ${formatMoney(employee.baseSalary)}</small>
        `;
        container.appendChild(card);
    });
    updateSelectionCount();
}

function toggleEmployeeSelection(id) {
    if (selectedEmployeeIds.has(id)) {
        selectedEmployeeIds.delete(id);
    } else {
        selectedEmployeeIds.add(id);
    }
    displaySelectableEmployees();
}

function clearSelection() {
    selectedEmployeeIds.clear();
    displaySelectableEmployees();
}

function updateSelectionCount() {
    const countElement = document.getElementById('selectedCount');
    if (countElement) {
        countElement.textContent = selectedEmployeeIds.size;
    }
}

async function generatePayslips(e) {
    e.preventDefault();
    if (selectedEmployeeIds.size === 0) {
        alert(currentLanguage === 'ar' ? 'يرجى اختيار موظف.' : 'Please select at least one employee');
        return;
    }
    
    const payPeriod = document.getElementById('payPeriod').value;
    const bonus = parseFloat(document.getElementById('bonus').value) || 0;
    const deductions = parseFloat(document.getElementById('deductions').value) || 0;
    
    if(!payPeriod) {
        alert("Please select a Pay Period");
        return;
    }

    const requestData = { 
        employeeIds: Array.from(selectedEmployeeIds), 
        payPeriod, 
        bonus, 
        deductions 
    };

    const btn = e.target.querySelector('button');
    const originalText = btn.textContent;
    btn.textContent = currentLanguage === 'ar' ? "جاري المعالجة..." : "Processing...";
    btn.disabled = true;

    try {
        const response = await fetch(`${API_BASE}/generate-payslips`, {
            method: 'POST', 
            headers: { 'Content-Type': 'application/json' }, 
            body: JSON.stringify(requestData)
        });
        
        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(errorText || 'Failed to generate payslips');
        }
        
        const results = await response.json();
        
        if (results.length === 0) {
            showMessage(currentLanguage === 'ar' ? 'لم يتم إنشاء أي قسائم (قد يكون الموظفون مستثنين)' : 'No payslips generated (employees may be excluded)', 'error');
        } else {
            displayGeneratedResults(results);
            showMessage(currentLanguage === 'ar' ? `تم إنشاء ${results.length} قسيمة!` : `Generated ${results.length} payslips!`, 'success');
        }
        
        selectedEmployeeIds.clear();
        displaySelectableEmployees();
        
    } catch (error) { 
        console.error(error);
        showMessage('Error: ' + error.message, 'error');
    } finally {
        btn.textContent = originalText;
        btn.disabled = false;
    }
}

// Store generated results globally
let lastGeneratedResults = [];

function displayGeneratedResults(results) {
    lastGeneratedResults = results; // Store for download all
    
    const container = document.getElementById('resultsList');
    const resultsDiv = document.getElementById('generatedResults');
    if (!container || !resultsDiv) return;
    
    resultsDiv.classList.remove('hidden');
    container.innerHTML = '';
    
    const ppLabel = currentLanguage === 'ar' ? 'فترة الدفع:' : 'Pay Period:';
    const baseLabel = currentLanguage === 'ar' ? 'الراتب الأساسي:' : 'Base Salary:';
    const netLabel = currentLanguage === 'ar' ? 'صافي الراتب:' : 'Net Salary:';
    const dlLabel = currentLanguage === 'ar' ? 'تحميل' : 'Download';

    results.forEach(payment => {
        let docLink = payment.documentPath ? 
            `<a href="/generated/${payment.documentPath}" target="_blank" class="btn btn-sm btn-secondary" style="margin-top: 10px; display: inline-block;">📄 ${dlLabel}</a>` : '';
            
        const card = document.createElement('div');
        card.className = 'result-card';
        card.innerHTML = `
            <div class="result-header">${payment.employeeName}</div>
            <div class="result-details">
                <div><strong>${ppLabel}</strong> ${formatPayPeriod(payment.payPeriod)}</div>
                <div><strong>${baseLabel}</strong> ${formatMoney(payment.baseSalary)}</div>
                <div><strong>${netLabel}</strong> ${formatMoney(payment.netSalary)}</div>
            </div>
            ${docLink}
        `;
        container.appendChild(card);
    });
    
    // Add "Download All" button
    const downloadAllBtn = document.createElement('button');
    downloadAllBtn.className = 'btn btn-primary btn-large';
    downloadAllBtn.style.marginTop = '20px';
    downloadAllBtn.textContent = currentLanguage === 'ar' ? '📥 تحميل جميع القسائم' : '📥 Download All Payslips';
    downloadAllBtn.onclick = downloadAllPayslips;
    container.appendChild(downloadAllBtn);
    
    resultsDiv.scrollIntoView({ behavior: 'smooth' });
}

async function downloadAllPayslips() {
    if (lastGeneratedResults.length === 0) {
        alert(currentLanguage === 'ar' ? 'لا توجد قسائم للتحميل' : 'No payslips to download');
        return;
    }
    
    const btn = event.target;
    const originalText = btn.textContent;
    btn.textContent = currentLanguage === 'ar' ? 'جاري التحميل...' : 'Downloading...';
    btn.disabled = true;
    
    try {
        // Create a temporary form to download files
        for (const result of lastGeneratedResults) {
            if (result.documentPath) {
                // Create temporary link and trigger download
                const link = document.createElement('a');
                link.href = `/generated/${result.documentPath}`;
                link.download = result.documentPath;
                link.style.display = 'none';
                document.body.appendChild(link);
                link.click();
                document.body.removeChild(link);
                
                // Small delay between downloads to prevent browser blocking
                await new Promise(resolve => setTimeout(resolve, 300));
            }
        }
        
        showMessage(currentLanguage === 'ar' ? 'تم بدء التحميل' : 'Download started', 'success');
    } catch (error) {
        console.error(error);
        showMessage('Error downloading files', 'error');
    } finally {
        btn.textContent = originalText;
        btn.disabled = false;
    }
}