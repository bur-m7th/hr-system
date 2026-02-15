async function loadHistoryTab() {
    const deptSelect = document.getElementById('historyFilterDepartment');
    const posSelect = document.getElementById('historyFilterPosition');
    try {
        const [depts, positions] = await Promise.all([
            fetch(`${API_BASE}/departments`).then(r => r.json()),
            fetch(`${API_BASE}/positions`).then(r => r.json())
        ]);
        deptSelect.innerHTML = `<option value="">${translations[currentLanguage].all_departments}</option>`;
        depts.forEach(d => deptSelect.appendChild(new Option(d, d)));
        posSelect.innerHTML = `<option value="">${translations[currentLanguage].all_positions}</option>`;
        positions.forEach(p => posSelect.appendChild(new Option(p, p)));
    } catch(e) { console.error("Error loading filters", e); }
    searchHistoryCandidates();
}

async function searchHistoryCandidates() {
    const dept = document.getElementById('historyFilterDepartment').value;
    const pos = document.getElementById('historyFilterPosition').value;
    const search = document.getElementById('historySearchEmployee').value;
    let url = `${API_BASE}/employees?`;
    const params = [];
    if (dept) params.push(`department=${encodeURIComponent(dept)}`);
    if (pos) params.push(`position=${encodeURIComponent(pos)}`);
    if (search) params.push(`search=${encodeURIComponent(search)}`);
    url += params.join('&');

    try {
        const res = await fetch(url);
        const employees = await res.json();
        renderHistoryCandidates(employees);
    } catch(e) { console.error(e); }
}

function renderHistoryCandidates(employees) {
    const container = document.getElementById('historyCandidatesList');
    container.innerHTML = "";
    if (employees.length === 0) {
        container.innerHTML = `<p>${currentLanguage === 'ar' ? 'لا يوجد موظفون.' : 'No employees found.'}</p>`;
        return;
    }
    const btnText = translations[currentLanguage].view_history;
    employees.forEach(emp => {
        const div = document.createElement('div');
        div.className = 'employee-card';
        div.innerHTML = `
            <div class="employee-name">${emp.name}</div>
            <div class="employee-info">${emp.position}</div>
            <div class="employee-info">${emp.department}</div>
            <button class="btn btn-primary btn-sm" style="width:100%; margin-top:10px;" onclick="viewEmployeeHistory(${emp.id}, '${emp.name}', ${emp.baseSalary})">
                ${btnText}
            </button>
        `;
        container.appendChild(div);
    });
}

function clearHistoryFilters() {
    document.getElementById('historyFilterDepartment').value = "";
    document.getElementById('historyFilterPosition').value = "";
    document.getElementById('historySearchEmployee').value = "";
    searchHistoryCandidates();
}

// ================= DETAIL VIEW & BULK ACTIONS =================

async function viewEmployeeHistory(empId, empName, baseSalary) {
    currentHistoryEmpId = empId;
    currentBaseSalary = baseSalary;
    
    document.getElementById('historyMainView').classList.add('hidden');
    document.getElementById('historyDetailView').classList.remove('hidden');
    
    const backBtn = document.getElementById('historyBackBtn');
    backBtn.classList.remove('hidden');
    backBtn.textContent = translations[currentLanguage].back_to_list;

    document.getElementById('historySelectedEmpName').textContent = empName;
    document.getElementById('historyBulkActions').style.display = 'none';

    const timelineContainer = document.getElementById('historyTimelineResults');
    timelineContainer.innerHTML = `<p>${translations[currentLanguage].loading}</p>`;

    try {
        const res = await fetch(`${API_BASE}/employee/stats?id=${empId}`);
        if(!res.ok) throw new Error("Failed to load stats");
        const data = await res.json();
        
        document.getElementById('statTotalPaid').textContent = formatMoney(data.totalPaid);
        document.getElementById('statPastUnpaid').textContent = formatMoney(data.pastUnpaid);
        document.getElementById('statTotalContract').textContent = data.totalContractValue > 0 ? formatMoney(data.totalContractValue) : "∞";
        document.getElementById('statToBePaid').textContent = data.totalContractValue > 0 ? formatMoney(data.toBePaid) : "---";

        timelineContainer.innerHTML = "";
        
        if(data.timeline.length === 0) {
            timelineContainer.innerHTML = `<p>${translations[currentLanguage].no_history}</p>`;
            return;
        }

        const netLabel = translations[currentLanguage].net_salary;

        data.timeline.forEach(item => {
            const div = document.createElement('div');
            div.className = "timeline-row";
            
            let statusClass = "status-future";
            let statusText = item.status;
            let checkValue = "";
            let canSelect = false;

            if(currentLanguage === 'ar') {
                if(item.status === 'Paid') statusText = 'مدفوع';
                else if(item.status === 'Unpaid') statusText = 'غير مدفوع';
                else if(item.status === 'Future') statusText = 'مستقبل';
                else if(item.status === 'Excluded') statusText = 'مستثنى';
            }

            if(item.status === 'Paid') {
                statusClass = "status-paid";
                checkValue = `DELETE:${item.paymentId}`;
                canSelect = true;
            } else if(item.status === 'Unpaid') {
                statusClass = "status-unpaid";
                checkValue = `PAY:${item.month}`;
                canSelect = true;
            } else if(item.status === 'Excluded') {
                statusClass = "status-excluded";
            }

            div.innerHTML = `
                <div class="t-period">
                    <div style="display:flex; align-items:center; gap:10px;">
                        ${canSelect ? `<input type="checkbox" class="history-chk" value="${checkValue}" onchange="updateBulkActions()">` : ''}
                        <strong>${formatPayPeriod(item.month)}</strong>
                    </div>
                    <span class="badge ${statusClass}">${statusText}</span>
                </div>
                <div class="t-details">
                    <span>${netLabel}: ${formatMoney(item.amount)}</span>
                    <div style="float:right; display:flex; gap:5px;">
                        ${item.status === 'Paid' ? `<button class="btn btn-sm btn-secondary" onclick="triggerDocUpload(${item.paymentId})" title="${translations[currentLanguage].upload_btn_tooltip || 'Upload'}">📂</button>` : ''}
                        ${item.docPath ? `<a href="/generated/${item.docPath}" target="_blank" class="btn btn-sm btn-secondary">📄</a>` : ''}
                    </div>
                </div>
            `;
            timelineContainer.appendChild(div);
        });

    } catch (e) { 
        console.error(e);
        timelineContainer.innerHTML = "<p>Error.</p>";
    }
}

function updateBulkActions() {
    const checkboxes = document.querySelectorAll('.history-chk:checked');
    const bar = document.getElementById('historyBulkActions');
    const countSpan = document.getElementById('bulkSelectionCount');
    const btnPayGen = document.getElementById('btnBulkPayGen');
    const btnPay = document.getElementById('btnBulkPay');
    const btnDelete = document.getElementById('btnBulkDelete');

    if(checkboxes.length === 0) {
        bar.style.display = 'none';
        return;
    }

    bar.style.display = 'flex';
    const selectedText = translations[currentLanguage].employees_selected || 'selected';
    countSpan.textContent = `${checkboxes.length} ${selectedText}`;

    let hasPay = false;
    let hasDelete = false;

    checkboxes.forEach(c => {
        if(c.value.startsWith("PAY:")) hasPay = true;
        if(c.value.startsWith("DELETE:")) hasDelete = true;
    });

    if(hasPay && hasDelete) {
        btnPayGen.style.display = 'none';
        btnPay.style.display = 'none';
        btnDelete.style.display = 'none';
    } else {
        btnPayGen.style.display = hasPay ? 'inline-block' : 'none';
        btnPay.style.display = hasPay ? 'inline-block' : 'none';
        btnDelete.style.display = hasDelete ? 'inline-block' : 'none';
    }
}

async function processBulkPay(withGenerate) {
    const checkboxes = document.querySelectorAll('.history-chk:checked');
    const monthsToPay = [];
    checkboxes.forEach(c => {
        if(c.value.startsWith("PAY:")) monthsToPay.push(c.value.split(":")[1]);
    });

    const msg = currentLanguage === 'ar' ? `دفع ${monthsToPay.length} أشهر؟` : `Pay ${monthsToPay.length} months?`;
    if(!confirm(msg)) return;

    for (const month of monthsToPay) {
        if (withGenerate) {
            const payload = { employeeIds: [currentHistoryEmpId], payPeriod: month, bonus: 0, deductions: 0 };
            await fetch(`${API_BASE}/generate-payslips`, {
                method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload)
            });
        } else {
            const payload = {
                employeeId: currentHistoryEmpId, payPeriod: month, baseSalary: currentBaseSalary,
                bonus: 0, deductions: 0, netSalary: currentBaseSalary 
            };
            await fetch(`${API_BASE}/payments/add`, {
                method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload)
            });
        }
    }
    viewEmployeeHistory(currentHistoryEmpId, document.getElementById('historySelectedEmpName').textContent, currentBaseSalary);
}

async function processBulkDelete() {
    const checkboxes = document.querySelectorAll('.history-chk:checked');
    const idsToDelete = [];
    const monthsToExclude = [];

    checkboxes.forEach(c => {
        if(c.value.startsWith("DELETE:")) idsToDelete.push(c.value.split(":")[1]);
        if(c.value.startsWith("PAY:")) monthsToExclude.push(c.value.split(":")[1]); 
    });

    const msg = currentLanguage === 'ar' ? `حذف ${idsToDelete.length + monthsToExclude.length} سجلات؟` : `Delete ${idsToDelete.length + monthsToExclude.length} items?`;
    if(!confirm(msg)) return;

    for (const id of idsToDelete) {
        await fetch(`${API_BASE}/payments/delete?id=${id}`, {method: 'DELETE'});
    }

    if (monthsToExclude.length > 0) {
        await fetch(`${API_BASE}/employees/exclude-bulk`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ employeeId: currentHistoryEmpId, months: monthsToExclude })
        });
    }

    viewEmployeeHistory(currentHistoryEmpId, document.getElementById('historySelectedEmpName').textContent, currentBaseSalary);
}

function triggerDocUpload(paymentId) {
    currentUploadPaymentId = paymentId;
    document.getElementById('manualDocUpload').click();
}

async function handleDocUpload(input) {
    if(!input.files[0] || !currentUploadPaymentId) return;
    const formData = new FormData();
    formData.append('document', input.files[0]);
    formData.append('paymentId', currentUploadPaymentId);
    try {
        const res = await fetch(`${API_BASE}/payments/upload-doc`, { method: 'POST', body: formData });
        if(res.ok) {
            alert(currentLanguage === 'ar' ? "تم الرفع" : "File Uploaded");
            viewEmployeeHistory(currentHistoryEmpId, document.getElementById('historySelectedEmpName').textContent, currentBaseSalary);
        } else alert("Error");
    } catch(e) { alert("Error"); }
    input.value = "";
}

function backToHistoryList() {
    document.getElementById('historyMainView').classList.remove('hidden');
    document.getElementById('historyDetailView').classList.add('hidden');
    document.getElementById('historyBackBtn').classList.add('hidden');
    currentHistoryEmpId = null;
}