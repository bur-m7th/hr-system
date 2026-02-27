async function displayEmployees() {
    const container = document.getElementById('employeesList');
    if (!container) return;
    if (employees.length === 0) {
        container.innerHTML = `<p>${currentLanguage === 'ar' ? 'لا يوجد موظفون.' : 'No employees found.'}</p>`;
        return;
    }
    container.innerHTML = '';
    employees.forEach(employee => {
        const card = document.createElement('div');
        card.className = 'employee-card';

        const safePos = employee.position ? employee.position.replace(/'/g, "\\'") : "";
        const safeDept = employee.department ? employee.department.replace(/'/g, "\\'") : "";
        const safeNameForJs = employee.name ? employee.name.replace(/'/g, "\\'") : "";

        const contractInfo = calculateContractRemaining(employee.contractStart, employee.contractEnd);
        const contractBadge = getContractBadge(contractInfo);

        const photoHtml = employee.photoUrl
            ? `<img src="${employee.photoUrl}" style="width:60px;height:60px;object-fit:cover;border-radius:50%;float:right;margin-left:10px;border:2px solid #28a140;">`
            : `<div style="width:60px;height:60px;border-radius:50%;background:#e0e0e0;display:inline-flex;align-items:center;justify-content:center;font-size:1.5em;float:right;margin-left:10px;">👤</div>`;

        card.innerHTML = `
            <div style="overflow:hidden;">
                ${photoHtml}
                <div class="employee-name">${employee.name}</div>
                ${contractBadge}
            </div>
            <div class="employee-info">📧 ${employee.email || "---"}</div>
            <div class="employee-info">💼 ${employee.position}</div>
            <div class="employee-info">🏢 ${employee.department}</div>
            <div class="employee-info">💰 ${formatMoney(employee.baseSalary)}</div>
            <div class="employee-info">📅 ${employee.contractStart} ${employee.contractEnd ? 'to ' + employee.contractEnd : ''}</div>
            <div class="employee-actions">
                <button class="btn btn-secondary btn-sm" onclick="editEmployee(${employee.id})">${translations[currentLanguage].edit}</button>
                <button class="btn btn-primary btn-sm" onclick="showRenewModal(${employee.id}, ${employee.baseSalary}, '${safePos}', '${safeDept}')">${translations[currentLanguage].renew_btn}</button>
                <button class="btn btn-secondary btn-sm" onclick="showEmployeeFilesModal(${employee.id}, '${safeNameForJs}')">📁 Files</button>
                <button class="btn btn-danger btn-sm" onclick="deleteEmployee(${employee.id})">${translations[currentLanguage].delete}</button>
            </div>
        `;
        container.appendChild(card);
    });
}

// NEW: Calculate months remaining in contract
function calculateContractRemaining(startDate, endDate) {
    const today = new Date();

    // If no end date, contract is indefinite
    if (!endDate || endDate === '') {
        return {
            type: 'indefinite',
            monthsRemaining: null,
            daysRemaining: null,
            isExpired: false,
            isExpiringSoon: false
        };
    }

    const end = new Date(endDate);
    const diffTime = end - today;
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
    const diffMonths = Math.floor(diffDays / 30);

    return {
        type: 'fixed',
        monthsRemaining: diffMonths,
        daysRemaining: diffDays,
        isExpired: diffDays < 0,
        isExpiringSoon: diffDays > 0 && diffDays <= 90, // Within 3 months
        exactDate: end
    };
}

// NEW: Generate contract status badge
function getContractBadge(info) {
    if (info.type === 'indefinite') {
        const text = currentLanguage === 'ar' ? '∞ عقد مفتوح' : '∞ Open-ended Contract';
        return `<div class="contract-badge contract-indefinite">${text}</div>`;
    }

    if (info.isExpired) {
        const text = currentLanguage === 'ar'
            ? `⚠️ منتهي منذ ${Math.abs(info.monthsRemaining)} شهر`
            : `⚠️ Expired ${Math.abs(info.monthsRemaining)} months ago`;
        return `<div class="contract-badge contract-expired">${text}</div>`;
    }

    if (info.isExpiringSoon) {
        const text = currentLanguage === 'ar'
            ? `⏰ ${info.monthsRemaining} شهر متبقي (${info.daysRemaining} يوم)`
            : `⏰ ${info.monthsRemaining} months left (${info.daysRemaining} days)`;
        return `<div class="contract-badge contract-expiring">${text}</div>`;
    }

    // More than 3 months remaining
    const text = currentLanguage === 'ar'
        ? `✓ ${info.monthsRemaining} شهر متبقي`
        : `✓ ${info.monthsRemaining} months remaining`;
    return `<div class="contract-badge contract-active">${text}</div>`;
}

function showRenewModal(empId, currentSalary, currentPos, currentDept) {
    document.getElementById('renewEmpId').value = empId;
    document.getElementById('renewSalary').value = currentSalary;
    document.getElementById('renewPosition').value = currentPos;
    document.getElementById('renewDepartment').value = currentDept;
    document.getElementById('renewDate').value = new Date().toISOString().split('T')[0];
    document.getElementById('renewContractModal').style.display = 'block';
}

function closeRenewModal() {
    document.getElementById('renewContractModal').style.display = 'none';
}

async function submitRenewContract(e) {
    e.preventDefault();
    const payload = {
        employeeId: parseInt(document.getElementById('renewEmpId').value),
        newSalary: parseFloat(document.getElementById('renewSalary').value),
        newPosition: document.getElementById('renewPosition').value,
        newDepartment: document.getElementById('renewDepartment').value,
        startDate: document.getElementById('renewDate').value
    };

    if (!confirm(translations[currentLanguage].confirm_renew)) return;

    try {
        const res = await fetch(`${API_BASE}/employees/renew-contract`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        if (res.ok) {
            showMessage(translations[currentLanguage].renew_success, 'success');
            closeRenewModal();
            loadEmployees();
        } else {
            const error = await res.text();
            showMessage("Error: " + error, 'error');
        }
    } catch (e) {
        console.error(e);
        showMessage(translations[currentLanguage].error_network, 'error');
    }
}

function showAddEmployeeModal() {
    document.getElementById('modalTitle').textContent = translations[currentLanguage].add_employee;
    document.getElementById('employeeForm').reset();
    document.getElementById('employeeId').value = '';
    renderMonthCheckboxes();

    // Setup searchable dropdowns for add mode
    setupSearchableDropdown('empPosition', 'position');
    setupSearchableDropdown('empDepartment', 'department');

    document.getElementById('employeeModal').style.display = 'block';
}

function renderMonthCheckboxes(excludedString = "") {
    const container = document.getElementById('excludedMonthsContainer');
    if (!container) return;
    container.innerHTML = "";
    const excluded = excludedString ? excludedString.split(',') : [];
    const months = currentLanguage === 'ar' ?
        ["يناير", "فبراير", "مارس", "أبريل", "مايو", "يونيو", "يوليو", "أغسطس", "سبتمبر", "أكتوبر", "نوفمبر", "ديسمبر"] :
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

    months.forEach((m, index) => {
        const monthNum = (index + 1).toString();
        const lbl = document.createElement('label');
        lbl.style.display = 'flex';
        lbl.style.alignItems = 'center';
        lbl.innerHTML = `<input type="checkbox" value="${monthNum}" ${excluded.includes(monthNum) ? 'checked' : ''} style="width: auto; margin-right: 5px;"> ${m}`;
        container.appendChild(lbl);
    });
}

function editEmployee(id) {
    const employee = employees.find(e => e.id === id);
    if (!employee) return;

    document.getElementById('modalTitle').textContent = translations[currentLanguage].edit;
    document.getElementById('employeeId').value = employee.id;
    document.getElementById('empName').value = employee.name;
    document.getElementById('empEmail').value = employee.email || '';
    document.getElementById('empPosition').value = employee.position;
    document.getElementById('empDepartment').value = employee.department;
    document.getElementById('empSalary').value = employee.baseSalary;
    document.getElementById('empPhone').value = employee.phoneNumber || '';
    document.getElementById('empContractStart').value = employee.contractStart;
    document.getElementById('empContractEnd').value = employee.contractEnd || '';
    document.getElementById('empAddress').value = employee.address || '';
    document.getElementById('empNationalId').value = employee.nationalId || '';

    renderMonthCheckboxes(employee.excludedMonths || "");

    // Setup searchable dropdowns for edit mode
    setupSearchableDropdown('empPosition', 'position');
    setupSearchableDropdown('empDepartment', 'department');

    document.getElementById('employeeModal').style.display = 'block';
}

async function saveEmployee(e) {
    e.preventDefault();
    const checkboxes = document.querySelectorAll('#excludedMonthsContainer input:checked');
    const excluded = Array.from(checkboxes).map(c => c.value).join(',');

    const employeeData = {
        id: parseInt(document.getElementById('employeeId').value) || 0,
        name: document.getElementById('empName').value,
        email: document.getElementById('empEmail').value,
        position: document.getElementById('empPosition').value,
        department: document.getElementById('empDepartment').value,
        baseSalary: parseFloat(document.getElementById('empSalary').value),
        phoneNumber: document.getElementById('empPhone').value,
        contractStart: document.getElementById('empContractStart').value,
        contractEnd: document.getElementById('empContractEnd').value,
        address: document.getElementById('empAddress').value,
        nationalId: document.getElementById('empNationalId').value,
        excludedMonths: excluded,
        contractId: 0
    };

    // For updates, find the contract ID
    if (employeeData.id > 0) {
        const emp = employees.find(e => e.id === employeeData.id);
        if (emp) {
            employeeData.contractId = emp.contractID;
        }
    }

    const isUpdate = employeeData.id > 0;
    const endpoint = isUpdate ? '/employees/update' : '/employees/add';
    const method = isUpdate ? 'PUT' : 'POST';

    try {
        const response = await fetch(`${API_BASE}${endpoint}`, {
            method: method,
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(employeeData)
        });

        if (!response.ok) {
            const error = await response.text();
            throw new Error(error || 'Failed to save');
        }

        closeEmployeeModal();
        await loadEmployees();
        await loadFilterOptions();
        showMessage(isUpdate ? translations[currentLanguage].success_employee_updated : translations[currentLanguage].success_employee_added, 'success');
    } catch (error) {
        showMessage('Error: ' + error.message, 'error');
    }
}

async function deleteEmployee(id) {
    if (!confirm(currentLanguage === 'ar' ? 'هل أنت متأكد؟' : 'Are you sure?')) return;
    try {
        const response = await fetch(`${API_BASE}/employees/delete?id=${id}`, { method: 'DELETE' });
        if (!response.ok) throw new Error('Failed');
        await loadEmployees();
        await loadFilterOptions();
        showMessage(translations[currentLanguage].success_employee_deleted, 'success');
    } catch (error) {
        showMessage('Error: ' + error.message, 'error');
    }
}

function closeEmployeeModal() {
    document.getElementById('employeeModal').style.display = 'none';
}

async function loadFilterOptions() {
    try {
        const [deptResponse, posResponse] = await Promise.all([
            fetch(`${API_BASE}/departments`),
            fetch(`${API_BASE}/positions`)
        ]);
        if (deptResponse.ok) updateDepartmentFilters(await deptResponse.json());
        if (posResponse.ok) updatePositionFilters(await posResponse.json());
    } catch (error) { console.error(error); }
}

function updateDepartmentFilters(departments) {
    window.allDepartments = departments;

    const selects = ['filterDepartment', 'genFilterDepartment', 'exportDepartment', 'historyFilterDepartment'];
    selects.forEach(id => {
        const select = document.getElementById(id);
        if (select) {
            const current = select.value;
            const defText = id === 'exportDepartment' ? (translations[currentLanguage].select_department_option) : translations[currentLanguage].all_departments;
            select.innerHTML = `<option value="">${defText}</option>`;
            departments.forEach(dept => select.appendChild(new Option(dept, dept)));
            select.value = current;
        }
    });
}

function updatePositionFilters(positions) {
    window.allPositions = positions;

    const selects = ['filterPosition', 'genFilterPosition', 'historyFilterPosition'];
    selects.forEach(id => {
        const select = document.getElementById(id);
        if (select) {
            const current = select.value;
            select.innerHTML = `<option value="">${translations[currentLanguage].all_positions}</option>`;
            positions.forEach(pos => select.appendChild(new Option(pos, pos)));
            select.value = current;
        }
    });
}

function setupSearchableDropdown(inputId, type) {
    const input = document.getElementById(inputId);
    if (!input) return;

    const suggestions = type === 'department' ? (window.allDepartments || []) : (window.allPositions || []);

    const existingDatalist = document.getElementById(inputId + '_datalist');
    if (existingDatalist) existingDatalist.remove();

    const datalist = document.createElement('datalist');
    datalist.id = inputId + '_datalist';
    suggestions.forEach(item => {
        const option = document.createElement('option');
        option.value = item;
        datalist.appendChild(option);
    });

    input.setAttribute('list', datalist.id);
    input.parentNode.appendChild(datalist);
}

async function applyFilters() {
    const department = document.getElementById('filterDepartment').value;
    const position = document.getElementById('filterPosition').value;
    const search = document.getElementById('searchEmployee').value;
    let url = `${API_BASE}/employees?`;
    const params = [];
    if (department) params.push(`department=${encodeURIComponent(department)}`);
    if (position) params.push(`position=${encodeURIComponent(position)}`);
    if (search) params.push(`search=${encodeURIComponent(search)}`);
    url += params.join('&');

    try {
        const response = await fetch(url);
        employees = await response.json();
        displayEmployees();
    } catch (error) {
        console.error(error);
        showMessage('Error loading employees', 'error');
    }
}

function clearFilters() {
    document.getElementById('filterDepartment').value = '';
    document.getElementById('filterPosition').value = '';
    document.getElementById('searchEmployee').value = '';
    loadEmployees();
}

async function loadEmployees() {
    try {
        const response = await fetch(`${API_BASE}/employees`);
        employees = await response.json();
        await loadEmployeePhotos();
        displayEmployees();
    } catch (error) {
        console.error(error);
        showMessage('Error loading employees', 'error');
    }
}

async function loadEmployeePhotos() {
    for (const emp of employees) {
        try {
            const res = await fetch(`${API_BASE}/employee/files?employeeId=${emp.id}`);
            const files = await res.json();
            const photo = files.find(f => f.fileType === 'photo');
            emp.photoUrl = photo ? `/employee_files/${photo.fileName}` : null;
        } catch (e) {
            emp.photoUrl = null;
        }
    }
}