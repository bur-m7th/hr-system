// ============ EMPLOYEE FILES (Photos & Documents) ============

let currentFilesEmpId = null;

async function showEmployeeFilesModal(empId, empName) {
    currentFilesEmpId = empId;
    document.getElementById('filesModalTitle').textContent = empName;
    document.getElementById('employeeFilesModal').style.display = 'block';
    await loadEmployeeFiles(empId);
}

async function loadEmployeeFiles(empId) {
    try {
        const res = await fetch(`${API_BASE}/employee/files?employeeId=${empId}`);
        const files = await res.json();
        renderEmployeeFiles(files);
    } catch(e) {
        console.error(e);
    }
}

function renderEmployeeFiles(files) {
    const photo = files.find(f => f.fileType === 'photo');
    const docs = files.filter(f => f.fileType === 'document');

    // Photo section
    const photoContainer = document.getElementById('empPhotoContainer');
    if (photo) {
        photoContainer.innerHTML = `
            <img src="/employee_files/${photo.fileName}" alt="Employee Photo"
                 style="width:150px;height:150px;object-fit:cover;border-radius:50%;border:3px solid #28a140;display:block;margin:0 auto;">
            <div style="margin-top:10px;display:flex;gap:8px;justify-content:center;">
                <button class="btn btn-sm btn-secondary" onclick="triggerEmpFileUpload('photo')">🔄 Replace Photo</button>
                <button class="btn btn-sm btn-danger" onclick="deleteEmployeeFile(${photo.id})">🗑 Remove</button>
            </div>`;
    } else {
        photoContainer.innerHTML = `
            <div style="width:150px;height:150px;border-radius:50%;border:3px dashed #ccc;display:flex;align-items:center;justify-content:center;font-size:3em;margin:0 auto;background:#f9f9f9;">👤</div>
            <div style="margin-top:10px;text-align:center;">
                <button class="btn btn-sm btn-primary" onclick="triggerEmpFileUpload('photo')">📷 Upload Photo</button>
            </div>`;
    }

    // Documents section
    const docsContainer = document.getElementById('empDocsContainer');
    if (docs.length === 0) {
        docsContainer.innerHTML = `<p style="color:#999;text-align:center;padding:20px;">No documents uploaded yet.</p>`;
    } else {
        docsContainer.innerHTML = docs.map(doc => `
            <div style="display:flex;align-items:center;justify-content:space-between;padding:12px;border:1px solid #eee;border-radius:6px;margin-bottom:8px;background:#fafafa;">
                <div>
                    <strong>${doc.originalName}</strong>
                    ${doc.description ? `<br><small style="color:#555;">📌 ${doc.description}</small>` : ''}
                    <br><small style="color:#999;">🕒 ${doc.uploadedAt}</small>
                </div>
                <div style="display:flex;gap:5px;flex-shrink:0;margin-left:10px;">
                    <a href="/employee_files/${doc.fileName}" target="_blank" class="btn btn-sm btn-secondary">📥 Download</a>
                    <button class="btn btn-sm btn-danger" onclick="deleteEmployeeFile(${doc.id})">🗑</button>
                </div>
            </div>
        `).join('');
    }
}

function triggerEmpFileUpload(fileType) {
    const input = document.getElementById('empFileInput');
    input.setAttribute('data-filetype', fileType);
    if (fileType === 'photo') {
        input.accept = '.jpg,.jpeg,.png,.webp';
    } else {
        input.accept = '.pdf,.jpg,.jpeg,.png,.docx';
    }
    input.click();
}

async function handleEmpFileUpload(input) {
    const file = input.files[0];
    if (!file || !currentFilesEmpId) return;
    const fileType = input.getAttribute('data-filetype');

    let description = '';
    if (fileType === 'document') {
        description = prompt(currentLanguage === 'ar'
            ? 'وصف المستند (مثال: رقم وطني، جواز سفر):'
            : 'Document description (e.g. National ID, Passport):') || '';
    }

    const formData = new FormData();
    formData.append('file', file);
    formData.append('employeeId', currentFilesEmpId);
    formData.append('fileType', fileType);
    formData.append('description', description);

    try {
        const res = await fetch(`${API_BASE}/employee/files/upload`, { method: 'POST', body: formData });
        if (res.ok) {
            await loadEmployeeFiles(currentFilesEmpId);
            await loadEmployees();
            showMessage(currentLanguage === 'ar' ? 'تم رفع الملف!' : 'File uploaded!', 'success');
        } else {
            const err = await res.text();
            showMessage('Error: ' + err, 'error');
        }
    } catch(e) {
        showMessage(currentLanguage === 'ar' ? 'خطأ في الرفع' : 'Upload error', 'error');
    }
    input.value = '';
}

async function deleteEmployeeFile(fileId) {
    if (!confirm(currentLanguage === 'ar' ? 'حذف هذا الملف؟' : 'Delete this file?')) return;
    try {
        const res = await fetch(`${API_BASE}/employee/files/delete?id=${fileId}`, { method: 'DELETE' });
        if (res.ok) {
            await loadEmployeeFiles(currentFilesEmpId);
            await loadEmployees();
            showMessage(currentLanguage === 'ar' ? 'تم الحذف' : 'File deleted', 'success');
        }
    } catch(e) {
        showMessage(currentLanguage === 'ar' ? 'خطأ في الحذف' : 'Error deleting file', 'error');
    }
}

function closeFilesModal() {
    document.getElementById('employeeFilesModal').style.display = 'none';
    currentFilesEmpId = null;
}