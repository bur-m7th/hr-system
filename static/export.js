// ============ EXPORT ============

function exportDepartmentData() {
    const select = document.getElementById('exportDepartment');
    if (select.options.length <= 1) loadFilterOptions();
    document.getElementById('exportModal').style.display = 'block';
}

async function exportDepartment(e) {
    e.preventDefault();
    const department = document.getElementById('exportDepartment').value;
    if (!department) { alert(currentLanguage === 'ar' ? 'يرجى الاختيار' : 'Please select'); return; }
    try {
        const response = await fetch(`${API_BASE}/export/department?department=${encodeURIComponent(department)}`);
        if (!response.ok) throw new Error('Failed');
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${department}_employees_${new Date().toISOString().split('T')[0]}.csv`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        window.URL.revokeObjectURL(url);
        closeExportModal();
        showMessage(currentLanguage === 'ar' ? 'تم التصدير!' : 'Exported!', 'success');
    } catch (error) { showMessage('Error: ' + error.message, 'error'); }
}

function closeExportModal() { document.getElementById('exportModal').style.display = 'none'; }