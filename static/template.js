async function loadTemplateInfo() {
    const container = document.getElementById('templateInfo');
    if(!container) return;
    
    try {
        const res = await fetch(`${API_BASE}/templates`);
        const templates = await res.json();
        
        if (templates.length === 0) {
            container.innerHTML = `<p>${translations[currentLanguage].no_template || "No template."}</p>`;
            return;
        }

        let html = '<ul class="template-list">';
        templates.forEach(t => {
            const activeClass = t.isActive ? 'active-template' : '';
            const activeText = t.isActive ? `<span class="badge status-paid">${translations[currentLanguage].active || "(Active)"}</span>` : '';
            const setBtn = !t.isActive ? `<button class="btn btn-sm btn-secondary" onclick="setActiveTemplate('${t.name}')">${translations[currentLanguage].set_active || "Set Active"}</button>` : '';
            
            // HIDE EXTENSION HERE
            const displayName = t.name.replace(/\.[^/.]+$/, "");

            html += `
            <li class="${activeClass}" style="display:flex; justify-content:space-between; align-items:center; padding:10px; border-bottom:1px solid #eee;">
                <span>
                    <strong>${displayName}</strong> <br>
                    <small style="color:#666">${t.updatedAt}</small>
                    ${activeText}
                </span>
                <div>
                    ${setBtn}
                    <button class="btn btn-sm btn-danger" onclick="deleteTemplate('${t.name}')">🗑</button>
                </div>
            </li>`;
        });
        html += '</ul>';
        container.innerHTML = html;
        
    } catch(e) { console.error(e); }
}

function handleFileSelect(event) {
    const file = event.target.files[0];
    if (file) {
        // Show name without extension in upload preview too
        const name = file.name.replace(/\.[^/.]+$/, "");
        document.getElementById('selectedFileName').textContent = name;
        document.getElementById('uploadBtn').disabled = false;
    }
}

async function uploadTemplate() {
    const fileInput = document.getElementById('templateFile');
    const file = fileInput.files[0];
    if (!file) return;

    const formData = new FormData();
    formData.append('template', file);

    try {
        const response = await fetch(`${API_BASE}/template/upload`, {
            method: 'POST',
            body: formData
        });

        if (response.ok) {
            alert(currentLanguage === 'ar' ? 'تم الرفع' : 'Template uploaded!');
            fileInput.value = ''; 
            document.getElementById('selectedFileName').textContent = '';
            document.getElementById('uploadBtn').disabled = true;
            loadTemplateInfo();
        } else {
            alert('Upload failed');
        }
    } catch (error) {
        alert('Error: ' + error.message);
    }
}

async function setActiveTemplate(filename) {
    await fetch(`${API_BASE}/template/activate`, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({filename})
    });
    loadTemplateInfo();
}

async function deleteTemplate(filename) {
    if(!confirm(currentLanguage === 'ar' ? 'حذف؟' : 'Delete?')) return;
    await fetch(`${API_BASE}/template/delete?filename=${filename}`, {method: 'DELETE'});
    loadTemplateInfo();
}