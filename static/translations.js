const translations = {
    en: {
        app_title: "Payroll Management System",

        // Tabs
        tab_employees: "👥 Employees",
        tab_generate: "💰 Generate Payslips",
        tab_history: "📊 Payment History",
        tab_template: "📄 Template",

        // User Menu
        add_user: "➕ Add User",
        setup_2fa: "🔐 Setup 2FA",
        change_password: "🔑 Change Password",
        delete_account: "❌ Delete Account",
        logout: "🚪 Logout",

        setup_2fa_step1: "1. Scan this QR code with Google Authenticator or Authy",
        setup_2fa_step2: "2. Enter the 6-digit code below to confirm",

        // Employee Tab
        employee_management: "Employee Management",
        export_department: "📊 Export Dept",
        export_full_db: "💾 Export Full DB",
        add_employee: "+ Add Employee",
        filter_department: "Department",
        filter_position: "Position",
        search_employee: "Search",
        search_placeholder: "Search name/email...",
        clear_filters: "Clear",
        all_departments: "All Departments",
        all_positions: "All Positions",

        // Generate Tab
        generate_payslips: "Generate Payslips",
        employees_selected: "selected",
        clear_selection: "Clear",
        pay_period: "Pay Period",
        bonus: "Bonus (BHD)",
        deductions: "Deductions (BHD)",
        generate_payslips_btn: "Generate Payslips",
        generated_payslips: "Generated Payslips",
        download_all: "📥 Download All Payslips",

        // History Tab
        payment_history: "Payment History",
        add_past_record: "+ Add Past Record",
        back_to_list: "⬅ Back to List",
        stat_total_paid: "Total Paid",
        stat_past_unpaid: "Past Unpaid",
        stat_contract_total: "Contract Total",
        stat_remaining: "Remaining",
        bulk_actions: "Bulk Actions:",
        bulk_pay_gen: "💰 Pay + Generate",
        bulk_pay_only: "💵 Pay Only",
        bulk_delete: "🗑 Delete/Exclude",
        view_history: "📄 View History",
        loading: "Loading...",
        no_history: "No history data available.",
        net_salary: "Net",

        // Template Tab
        document_template: "Document Template",
        no_template: "No template uploaded yet.",
        upload_template: "Upload New Template",
        choose_template: "📤 Choose File",
        upload_btn: "Upload",
        template_guide_title: "How to Create Your Template",
        template_guide_intro: "Use these placeholders in your Word document:",
        available_placeholders: "Available placeholders:",

        // Forms & Modals
        full_name: "Full Name *",
        email: "Email",
        position: "Position *",
        department: "Department *",
        base_salary: "Base Salary (BHD) *",
        phone_number: "Phone Number",
        contract_start: "Contract Start *",
        contract_end: "Contract End",
        excluded_months: "Excluded Months (Unpaid)",
        address: "Address",
        national_id: "National ID / SSN",
        save_employee: "Save Employee",
        cancel: "Cancel",

        // Renew Contract
        renew_btn: "📜 Renew",
        renew_title: "Renew Contract / Promotion",
        renew_desc: "This will archive the current contract and start a new one.",
        new_position: "New Position",
        new_department: "New Department",
        new_salary: "New Base Salary (BHD)",
        effective_date: "Effective Start Date",
        start_contract_btn: "Start New Contract",
        confirm_renew: "Are you sure? This will archive the current contract.",
        renew_success: "Contract Renewed!",

        // Payment Modal
        add_past_payment: "Add Past Payment Record",
        select_employee: "Select Employee *",
        select_employee_option: "-- Select an employee --",
        add_record: "Add Record",

        // Export Modal
        export_department_data: "Export Department Data",
        select_department: "Select Department *",
        select_department_option: "-- Select a department --",
        export_excel: "📊 Export to Excel",

        // Error Messages
        error_invalid_credentials: "Invalid username or password",
        error_no_template: "No template uploaded. Please upload a template first.",
        error_template_invalid: "Template validation failed. Please upload a valid template.",
        error_network: "Network error. Please check your connection.",
        error_server: "Server error. Please try again.",
        error_required_fields: "Please fill in all required fields",

        // Success Messages
        success_employee_added: "Employee added successfully",
        success_employee_updated: "Employee updated successfully",
        success_employee_deleted: "Employee deleted",
        success_payslips_generated: "Payslips generated successfully",
        success_template_uploaded: "Template uploaded successfully",

        // Misc
        edit: "Edit",
        delete: "Delete",
        upload_btn_tooltip: "Upload Document",
        set_active: "Set Active",
        active: "(Active)",

        ph_name: "Name", ph_id: "ID", ph_position: "Position", ph_department: "Department",
        ph_email: "Email", ph_phone: "Phone", ph_address: "Address", ph_national_id: "National ID",
        ph_base_salary: "Base Salary", ph_bonus: "Bonus", ph_deductions: "Deductions",
        ph_net_salary: "Net Salary", ph_pay_period: "Pay Period", ph_contract_start: "Start Date",
        ph_contract_end: "End Date", ph_generated_date: "Generated Date",

        // Contract Status
        contract_indefinite: "∞ Open-ended Contract",
        contract_expired: "⚠️ Expired",
        contract_expiring: "⏰ Expiring Soon",
        contract_active: "✓ Active Contract",
        months_remaining: "months remaining",
        months_left: "months left",
        days_left: "days",
        expired_since: "Expired",
        months_ago: "months ago",
    },
    ar: {
        app_title: "نظام إدارة الرواتب",
        tab_employees: "👥 الموظفون",
        tab_generate: "💰 إصدار الرواتب",
        tab_history: "📊 السجل",
        tab_template: "📄 النماذج",
        add_user: "➕ إضافة مستخدم",
        setup_2fa: "🔐 المصادقة الثنائية",
        change_password: "🔑 تغيير كلمة المرور",
        delete_account: "❌ حذف الحساب",
        logout: "🚪 خروج",

        setup_2fa_step1: "1. امسح الكود باستخدام تطبيق Google Authenticator",
        setup_2fa_step2: "2. أدخل الرمز المكون من 6 أرقام للتأكيد",

        employee_management: "إدارة الموظفين",
        export_department: "📊 تصدير قسم",
        export_full_db: "💾 تصدير الكل",
        add_employee: "+ إضافة موظف",
        filter_department: "القسم",
        filter_position: "المنصب",
        search_employee: "بحث",
        search_placeholder: "بحث بالاسم...",
        clear_filters: "مسح",
        all_departments: "كل الأقسام",
        all_positions: "كل المناصب",
        generate_payslips: "إصدار قسائم الرواتب",
        employees_selected: "محدد",
        clear_selection: "مسح",
        pay_period: "فترة الدفع",
        bonus: "مكافأة (دينار)",
        deductions: "خصومات (دينار)",
        generate_payslips_btn: "إصدار القسائم",
        generated_payslips: "القسائم المصدرة",
        download_all: "📥 تحميل جميع القسائم",
        payment_history: "سجل المدفوعات",
        add_past_record: "+ سجل سابق",
        back_to_list: "⬅ عودة للقائمة",
        stat_total_paid: "إجمالي المدفوع",
        stat_past_unpaid: "غير مدفوع (سابق)",
        stat_contract_total: "إجمالي العقد",
        stat_remaining: "المتبقي",
        bulk_actions: "إجراءات جماعية:",
        bulk_pay_gen: "💰 دفع + إصدار",
        bulk_pay_only: "💵 دفع فقط",
        bulk_delete: "🗑 حذف/استثناء",
        view_history: "📄 عرض السجل",
        loading: "جاري التحميل...",
        no_history: "لا يوجد سجل مدفوعات.",
        net_salary: "الصافي",

        document_template: "نموذج المستند",
        no_template: "لم يتم رفع نموذج بعد.",
        upload_template: "رفع نموذج جديد",
        choose_template: "📤 اختر ملف",
        upload_btn: "رفع",
        template_guide_title: "دليل المتغيرات",
        template_guide_intro: "استخدم المتغيرات التالية في ملف الوورد:",
        available_placeholders: "المتغيرات المتاحة:",

        full_name: "الاسم الكامل *",
        email: "البريد",
        position: "المنصب *",
        department: "القسم *",
        base_salary: "الراتب الأساسي (دينار) *",
        phone_number: "رقم الهاتف",
        contract_start: "بداية العقد *",
        contract_end: "نهاية العقد",
        excluded_months: "أشهر مستثناة (غير مدفوعة)",
        address: "العنوان",
        national_id: "الرقم الوطني",
        save_employee: "حفظ",
        cancel: "إلغاء",

        renew_btn: "📜 تجديد",
        renew_title: "تجديد العقد / ترقية",
        renew_desc: "سيتم أرشفة العقد الحالي وبدء عقد جديد.",
        new_position: "المنصب الجديد",
        new_department: "القسم الجديد",
        new_salary: "الراتب الأساسي الجديد (دينار)",
        effective_date: "تاريخ البدء الفعلي",
        start_contract_btn: "بدء العقد الجديد",
        confirm_renew: "هل أنت متأكد؟",
        renew_success: "تم تجديد العقد!",

        add_past_payment: "إضافة سجل سابق",
        select_employee: "اختر الموظف *",
        select_employee_option: "-- اختر موظفاً --",
        add_record: "إضافة",
        export_department_data: "تصدير بيانات القسم",
        select_department: "اختر القسم *",
        select_department_option: "-- اختر قسماً --",
        export_excel: "📊 تصدير Excel",

        error_invalid_credentials: "اسم المستخدم أو كلمة المرور غير صحيحة",
        error_no_template: "لم يتم رفع نموذج. الرجاء رفع نموذج أولاً.",
        error_template_invalid: "فشل التحقق من النموذج. الرجاء رفع نموذج صالح.",
        error_network: "خطأ في الشبكة. تحقق من اتصالك.",
        error_server: "خطأ في الخادم. حاول مرة أخرى.",
        error_required_fields: "الرجاء ملء جميع الحقول المطلوبة",

        success_employee_added: "تمت إضافة الموظف بنجاح",
        success_employee_updated: "تم تحديث الموظف بنجاح",
        success_employee_deleted: "تم حذف الموظف",
        success_payslips_generated: "تم إصدار قسائم الرواتب بنجاح",
        success_template_uploaded: "تم رفع النموذج بنجاح",

        edit: "تعديل",
        delete: "حذف",
        upload_btn_tooltip: "رفع مستند",
        set_active: "تفعيل",
        active: "(نشط)",

        ph_name: "الاسم", ph_id: "الرقم", ph_position: "المنصب", ph_department: "القسم",
        ph_email: "البريد", ph_phone: "الهاتف", ph_address: "العنوان", ph_national_id: "الرقم الوطني",
        ph_base_salary: "الراتب الأساسي", ph_bonus: "المكافأة", ph_deductions: "الخصومات",
        ph_net_salary: "الصافي", ph_pay_period: "الفترة", ph_contract_start: "البداية",
        ph_contract_end: "النهاية", ph_generated_date: "التاريخ",

        contract_indefinite: "∞ عقد مفتوح",
        contract_expired: "⚠️ منتهي",
        contract_expiring: "⏰ ينتهي قريباً",
        contract_active: "✓ عقد نشط",
        months_remaining: "شهر متبقي",
        months_left: "شهر متبقي",
        days_left: "يوم",
        expired_since: "منتهي منذ",
        months_ago: "شهر",
    }
};

function switchLanguage(lang) {
    currentLanguage = lang;
    localStorage.setItem('language', lang);
    document.documentElement.lang = lang;
    document.documentElement.dir = lang === 'ar' ? 'rtl' : 'ltr';

    document.querySelectorAll('.lang-btn').forEach(btn => btn.classList.remove('active'));
    const activeBtn = document.getElementById('btn-' + lang);
    if (activeBtn) activeBtn.classList.add('active');

    // Static HTML Translations
    document.querySelectorAll('[data-translate]').forEach(element => {
        const key = element.getAttribute('data-translate');
        if (translations[lang][key]) {
            element.textContent = translations[lang][key];
        }
    });

    document.querySelectorAll('[data-translate-placeholder]').forEach(element => {
        const key = element.getAttribute('data-translate-placeholder');
        if (translations[lang][key]) {
            element.placeholder = translations[lang][key];
        }
    });

    // Refresh Dynamic Lists
    if (typeof loadFilterOptions === 'function') loadFilterOptions();
    if (typeof displayEmployees === 'function') displayEmployees();

    // Refresh History if active
    if (typeof currentHistoryEmpId !== 'undefined' && currentHistoryEmpId && document.getElementById('historyDetailView') && !document.getElementById('historyDetailView').classList.contains('hidden')) {
        const backBtn = document.getElementById('historyBackBtn');
        if (backBtn && translations[lang].back_to_list) backBtn.textContent = translations[lang].back_to_list;
        if (typeof viewEmployeeHistory === 'function') viewEmployeeHistory(currentHistoryEmpId, document.getElementById('historySelectedEmpName').textContent, currentBaseSalary);
    }
}