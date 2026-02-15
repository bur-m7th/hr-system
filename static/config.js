// ==========================================
// CONFIGURATION & GLOBALS
// ==========================================
const API_BASE = '/api'; 

// Global State Variables
let employees = [];
let selectedEmployeeIds = new Set();
let filteredEmployeesForGenerate = [];
let currentLanguage = localStorage.getItem('language') || 'en';

// History Tab Globals
let currentHistoryEmpId = null;
let currentBaseSalary = 0;
let currentUploadPaymentId = null;