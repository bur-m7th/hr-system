# HR Payroll System

A secure HR and payroll management system built with Go, SQLite, and Python scripts for automated payslip generation.

## Features

- User authentication with 2FA support
- Employee management (add, update, delete, renew contracts)
- Payroll management (record payments, upload payslips, generate bulk payslips)
- Document templates (.docx) for automated payslip generation
- Export data (all employees or by department) in CSV format
- Employee stats and timeline visualization
- Audit logging for all critical actions
- Dockerized deployment for development and production

## Prerequisites

- Docker
- Optional: Local Go and Python if running outside Docker

## Running the Server with Docker

### Build the Docker image

docker build -t hr-payroll-system .
Run the container
Development mode (HTTP):

docker run -d -p 8080:8080 \
  -v $(pwd)/static:/app/static \
  -v $(pwd)/templates:/app/templates \
  -v $(pwd)/generated:/app/generated \
  --name hr-payroll-dev hr-payroll-system
Production mode (HTTPS):

docker run -d -p 8443:8443 \
  -v $(pwd)/static:/app/static \
  -v $(pwd)/templates:/app/templates \
  -v $(pwd)/generated:/app/generated \
  -v $(pwd)/certs:/app/certs \
  -e PRODUCTION=true \
  --name hr-payroll-prod hr-payroll-system
Access the application
Development: http://localhost:8080

Production: https://localhost:8443

Manage container
docker logs -f hr-payroll-dev
docker stop hr-payroll-dev
docker start hr-payroll-dev
docker rm hr-payroll-dev
File Structure
app/
├─ main.go
├─ static/
├─ templates/
├─ generated/
└─ scripts/
   └─ generate_doc.py
Configuration
Production mode: set PRODUCTION=true and provide certificates in ./certs

SQLite database initialized automatically (db.sqlite)

Persistent volumes: templates, static, generated

API Endpoints
Authentication
POST /api/login

POST /api/verify-2fa

POST /api/register-owner

GET /api/auth-status

POST /api/logout

Users
POST /api/users/add

POST /api/user/change-password

DELETE /api/user/delete-account

Employees
GET /api/employees

POST /api/employees/add

POST /api/employees/update

DELETE /api/employees/delete

POST /api/employees/renew-contract

POST /api/employees/exclude-bulk

Departments & Positions
GET /api/departments

GET /api/positions

Payments
GET /api/payments

POST /api/payments/add

DELETE /api/payments/delete

POST /api/payments/upload-doc

POST /api/generate-payslips

Templates
GET /api/templates

POST /api/template/upload

POST /api/template/activate

DELETE /api/template/delete

Exports
GET /api/export/department?department=...

GET /api/export/all

Employee Stats
GET /api/employee/stats?id=...

Notes
Maximum file upload: 10MB

Payslips generated via generate_doc.py

Audit logs created for all critical actions

Sensitive employee data is encrypted in the database

License
MIT License. See LICENSE for details.

# Author
Mahmood Burashid