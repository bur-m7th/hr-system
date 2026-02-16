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
```bash
docker build -t hr-payroll-system .
```

### Run the container

**Development mode (HTTP):**
```bash
docker run -d -p 8080:8080 \
  -v $(pwd)/static:/app/static \
  -v $(pwd)/templates:/app/templates \
  -v $(pwd)/generated:/app/generated \
  --name hr-payroll-dev hr-payroll-system
```

**Production mode (HTTP behind reverse proxy like Cloudflare):**
```bash
docker run -d -p 8080:8080 \
  -v $(pwd)/static:/app/static \
  -v $(pwd)/templates:/app/templates \
  -v $(pwd)/generated:/app/generated \
  -e PRODUCTION=true \
  --name hr-payroll-prod hr-payroll-system
```

**Production mode with TLS certificates (optional):**
```bash
docker run -d -p 8443:8443 \
  -v $(pwd)/static:/app/static \
  -v $(pwd)/templates:/app/templates \
  -v $(pwd)/generated:/app/generated \
  -v $(pwd)/certs:/app/certs \
  -e PRODUCTION=true \
  --name hr-payroll-prod hr-payroll-system
```

*Note: The system automatically detects if TLS certificates exist. If certificates are found in `./certs/`, it runs HTTPS on port 8443. Otherwise, it runs HTTP on port 8080 (ideal for reverse proxy setups).*

### Access the application

- Development: http://localhost:8080
- Production (HTTP): http://localhost:8080
- Production (HTTPS): https://localhost:8443

### Manage containers
```bash
# View logs
docker logs -f hr-payroll-prod

# Stop container
docker stop hr-payroll-prod

# Start container
docker start hr-payroll-prod

# Remove container
docker rm hr-payroll-prod

# Remove image
docker rmi hr-payroll-system
```

## Deployment with Cloudflare

The system is designed to run behind reverse proxies like Cloudflare:

1. **Run the container in production mode** (no certificates needed):
```bash
   docker run -d -p 8080:8080 \
     -v $(pwd)/static:/app/static \
     -v $(pwd)/templates:/app/templates \
     -v $(pwd)/generated:/app/generated \
     -e PRODUCTION=true \
     --name hr-payroll-prod hr-payroll-system
```

2. **Configure Cloudflare**:
   - Point your domain's A record to your server's IP
   - Set SSL/TLS mode to **Full** (encrypts between Cloudflare and visitors)
   - Enable "Always Use HTTPS"

3. **Architecture**:
```
   User (HTTPS) → Cloudflare (HTTPS) → Your Server (HTTP on port 8080)
```

## File Structure
```
app/
├─ main.go
├─ static/
├─ templates/
├─ generated/
├─ db/
│  ├─ hrpayroll.db
│  ├─ .encryption_key
│  └─ audit.log
└─ scripts/
   └─ generate_doc.py
```

## Configuration

- **Production mode**: Set `PRODUCTION=true` environment variable
- **TLS certificates**: Place `server.crt` and `server.key` in `./certs/` (optional, auto-detected)
- **SQLite database**: Automatically initialized at `db/hrpayroll.db`
- **Persistent volumes**: `templates`, `static`, `generated`
- **Encryption key**: Auto-generated at `db/.encryption_key` (backup this file!)

## API Endpoints

### Authentication
- `POST /api/login`
- `POST /api/verify-2fa`
- `POST /api/register-owner`
- `GET /api/auth-status`
- `POST /api/logout`

### Users
- `POST /api/users/add`
- `POST /api/user/change-password`
- `DELETE /api/user/delete-account`

### Employees
- `GET /api/employees`
- `POST /api/employees/add`
- `POST /api/employees/update`
- `DELETE /api/employees/delete`
- `POST /api/employees/renew-contract`
- `POST /api/employees/exclude-bulk`

### Departments & Positions
- `GET /api/departments`
- `GET /api/positions`

### Payments
- `GET /api/payments`
- `POST /api/payments/add`
- `DELETE /api/payments/delete`
- `POST /api/payments/upload-doc`
- `POST /api/generate-payslips`

### Templates
- `GET /api/templates`
- `POST /api/template/upload`
- `POST /api/template/activate`
- `DELETE /api/template/delete`

### Exports
- `GET /api/export/department?department=...`
- `GET /api/export/all`

### Employee Stats
- `GET /api/employee/stats?id=...`

## Security Features

- **Encryption**: All sensitive employee data (name, email, phone, address, national ID) is encrypted at rest using AES-256-GCM
- **2FA Support**: Optional TOTP-based two-factor authentication
- **Rate Limiting**: Login attempts are rate-limited (5 attempts per minute per IP)
- **Session Management**: Secure HTTP-only cookies with SameSite protection
- **Audit Logging**: All critical actions are logged to `db/audit.log`
- **Input Validation**: All user inputs are sanitized and validated
- **CORS Protection**: Configurable origin restrictions
- **Security Headers**: X-Frame-Options, X-XSS-Protection, X-Content-Type-Options, HSTS (in production)

## Notes

- **Maximum file upload**: 10MB
- **Payslips generated via**: `generate_doc.py` script
- **Audit logs**: Created for all critical actions in `db/audit.log`
- **Sensitive data**: Encrypted in database using AES-256-GCM
- **Backup reminder**: Always backup `db/.encryption_key` - without it, encrypted data cannot be recovered

## Troubleshooting

**Container exits immediately:**
- Check logs: `docker logs hr-payroll-prod`
- Ensure you're in the correct directory with all required files

**Can't access on port 8080:**
- Check if container is running: `docker ps`
- Check if port is already in use: `sudo lsof -i :8080`

**Database locked errors:**
- Ensure only one instance is running
- Check file permissions in `./db/` directory

## License

MIT License. See LICENSE for details.

## Author

Mahmood Burashid