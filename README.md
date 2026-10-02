# Web Technology Course Project

A web technology course project developed as part of the Web Technology curriculum.  
The project demonstrates the use of front-end development, back-end/database integration, and web application concepts.

## Project Overview

This project is developed using modern web development technologies and is organized into separate sections for the application source code, public assets, and database-related files.

The main objective of the project is to apply concepts learned in Web Technology, including:

- Web page design and structure
- Styling and responsive layouts
- Client-side scripting
- Server-side development
- Database integration
- CRUD operations
- Form handling and validation
- Dynamic web application development

## Technologies Used

- HTML5
- CSS3
- JavaScript
- PHP
- MySQL
- XAMPP
- Git & GitHub

## Project Structure

```text
Web_Tech_CP/
├── database/
│   └── Database-related files
├── public/
│   └── Publicly accessible files and assets
├── src/
│   └── Main source code of the application
└── README.md
```

# Setup

1. **Clone** the repository into your XAMPP `htdocs` folder.
2. **Folders** — `public/qrcodes/`, `private_data/`, and `private_data/uploads/` are committed as empty directories (via committed `.gitkeep` placeholder files), so a fresh clone works out of the box. If they are missing for any reason, create them manually:
   ```
   mkdir public/qrcodes private_data private_data/uploads
   ```
3. **Database** — import `database/schema.sql` into MySQL (e.g. via phpMyAdmin or `mysql -u root < database/schema.sql`). It creates the `certivault` database, all tables, and a seeded super admin.
4. **Configuration** — all settings are read from environment variables (see `src/config/config.php`):
   - `CV_DB_HOST`, `CV_DB_USER`, `CV_DB_PASS`, `CV_DB_NAME`
   - `CV_BASE_URL`
   - `CV_ENCRYPTION_KEY`
   - `CV_ENV` (set to `production` in production; anything else is treated as local dev)

   The committed defaults (localhost, root, empty password, `certivault`) work for a standard local XAMPP setup, so env vars are optional locally.
5. **Document root** — point Apache/XAMPP at the `/public` directory (e.g. `http://localhost/<repo>/public`), not the repo root.

After that, register an institution, have the super admin approve it, and you can issue certificates.
