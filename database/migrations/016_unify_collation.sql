-- database/migrations/016_unify_collation.sql
-- One character set + collation for every table: utf8mb4 / utf8mb4_unicode_ci.
--
-- Why: the original tables were created without an explicit collation and
-- inherited the server default (utf8mb4_general_ci on XAMPP), while newer
-- tables declare utf8mb4_unicode_ci. Comparing string columns across the
-- two (e.g. certificates.certificate_id = tlog_entries.certificate_id)
-- fails on MariaDB/MySQL with "Illegal mix of collations" (error 1267).
--
-- Safe to re-run (converting an already-converted table is a no-op).
-- Run it during a quiet moment: each ALTER rebuilds the table.

ALTER DATABASE CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

ALTER TABLE users             CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
ALTER TABLE otp_codes         CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
ALTER TABLE institutions      CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
ALTER TABLE students          CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
ALTER TABLE certificates      CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
ALTER TABLE verification_logs CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
ALTER TABLE remember_tokens   CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
ALTER TABLE login_attempts    CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
