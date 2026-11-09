-- Roles and databases for a Vaulty host. Run once by the installer as the postgres superuser:
--   sudo -u postgres psql -v temporal_password="'...'" -f roles.sql
--
-- Vaulty roles have LOGIN but no password: they authenticate with peer over the Unix socket.
-- Only the Temporal role has a password, because Temporal connects over loopback TCP.
-- Table-level grants and row-level security are created by the EF Core migrations, which run as
-- vaulty_migrator (owner of the schema). Application roles never get BYPASSRLS or DDL rights.

\set ON_ERROR_STOP on

-- Schema owner, used only by vaulty-migrate.service
CREATE ROLE vaulty_migrator LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;

-- Application roles
CREATE ROLE vaulty_api     LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE ROLE vaulty_worker  LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE ROLE vaulty_gc      LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;

-- Temporal (container, loopback TCP, scram-sha-256)
CREATE ROLE temporal LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS
    PASSWORD :temporal_password;

-- Databases
CREATE DATABASE vaulty              OWNER vaulty_migrator ENCODING 'UTF8' LOCALE_PROVIDER icu ICU_LOCALE 'und' TEMPLATE template0;
CREATE DATABASE temporal            OWNER temporal        ENCODING 'UTF8' TEMPLATE template0;
CREATE DATABASE temporal_visibility OWNER temporal        ENCODING 'UTF8' TEMPLATE template0;

-- Nobody connects to vaulty except the roles listed in pg_hba.conf
REVOKE ALL ON DATABASE vaulty FROM PUBLIC;
GRANT CONNECT ON DATABASE vaulty TO vaulty_migrator, vaulty_api, vaulty_worker, vaulty_gc;

\connect vaulty

REVOKE ALL ON SCHEMA public FROM PUBLIC;
CREATE SCHEMA vaulty AUTHORIZATION vaulty_migrator;
GRANT USAGE ON SCHEMA vaulty TO vaulty_api, vaulty_worker, vaulty_gc;
ALTER DATABASE vaulty SET search_path = vaulty;

-- Grants on future tables and sequences created by the migrator. The migrations tighten these
-- per table (for example append-only audit_events, no DELETE for vaulty_api).
ALTER DEFAULT PRIVILEGES FOR ROLE vaulty_migrator IN SCHEMA vaulty
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO vaulty_api, vaulty_worker;
ALTER DEFAULT PRIVILEGES FOR ROLE vaulty_migrator IN SCHEMA vaulty
    GRANT SELECT ON TABLES TO vaulty_gc;
ALTER DEFAULT PRIVILEGES FOR ROLE vaulty_migrator IN SCHEMA vaulty
    GRANT USAGE, SELECT ON SEQUENCES TO vaulty_api, vaulty_worker;

-- Extensions needed by Vaulty (the migrator cannot create extensions itself)
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;
CREATE EXTENSION IF NOT EXISTS pgcrypto;
