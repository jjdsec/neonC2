# Database Setup and Migration Guide

## Initial Setup

The database is automatically created when the application starts if it doesn't exist. The database file is stored in the `data/` directory and persists across Docker container restarts via a Docker volume.

## Manual Migration Commands

If you need to manually manage migrations:

### 1. Initialize migrations (first time only)
```bash
flask db init
```

### 2. Create a new migration after model changes
```bash
flask db migrate -m "Description of changes"
```

### 3. Apply migrations
```bash
flask db upgrade
```

### 4. Rollback migration
```bash
flask db downgrade
```

## Automatic Setup

The application automatically:
- Creates the `data/` directory if it doesn't exist
- Applies migrations on startup (if migrations exist)
- Falls back to `db.create_all()` if migrations aren't initialized
- Creates a default admin user if no users exist (username: `admin`, password: `admin`)

## Database Location

- **Development**: `data/neonc2.db` (in the server directory)
- **Docker**: `/app/data/neonc2.db` (persisted via Docker volume `neonc2_data`)

## Docker Volume Persistence

The database persists across container restarts via the `neonc2_data` Docker volume defined in `docker-compose.yaml`. The volume is stored on the host system and persists even if the container is removed.
