# Database (PostgreSQL)

This folder contains SQL migrations and seed data.

## Run migrations
```bash
psql "$DB_URL" -f database/migrations/001_init.sql
```

## Seed
```bash
psql "$DB_URL" -f database/seed/001_seed.sql
```
