-- 000006_drop_replays.up.sql
-- Dialect: PostgreSQL
-- Drops the gs_replays table following extraction of BulletproofAuth into its standalone repository.

DROP INDEX IF EXISTS idx_gs_replays_expires_at;
DROP TABLE IF EXISTS gs_replays;

