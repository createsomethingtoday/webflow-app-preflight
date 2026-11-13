-- How the review was submitted: 'designer' (Designer Extension ID token) or
-- 'oauth' (creator CLI with a Webflow OAuth token). NULL on rows created
-- before this column existed; read NULL as 'designer'.
-- NOTE: ALTER TABLE ... ADD COLUMN is not re-runnable (no IF NOT EXISTS).
ALTER TABLE reviews ADD COLUMN auth_via TEXT;
