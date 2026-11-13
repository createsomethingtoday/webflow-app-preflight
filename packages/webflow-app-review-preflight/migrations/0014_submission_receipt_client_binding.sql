PRAGMA foreign_keys = ON;

-- Binds a submission receipt to the Webflow app (client ID, 64 lowercase hex)
-- that first redeemed it with `bind: true`, so a receipt cannot be reused for a
-- different app. Nullable: unbound until first bound. Never returned by the
-- verify endpoint. NOTE: ALTER TABLE ... ADD COLUMN is not re-runnable.
ALTER TABLE submission_receipts ADD COLUMN bound_client_id TEXT;
