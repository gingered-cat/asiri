-- The public half of an ssh_key item, in authorized_keys form. Not secret.
ALTER TABLE items ADD COLUMN public_key TEXT NOT NULL DEFAULT '';

-- SSH requests and grants are bound to the destination's host key
-- (SHA256 fingerprint); asiri run requests leave it empty.
ALTER TABLE requests ADD COLUMN host_fp TEXT NOT NULL DEFAULT '';
ALTER TABLE grants ADD COLUMN host_fp TEXT NOT NULL DEFAULT '';
DROP INDEX grants_reuse;
CREATE INDEX grants_reuse ON grants (client_id, item_id, bin_sha256, host_fp, expires_at);
