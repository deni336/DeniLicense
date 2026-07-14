-- Self-service account security, revision-safe products, and inventory lookup support.

ALTER TABLE products
    ADD COLUMN revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0);

CREATE INDEX activations_thumbprint_idx
    ON activations(device_key_thumbprint);
