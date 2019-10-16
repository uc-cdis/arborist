UPDATE db_version SET (id, version) = (2, '2019-08-26T190435Z_expires_at');

ALTER TABLE resource DROP COLUMN namespace;
