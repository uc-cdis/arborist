UPDATE db_version SET (id, version) = (3, '2019-09-03T155025Z_authz_provider');

ALTER TABLE resource DROP COLUMN namespace;
