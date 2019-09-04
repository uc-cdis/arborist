UPDATE db_version SET (id, version) = (2, '2019-08-26T190435Z_expires_at');

ALTER TABLE usr_policy DROP COLUMN authz_provider;
ALTER TABLE usr_grp DROP COLUMN authz_provider;
ALTER TABLE grp_policy DROP COLUMN authz_provider;
ALTER TABLE client_policy DROP COLUMN authz_provider;
