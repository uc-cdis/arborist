UPDATE db_version SET (id, version) = (3, '2019-09-03T155025Z_authz_provider');

ALTER TABLE usr_policy ADD COLUMN authz_provider VARCHAR;
ALTER TABLE grp_policy ADD COLUMN authz_provider VARCHAR;
ALTER TABLE client_policy ADD COLUMN authz_provider VARCHAR;
