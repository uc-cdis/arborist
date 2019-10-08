UPDATE db_version SET (id, version) = (3, '2019-09-03T155025Z_authz_provider');

ALTER TABLE usr_policy ADD COLUMN authz_provider VARCHAR;
ALTER TABLE usr_grp ADD COLUMN authz_provider VARCHAR;
ALTER TABLE grp_policy ADD COLUMN authz_provider VARCHAR;
ALTER TABLE client_policy ADD COLUMN authz_provider VARCHAR;

-- assuming all commons are only running user sync as AuthZ provider
UPDATE usr_grp SET authz_provider = 'user-sync' WHERE authz_provider is NULL;
UPDATE usr_policy SET authz_provider = 'user-sync' WHERE authz_provider is NULL;
UPDATE grp_policy SET authz_provider = 'user-sync' WHERE authz_provider is NULL;
UPDATE client_policy SET authz_provider = 'user-sync' WHERE authz_provider is NULL;
