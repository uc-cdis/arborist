UPDATE db_version SET (id, version) = (4, '2022-02-09T183911Z_primary_keys_with_authz_provider');

ALTER TABLE usr_policy DROP CONSTRAINT usr_policy_pkey;
ALTER TABLE usr_grp DROP CONSTRAINT usr_grp_pkey;
ALTER TABLE grp_policy DROP CONSTRAINT grp_policy_pkey;
ALTER TABLE client_policy DROP CONSTRAINT client_policy_pkey;

-- there should not be any NULL values since Fence always supplies authz_provider
-- corresponding to user sync, DRS, RAS login, or access token polling. however,
-- since primary key columns cannot have NULL values, 'default' replaces NULL here
-- just in case policies have been granted separately through the API
UPDATE usr_grp SET authz_provider = 'default' WHERE authz_provider is NULL;
UPDATE usr_policy SET authz_provider = 'default' WHERE authz_provider is NULL;
UPDATE grp_policy SET authz_provider = 'default' WHERE authz_provider is NULL;
UPDATE client_policy SET authz_provider = 'default' WHERE authz_provider is NULL;

ALTER TABLE usr_policy ADD PRIMARY KEY(usr_id, policy_id, authz_provider);
ALTER TABLE usr_grp ADD PRIMARY KEY(usr_id, grp_id, authz_provider);
ALTER TABLE grp_policy ADD PRIMARY KEY(grp_id, policy_id, authz_provider);
ALTER TABLE client_policy ADD PRIMARY KEY(client_id, policy_id, authz_provider);
