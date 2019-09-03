UPDATE db_version SET (id, version) = (1, '2019-06-04T173047Z_resource_triggers');

ALTER TABLE usr_grp DROP COLUMN expires_at;
ALTER TABLE usr_policy DROP COLUMN expires_at;
