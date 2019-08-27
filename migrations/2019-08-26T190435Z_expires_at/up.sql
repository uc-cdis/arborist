UPDATE db_version SET (id, version) = (2, '2019-08-26T190435Z_expires_at');

ALTER TABLE usr_grp ADD COLUMN expires_at TIMESTAMP WITH TIME ZONE;
ALTER TABLE usr_policy ADD COLUMN expires_at TIMESTAMP WITH TIME ZONE;
