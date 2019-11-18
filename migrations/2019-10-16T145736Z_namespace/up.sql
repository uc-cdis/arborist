UPDATE db_version SET (id, version) = (4, '2019-10-16T145736Z_namespace');

ALTER TABLE resource ADD COLUMN namespace BOOLEAN DEFAULT FALSE NOT NULL;
