UPDATE db_version SET (id, version) = (3, '2019-09-03T155025Z_authz_provider');

CREATE OR REPLACE FUNCTION resource_has_parent() RETURNS TRIGGER LANGUAGE plpgsql AS
$$
DECLARE parent integer;
BEGIN
    -- If there's only one path segment, we're at the root, so it's fine if there's no parent.
    IF (nlevel(NEW.path) = 1) THEN
        RETURN NEW;
    END IF;
    parent := (SELECT COUNT(*) FROM resource WHERE path = subpath(NEW.path, 0, -1));
    IF (parent = 0) THEN
        RAISE EXCEPTION 'Parent resource % does not exist; cannot create resource with path %', subpath(NEW.path, 0, -1), NEW.path;
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER resource_has_parent_check ON resource;

CREATE CONSTRAINT TRIGGER resource_has_parent_check
    AFTER INSERT ON resource
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE PROCEDURE resource_has_parent();
