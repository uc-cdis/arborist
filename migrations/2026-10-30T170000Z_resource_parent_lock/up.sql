UPDATE db_version SET (id, version) = (4, '2026-10-30T170000Z_resource_parent_lock');

-- Check for the parent at INSERT time instead of at COMMIT, and lock the parent
-- row while doing so, the same way a foreign key check does. Without the lock, a
-- resource could be created under a parent that a concurrent transaction was
-- deleting: the child's check still saw the parent, and the parent's recursive
-- delete couldn't see the uncommitted child, leaving an orphan. With the lock,
-- whichever transaction gets the parent row first wins; the other waits, then
-- either fails (parent gone) or deletes the now-visible child.
CREATE OR REPLACE FUNCTION resource_has_parent() RETURNS TRIGGER LANGUAGE plpgsql AS
$$
BEGIN
    -- If there's only one path segment, we're at the root, so it's fine if there's no parent.
    IF (nlevel(NEW.path) = 1) THEN
        RETURN NEW;
    END IF;
    PERFORM 1 FROM resource WHERE path = subpath(NEW.path, 0, -1) FOR KEY SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Parent resource % does not exist; cannot create resource with path %', subpath(NEW.path, 0, -1), NEW.path
            USING ERRCODE = 'foreign_key_violation';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER resource_has_parent_check ON resource;

CREATE CONSTRAINT TRIGGER resource_has_parent_check
    AFTER INSERT ON resource
    NOT DEFERRABLE
    FOR EACH ROW EXECUTE PROCEDURE resource_has_parent();
