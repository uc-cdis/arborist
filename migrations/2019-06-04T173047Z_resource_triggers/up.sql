UPDATE db_version SET (id, version) = (1, '2019-06-04T173047Z_resource_triggers');

DROP TRIGGER resource_has_parent_check ON resource;
DROP FUNCTION resource_path;

CREATE CONSTRAINT TRIGGER resource_has_parent_check
    AFTER INSERT ON resource
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE PROCEDURE resource_has_parent();

CREATE OR REPLACE FUNCTION resource_path_insert() RETURNS TRIGGER LANGUAGE plpgsql AS
$$
DECLARE found integer;
BEGIN
    NEW.name = (ltree2text(subpath(NEW.path, -1)));

    -- also generate a unique "tag" for the resource
    LOOP
        NEW.tag = encode(random_bytea(6), 'base64');
        -- make it URL safe
        NEW.tag = replace(NEW.tag, '/', '_');
        NEW.tag = replace(NEW.tag, '+', '-');
        -- try to guarantee uniqueness
        -- (no guarantees for concurrent transactions)
        EXECUTE 'SELECT COUNT(*) FROM resource WHERE tag = ' || quote_literal(NEW.tag) INTO found;
        IF (found = 0) THEN
            -- not a duplicate; exit loop
            EXIT;
        END IF;
    END LOOP;

    RETURN NEW;
END;
$$;

CREATE TRIGGER resource_path_compute_name_insert
    BEFORE INSERT ON resource
    FOR EACH ROW EXECUTE PROCEDURE resource_path_insert();

CREATE OR REPLACE FUNCTION resource_path_update() RETURNS TRIGGER LANGUAGE plpgsql AS
$$
DECLARE found integer;
BEGIN
    NEW.name = (ltree2text(subpath(NEW.path, -1)));
    RETURN NEW;
END;
$$;

CREATE TRIGGER resource_path_compute_name_update
    BEFORE UPDATE ON resource
    FOR EACH ROW EXECUTE PROCEDURE resource_path_update();
