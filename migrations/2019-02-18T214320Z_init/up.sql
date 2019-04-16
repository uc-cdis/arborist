CREATE TABLE db_version (
    id integer PRIMARY KEY,
    version text NOT NULL
);

INSERT INTO db_version(id, version) VALUES (0, '2019-02-18T214320Z_init');

-- Use the ltree extension for handling tree operations. This allows us to do
-- pretty powerful operations on the resource hierarchy without having to go to
-- the trouble of implementing any of it ourselves.
-- Documentation: https://www.postgresql.org/docs/current/ltree.html
CREATE EXTENSION IF NOT EXISTS ltree;

CREATE TABLE resource (
    id serial PRIMARY KEY,
    tag text UNIQUE NOT NULL,
    -- name is NOT unique
    name text NOT NULL,
    description text,
    -- resource path should always start with 'root'; don't allow anything which
    -- would use some other structure.
    path ltree UNIQUE NOT NULL CONSTRAINT path_starts_at_root CHECK (path ~ 'root.*')
);

-- This index, using specifically GiST index, is required for ltree.
CREATE INDEX resource_path_idx ON resource USING gist(path);

INSERT INTO resource(name, path, tag) VALUES ('root', 'root', 'AAAAAAAA');

-- Define a trigger which validates resource inputs; the path must have a valid
-- parent which already exists in the table.
CREATE OR REPLACE FUNCTION resource_has_parent() RETURNS TRIGGER LANGUAGE plpgsql AS
$$
DECLARE parent integer;
BEGIN
    parent := (SELECT COUNT(*) FROM resource WHERE path = subpath(NEW.path, 0, -1));
    IF (parent = 0) THEN
        RAISE EXCEPTION 'Parent resource % does not exist; cannot create resource with path %', subpath(NEW.path, 0, -1), NEW.path;
    END IF;
    RETURN NEW;
END;
$$;

-- Add the trigger to check that resources have valid parents.
CREATE CONSTRAINT TRIGGER resource_has_parent_check
    AFTER INSERT OR UPDATE ON resource
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE PROCEDURE resource_has_parent();

-- Define a trigger function which fills in the resource name from the path.
CREATE OR REPLACE FUNCTION resource_path() RETURNS TRIGGER LANGUAGE plpgsql AS
$$
DECLARE found integer;
BEGIN
    NEW.name = (ltree2text(subpath(NEW.path, -1)));

    LOOP
        NEW.tag = encode(random_bytea(6), 'base64');
        NEW.tag = replace(NEW.tag, '/', '_');
        NEW.tag = replace(NEW.tag, '+', '-');
        -- guarantee uniqueness
        EXECUTE 'SELECT COUNT(*) FROM resource WHERE tag = ' || quote_literal(NEW.tag) INTO found;
        IF (found = 0) THEN
            EXIT;
        END IF;
    END LOOP;

    RETURN NEW;
END;
$$;

-- Add the trigger to fill in resource name from the path automatically.
CREATE TRIGGER resource_path_compute_name
    BEFORE INSERT OR UPDATE ON resource
    FOR EACH ROW EXECUTE PROCEDURE resource_path();

-- Define a trigger function which recursively deletes the entire resource
-- subtree when a resource is deleted.
CREATE OR REPLACE FUNCTION resource_recursive_delete() RETURNS TRIGGER LANGUAGE plpgsql AS
$$
BEGIN
    -- `x <@ y` is satisfied when x is a descendant of y. Also omit the resource
    -- itself from this delete to prevent recursively activating this trigger
    -- with the same delete.
    DELETE FROM resource WHERE (path != OLD.path) AND (path <@ OLD.path);
    RETURN OLD;
END;
$$;

-- Add the trigger to recursively delete subresources before a resource delete.
CREATE TRIGGER resource_path_delete_children
    AFTER DELETE ON resource
    FOR EACH ROW EXECUTE PROCEDURE resource_recursive_delete();

CREATE OR REPLACE FUNCTION resource_recursive_update() RETURNS TRIGGER LANGUAGE plpgsql AS
$$
BEGIN
    UPDATE resource SET path = subpath(path, 0, nlevel(OLD.path)-1) || subpath(NEW.PATH, -1) || subpath(path, nlevel(OLD.path)) WHERE (path <@ OLD.path AND path != OLD.path);
    RETURN NEW;
END;
$$;

CREATE TRIGGER resource_path_update_children
    AFTER UPDATE ON resource
    FOR EACH ROW EXECUTE PROCEDURE resource_recursive_update();

CREATE TABLE role (
    id serial PRIMARY KEY,
    name text UNIQUE NOT NULL,
    description text
);

CREATE TABLE permission (
    role_id integer NOT NULL REFERENCES role(id) ON DELETE CASCADE,
    name text NOT NULL,
    service text NOT NULL,
    method text NOT NULL,
    constraints jsonb DEFAULT '{}'::jsonb,
    description text,
    PRIMARY KEY(role_id, name)
);

CREATE INDEX permission_idx ON permission USING btree(role_id, service, method);

CREATE TABLE policy (
    id serial PRIMARY KEY,
    name text UNIQUE NOT NULL,
    description text
);

CREATE TABLE policy_role (
    policy_id integer REFERENCES policy(id) ON DELETE CASCADE,
    role_id integer REFERENCES role(id) ON DELETE CASCADE,
    PRIMARY KEY(policy_id, role_id)
);

CREATE TABLE policy_resource (
    policy_id integer REFERENCES policy(id) ON DELETE CASCADE,
    resource_id integer REFERENCES resource(id) ON DELETE CASCADE,
    PRIMARY KEY(policy_id, resource_id)
);

CREATE TABLE usr (
    id serial PRIMARY KEY, -- arborist only---not fence
    name text UNIQUE NOT NULL, -- SHARED with fence
    email text
);

CREATE TABLE usr_policy (
    usr_id integer REFERENCES usr(id) ON DELETE CASCADE,
    policy_id integer REFERENCES policy(id) ON DELETE CASCADE,
    PRIMARY KEY(usr_id, policy_id)
);

CREATE TABLE grp (
    id serial PRIMARY KEY,
    name text UNIQUE NOT NULL
);

CREATE TABLE usr_grp (
    usr_id integer REFERENCES usr(id) ON DELETE CASCADE,
    grp_id integer REFERENCES grp(id) ON DELETE CASCADE,
    PRIMARY KEY(usr_id, grp_id)
);

CREATE TABLE grp_policy (
    grp_id integer REFERENCES grp(id) ON DELETE CASCADE,
    policy_id integer REFERENCES policy(id) ON DELETE CASCADE,
    PRIMARY KEY(grp_id, policy_id)
);
