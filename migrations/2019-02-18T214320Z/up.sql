CREATE TABLE db_version (
    version integer PRIMARY KEY
);

INSERT INTO db_version VALUES (0);

-- Use the ltree extension for handling tree operations. This allows us to do
-- pretty powerful operations on the resource hierarchy without having to go to
-- the trouble of implementing any of it ourselves.
-- Documentation: https://www.postgresql.org/docs/current/ltree.html
CREATE EXTENSION IF NOT EXISTS ltree;

CREATE TABLE resource (
    id serial PRIMARY KEY,
    -- name is NOT unique
    name text NOT NULL,
    -- resource path should always start with 'root'; don't allow anything which
    -- would use some other structure.
    path ltree UNIQUE NOT NULL CONSTRAINT path_starts_at_root CHECK (path ~ 'root.*')
);

-- This index, using specifically GiST index, is required for ltree.
CREATE INDEX resource_path_idx ON resource USING gist(path);

INSERT INTO resource(name, path) VALUES ('root', 'root');

-- Define a trigger which validates resource inputs; the path must have a valid
-- parent which already exists in the table.
CREATE OR REPLACE FUNCTION resource_has_parent() RETURNS TRIGGER LANGUAGE plpgsql AS
$$
DECLARE parent integer;
BEGIN
    parent := (SELECT COUNT(*) FROM resource WHERE path = lca(NEW.path, NEW.path));
    IF (parent = 0) THEN
        RAISE EXCEPTION 'Parent resource does not exist; cannot create resource with path %', NEW.path;
    END IF;
    RETURN NEW;
END;
$$;

-- Add the trigger to check that resources have valid parents.
CREATE TRIGGER resource_has_parent_check
    BEFORE INSERT OR UPDATE ON resource
    FOR EACH ROW EXECUTE PROCEDURE resource_has_parent();

-- Define a trigger function which fills in the resource name from the path.
CREATE OR REPLACE FUNCTION resource_path() RETURNS TRIGGER LANGUAGE plpgsql AS
$$
BEGIN
    NEW.name = (regexp_matches(ltree2text(NEW.path), '\.?(\w+)$'))[1];
    RETURN NEW;
END;
$$;

-- Add the trigger to fill in resource name from the path automatically.
CREATE TRIGGER resource_path_compute_name
    BEFORE INSERT ON resource
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
    BEFORE DELETE ON resource
    FOR EACH ROW EXECUTE PROCEDURE resource_recursive_delete();

CREATE TABLE role (
    id serial PRIMARY KEY,
    name text NOT NULL,
    description text
);

CREATE TABLE permission (
    id serial PRIMARY KEY,
    role_id integer NOT NULL REFERENCES role(id),
    name text NOT NULL,
    service text,
    method text,
    description text
);

CREATE TABLE policy (
    id serial PRIMARY KEY,
    name text NOT NULL,
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
    id serial PRIMARY KEY,
    name text NOT NULL,
    email text NOT NULL
);

CREATE TABLE usr_policy (
    usr_id integer REFERENCES usr(id) ON DELETE CASCADE,
    policy_id integer REFERENCES policy(id) ON DELETE CASCADE,
    PRIMARY KEY(usr_id, policy_id)
);

CREATE TABLE grp (
    id serial PRIMARY KEY,
    name text NOT NULL
);

CREATE TABLE usr_grp (
    usr_id integer REFERENCES usr(id) ON DELETE CASCADE,
    grp_id integer REFERENCES grp(id) ON DELETE CASCADE,
    PRIMARY KEY(usr_id, grp_id)
);
