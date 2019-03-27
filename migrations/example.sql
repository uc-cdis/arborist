--
-- PostgreSQL database dump
--

-- Dumped from database version 9.5.14
-- Dumped by pg_dump version 9.5.14

SET statement_timeout = 0;
SET lock_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: plpgsql; Type: EXTENSION; Schema: -; Owner: 
--

CREATE EXTENSION IF NOT EXISTS plpgsql WITH SCHEMA pg_catalog;


--
-- Name: EXTENSION plpgsql; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION plpgsql IS 'PL/pgSQL procedural language';


--
-- Name: ltree; Type: EXTENSION; Schema: -; Owner: 
--

CREATE EXTENSION IF NOT EXISTS ltree WITH SCHEMA public;


--
-- Name: EXTENSION ltree; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION ltree IS 'data type for hierarchical tree-like structures';


--
-- Name: resource_has_parent(); Type: FUNCTION; Schema: public; Owner: rudyard
--

CREATE FUNCTION public.resource_has_parent() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE parent integer;
BEGIN
    parent := (SELECT COUNT(*) FROM resource WHERE path = subpath(NEW.path, 0, -1));
    IF (parent = 0) THEN
        RAISE EXCEPTION 'Parent resource % does not exist; cannot create resource with path %', subpath(NEW.path, 0, -1), NEW.path;
    END IF;
    RETURN NEW;
END;
$$;


ALTER FUNCTION public.resource_has_parent() OWNER TO rudyard;

--
-- Name: resource_path(); Type: FUNCTION; Schema: public; Owner: rudyard
--

CREATE FUNCTION public.resource_path() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.name = (ltree2text(subpath(NEW.path, -1)));
    RETURN NEW;
END;
$$;


ALTER FUNCTION public.resource_path() OWNER TO rudyard;

--
-- Name: resource_recursive_delete(); Type: FUNCTION; Schema: public; Owner: rudyard
--

CREATE FUNCTION public.resource_recursive_delete() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    -- `x <@ y` is satisfied when x is a descendant of y. Also omit the resource
    -- itself from this delete to prevent recursively activating this trigger
    -- with the same delete.
    DELETE FROM resource WHERE (path != OLD.path) AND (path <@ OLD.path);
    RETURN OLD;
END;
$$;


ALTER FUNCTION public.resource_recursive_delete() OWNER TO rudyard;

--
-- Name: resource_recursive_update(); Type: FUNCTION; Schema: public; Owner: rudyard
--

CREATE FUNCTION public.resource_recursive_update() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    UPDATE resource SET path = subpath(path, 0, nlevel(OLD.path)-1) || subpath(NEW.PATH, -1) || subpath(path, nlevel(OLD.path)) WHERE (path <@ OLD.path AND path != OLD.path);
    RETURN NEW;
END;
$$;


ALTER FUNCTION public.resource_recursive_update() OWNER TO rudyard;

SET default_tablespace = '';

SET default_with_oids = false;

--
-- Name: db_version; Type: TABLE; Schema: public; Owner: rudyard
--

CREATE TABLE public.db_version (
    id integer NOT NULL,
    version text NOT NULL
);


ALTER TABLE public.db_version OWNER TO rudyard;

--
-- Name: grp; Type: TABLE; Schema: public; Owner: rudyard
--

CREATE TABLE public.grp (
    id integer NOT NULL,
    name text NOT NULL
);


ALTER TABLE public.grp OWNER TO rudyard;

--
-- Name: grp_id_seq; Type: SEQUENCE; Schema: public; Owner: rudyard
--

CREATE SEQUENCE public.grp_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.grp_id_seq OWNER TO rudyard;

--
-- Name: grp_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: rudyard
--

ALTER SEQUENCE public.grp_id_seq OWNED BY public.grp.id;


--
-- Name: grp_policy; Type: TABLE; Schema: public; Owner: rudyard
--

CREATE TABLE public.grp_policy (
    grp_id integer NOT NULL,
    policy_id integer NOT NULL
);


ALTER TABLE public.grp_policy OWNER TO rudyard;

--
-- Name: permission; Type: TABLE; Schema: public; Owner: rudyard
--

CREATE TABLE public.permission (
    role_id integer NOT NULL,
    name text NOT NULL,
    service text NOT NULL,
    method text NOT NULL,
    constraints jsonb DEFAULT '{}'::jsonb,
    description text
);


ALTER TABLE public.permission OWNER TO rudyard;

--
-- Name: policy; Type: TABLE; Schema: public; Owner: rudyard
--

CREATE TABLE public.policy (
    id integer NOT NULL,
    name text NOT NULL,
    description text
);


ALTER TABLE public.policy OWNER TO rudyard;

--
-- Name: policy_id_seq; Type: SEQUENCE; Schema: public; Owner: rudyard
--

CREATE SEQUENCE public.policy_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.policy_id_seq OWNER TO rudyard;

--
-- Name: policy_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: rudyard
--

ALTER SEQUENCE public.policy_id_seq OWNED BY public.policy.id;


--
-- Name: policy_resource; Type: TABLE; Schema: public; Owner: rudyard
--

CREATE TABLE public.policy_resource (
    policy_id integer NOT NULL,
    resource_id integer NOT NULL
);


ALTER TABLE public.policy_resource OWNER TO rudyard;

--
-- Name: policy_role; Type: TABLE; Schema: public; Owner: rudyard
--

CREATE TABLE public.policy_role (
    policy_id integer NOT NULL,
    role_id integer NOT NULL
);


ALTER TABLE public.policy_role OWNER TO rudyard;

--
-- Name: resource; Type: TABLE; Schema: public; Owner: rudyard
--

CREATE TABLE public.resource (
    id integer NOT NULL,
    name text NOT NULL,
    description text,
    path public.ltree NOT NULL,
    CONSTRAINT path_starts_at_root CHECK ((path OPERATOR(public.~) 'root.*'::public.lquery))
);


ALTER TABLE public.resource OWNER TO rudyard;

--
-- Name: resource_id_seq; Type: SEQUENCE; Schema: public; Owner: rudyard
--

CREATE SEQUENCE public.resource_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.resource_id_seq OWNER TO rudyard;

--
-- Name: resource_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: rudyard
--

ALTER SEQUENCE public.resource_id_seq OWNED BY public.resource.id;


--
-- Name: role; Type: TABLE; Schema: public; Owner: rudyard
--

CREATE TABLE public.role (
    id integer NOT NULL,
    name text NOT NULL,
    description text
);


ALTER TABLE public.role OWNER TO rudyard;

--
-- Name: role_id_seq; Type: SEQUENCE; Schema: public; Owner: rudyard
--

CREATE SEQUENCE public.role_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.role_id_seq OWNER TO rudyard;

--
-- Name: role_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: rudyard
--

ALTER SEQUENCE public.role_id_seq OWNED BY public.role.id;


--
-- Name: usr; Type: TABLE; Schema: public; Owner: rudyard
--

CREATE TABLE public.usr (
    id integer NOT NULL,
    name text NOT NULL,
    email text
);


ALTER TABLE public.usr OWNER TO rudyard;

--
-- Name: usr_grp; Type: TABLE; Schema: public; Owner: rudyard
--

CREATE TABLE public.usr_grp (
    usr_id integer NOT NULL,
    grp_id integer NOT NULL
);


ALTER TABLE public.usr_grp OWNER TO rudyard;

--
-- Name: usr_id_seq; Type: SEQUENCE; Schema: public; Owner: rudyard
--

CREATE SEQUENCE public.usr_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.usr_id_seq OWNER TO rudyard;

--
-- Name: usr_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: rudyard
--

ALTER SEQUENCE public.usr_id_seq OWNED BY public.usr.id;


--
-- Name: usr_policy; Type: TABLE; Schema: public; Owner: rudyard
--

CREATE TABLE public.usr_policy (
    usr_id integer NOT NULL,
    policy_id integer NOT NULL
);


ALTER TABLE public.usr_policy OWNER TO rudyard;

--
-- Name: id; Type: DEFAULT; Schema: public; Owner: rudyard
--

ALTER TABLE ONLY public.grp ALTER COLUMN id SET DEFAULT nextval('public.grp_id_seq'::regclass);


--
-- Name: id; Type: DEFAULT; Schema: public; Owner: rudyard
--

ALTER TABLE ONLY public.policy ALTER COLUMN id SET DEFAULT nextval('public.policy_id_seq'::regclass);


--
-- Name: id; Type: DEFAULT; Schema: public; Owner: rudyard
--

ALTER TABLE ONLY public.resource ALTER COLUMN id SET DEFAULT nextval('public.resource_id_seq'::regclass);


--
-- Name: id; Type: DEFAULT; Schema: public; Owner: rudyard
--

ALTER TABLE ONLY public.role ALTER COLUMN id SET DEFAULT nextval('public.role_id_seq'::regclass);


--
-- Name: id; Type: DEFAULT; Schema: public; Owner: rudyard
--

ALTER TABLE ONLY public.usr ALTER COLUMN id SET DEFAULT nextval('public.usr_id_seq'::regclass);


--
-- Data for Name: db_version; Type: TABLE DATA; Schema: public; Owner: rudyard
--

COPY public.db_version (id, version) FROM stdin;
0	2019-02-18T214320Z_init
\.


--
-- Data for Name: grp; Type: TABLE DATA; Schema: public; Owner: rudyard
--

COPY public.grp (id, name) FROM stdin;
1	a
2	b
3	c
4	d
\.


--
-- Name: grp_id_seq; Type: SEQUENCE SET; Schema: public; Owner: rudyard
--

SELECT pg_catalog.setval('public.grp_id_seq', 4, true);


--
-- Data for Name: grp_policy; Type: TABLE DATA; Schema: public; Owner: rudyard
--

COPY public.grp_policy (grp_id, policy_id) FROM stdin;
\.


--
-- Data for Name: permission; Type: TABLE DATA; Schema: public; Owner: rudyard
--

COPY public.permission (role_id, name, service, method, constraints, description) FROM stdin;
2	foo	bazgo	create	{}	
\.


--
-- Data for Name: policy; Type: TABLE DATA; Schema: public; Owner: rudyard
--

COPY public.policy (id, name, description) FROM stdin;
1	bazgo-create-b	
\.


--
-- Name: policy_id_seq; Type: SEQUENCE SET; Schema: public; Owner: rudyard
--

SELECT pg_catalog.setval('public.policy_id_seq', 2, true);


--
-- Data for Name: policy_resource; Type: TABLE DATA; Schema: public; Owner: rudyard
--

COPY public.policy_resource (policy_id, resource_id) FROM stdin;
\.


--
-- Data for Name: policy_role; Type: TABLE DATA; Schema: public; Owner: rudyard
--

COPY public.policy_role (policy_id, role_id) FROM stdin;
1	2
\.


--
-- Data for Name: resource; Type: TABLE DATA; Schema: public; Owner: rudyard
--

COPY public.resource (id, name, description, path) FROM stdin;
1	root	\N	root
9	a		root.a
10	b		root.a.b
11	c		root.a.b.c
\.


--
-- Name: resource_id_seq; Type: SEQUENCE SET; Schema: public; Owner: rudyard
--

SELECT pg_catalog.setval('public.resource_id_seq', 11, true);


--
-- Data for Name: role; Type: TABLE DATA; Schema: public; Owner: rudyard
--

COPY public.role (id, name, description) FROM stdin;
2	bazgo-create	
\.


--
-- Name: role_id_seq; Type: SEQUENCE SET; Schema: public; Owner: rudyard
--

SELECT pg_catalog.setval('public.role_id_seq', 4, true);


--
-- Data for Name: usr; Type: TABLE DATA; Schema: public; Owner: rudyard
--

COPY public.usr (id, name, email) FROM stdin;
1	boboo	\N
2	awllw	\N
3	dbnnn	\N
\.


--
-- Data for Name: usr_grp; Type: TABLE DATA; Schema: public; Owner: rudyard
--

COPY public.usr_grp (usr_id, grp_id) FROM stdin;
1	1
1	2
1	4
2	4
3	1
\.


--
-- Name: usr_id_seq; Type: SEQUENCE SET; Schema: public; Owner: rudyard
--

SELECT pg_catalog.setval('public.usr_id_seq', 3, true);


--
-- Data for Name: usr_policy; Type: TABLE DATA; Schema: public; Owner: rudyard
--

COPY public.usr_policy (usr_id, policy_id) FROM stdin;
\.


--
-- Name: db_version_pkey; Type: CONSTRAINT; Schema: public; Owner: rudyard
--

ALTER TABLE ONLY public.db_version
    ADD CONSTRAINT db_version_pkey PRIMARY KEY (id);


--
-- Name: grp_name_key; Type: CONSTRAINT; Schema: public; Owner: rudyard
--

ALTER TABLE ONLY public.grp
    ADD CONSTRAINT grp_name_key UNIQUE (name);


--
-- Name: grp_pkey; Type: CONSTRAINT; Schema: public; Owner: rudyard
--

ALTER TABLE ONLY public.grp
    ADD CONSTRAINT grp_pkey PRIMARY KEY (id);


--
-- Name: grp_policy_pkey; Type: CONSTRAINT; Schema: public; Owner: rudyard
--

ALTER TABLE ONLY public.grp_policy
    ADD CONSTRAINT grp_policy_pkey PRIMARY KEY (grp_id, policy_id);


--
-- Name: permission_pkey; Type: CONSTRAINT; Schema: public; Owner: rudyard
--

ALTER TABLE ONLY public.permission
    ADD CONSTRAINT permission_pkey PRIMARY KEY (role_id, name);


--
-- Name: policy_name_key; Type: CONSTRAINT; Schema: public; Owner: rudyard
--

ALTER TABLE ONLY public.policy
    ADD CONSTRAINT policy_name_key UNIQUE (name);


--
-- Name: policy_pkey; Type: CONSTRAINT; Schema: public; Owner: rudyard
--

ALTER TABLE ONLY public.policy
    ADD CONSTRAINT policy_pkey PRIMARY KEY (id);


--
-- Name: policy_resource_pkey; Type: CONSTRAINT; Schema: public; Owner: rudyard
--

ALTER TABLE ONLY public.policy_resource
    ADD CONSTRAINT policy_resource_pkey PRIMARY KEY (policy_id, resource_id);


--
-- Name: policy_role_pkey; Type: CONSTRAINT; Schema: public; Owner: rudyard
--

ALTER TABLE ONLY public.policy_role
    ADD CONSTRAINT policy_role_pkey PRIMARY KEY (policy_id, role_id);


--
-- Name: resource_path_key; Type: CONSTRAINT; Schema: public; Owner: rudyard
--

ALTER TABLE ONLY public.resource
    ADD CONSTRAINT resource_path_key UNIQUE (path);


--
-- Name: resource_pkey; Type: CONSTRAINT; Schema: public; Owner: rudyard
--

ALTER TABLE ONLY public.resource
    ADD CONSTRAINT resource_pkey PRIMARY KEY (id);


--
-- Name: role_name_key; Type: CONSTRAINT; Schema: public; Owner: rudyard
--

ALTER TABLE ONLY public.role
    ADD CONSTRAINT role_name_key UNIQUE (name);


--
-- Name: role_pkey; Type: CONSTRAINT; Schema: public; Owner: rudyard
--

ALTER TABLE ONLY public.role
    ADD CONSTRAINT role_pkey PRIMARY KEY (id);


--
-- Name: usr_grp_pkey; Type: CONSTRAINT; Schema: public; Owner: rudyard
--

ALTER TABLE ONLY public.usr_grp
    ADD CONSTRAINT usr_grp_pkey PRIMARY KEY (usr_id, grp_id);


--
-- Name: usr_name_key; Type: CONSTRAINT; Schema: public; Owner: rudyard
--

ALTER TABLE ONLY public.usr
    ADD CONSTRAINT usr_name_key UNIQUE (name);


--
-- Name: usr_pkey; Type: CONSTRAINT; Schema: public; Owner: rudyard
--

ALTER TABLE ONLY public.usr
    ADD CONSTRAINT usr_pkey PRIMARY KEY (id);


--
-- Name: usr_policy_pkey; Type: CONSTRAINT; Schema: public; Owner: rudyard
--

ALTER TABLE ONLY public.usr_policy
    ADD CONSTRAINT usr_policy_pkey PRIMARY KEY (usr_id, policy_id);


--
-- Name: resource_path_idx; Type: INDEX; Schema: public; Owner: rudyard
--

CREATE INDEX resource_path_idx ON public.resource USING gist (path);


--
-- Name: resource_has_parent_check; Type: TRIGGER; Schema: public; Owner: rudyard
--

CREATE CONSTRAINT TRIGGER resource_has_parent_check AFTER INSERT OR UPDATE ON public.resource DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE PROCEDURE public.resource_has_parent();


--
-- Name: resource_path_compute_name; Type: TRIGGER; Schema: public; Owner: rudyard
--

CREATE TRIGGER resource_path_compute_name BEFORE INSERT OR UPDATE ON public.resource FOR EACH ROW EXECUTE PROCEDURE public.resource_path();


--
-- Name: resource_path_delete_children; Type: TRIGGER; Schema: public; Owner: rudyard
--

CREATE TRIGGER resource_path_delete_children AFTER DELETE ON public.resource FOR EACH ROW EXECUTE PROCEDURE public.resource_recursive_delete();


--
-- Name: resource_path_update_children; Type: TRIGGER; Schema: public; Owner: rudyard
--

CREATE TRIGGER resource_path_update_children AFTER UPDATE ON public.resource FOR EACH ROW EXECUTE PROCEDURE public.resource_recursive_update();


--
-- Name: grp_policy_grp_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: rudyard
--

ALTER TABLE ONLY public.grp_policy
    ADD CONSTRAINT grp_policy_grp_id_fkey FOREIGN KEY (grp_id) REFERENCES public.grp(id) ON DELETE CASCADE;


--
-- Name: grp_policy_policy_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: rudyard
--

ALTER TABLE ONLY public.grp_policy
    ADD CONSTRAINT grp_policy_policy_id_fkey FOREIGN KEY (policy_id) REFERENCES public.policy(id) ON DELETE CASCADE;


--
-- Name: permission_role_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: rudyard
--

ALTER TABLE ONLY public.permission
    ADD CONSTRAINT permission_role_id_fkey FOREIGN KEY (role_id) REFERENCES public.role(id) ON DELETE CASCADE;


--
-- Name: policy_resource_policy_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: rudyard
--

ALTER TABLE ONLY public.policy_resource
    ADD CONSTRAINT policy_resource_policy_id_fkey FOREIGN KEY (policy_id) REFERENCES public.policy(id) ON DELETE CASCADE;


--
-- Name: policy_resource_resource_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: rudyard
--

ALTER TABLE ONLY public.policy_resource
    ADD CONSTRAINT policy_resource_resource_id_fkey FOREIGN KEY (resource_id) REFERENCES public.resource(id) ON DELETE CASCADE;


--
-- Name: policy_role_policy_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: rudyard
--

ALTER TABLE ONLY public.policy_role
    ADD CONSTRAINT policy_role_policy_id_fkey FOREIGN KEY (policy_id) REFERENCES public.policy(id) ON DELETE CASCADE;


--
-- Name: policy_role_role_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: rudyard
--

ALTER TABLE ONLY public.policy_role
    ADD CONSTRAINT policy_role_role_id_fkey FOREIGN KEY (role_id) REFERENCES public.role(id) ON DELETE CASCADE;


--
-- Name: usr_grp_grp_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: rudyard
--

ALTER TABLE ONLY public.usr_grp
    ADD CONSTRAINT usr_grp_grp_id_fkey FOREIGN KEY (grp_id) REFERENCES public.grp(id) ON DELETE CASCADE;


--
-- Name: usr_grp_usr_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: rudyard
--

ALTER TABLE ONLY public.usr_grp
    ADD CONSTRAINT usr_grp_usr_id_fkey FOREIGN KEY (usr_id) REFERENCES public.usr(id) ON DELETE CASCADE;


--
-- Name: usr_policy_policy_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: rudyard
--

ALTER TABLE ONLY public.usr_policy
    ADD CONSTRAINT usr_policy_policy_id_fkey FOREIGN KEY (policy_id) REFERENCES public.policy(id) ON DELETE CASCADE;


--
-- Name: usr_policy_usr_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: rudyard
--

ALTER TABLE ONLY public.usr_policy
    ADD CONSTRAINT usr_policy_usr_id_fkey FOREIGN KEY (usr_id) REFERENCES public.usr(id) ON DELETE CASCADE;


--
-- Name: SCHEMA public; Type: ACL; Schema: -; Owner: postgres
--

REVOKE ALL ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM postgres;
GRANT ALL ON SCHEMA public TO postgres;
GRANT ALL ON SCHEMA public TO PUBLIC;


--
-- PostgreSQL database dump complete
--

