-- tamperlog PostgreSQL role template. Run once with administrator
-- credentials after schema.sql, replacing __SCHEMA__ with the schema name and
-- __APP_ROLE__ with the role the application connects as. Migrate() does not
-- run this file: creating roles needs CREATEROLE and is a deployment decision.
--
-- Result: the tables are owned by a sealed NOLOGIN role nobody can SET ROLE
-- to, and the application role can only read and append. A migrating role
-- with CREATEROLE keeps ADMIN on roles it creates on PostgreSQL 16 and later,
-- so that credential is administrator-tier; seals and anchors are what detect
-- its edits.

DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'tamperlog_owner') THEN
    CREATE ROLE tamperlog_owner NOLOGIN;
  END IF;
END
$$;

ALTER TABLE __SCHEMA__.tamperlog_event        OWNER TO tamperlog_owner;
ALTER TABLE __SCHEMA__.tamperlog_stream_head  OWNER TO tamperlog_owner;
ALTER TABLE __SCHEMA__.tamperlog_seal         OWNER TO tamperlog_owner;
ALTER TABLE __SCHEMA__.tamperlog_proof        OWNER TO tamperlog_owner;
ALTER TABLE __SCHEMA__.tamperlog_schema       OWNER TO tamperlog_owner;
ALTER FUNCTION __SCHEMA__.tamperlog_refuse_change() OWNER TO tamperlog_owner;
ALTER FUNCTION __SCHEMA__.tamperlog_check_link()    OWNER TO tamperlog_owner;
ALTER FUNCTION __SCHEMA__.tamperlog_check_seal()    OWNER TO tamperlog_owner;
ALTER FUNCTION __SCHEMA__.tamperlog_lp(bytea)       OWNER TO tamperlog_owner;
ALTER FUNCTION __SCHEMA__.tamperlog_canonical_binary_v1(__SCHEMA__.tamperlog_event) OWNER TO tamperlog_owner;
ALTER FUNCTION __SCHEMA__.tamperlog_link_binary_v1_sha256(__SCHEMA__.tamperlog_event) OWNER TO tamperlog_owner;

REVOKE ALL ON __SCHEMA__.tamperlog_event, __SCHEMA__.tamperlog_stream_head,
              __SCHEMA__.tamperlog_seal, __SCHEMA__.tamperlog_proof,
              __SCHEMA__.tamperlog_schema FROM PUBLIC;
GRANT USAGE ON SCHEMA __SCHEMA__ TO __APP_ROLE__;
GRANT SELECT, INSERT ON __SCHEMA__.tamperlog_event       TO __APP_ROLE__;
GRANT SELECT, INSERT ON __SCHEMA__.tamperlog_stream_head TO __APP_ROLE__;
GRANT SELECT, INSERT ON __SCHEMA__.tamperlog_seal        TO __APP_ROLE__;
GRANT SELECT, INSERT ON __SCHEMA__.tamperlog_proof       TO __APP_ROLE__;
GRANT SELECT         ON __SCHEMA__.tamperlog_schema      TO __APP_ROLE__;

-- Postconditions: fail loudly if the result is weaker than intended.
DO $$
BEGIN
  IF EXISTS (
    SELECT FROM pg_roles
    WHERE rolname = 'tamperlog_owner'
      AND (rolcanlogin OR rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls)
  ) THEN
    RAISE EXCEPTION 'tamperlog_owner must have no attributes';
  END IF;
  IF EXISTS (
    SELECT FROM pg_auth_members
    WHERE roleid = 'tamperlog_owner'::regrole AND (set_option OR inherit_option)
  ) THEN
    RAISE EXCEPTION 'tamperlog_owner must have no usable members';
  END IF;
  IF EXISTS (
    SELECT FROM pg_class AS c, aclexplode(c.relacl) AS a
    WHERE c.relnamespace = '__SCHEMA__'::regnamespace
      AND c.relname LIKE 'tamperlog\_%'
      AND c.relkind IN ('r', 'p')
      AND a.grantee <> c.relowner
      AND NOT (a.grantee = '__APP_ROLE__'::regrole AND a.privilege_type IN ('SELECT', 'INSERT'))
  ) THEN
    RAISE EXCEPTION 'tamperlog tables may grant only SELECT and INSERT, only to __APP_ROLE__';
  END IF;
END
$$;
