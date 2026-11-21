-- Append-only audit log (server-8). The runtime role has no UPDATE or DELETE on "AuditEvent" (runtimeRole.ts); the
-- cleanup job prunes through this owner function instead. The minimum ages live here, not in the caller: 365 days
-- for admin actions (every ADMIN_* action), 90 days for everything else, counted back from the given time, which
-- is clamped to the database clock so a caller cannot move it forward. Account deletion still removes a user's
-- own events (the foreign-key cascade runs as the table owner).
CREATE FUNCTION prune_audit_events(p_now TIMESTAMP(3)) RETURNS INTEGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path FROM CURRENT
AS $$
DECLARE
  t TIMESTAMP(3) := LEAST(p_now, (now() AT TIME ZONE 'UTC')::TIMESTAMP(3));
  n INTEGER;
BEGIN
  DELETE FROM "AuditEvent"
  WHERE ("action"::TEXT LIKE 'ADMIN\_%' AND "createdAt" <= t - INTERVAL '365 days')
     OR ("action"::TEXT NOT LIKE 'ADMIN\_%' AND "createdAt" <= t - INTERVAL '90 days');
  GET DIAGNOSTICS n = ROW_COUNT;
  RETURN n;
END
$$;

REVOKE ALL ON FUNCTION prune_audit_events(TIMESTAMP(3)) FROM PUBLIC;
