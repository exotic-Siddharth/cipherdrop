-- AuditEvent's foreign keys no longer cascade an update of "User".id (ids are cuids and never change): the
-- cascade runs as the table owner, so the runtime role, which keeps UPDATE on "User", could rewrite who an
-- append-only audit row is about or who acted.

-- DropForeignKey
ALTER TABLE "AuditEvent" DROP CONSTRAINT "AuditEvent_userId_fkey";

-- DropForeignKey
ALTER TABLE "AuditEvent" DROP CONSTRAINT "AuditEvent_actorId_fkey";

-- AddForeignKey
ALTER TABLE "AuditEvent" ADD CONSTRAINT "AuditEvent_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "AuditEvent" ADD CONSTRAINT "AuditEvent_actorId_fkey" FOREIGN KEY ("actorId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE RESTRICT;

-- A recipient's download grant keeps no network prefix (critic-7); clear the ones stored before.
UPDATE "DownloadGrant" SET "ipPrefix" = NULL WHERE "isAdmin" = false;
