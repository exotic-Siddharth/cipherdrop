-- AlterEnum
ALTER TYPE "AuditAction" ADD VALUE 'ADMIN_USER_UPDATED';
ALTER TYPE "AuditAction" ADD VALUE 'ADMIN_USER_SUSPENDED';
ALTER TYPE "AuditAction" ADD VALUE 'ADMIN_USER_UNSUSPENDED';
ALTER TYPE "AuditAction" ADD VALUE 'ADMIN_SESSIONS_REVOKED';
ALTER TYPE "AuditAction" ADD VALUE 'ADMIN_REPORT_DISMISSED';
ALTER TYPE "AuditAction" ADD VALUE 'ADMIN_DROP_DISABLED';

-- AlterTable
ALTER TABLE "User" ADD COLUMN     "suspendedAt" TIMESTAMP(3),
ADD COLUMN     "suspendedReason" TEXT;

-- AlterTable
ALTER TABLE "AuditEvent" ADD COLUMN     "actorId" TEXT;

-- CreateIndex
CREATE INDEX "AuditEvent_actorId_createdAt_idx" ON "AuditEvent"("actorId", "createdAt");

-- AddForeignKey
ALTER TABLE "AuditEvent" ADD CONSTRAINT "AuditEvent_actorId_fkey" FOREIGN KEY ("actorId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;
