-- AlterTable
ALTER TABLE "Session" ADD COLUMN     "authenticatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP;

-- Existing sessions last authenticated when they were created (sign-in); refreshes never re-authenticate.
UPDATE "Session" SET "authenticatedAt" = "createdAt";
