-- AlterTable
ALTER TABLE "DropChunk" ADD COLUMN     "storedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP;

-- CreateIndex
CREATE INDEX "DropChunk_dropId_storedAt_idx" ON "DropChunk"("dropId", "storedAt");
