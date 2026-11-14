-- AlterTable
ALTER TABLE "RefreshToken" ADD COLUMN     "rotatedFromId" TEXT;

-- CreateIndex
CREATE INDEX "RefreshToken_rotatedFromId_idx" ON "RefreshToken"("rotatedFromId");
