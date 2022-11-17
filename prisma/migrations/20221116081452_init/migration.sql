-- CreateTable
CREATE TABLE "User" (
    "id" SERIAL NOT NULL,
    "email" TEXT NOT NULL,
    "password" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "refreshToken" TEXT,
    "uuidForRefreshToken" TEXT,

    CONSTRAINT "User_pkey" PRIMARY KEY ("id")
);
