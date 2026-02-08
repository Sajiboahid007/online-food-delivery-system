import express, { Request, Response } from "express";
import { PrismaClient } from "@prisma/client";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { FDSConfig } from "../FDSConfig";
import { generateGUID } from "../guid-generator";

const prisma = new PrismaClient();

const router = express.Router();

router.post("/login", async (req: Request, res: Response) => {
  try {
    const { Email, Password } = req?.body;

    const user = await prisma.users.findUnique({
      include: { Roles: true },
      where: { Email },
    });

    if (!user) {
      res.status(401).json({ error: "Invalid email or password" });
      return;
    }

    const isMatch = await bcrypt.compare(Password, user.Password);

    if (!isMatch) {
      res.status(401).json({ error: "Invalid email or password" });
      return;
    }

    const token = jwt.sign(
      { userId: user.Id, userEmail: user.Email, role: user?.Roles?.RoleName },
      FDSConfig.JwtSecret,
      {
        expiresIn: "7m", // "1h",
      },
    );

    res.json({
      message: "Login successful",
      token,
    });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

router.get("/getToken/:refreshToken", async (req, res) => {
  try {
    const refreshToken = req?.params?.refreshToken;
    const sessionInfo = await insertOrUpdateRefreshToken("", refreshToken);

    if (!sessionInfo) {
      res.status(404).json({
        message: "invalid refresh token",
      });
    }

    const user = await prisma.users.findUnique({
      where: {
        Id: sessionInfo?.UserId,
      },
    });

    sendJwtToken(user, res, sessionInfo?.RefreshToken ?? "");
  } catch (error) {}
});

function sendJwtToken(user: any, response: any, refreshToken: string) {
  const token = jwt.sign(
    {
      userId: user?.Id,
      userEmail: user?.Email,
      role: user?.Roles?.RoleName,
      refreshToken,
    },
    FDSConfig.JwtSecret,
    {
      expiresIn: "7m", // "1h",
    },
  );

  response.json({
    message: "Login successful",
    token,
  });
}

async function insertOrUpdateRefreshToken(
  userId: string,
  refreshToken: string = "",
  isCreationRequired: boolean = false,
) {
  const userSession = await prisma.UserSessions.findFirst({
    where: {
      OR: [{ UserId: userId }, { RefreshToken: refreshToken }],
      AND: [{ IsActive: true }],
    },
  });

  if (!userSession) {
    return null;
  }
  const newToken = generateGUID();

  await prisma.UserSessions.update({
    data: { RefreshToken: newToken },
  });

  return { UserId: userSession.UserId, RefreshToken: newToken };
}

module.exports = router;
