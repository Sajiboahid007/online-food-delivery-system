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

    const userSession = await refreshTokenForLogin(user.Id);

    sendJwtToken(user, res, userSession?.RefreshToken ?? "");
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

router.get("/getToken/:refreshToken", async (req, res) => {
  try {
    const refreshToken = req?.params?.refreshToken;
    const sessionInfo = await refreshTokenForAlreadyExist(refreshToken);

    if (!sessionInfo) {
      res.status(404).json({
        message: "invalid refresh token",
      });
    }

    const user = await prisma.users.findUnique({
      where: {
        Id: Number(sessionInfo?.UserId),
      },
    });

    sendJwtToken(user, res, sessionInfo?.RefreshToken ?? "");
  } catch (error) {
    console.error(error);
    res.status(404).json({ error: error });
  }
});

async function refreshTokenForLogin(userId: number) {
  if (userId <= 0) {
    return null;
  }
  console.log("here ", userId);
  const userSession = await prisma.userSessions.findFirst({
    where: {
      AND: [{ UserId: userId.toString() }, { IsActive: true }],
    },
  });

  const newToken = generateGUID();

  if (userSession) {
    console.log("user session null");
    await prisma.userSessions.updateMany({
      data: {
        RefreshtokenId: newToken,
        IsActive: true,
        CreatedDate: new Date(),
        Id: userSession.Id,
      },
    });
  } else {
    console.log("user session creatrnm");
    await prisma.userSessions.create({
      data: {
        RefreshtokenId: newToken,
        CreatedDate: new Date(),
        IsActive: true,
        Id: generateGUID(),
        UserId: userId.toString(),
      },
    });
  }
  console.log("returning ", {
    UserId: userId.toString(),
    RefreshToken: newToken,
  });
  return { UserId: userId.toString(), RefreshToken: newToken };
}

async function refreshTokenForAlreadyExist(refreshToken: string) {
  const userSession = await prisma.userSessions.findFirst({
    where: {
      AND: [{ RefreshtokenId: refreshToken }, { IsActive: true }],
    },
  });

  if (!userSession) {
    return null;
  }

  const guid = generateGUID();
  await prisma.userSessions.updateMany({
    data: { RefreshtokenId: guid, IsActive: true },
    where: {
      AND: [{ RefreshtokenId: refreshToken }, { IsActive: true }],
    },
  });

  return { UserId: userSession.UserId, RefreshToken: guid };
}

function sendJwtToken(user: any, response: any, refreshToken: string) {
  const token = jwt.sign(
    {
      userId: user?.Id,
      userEmail: user?.Email,
      role: user?.Roles?.RoleName,
    },
    FDSConfig.JwtSecret,
    {
      expiresIn: "7m", // "1h",
    },
  );

  response.json({
    message: "Login successful",
    token,
    refreshToken,
  });
}

module.exports = router;
