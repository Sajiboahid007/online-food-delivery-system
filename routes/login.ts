import express, { Request, Response } from "express";
import { PrismaClient } from "@prisma/client";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { FDSConfig } from "../FDSConfig";
import { authenticate } from "../authenticate";
import { AuthenticatedRequest } from "../interfaces";
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

router.post("/refresh-token", async (req, res) => {
  try {
    const refreshTokenId = req?.body.refreshTokenId;
    const usersession = await prisma.UserSessions.findFirst({
      where: { RefreshtokenId: refreshTokenId },
    });
    if (!usersession) {
      res.status(404).json({ message: "Invalid refresh Token" });
    }
    const guid = generateGUID();
    const updateUserSession = await prisma.UserSessions.update({
      data: {
        RefreshtokenId: guid,
      },
      where: {
        RefreshtokenId: refreshTokenId,
      },
    });
  } catch (error) {}
});

module.exports = router;
