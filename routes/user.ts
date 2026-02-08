import express, { Request, Response } from "express";
import { PrismaClient } from "@prisma/client";
import bcrypt from "bcrypt";
import { authenticate } from "../authenticate";
import { AuthenticatedRequest } from "../interfaces";
import { User } from "../entity-models";

const prisma = new PrismaClient();

const router = express.Router();

router.get(
  "/users/get",
  authenticate,
  async (_req: AuthenticatedRequest, res: Response) => {
    try {
      const userGet = await prisma.users.findMany();
      res.json(userGet);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch users" });
    }
  },
);

router.get(
  "/users/getById/:id",
  authenticate,
  async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      const id = Number(req?.params?.id);

      if (isNaN(id) || id <= 0) {
        res.status(400).json({ message: "Invalid user ID" });
        return;
      }

      const user = await prisma.users.findFirst({
        where: {
          Id: id,
        },
      });

      if (!user) {
        res.status(404).json({ message: "User not found" });
        return;
      }

      res.json({ user, message: "Successfully retrieved user by id" });
    } catch (error: any) {
      res.status(500).json({ error: error.message });
    }
  },
);

router.post("/users/create", async (req: Request, res: Response) => {
  try {
    const { RoleId, Name, Email, Phone, Password, Address, Status } = req?.body;

    const hashPassword = await bcrypt.hash(Password, 17);
    type UserWithoutPassword = Omit<User, "Password">;

    const user: UserWithoutPassword = await prisma.users.create({
      data: {
        RoleId,
        Name,
        Email,
        Phone,
        Password: hashPassword,
        Address,
        Status,
      },
    });

    res.json({ user, message: "User create successfully" });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

router.put(
  "/users/update/:id",
  authenticate,
  async (req: AuthenticatedRequest, res: Response) => {
    try {
      const id = Number(req.params.id);

      const isExist = await prisma.users.findFirst({
        where: {
          Id: id,
        },
      });

      if (!isExist) {
        return res.status(401).json({ message: "user not found!" });
      }

      const { RoleId, Name, Email, Phone, Address } = req?.body;

      const updateUser = await prisma.users.update({
        data: {
          RoleId: RoleId,
          Name: Name,
          Email: Email,
          Phone: Phone,
          Address: Address,
        },
        where: {
          Id: id,
        },
      });
      return res.json(updateUser);
    } catch (err: any) {
      return res.status(500).json({ error: err.message });
    }
  },
);

router.delete(
  "/users/delete/:id",
  authenticate,
  async (req: AuthenticatedRequest, res: Response) => {
    try {
      const id = Number(req.params.id);
      await prisma.users.delete({
        where: { Id: id },
      });
      res.json({ message: `Successfull deleted Id number ${id}` });
    } catch (error) {
      res.status(501).json({ message: error });
    }
  },
);

module.exports = router;
