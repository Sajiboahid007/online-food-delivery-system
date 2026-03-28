import express, { Response } from "express";
import { PrismaClient } from "@prisma/client";
import { authenticate } from "../authenticate";
import { AuthenticatedRequest } from "../interfaces";
import { FDSConfig } from "../FDSConfig";

const prisma = new PrismaClient();
const router = express.Router();

router.get("/categories/get", async (_req, res) => {
  try {
    const categories = await prisma.categories.findMany({
      where: {
        IsMarkToDelete: false,
      },
      orderBy: {
        CreatedDate: "desc",
      },
    });

    res.json({ message: "", data: categories, error: null, statusCode: 200 });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
    console.log(error);
  }
});

router.get("/categories/get/:id", authenticate, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (isNaN(id) || id <= 0) {
      res.status(400).json({ message: "Invalid category ID" });
      return;
    }
    const category = await prisma.categories.findUnique({
      where: {
        Id: id,
      },
    });
    res.json({ message: "", data: category, error: null, statusCode: 200 });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

router.post(
  "/categories/create",
  async (req: AuthenticatedRequest, res: Response) => {
    try {
      const { Name, Status, ImageUrl } = req.body;
      const category = await prisma.categories.create({
        data: {
          Name,
          Status,
          ImageUrl,
          CreatedBy: req?.userEmail ?? FDSConfig.DefaultAdminEmail,
        },
      });
      res.json({ category, message: "Category created successfully" });
    } catch (error: any) {
      res.status(500).json({ error: error.message });
    }
  },
);

router.put(
  "/categories/update/:id",
  authenticate,
  async (req: AuthenticatedRequest, res: Response) => {
    try {
      const id = Number(req.params.id);
      if (isNaN(id) || id <= 0) {
        res.status(400).json({ message: "Invalid category ID" });
        return;
      }
      const { Name, UpdatedBy } = req.body;
      const category = await prisma.categories.update({
        data: {
          Name,
          UpdatedBy: UpdatedBy ?? req.userEmail,
          UpdatedDate: new Date(),
        },
        where: {
          Id: id,
        },
      });
      res.json({ category, message: "Category updated successfully" });
    } catch (error: any) {
      res.status(500).json({ error: error.message });
    }
  },
);

// Soft Delete
router.put("/categories/delete/:id", async (req, res) => {
  try {
    const id = parseInt(req.params.id);

    const deleted = await prisma.categories.update({
      where: { Id: id },
      data: {
        IsMarkToDelete: true,
      },
    });

    res.json({
      message: "Category soft deleted successfully",
      data: deleted,
      error: null,
      statusCode: 200,
    });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;
