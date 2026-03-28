import express, { Router } from "express";
import { PrismaClient } from "@prisma/client";
import { authenticate } from "../authenticate";
import { AuthenticatedRequest } from "../interfaces";
import { FDSConfig } from "../FDSConfig";

const prisma = new PrismaClient();

const router = Router();

router.get("/sub-categories/get", async (_req, res) => {
  try {
    const subCategories = await prisma.subCategories.findMany({
      where: {
        IsMarkToDelete: false,
      },
      orderBy: {
        CreatedDate: "desc",
      },
    });
    res.json({
      message: "",
      data: subCategories,
      error: null,
      statusCode: 200,
    });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
    console.log(error);
  }
});

router.get("/sub-categories/get/:id", authenticate, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (isNaN(id) || id <= 0) {
      res.status(400).json({ message: "Invalid sub-category ID" });
      return;
    }
    const subCategory = await prisma.subCategories.findUnique({
      where: {
        Id: id,
      },
    });
    res.json({ message: "", data: subCategory, error: null, statusCode: 200 });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

router.post(
  "/sub-categories/create",
  async (req: AuthenticatedRequest, res) => {
    try {
      const { Name, Status, ImageUrl, CategoriesId } = req.body;
      const subCategory = await prisma.subCategories.create({
        data: {
          Name,
          Status,
          ImageUrl,
          CategoriesId,
          CreatedBy: req?.userEmail ?? FDSConfig.DefaultAdminEmail,
          CreatedDate: new Date(),
        },
      });
      res.json({
        data: subCategory,
        message: "Sub-category created successfully",
        error: null,
        statusCode: 200,
      });
    } catch (error: any) {
      res.status(500).json({ error: error.message });
    }
  },
);

router.put(
  "/sub-categories/update/:id",
  authenticate,
  async (req: AuthenticatedRequest, res) => {
    try {
      const id = Number(req.params.id);
      if (isNaN(id) || id <= 0) {
        res.status(400).json({ message: "Invalid sub-category ID" });
        return;
      }
      const { Name, Status, ImageUrl, CategoriesId } = req.body;
      const subCategory = await prisma.subCategories.update({
        where: {
          Id: id,
        },
        data: {
          Name,
          Status,
          ImageUrl,
          CategoriesId,
          UpdatedBy: req?.userEmail ?? FDSConfig.DefaultAdminEmail,
          UpdatedDate: new Date(),
        },
      });
      res.json({
        data: subCategory,
        message: "Sub-category updated successfully",
        error: null,
        statusCode: 200,
      });
    } catch (error: any) {
      res.status(500).json({ error: error.message });
    }
  },
);

router.delete(
  "/sub-categories/delete/:id",
  authenticate,
  async (req: AuthenticatedRequest, res) => {
    try {
      const id = Number(req.params.id);
      if (isNaN(id) || id <= 0) {
        res.status(400).json({ message: "Invalid sub-category ID" });
        return;
      }
      const subCategory = await prisma.subCategories.update({
        where: {
          Id: id,
        },
        data: {
          IsMarkToDelete: true,
          UpdatedBy: req?.userEmail ?? FDSConfig.DefaultAdminEmail,
          UpdatedDate: new Date(),
        },
      });
      res.json({
        data: subCategory,
        message: "Sub-category deleted successfully",
        error: null,
        statusCode: 200,
      });
    } catch (error: any) {
      res.status(500).json({ error: error.message });
    }
  },
);
module.exports = router;
