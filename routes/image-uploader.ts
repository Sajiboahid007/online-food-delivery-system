import express, { Response } from "express";
import { v2 as cloudinary } from "cloudinary";
import { FDSConfig } from "../FDSConfig";
const router = express.Router();
cloudinary.config(FDSConfig.CloudinaryConfig);

router.post("/upload", async (req: any, res: Response) => {
  try {
    console.debug("Received image upload request with body:", req.body);
    const result = await cloudinary.uploader.upload(req.body.image);
    res.json({
      message: "Image uploaded successfully",
      data: { ImageUrl: result.secure_url },
      error: null,
      statusCode: 200,
    });
  } catch (error: any) {
    console.error(error);
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;
