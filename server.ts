import express from "express";
import cors from "cors";
const app = express();
app.use(
  cors({
    origin: "*", // Allows all origins (only for development!)
  }),
);

app.use(express.json());

// importer
const loginRouter = require("./routes/login");
const userRouter = require("./routes/user");
const categoryRouter = require("./routes/categories");

// api's
app.use("/api", loginRouter);
app.use("/api", userRouter);
app.use("/api", categoryRouter);
app.listen(4000, () => {
  console.log("server run on 4000");
});
