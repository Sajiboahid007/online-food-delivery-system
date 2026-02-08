import express from "express";

const app = express();
app.use(express.json());

// importer
const loginRouter = require("./routes/login");
const userRouter = require("./routes/user");

// api's
app.use("/api", loginRouter);
app.use("/api", userRouter);

app.listen(4000, () => {
  console.log("server run on 4000");
});
