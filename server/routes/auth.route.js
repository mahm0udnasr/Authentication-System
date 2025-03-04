import express from "express";
import {
  register,
  login,
  logout,
  refreshToken,
} from "../controller/auth.controller.js";

const authRouter = express.Router();

authRouter.post("/register", register);

authRouter.post("/login", login);

authRouter.post("/logout", logout);

export default authRouter;
