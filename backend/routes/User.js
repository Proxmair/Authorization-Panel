import express from "express";
import { register, login ,logout ,forgotPassword,resetPassword,loadUser ,googleJoin} from '../controllers/User.js';
import { isAuthenticated } from "../middleware/auth.js";
export const userRouter=express.Router();

userRouter.route("/register").post(register);
userRouter.route("/login").post(login);
userRouter.route("/googlejoin").post(googleJoin);
userRouter.route("/logout").get(logout);
userRouter.route("/password/forgot").post(forgotPassword);
userRouter.route("/password/reset/:token").put(resetPassword);
userRouter.route("/me").get( isAuthenticated ,loadUser);
