import { User } from "../model/User.js";
import jwt from "jsonwebtoken";
import { sendEmail } from "../utils/SendEmail.js";
import crypto from "crypto";
export const register = async (req, res) => {
  try {
    const { email, password, name, image } = req.body;
    const user = await User.findOne({ email });
    if (user) {
      if (user.password == password) {
        const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET);
        return res
          .status(200)
          .cookie("token", token, {
            expires: new Date(Date.now() + 600000),
            httpOnly: true,
          })
          .json({
            success: true,
            message: "Logged In Successfully",
            user,
          });
      }
      return res.status(400).json({
        success: false,
        message: "This mail is already in use",
      });
    }
    const newUser = await User.create({
      name,
      email,
      password,
      image,
    });
    const token = jwt.sign({ _id: newUser._id }, process.env.JWT_SECRET);
    if (!newUser) {
      return res.status(400).json({
        success: false,
        message: "Cannot Register",
      });
    }
    return res
      .status(201)
      .cookie("token", token, {
        expires: new Date(Date.now() + 600000),
        httpOnly: true,
      })
      .json({
        success: true,
        message: "You are Registered Successfully",
        user: newUser,
      });
  } catch (error) {
    return res.status(400).json({
      success: false,
      message: error.message,
    });
  }
};
export const googleJoin = async (req, res) => {
  try {
    const { email, password, name, image } = req.body;
    const user = await User.findOne({ email });
    if (user) {
      const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET);
      return res
        .status(200)
        .cookie("token", token, {
          expires: new Date(Date.now() + 600000),
          httpOnly: true,
        })
        .json({
          success: true,
          message: "Logged In Successfully",
          user,
        });
    }
    const newUser = await User.create({
      name,
      email,
      password,
      image,
    });
    const token = jwt.sign({ _id: newUser._id }, process.env.JWT_SECRET);
    if (!newUser) {
      return res.status(400).json({
        success: false,
        message: "Cannot Register",
      });
    }
    return res
      .status(201)
      .cookie("token", token, {
        expires: new Date(Date.now() + 600000),
        httpOnly: true,
      })
      .json({
        success: true,
        message: "You are Registered Successfully",
        user: newUser,
      });
  } catch (error) {
    return res.status(400).json({
      success: false,
      message: error.message,
    });
  }
};
export const login = async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email, password });
    if (!user) {
      return res.status(400).json({
        success: false,
        message: "Invalid email or password",
      });
    }
    const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET);
    res
      .status(200)
      .cookie("token", token, {
        expires: new Date(Date.now() + 600000),
        httpOnly: true,
      })
      .json({
        success: true,
        message: "Logged In Successfully",
        user,
      });
  } catch (error) {
    return res.status(400).json({
      success: false,
      message: error.message,
    });
  }
};
export const logout = async (req, res) => {
  try {
    res
      .status(200)
      .cookie("token", null, {
        expires: new Date(Date.now()),
        httpOnly: true,
      })
      .json({
        success: true,
        message: "Logged Out Successfully",
      });
  } catch (error) {
    return res.status(400).json({
      success: false,
      message: error.message,
    });
  }
};
export const forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({
        success: false,
        message: "email not found",
      });
    }
    const resetToken = user.getResetPasswordToken();
    await user.save({ validateBeforeSave: false });
    const resetPasswordUrl = `${process.env.FRONTEND_URL}/password/reset/${resetToken}`;
    const message = `Your password reset token is :- \n\n ${resetPasswordUrl} \n\nIf you have not requested this email then, please ignore it.`;
    try {
      await sendEmail(user.email, "Recovery Password Mail", message);
      res.status(200).json({
        success: true,
        message: `Email sent to ${user.email} successfully`,
      });
    } catch (error) {
      user.resetPasswordToken = undefined;
      user.resetPasswordExpire = undefined;
      await user.save({ validateBeforeSave: false });
      return res.status(500).json({
        success: false,
        message: error.message,
      });
    }
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error.message,
    });
  }
};
export const resetPassword = async (req, res) => {
  try {
    console.log(req.params.token);
    const resetPasswordToken = crypto
      .createHash("sha256")
      .update(req.params.token)
      .digest("hex");
    const user = await User.findOne({
      resetPasswordToken,
      resetPasswordExpire: { $gt: Date.now() },
    });
    if (!user) {
      return res.status(400).json({
        success: false,
        message: "Token is either invalid or expire",
      });
    }
    user.password = req.body.newPassword;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpire = undefined;
    await user.save();
    return res.status(200).json({
      success: true,
      message: "Password is Updated You can now login with new password",
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error.message,
    });
  }
};
export const loadUser = async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    res.status(200).json({
      success: true,
      user,
    });
  } catch (error) {
    return res.status(400).json({
      success: false,
      message: error.message,
    });
  }
};
