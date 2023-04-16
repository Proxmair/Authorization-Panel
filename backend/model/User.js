import mongoose from "mongoose";
import crypto from 'crypto';
const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, "Enter Your Name"],
    },
    email: {
      type: String,
      unique: true,
      required: [true, "Enter Email"],
    },
    password: {
      type: String,
      required: [true, "Enter Password"],
    },
    image: {
      type: "String",
      required: true,
      default:
        "https://icon-library.com/images/anonymous-avatar-icon/anonymous-avatar-icon-25.jpg",
    },
    resetPasswordToken: String,
    resetPasswordExpire: Date,
  },
  { timestaps: true }
);
userSchema.methods.getResetPasswordToken=function(){
  const resetToken=crypto.randomBytes(20).toString("hex");
//Hashing and adding resetPassword to UserSchema
this.resetPasswordToken=crypto
.createHash("sha256")
.update(resetToken)
.digest("hex");
this.resetPasswordExpire=Date.now()+15*60*1000;
return resetToken;
}  
export const User = mongoose.model("User", userSchema);
