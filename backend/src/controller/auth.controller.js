import tryCatch from "../utils/tryCatch.js";
import User from "../models/user.model.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { generateAccessToken, generateRefreshToken } from "../utils/token.js";

const register = tryCatch(async (req, res, next) => {
  const { fullName, email, password, username } = req.body;

  if (!fullName || !email || !password || !username) {
    res.status(400);
    throw new Error("Invalid request");
  }

  // Check the username is valid charachter
  const usernameRegex = /^(?!.*\.\.)(?!.*\.$)[a-zA-Z0-9._]{1,30}$/;
  if (!usernameRegex.test(username)) {
    res.status(400);
    throw new Error("Invalid username try again");
  }

  const normalizedUsername = username.toLowerCase().trim();
  const normalizedEmail = email.toLowerCase().trim();

  // Checking Username is Taken 
  const isUsernameTaken = await User.exists({ username: normalizedUsername });
  if (isUsernameTaken) {
    res.status(400);
    throw new Error("Username Already is taken");
  }

  // Checking Email is Taken 
  const isEmailTaken = await User.exists({ email: normalizedEmail });
  if (isEmailTaken) {
    res.status(400);
    throw new Error("Email Already is taken");
  }

  // Hashing Password
  const salt = bcrypt.genSaltSync(10);
  const hashedPassword = bcrypt.hashSync(password, salt);

  // Storing User Info to Database 
  await User.create({
    email: normalizedEmail,
    fullName,
    username: normalizedUsername,
    password: hashedPassword,
  });

  res
    .status(201)
    .json({ status: "success", message: "Account Created Successfully" });
});

const login = tryCatch(async (req, res, next) => {
  // Validation 
  const { password, username } = req.body;
  if (!password || !username) {
    res.status(400);
    throw new Error("Invalid request");
  }

  const normalizedUsername = username.toLowerCase().trim();

  // Getting UserInfo Using Username 
  const userDoc = await User.findOne({
    username: normalizedUsername,
  }).select("+password");

  if (!userDoc) {
    res.status(404);
    throw new Error("User not found");
  }

  // Compare User Hashed Pass to req pass 
  const isPassOk = bcrypt.compareSync(password, userDoc.password);
  if (!isPassOk) {
    res.status(400);
    throw new Error("Invalid credentials");
  }

  // Generate Token then Send Refresh Token Via Cookie and send accessToken as a response
  const refreshToken = generateRefreshToken(userDoc._id);
  const accessToken = generateAccessToken({
    userId: userDoc._id,
  });

  // Set refresh token as a HTTP-only cookie
  res
    .cookie("refreshToken", refreshToken, {
      httpOnly: true,
      path: "/",
      secure: process.env.NODE_ENV === "production",
      sameSite: "None",
      maxAge: 30 * 24 * 60 * 60 * 1000, //30 days
    })
    .json({ accessToken, message: "Login Successfully" });
});

const refreshToken = tryCatch(async (req, res) => {
  const _refreshToken = req.cookies.refreshToken;

  if (!_refreshToken) {
    res.status(401);
    throw new Error("Please login again");
  }

  const decoded = jwt.verify(
    _refreshToken,
    process.env.REFRESH_TOKEN_SECRET
  );

  // decoded the refresh token and get user id from decoded token
  const userId = decoded.userId;
  const userDoc = await User.findById(userId);

  if (!userDoc) {
    res.status(401);
    throw new Error("Can't find this account");
  }

  const accessToken = generateAccessToken({ userId });
  res.json({ accessToken });
});

const logout = tryCatch(async (req, res, next) => {
  // Clear Client Cookie 
  res.clearCookie("refreshToken").json({ message: "Logout Successfull" });
});

const authController = { login, register, logout, refreshToken };
export default authController;
