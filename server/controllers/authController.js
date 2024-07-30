const User = require('../models/User');
const { StatusCodes } = require('http-status-codes');
const CustomError = require('../errors');
const {
  attachCookiesToResponse, createTokenUser,
  sendVerificationEmail, sendResetPasswordEmail
 } = require('../utils');
const crypto = require('crypto');
const Token = require('../models/Token');

const register = async (req, res) => {
  const { email, name, password } = req.body;

  const emailAlreadyExists = await User.findOne({ email });
  if (emailAlreadyExists) {
    throw new CustomError.BadRequestError('Email already exists');
  }

  // first registered user is an admin
  const isFirstAccount = (await User.countDocuments({})) === 0;
  const role = isFirstAccount ? 'admin' : 'user';

  const verificationToken = crypto.randomBytes(40).toString('hex');
  const user = await User.create({ name, email, password, role, verificationToken });

  const forwardedHost = req.get('x-forwarded-host');
  const forwardedProtocol = req.get('x-forwarded-proto');
  const origin = `${forwardedProtocol}://${forwardedHost}`;

  await sendVerificationEmail({
    name: user.name,
    email: user.email,
    verificationToken: user.verificationToken,
    origin
  });

  res.status(StatusCodes.CREATED).json({
    msg: 'Sucess! Please check your email to verify account',
  });
};

const verifyEmail = async (req, res) => {
  const { verificationToken, email } = req.body;

  const user = await User.findOne({ email: email });
  if (!user) {
    throw new CustomError.UnauthenticatedError("Verification failed.");
  }

  if (user.verificationToken !== verificationToken) {
    throw new CustomError.UnauthenticatedError('Verification failed.');
  }

  user.isVerified = true;
  user.verified = Date.now();
  user.verificationToken = '';
  await user.save();

  res.status(StatusCodes.OK).json({ msg: 'Email verified.' });
}

const login = async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    throw new CustomError.BadRequestError('Please provide email and password.');
  }
  const user = await User.findOne({ email });

  if (!user) {
    throw new CustomError.UnauthenticatedError('Invalid Credentials.');
  }

  const isPasswordCorrect = await user.comparePassword(password);
  if (!isPasswordCorrect) {
    throw new CustomError.UnauthenticatedError('Invalid Credentials.');
  }

  if (!user.isVerified) {
    throw new CustomError.UnauthenticatedError('Please verify your email.');
  }

  const tokenUser = createTokenUser(user);

  let refreshToken = '';
  // check for existing token
  const existingToken = await Token.findOne({ user: user._id });
  if (existingToken) {
    const {isValid} = existingToken
    if (!isValid) throw new CustomError.UnauthenticatedError('Invalid Credentials');
    refreshToken = existingToken.refreshToken;
    attachCookiesToResponse({ res, user: tokenUser, refreshToken });

    res.status(StatusCodes.OK).json({ user: tokenUser });
    return;
  }

  // create refresh token
  refreshToken = crypto.randomBytes(4).toString('hex');
  const userAgent = req.headers['user-agent'];
  const ip = req.ip;
  const userToken = { refreshToken, ip, userAgent, user: user._id };
  await Token.create(userToken);

  attachCookiesToResponse({ res, user: tokenUser, refreshToken });

  res.status(StatusCodes.OK).json({ user: tokenUser });
};

const logout = async (req, res) => {
  await Token.findOneAndDelete({
    user: req.user.userId
  });

  res.cookie('accessToken', 'logout', {
    httpOnly: true,
    expires: new Date(Date.now()),
  });

  res.cookie('refreshToken', 'logout', {
    httpOnly: true,
    expires: new Date(Date.now()),
  });

  res.status(StatusCodes.OK).json({ msg: 'user logged out!' });
};

const forgotPassword = async (req, res) => {
  const {email} = req.body;
  if (!email) throw new CustomError.BadRequestError('Please provide valid email.');

  const user = await User.findOne({ email: email });
  if (user) {
    const passwordToken = crypto.randomBytes(70).toString('hex');

    // send email
    const forwardedHost = req.get('x-forwarded-host');
    const forwardedProtocol = req.get('x-forwarded-proto');
    const origin = `${forwardedProtocol}://${forwardedHost}`;
    await sendResetPasswordEmail({
      name: user.name,
      email: user.email,
      token: passwordToken,
      origin
    });
    console.log("password blah", passwordToken)
    const tenMinutes = 1000 * 60 * 10;
    const passwordTokenExpirationDate = new Date(Date.now() + tenMinutes);
    user.passwordToken = passwordToken;
    user.passwordTokenExpirationDate = passwordTokenExpirationDate;
    await user.save();
  }

  res.status(StatusCodes.OK).json({ msg: 'Please check your email for reset password link.' });
}

/*
http://localhost:3000/user/reset-password?token=be81c683091bf7649bf0470c21e05a4145b332d5d46e2115a477191e329b5d31f593b55d77767e1d6bc0af0a9137d547b0249e08ced2dc35f539ce24df50c9e862ba88f58f30&email=lucky@gmail.com
*/

const resetPassword = async (req, res) => {
  const { token, email, password } = req.body;
  if (!token || !email || !password) {
    throw new CustomError.BadRequestError('Please provide all values');
  }

  const user = await User.findOne({ email });
  if (user) {
    const currentDate = new Date();
    if (user.passwordToken === token && user.passwordTokenExpirationDate > currentDate) {
      user.password = password;
      user.passwordToken = null;
      user.passwordTokenExpirationDate = null;
      await user.save();
    }
  }

  res.status(StatusCodes.OK).json({ msg: 'user reset password' });
}

module.exports = {
  register,
  login,
  logout,
  verifyEmail,
  forgotPassword,
  resetPassword,
};
