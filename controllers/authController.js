const User = require('../models/administrator/auth');
const CryptoJs = require('crypto-js');
const jwt = require('jsonwebtoken');

module.exports = {
  createUser: async (req, res) => {
    try {
      const { username, email, password, avatar, role } = req.body;

      const encryptedPassword = CryptoJs.AES.encrypt(password, process.env.SECRET).toString();

      const newUser = new User({
        username,
        email,
        password: encryptedPassword,
        avatar,
        role
      });

      const savedUser = await newUser.save();
      res.json({ savedUser: { ...savedUser._doc, password: undefined } });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  },

  loginUser: async (req, res) => {
    try {
      const { email, password } = req.body;
      const user = await User.findOne({ email });

      if (!user) {
        return res.status(401).json({ error: 'User not found' });
      }

      const bytes = CryptoJs.AES.decrypt(user.password, process.env.SECRET);
      const originalPassword = bytes.toString(CryptoJs.enc.Utf8);

      if (originalPassword !== password) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      const accessToken = jwt.sign(
        { userId: user._id, role: user.role },
        process.env.JWT_SEC,
        { expiresIn: '1h' }
      );

      const refreshToken = jwt.sign(
        { userId: user._id },
        process.env.REFRESH_TOKEN_SEC,
        { expiresIn: '7d' }
      );

      user.refreshToken = refreshToken;
      await user.save();

      res.json({
        user: { ...user._doc, password: undefined, refreshToken: undefined },
        accessToken,
        refreshToken,
      });

    } catch (error) {
      console.error(error);
      res.status(500).json({ error: 'Internal Server Error' });
    }
  },

  refreshToken: async (req, res) => {
    try {
      const { refreshToken } = req.body;
      if (!refreshToken) {
        return res.status(401).json({ error: 'No refresh token provided' });
      }
  
      const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SEC);
      const user = await User.findById(decoded.userId);
  
      if (!user || user.refreshToken !== refreshToken) {
        return res.status(403).json({ error: 'Invalid refresh token' });
      }
  
      const newAccessToken = jwt.sign(
        { userId: user._id, role: user.role },
        process.env.JWT_SEC,
        { expiresIn: '1h' }
      );
  
      res.json({ accessToken: newAccessToken });
    } catch (error) {
      console.error(error);
      res.status(403).json({ error: 'Invalid refresh token' });
    }
  }

};