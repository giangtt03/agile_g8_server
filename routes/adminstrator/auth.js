const express = require('express');
const router = express.Router();
const sessionMiddleware = require('../../middleware/sessionMiddleware'); 
const authController = require('../../controllers/authController');

router.post('/signup', authController.createUser);

router.get('/login', sessionMiddleware, authController.loginUser);
router.post('/login', sessionMiddleware, authController.loginUser);

module.exports = router;