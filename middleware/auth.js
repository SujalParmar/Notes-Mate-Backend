const admin = require('../config/firebase-admin');
const { User } = require('../models/User');

const auth = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        success: false,
        message: 'No token provided'
      });
    }

    const token = authHeader.split(' ')[1];
    const decodedToken = await admin.auth().verifyIdToken(token);

    if (!decodedToken.uid) {
      throw new Error('Invalid token: No user ID found');
    }

    // Use findOneAndUpdate with upsert to handle both create and update cases
    const user = await User.findOneAndUpdate(
      { firebaseUid: decodedToken.uid },
      {
        $set: {
          email: decodedToken.email,
          name: decodedToken.name || decodedToken.email.split('@')[0],
          photoURL: decodedToken.picture || null,
          isAdmin: decodedToken.email === 'sujalparmar@gmail.com',
          lastLogin: new Date()
        }
      },
      {
        new: true, // Return the updated document
        upsert: true, // Create if doesn't exist
        setDefaultsOnInsert: true // Apply schema defaults on insert
      }
    );

    console.log('User found/created in auth middleware:', {
      email: user.email,
      isAdmin: user.isAdmin,
      lastLogin: user.lastLogin
    });

    // Attach user to request
    req.user = user;
    next();
  } catch (error) {
    console.error('Auth middleware error:', error);
    res.status(401).json({
      success: false,
      message: error.message || 'Invalid or expired token',
      error: error.code === 11000 ? 'User already exists with different credentials' : error.message
    });
  }
};

const adminAuth = async (req, res, next) => {
  try {
    // First run the regular auth middleware to get the user
    await auth(req, res, async () => {
      // Check if the user is an admin
      if (!req.user.isAdmin) {
        return res.status(403).json({
          success: false,
          message: 'Access denied. Admin privileges required.'
        });
      }
      
      // If user is admin, proceed
      next();
    });
  } catch (error) {
    console.error('Admin auth middleware error:', error);
    res.status(401).json({
      success: false,
      message: error.message || 'Authentication failed',
      error: error.message
    });
  }
};

module.exports = { auth, adminAuth }; 