const express = require('express');
const router = express.Router();
const admin = require('../config/firebase-admin');
const { User } = require('../models/User');

// Admin login endpoint
router.post('/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    console.log('Admin login attempt:', { email });

    // Set CORS headers explicitly for this response
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, Cache-Control, X-Requested-With, Accept, Origin');

    // Verify admin credentials
    if (email !== 'sujalparmar@gmail.com' || password !== 'suj@l123') {
      console.log('Invalid admin credentials');
      return res.status(401).json({
        success: false,
        message: 'Invalid admin credentials'
      });
    }

    // Create a Firebase custom token for admin authentication
    // The Firebase Admin SDK must be used for this
    const adminUid = 'admin-user-id';
    let customToken;
    
    try {
      console.log('Creating Firebase custom token for admin...');
      
      // First, make sure the admin user exists in Firebase
      try {
        // Try to get the user first
        await admin.auth().getUser(adminUid);
        console.log('Admin user exists in Firebase');
      } catch (userError) {
        // If user doesn't exist, create it
        if (userError.code === 'auth/user-not-found') {
          try {
            await admin.auth().createUser({
              uid: adminUid,
              email: 'sujalparmar@gmail.com',
              displayName: 'Admin User'
            });
            console.log('Created admin user in Firebase');
          } catch (createError) {
            // If we can't create the user, just log the error but continue
            // This might happen if the user already exists but we got a different error
            console.error('Note: Could not create admin user:', createError.message);
          }
        } else {
          // Log other errors but continue
          console.error('Note: Error checking admin user:', userError.message);
        }
      }
      
      // Create the custom token
      customToken = await admin.auth().createCustomToken(adminUid, { isAdmin: true });
      console.log('Firebase custom token created successfully');
    } catch (error) {
      console.error('Error creating Firebase custom token:', error);
      return res.status(500).json({
        success: false,
        message: 'Error creating authentication token',
        error: error.message
      });
    }

    res.json({
      success: true,
      data: {
        customToken,
        email,
        isAdmin: true
      }
    });
  } catch (error) {
    console.error('Admin login error:', error);
    res.status(500).json({
      success: false,
      message: 'Error during admin login'
    });
  }
});

// Verify token endpoint
router.post('/verify', async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    console.log('Verify token request received');

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      console.log('No token provided in request');
      return res.status(401).json({
        success: false,
        message: 'No token provided'
      });
    }

    const token = authHeader.split(' ')[1];
    console.log('Verifying token...');

    const decodedToken = await admin.auth().verifyIdToken(token);
    console.log('Token decoded:', { 
      uid: decodedToken.uid, 
      email: decodedToken.email,
      name: decodedToken.name,
      picture: decodedToken.picture 
    });

    if (!decodedToken.uid) {
      throw new Error('Invalid token: No user ID found');
    }

    // Variable to store the user data
    let user;
    
    try {
      // First try to find the user by Firebase UID
      user = await User.findOne({ firebaseUid: decodedToken.uid });
      
      if (user) {
        // If user exists, update it
        console.log('User found, updating...');
        user = await User.findByIdAndUpdate(
          user._id,
          {
            $set: {
              email: decodedToken.email,
              // Only update name if it doesn't exist (preserve user's custom name)
              ...(user.name ? {} : { name: decodedToken.name || decodedToken.email.split('@')[0] }),
              photoURL: decodedToken.picture || null,
              isAdmin: decodedToken.email === 'hiteshboss@gmail.com',
              lastLogin: new Date()
            }
          },
          { new: true }
        );
      } else {
        // If user doesn't exist, try to find by email first
        console.log('User not found by UID, checking by email...');
        user = await User.findOne({ email: decodedToken.email });
        
        if (user) {
          // If user exists with this email but different UID, update the UID
          console.log('User found by email, updating UID...');
          user = await User.findByIdAndUpdate(
            user._id,
            {
              $set: {
                firebaseUid: decodedToken.uid,
                // Only update name if it doesn't exist (preserve user's custom name)
                ...(user.name ? {} : { name: decodedToken.name || decodedToken.email.split('@')[0] }),
                photoURL: decodedToken.picture || null,
                isAdmin: decodedToken.email === 'hiteshboss@gmail.com',
                lastLogin: new Date()
              }
            },
            { new: true }
          );
        } else {
          // If user doesn't exist at all, create a new one
          console.log('Creating new user...');
          try {
            user = new User({
              firebaseUid: decodedToken.uid,
              email: decodedToken.email,
              name: decodedToken.name || decodedToken.email.split('@')[0],
              photoURL: decodedToken.picture || null,
              isAdmin: decodedToken.email === 'hiteshboss@gmail.com',
              // Set default values for semester and branch to avoid validation errors
              semester: '',
              branch: '',
              lastLogin: new Date()
            });
            await user.save();
            console.log('New user created successfully');
          } catch (createError) {
            console.error('Error creating new user:', createError);
            // If there's a validation error, try with explicit null values
            if (createError.name === 'ValidationError') {
              console.log('Attempting to create user with explicit null values for enum fields');
              user = new User({
                firebaseUid: decodedToken.uid,
                email: decodedToken.email,
                name: decodedToken.name || decodedToken.email.split('@')[0],
                photoURL: decodedToken.picture || null,
                isAdmin: decodedToken.email === 'hiteshboss@gmail.com',
                // Set to empty string which should be valid
                semester: '',
                branch: '',
                lastLogin: new Date()
              });
              await user.save();
              console.log('User created with fallback values');
            } else {
              throw createError; // Re-throw if it's not a validation error
            }
          }
        }
      }
      
      // Log user info after successful processing
      console.log('User found/created in verify endpoint:', {
        email: user.email,
        isAdmin: user.isAdmin,
        lastLogin: user.lastLogin
      });
    } catch (dbError) {
      console.error('Error handling user in database:', dbError);
      return res.status(500).json({
        success: false,
        message: 'Error processing user data',
        error: dbError.message
      });
    }
    
    // Check if user was successfully retrieved or created
    if (!user) {
      console.error('User not found or created');
      return res.status(401).json({
        success: false,
        message: 'User not found or created'
      });
    }

    res.json({
      success: true,
      data: {
        email: user.email,
        name: user.name,
        photoURL: user.photoURL,
        isAdmin: user.isAdmin,
        semester: user.semester,
        branch: user.branch
      }
    });
  } catch (error) {
    console.error('Token verification error:', error);
    res.status(401).json({
      success: false,
      message: error.message || 'Invalid or expired token',
      error: error.code === 11000 ? 'User already exists with different credentials' : error.message
    });
  }
});

// Update profile endpoint
router.put('/profile', async (req, res) => {
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

    const { name, semester, branch } = req.body;
    const updates = {};

    if (name) updates.name = name;
    if (semester) updates.semester = semester;
    if (branch) updates.branch = branch;

    const user = await User.findOneAndUpdate(
      { firebaseUid: decodedToken.uid },
      { $set: updates },
      { new: true }
    );

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    res.json({
      success: true,
      data: {
        email: user.email,
        name: user.name,
        photoURL: user.photoURL,
        isAdmin: user.isAdmin,
        semester: user.semester,
        branch: user.branch
      }
    });
  } catch (error) {
    console.error('Profile update error:', error);
    res.status(500).json({
      success: false,
      message: 'Error updating profile',
      error: error.message
    });
  }
});

// Register endpoint
router.post('/register', async (req, res) => {
  try {
    const { email, password, name, semester, branch } = req.body;
    console.log('Registration attempt:', { email, name });

    // Create user in Firebase
    const userRecord = await admin.auth().createUser({
      email,
      password,
      displayName: name
    });

    // Create user in MongoDB
    const user = await User.create({
      firebaseUid: userRecord.uid,
      email: userRecord.email,
      name: userRecord.displayName,
      semester,
      branch,
      isAdmin: false
    });

    console.log('User registered successfully:', {
      email: user.email,
      name: user.name
    });

    res.json({
      success: true,
      data: {
        email: user.email,
        name: user.name,
        photoURL: user.photoURL,
        isAdmin: user.isAdmin,
        semester: user.semester,
        branch: user.branch
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({
      success: false,
      message: error.message || 'Error during registration',
      error: error.code === 11000 ? 'Email already exists' : error.message
    });
  }
});

module.exports = router; 