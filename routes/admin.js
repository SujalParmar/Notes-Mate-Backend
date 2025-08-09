const express = require('express');
const router = express.Router();
const { User } = require('../models/User');
const { adminAuth } = require('../middleware/auth');

// Get all users with wallet info (for admin dashboard)
router.get('/users', adminAuth, async (req, res) => {
  try {
    const users = await User.find({})
      .select('name email wallet purchasedPapers isAdmin lastLogin')
      .sort({ lastLogin: -1 });

    const usersWithPaperCount = users.map(user => {
      const userObj = user.toObject();
      userObj.purchasedPaperCount = user.purchasedPapers.length;
      delete userObj.purchasedPapers; // Remove the array to reduce payload size
      return userObj;
    });

    res.json({
      success: true,
      data: usersWithPaperCount
    });
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Error fetching users', 
      error: error.message 
    });
  }
});

// Restore user's wallet
router.patch('/users/:id/restore-wallet', adminAuth, async (req, res) => {
  try {
    const userId = req.params.id;
    console.log(`Attempting to restore wallet for user ID: ${userId}`);
    
    // Check if user exists
    const userExists = await User.exists({ _id: userId });
    if (!userExists) {
      console.log('User not found');
      return res.status(404).json({ 
        success: false, 
        message: 'User not found' 
      });
    }

    // First check the current wallet balance
    const user = await User.findById(userId);
    console.log('Current wallet balance:', user.wallet);
    
    // Always set wallet to 100 regardless of current value
    console.log('Restoring wallet to ₹100');
    await User.findByIdAndUpdate(
      userId,
      { wallet: 100 },
      { new: true, runValidators: true }
    );
    
    // Verify the update
    const updatedUser = await User.findById(userId);
    console.log('New wallet balance:', updatedUser.wallet);
    
    if (updatedUser.wallet !== 100) {
      console.log('Wallet not updated correctly');
      return res.status(500).json({
        success: false,
        message: 'Failed to update wallet'
      });
    }
    
    console.log('Wallet restored successfully');
    
    res.json({
      success: true,
      message: 'Wallet restored successfully',
      data: {
        userId: updatedUser._id,
        wallet: updatedUser.wallet
      }
    });
  } catch (error) {
    console.error('Error restoring wallet:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Error restoring wallet', 
      error: error.message 
    });
  }
});

module.exports = router;
