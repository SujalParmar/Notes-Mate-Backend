const express = require('express');
const router = express.Router();
const QuestionPaper = require('../models/QuestionPaper');
const { User } = require('../models/User');
const { auth, adminAuth } = require('../middleware/auth');
const cloudinary = require('../config/cloudinary');
const multer = require('multer');
const { CloudinaryStorage } = require('multer-storage-cloudinary');

// Configure Cloudinary storage for multer
const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: 'question_papers',
    resource_type: 'auto',
    allowed_formats: ['pdf']
  }
});

const upload = multer({ storage });

// Upload Question Paper (Admin only)
router.post('/upload', adminAuth, upload.single('file'), async (req, res) => {
  try {
    const { title, semester, branch, price } = req.body;
    
    // Validate required fields
    if (!title || !semester || !branch || !price || !req.file) {
      return res.status(400).json({ 
        success: false, 
        message: 'All fields are required (title, semester, branch, price, file)' 
      });
    }

    // Create new question paper
    const questionPaper = new QuestionPaper({
      title,
      semester,
      branch,
      price: Number(price),
      fileUrl: req.file.path,
      cloudinaryId: req.file.filename,
      uploadedBy: req.user._id
    });

    await questionPaper.save();

    res.status(201).json({
      success: true,
      message: 'Question paper uploaded successfully',
      data: questionPaper
    });
  } catch (error) {
    console.error('Error uploading question paper:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Error uploading question paper', 
      error: error.message 
    });
  }
});

// Get All Question Papers
router.get('/', auth, async (req, res) => {
  try {
    console.log('Fetching question papers...');
    const { semester, branch } = req.query;
    const query = {};

    // Add filters if provided
    if (semester) query.semester = semester;
    if (branch) query.branch = branch;

    console.log('Query filters:', query);

    // Get all question papers
    const questionPapers = await QuestionPaper.find(query)
      .sort({ uploadedAt: -1 })
      .populate('uploadedBy', 'name email');

    console.log(`Found ${questionPapers.length} question papers`);

    // Get user's purchased papers
    try {
      const user = await User.findById(req.user._id);
      
      if (!user) {
        console.error('User not found:', req.user._id);
        return res.status(404).json({
          success: false,
          message: 'User not found'
        });
      }

      const purchasedPaperIds = user.purchasedPapers.map(id => id.toString());

      // Add a 'purchased' field to each paper
      const papersWithPurchaseInfo = questionPapers.map(paper => {
        const paperObj = paper.toObject();
        paperObj.purchased = purchasedPaperIds.includes(paper._id.toString());
        return paperObj;
      });

      // Set CORS headers explicitly for this response
      res.header('Access-Control-Allow-Origin', '*');
      res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
      res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');

      res.json({
        success: true,
        data: papersWithPurchaseInfo,
        walletBalance: user.wallet
      });
    } catch (userError) {
      console.error('Error processing user data:', userError);
      
      // Even if user data processing fails, return the papers without purchase info
      const simplePapers = questionPapers.map(paper => {
        const paperObj = paper.toObject();
        paperObj.purchased = false; // Default to not purchased
        return paperObj;
      });

      // Set CORS headers explicitly for this response
      res.header('Access-Control-Allow-Origin', '*');
      res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
      res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');

      res.json({
        success: true,
        data: simplePapers,
        walletBalance: 0,
        note: 'User data could not be processed, showing papers without purchase info'
      });
    }
  } catch (error) {
    console.error('Error fetching question papers:', error);
    
    // Set CORS headers even for error responses
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    
    res.status(500).json({ 
      success: false, 
      message: 'Error fetching question papers', 
      error: error.message 
    });
  }
});

// Purchase Question Paper
router.post('/purchase/:id', auth, async (req, res) => {
  try {
    const paperId = req.params.id;
    console.log(`Attempting to purchase paper with ID: ${paperId}`);
    
    // Find the question paper
    const questionPaper = await QuestionPaper.findById(paperId);
    if (!questionPaper) {
      console.log('Question paper not found');
      return res.status(404).json({ 
        success: false, 
        message: 'Question paper not found' 
      });
    }
    console.log(`Found question paper: ${questionPaper.title}, price: ${questionPaper.price}`);

    // Find the user
    const user = await User.findById(req.user._id);
    if (!user) {
      console.log('User not found');
      return res.status(404).json({ 
        success: false, 
        message: 'User not found' 
      });
    }
    console.log(`Found user: ${user.email}, wallet: ${user.wallet}, isAdmin: ${user.isAdmin}`);
    
    // Check if user has already purchased this paper
    const alreadyPurchased = user.purchasedPapers.some(id => id.toString() === paperId.toString());
    if (alreadyPurchased) {
      console.log('User has already purchased this paper');
      return res.status(400).json({ 
        success: false, 
        message: 'You have already purchased this question paper' 
      });
    }

    // Check if user has enough wallet balance
    if (user.wallet < questionPaper.price) {
      console.log('Insufficient wallet balance');
      return res.status(400).json({ 
        success: false, 
        message: 'Insufficient wallet balance' 
      });
    }

    console.log(`Deducting ${questionPaper.price} from wallet balance ${user.wallet}`);
    
    // Calculate new wallet balance (only deduct once)
    const newWalletBalance = Math.max(0, user.wallet - questionPaper.price);
    console.log(`New wallet balance: ${newWalletBalance}`);
    
    // Increment purchase count
    const newPurchaseCount = (questionPaper.purchaseCount || 0) + 1;
    console.log(`Updated purchase count to ${newPurchaseCount}`);

    // Use updateOne for user to avoid validation issues
    console.log('Updating user...');
    await User.updateOne(
      { _id: user._id },
      { 
        $set: { wallet: newWalletBalance },
        $push: { purchasedPapers: paperId }
      }
    );
    
    // Use updateOne for question paper to avoid validation issues
    console.log('Updating question paper...');
    await QuestionPaper.updateOne(
      { _id: paperId },
      { $set: { purchaseCount: newPurchaseCount } }
    );
    console.log('Changes saved successfully');
    
    // Update local variables for response
    user.wallet = newWalletBalance;

    res.json({
      success: true,
      message: 'Question paper purchased successfully',
      walletBalance: user.wallet
    });
  } catch (error) {
    console.error('Error purchasing question paper:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Error purchasing question paper', 
      error: error.message 
    });
  }
});

// Download Purchased Paper
router.get('/download/:id', auth, async (req, res) => {
  try {
    const paperId = req.params.id;
    
    // Find the user
    const user = await User.findById(req.user._id);
    
    // Check if user has purchased this paper
    const hasPurchased = user.purchasedPapers.some(id => id.toString() === paperId);
    
    if (!hasPurchased && !req.user.isAdmin) {
      return res.status(403).json({ 
        success: false, 
        message: 'You have not purchased this question paper' 
      });
    }

    // Find the question paper
    const questionPaper = await QuestionPaper.findById(paperId);
    if (!questionPaper) {
      return res.status(404).json({ 
        success: false, 
        message: 'Question paper not found' 
      });
    }

    // Return the file URL
    res.json({
      success: true,
      fileUrl: questionPaper.fileUrl
    });
  } catch (error) {
    console.error('Error downloading question paper:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Error downloading question paper', 
      error: error.message 
    });
  }
});

// Get User's Purchased Papers
router.get('/my-papers', auth, async (req, res) => {
  try {
    // Find the user and populate purchased papers
    const user = await User.findById(req.user._id)
      .populate({
        path: 'purchasedPapers',
        select: 'title semester branch price fileUrl uploadedAt'
      });

    res.json({
      success: true,
      data: user.purchasedPapers,
      walletBalance: user.wallet
    });
  } catch (error) {
    console.error('Error fetching purchased papers:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Error fetching purchased papers', 
      error: error.message 
    });
  }
});

module.exports = router;
