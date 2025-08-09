const express = require('express');
const router = express.Router();
const Note = require('../models/Note');
const { User } = require('../models/User');
const { auth } = require('../middleware/auth');
const admin = require('firebase-admin');

// Get all notes
router.get('/', async (req, res) => {
  try {
    const { semester, branch, subject, status } = req.query;
    const query = {};

    // Add filters if provided
    if (semester) query.semester = semester;
    if (branch) query.branch = branch;
    if (subject) query.subject = subject;
    if (status) query.status = status;

    // Only show approved notes to non-admin users
    if (!req.user?.isAdmin) {
      query.status = 'approved';
    }

    const notes = await Note.find(query)
      .sort({ createdAt: -1 })
      .populate('uploadedBy', 'name email');

    res.json({
      success: true,
      data: notes
    });
  } catch (error) {
    console.error('Error fetching notes:', error);
    res.status(500).json({ 
      success: false,
      message: 'Error fetching notes', 
      error: error.message 
    });
  }
});

// Public stats endpoint
router.get('/stats', async (req, res) => {
  try {
    const stats = await Note.aggregate([
      {
        $group: {
          _id: null,
          totalNotes: { $sum: 1 },
          totalDownloads: { $sum: { $ifNull: ['$downloads', 0] } },
          pendingNotes: {
            $sum: { $cond: [{ $eq: ['$status', 'pending'] }, 1, 0] }
          },
          approvedNotes: {
            $sum: { $cond: [{ $eq: ['$status', 'approved'] }, 1, 0] }
          }
        }
      }
    ]);

    // Get the count of question papers from the QuestionPaper model
    const QuestionPaper = require('../models/QuestionPaper');
    const totalQuestionPapers = await QuestionPaper.countDocuments();

    const totalUsers = await User.countDocuments();
    const recentUploads = await Note.find()
      .sort({ createdAt: -1 })
      .limit(5)
      .populate('uploadedBy', 'name');

    const popularSubjects = await Note.aggregate([
      { $match: { status: 'approved' } },
      { $group: { _id: '$subject', count: { $sum: 1 } } },
      { $sort: { count: -1 } },
      { $limit: 5 }
    ]);

    res.json({
      success: true,
      data: {
        totalNotes: stats[0]?.totalNotes || 0,
        totalDownloads: stats[0]?.totalDownloads || 0,
        totalUsers,
        totalQuestionPapers: totalQuestionPapers || 0,
        recentUploads,
        popularSubjects
      }
    });
  } catch (error) {
    console.error('Error fetching stats:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching statistics',
      error: error.message
    });
  }
});

// Admin stats endpoint
router.get('/admin/stats', auth, async (req, res) => {
  try {
    if (!req.user.isAdmin) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to access admin stats'
      });
    }

    const stats = await Note.aggregate([
      {
        $group: {
          _id: null,
          totalNotes: { $sum: 1 },
          totalDownloads: { $sum: { $ifNull: ['$downloads', 0] } },
          pendingNotes: {
            $sum: { $cond: [{ $eq: ['$status', 'pending'] }, 1, 0] }
          },
          approvedNotes: {
            $sum: { $cond: [{ $eq: ['$status', 'approved'] }, 1, 0] }
          },
          rejectedNotes: {
            $sum: { $cond: [{ $eq: ['$status', 'rejected'] }, 1, 0] }
          }
        }
      }
    ]);

    const totalUsers = await User.countDocuments();
    const recentUploads = await Note.find()
      .sort({ createdAt: -1 })
      .limit(5)
      .populate('uploadedBy', 'name');

    const popularSubjects = await Note.aggregate([
      { $match: { status: 'approved' } },
      { $group: { _id: '$subject', count: { $sum: 1 } } },
      { $sort: { count: -1 } },
      { $limit: 5 }
    ]);

    res.json({
      success: true,
      data: {
        totalNotes: stats[0]?.totalNotes || 0,
        totalDownloads: stats[0]?.totalDownloads || 0,
        totalUsers,
        pendingNotes: stats[0]?.pendingNotes || 0,
        approvedNotes: stats[0]?.approvedNotes || 0,
        rejectedNotes: stats[0]?.rejectedNotes || 0,
        recentUploads,
        popularSubjects
      }
    });
  } catch (error) {
    console.error('Error fetching admin stats:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching admin statistics',
      error: error.message
    });
  }
});

// Admin notes endpoint
router.get('/admin', auth, async (req, res) => {
  try {
    if (!req.user.isAdmin) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to access admin notes'
      });
    }

    const notes = await Note.find()
      .sort({ createdAt: -1 })
      .populate('uploadedBy', 'name email');

    res.json({
      success: true,
      data: notes
    });
  } catch (error) {
    console.error('Error fetching admin notes:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching notes',
      error: error.message
    });
  }
});

// Admin users endpoint
router.get('/admin/users', auth, async (req, res) => {
  try {
    if (!req.user.isAdmin) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to access user list'
      });
    }

    const users = await User.find()
      .select('-firebaseUid')
      .sort({ createdAt: -1 });

    res.json({
      success: true,
      data: users
    });
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching users'
    });
  }
});

// Approve note endpoint
router.put('/:id/approve', auth, async (req, res) => {
  try {
    if (!req.user.isAdmin) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to approve notes'
      });
    }

    const note = await Note.findByIdAndUpdate(
      req.params.id,
      { status: 'approved' },
      { new: true }
    ).populate('uploadedBy', 'name email');

    if (!note) {
      return res.status(404).json({
        success: false,
        message: 'Note not found'
      });
    }

    res.json({
      success: true,
      data: note
    });
  } catch (error) {
    console.error('Error approving note:', error);
    res.status(500).json({
      success: false,
      message: 'Error approving note',
      error: error.message
    });
  }
});

// Reject note endpoint
router.put('/:id/reject', auth, async (req, res) => {
  try {
    if (!req.user.isAdmin) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to reject notes'
      });
    }

    const note = await Note.findByIdAndUpdate(
      req.params.id,
      { status: 'rejected' },
      { new: true }
    ).populate('uploadedBy', 'name email');

    if (!note) {
      return res.status(404).json({
        success: false,
        message: 'Note not found'
      });
    }

    res.json({
      success: true,
      data: note
    });
  } catch (error) {
    console.error('Error rejecting note:', error);
    res.status(500).json({
      success: false,
      message: 'Error rejecting note',
      error: error.message
    });
  }
});

// Admin delete user endpoint
router.delete('/admin/users/:userId', auth, async (req, res) => {
  try {
    if (!req.user.isAdmin) {
      return res.status(403).json({
        success: false,
        message: 'Not authorized to delete users'
      });
    }

    const { userId } = req.params;
    console.log('Attempting to delete user:', userId);

    // Find user in MongoDB
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Delete user from Firebase
    try {
      await admin.auth().deleteUser(user.firebaseUid);
      console.log('User deleted from Firebase:', user.firebaseUid);
    } catch (firebaseError) {
      console.error('Error deleting user from Firebase:', firebaseError);
      // Continue with MongoDB deletion even if Firebase deletion fails
    }

    // Delete user from MongoDB
    await User.findByIdAndDelete(userId);
    console.log('User deleted from MongoDB:', userId);

    res.json({
      success: true,
      message: 'User deleted successfully'
    });
  } catch (error) {
    console.error('Error deleting user:', error);
    res.status(500).json({
      success: false,
      message: 'Error deleting user',
      error: error.message
    });
  }
});

// Delete note (admin only)
router.delete('/:id', auth, async (req, res) => {
  try {
    // Check if user is admin
    if (!req.user.isAdmin) {
      return res.status(403).json({
        success: false,
        message: 'Only admins can delete notes'
      });
    }

    const noteId = req.params.id;
    console.log('Attempting to delete note:', noteId);

    // Find the note
    const note = await Note.findById(noteId);
    if (!note) {
      return res.status(404).json({
        success: false,
        message: 'Note not found'
      });
    }

    // If note has cloudinaryId, delete from Cloudinary
    if (note.cloudinaryId) {
      try {
        // You would typically delete from Cloudinary here
        // For example: await cloudinary.uploader.destroy(note.cloudinaryId);
        console.log('File would be deleted from Cloudinary:', note.cloudinaryId);
      } catch (cloudinaryError) {
        console.error('Error deleting file from Cloudinary:', cloudinaryError);
        // Continue with note deletion even if Cloudinary deletion fails
      }
    }

    // Delete the note from database
    await Note.findByIdAndDelete(noteId);
    console.log('Note deleted from database:', noteId);

    res.json({
      success: true,
      message: 'Note deleted successfully'
    });
  } catch (error) {
    console.error('Error deleting note:', error);
    res.status(500).json({
      success: false,
      message: 'Error deleting note',
      error: error.message
    });
  }
});

// Create new note
router.post('/', auth, async (req, res) => {
  try {
    const { title, description, semester, branch, subject, fileUrl, cloudinaryId } = req.body;

    // Validate required fields
    if (!title || !description || !semester || !branch || !subject || !fileUrl || !cloudinaryId) {
      return res.status(400).json({
        success: false,
        message: 'All fields are required'
      });
    }

    // Create new note
    const note = new Note({
      title,
      description,
      semester,
      branch,
      subject,
      fileUrl,
      cloudinaryId,
      uploadedBy: req.user._id,
      status: 'pending'
    });

    await note.save();

    res.status(201).json({
      success: true,
      data: note
    });
  } catch (error) {
    console.error('Error creating note:', error);
    res.status(500).json({
      success: false,
      message: 'Error creating note'
    });
  }
});

// Get subjects for a semester and branch
router.get('/subjects', async (req, res) => {
  try {
    const { semester, branch } = req.query;

    if (!semester || !branch) {
      return res.status(400).json({
        success: false,
        message: 'Semester and branch are required'
      });
    }

    const subjects = await Note.distinct('subject', {
      semester,
      branch,
      status: 'approved'
    });

    res.json({
      success: true,
      data: subjects
    });
  } catch (error) {
    console.error('Error fetching subjects:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching subjects',
      error: error.message
    });
  }
});

// Download note endpoint
router.get('/:id/download', auth, async (req, res) => {
  try {
    const note = await Note.findById(req.params.id);
    
    if (!note) {
      return res.status(404).json({
        success: false,
        message: 'Note not found'
      });
    }

    // Only allow download if note is approved or user is admin
    if (note.status !== 'approved' && !req.user.isAdmin) {
      return res.status(403).json({
        success: false,
        message: 'This note is not available for download'
      });
    }

    // Increment download count - using updateOne to ensure atomic update
    await Note.updateOne(
      { _id: note._id },
      { $inc: { downloads: 1 } }
    );
    
    console.log(`Incremented download count for note: ${note._id}, new count: ${(note.downloads || 0) + 1}`);

    // Redirect to the file URL
    res.redirect(note.fileUrl);
  } catch (error) {
    console.error('Error downloading note:', error);
    res.status(500).json({
      success: false,
      message: 'Error downloading note',
      error: error.message
    });
  }
});

module.exports = router; 