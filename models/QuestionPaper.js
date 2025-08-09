const mongoose = require('mongoose');

const questionPaperSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true,
    trim: true
  },
  semester: {
    type: String,
    required: true,
    enum: ['1', '2', '3', '4', '5', '6', '7', '8']
  },
  branch: {
    type: String,
    required: true,
    enum: ['CSE', 'ISE', 'ECE', 'EEE', 'MECH', 'CIVIL']
  },
  price: {
    type: Number,
    required: true,
    min: 0
  },
  fileUrl: {
    type: String,
    required: true
  },
  cloudinaryId: {
    type: String,
    required: true
  },
  uploadedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  purchaseCount: {
    type: Number,
    default: 0
  },
  uploadedAt: {
    type: Date,
    default: Date.now
  }
});

module.exports = mongoose.model('QuestionPaper', questionPaperSchema);
