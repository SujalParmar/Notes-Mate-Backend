const mongoose = require('mongoose');

const noteSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true
  },
  description: {
    type: String,
    required: true
  },
  semester: {
    type: String,
    required: true,
    enum: ['1', '2', '3', '4', '5', '6', '7', '8']
  },
  branch: {
    type: String,
    required: true,
    enum: ['CSE', 'ISE', 'ECE', 'EEE', 'ME', 'CE', 'IPE', 'BT', 'AE', 'IEM']
  },
  subject: {
    type: String,
    required: true
  },
  fileUrl: {
    type: String,
    required: true
  },
  uploadedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  status: {
    type: String,
    enum: ['pending', 'approved', 'rejected'],
    default: 'pending'
  },
  views: {
    type: Number,
    default: 0
  },
  downloads: {
    type: Number,
    default: 0
  },
  cloudinaryId: {
    type: String,
    required: true
  }
}, {
  timestamps: true
});

module.exports = mongoose.model('Note', noteSchema); 