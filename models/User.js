const mongoose = require('mongoose');

// Drop all existing indexes before creating the schema
const dropIndexes = async () => {
  try {
    const collections = await mongoose.connection.db.collections();
    for (let collection of collections) {
      if (collection.collectionName === 'users') {
        await collection.dropIndexes();
        console.log('Dropped all indexes from users collection');
      }
    }
  } catch (error) {
    console.error('Error dropping indexes:', error);
  }
};

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true
  },
  name: {
    type: String,
    required: true
  },
  firebaseUid: {
    type: String,
    required: true,
    unique: true
  },
  photoURL: {
    type: String,
    default: null
  },
  isAdmin: {
    type: Boolean,
    default: false
  },
  semester: {
    type: String,
    enum: ['1', '2', '3', '4', '5', '6', '7', '8', '', null],
    default: ''
  },
  branch: {
    type: String,
    enum: ['CSE', 'ISE', 'ECE', 'EEE', 'ME', 'CE', 'IPE', 'BT', 'AE', 'IEM', '', null],
    default: ''
  },
  phoneNumber: {
    type: String,
    default: null
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  lastLogin: {
    type: Date,
    default: Date.now
  },
  wallet: {
    type: Number,
    default: 100
  },
  purchasedPapers: [
    {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'QuestionPaper'
    }
  ],
  stats: {
    notesUploaded: {
      type: Number,
      default: 0
    },
    downloadsReceived: {
      type: Number,
      default: 0
    }
  }
});

// Create indexes after schema definition
userSchema.index({ firebaseUid: 1 }, { unique: true, name: 'firebaseUid_unique' });
userSchema.index({ email: 1 }, { unique: true, name: 'email_unique' });

const User = mongoose.model('User', userSchema);

// Export both the model and the dropIndexes function
module.exports = { User, dropIndexes }; 