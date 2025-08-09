require('dotenv').config();
const mongoose = require('mongoose');

// Extract the connection string from environment variables
const connectionString = process.env.MONGODB_URI || 'mongodb+srv://hiteshboss:boss321@notesmate.xfhzfou.mongodb.net/notes_mate?retryWrites=true&w=majority&appName=notesmate';

// Log the connection string with password masked
const maskedConnectionString = connectionString.replace(/\/\/([^:]+):([^@]+)@/, '//$1:****@');
console.log('Attempting to connect with:', maskedConnectionString);

// Connect to MongoDB
mongoose.connect(connectionString, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  serverSelectionTimeoutMS: 5000,
  socketTimeoutMS: 45000,
  family: 4
})
.then(() => {
  console.log('Connected to MongoDB successfully');
  process.exit(0);
})
.catch(err => {
  console.error('MongoDB connection error:', err);
  
  if (err.name === 'MongoServerSelectionError') {
    console.error('Could not connect to any MongoDB server. Please check your network connection and MongoDB Atlas status.');
  } else if (err.name === 'MongoParseError') {
    console.error('Invalid MongoDB connection string. Please check your MONGODB_URI environment variable.');
  } else if (err.message && err.message.includes('bad auth')) {
    console.error('Authentication failed. Please check your MongoDB username and password.');
    console.error('Make sure the user exists and has the correct permissions.');
  }
  
  process.exit(1);
});
