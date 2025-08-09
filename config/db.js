const mongoose = require('mongoose');

const connectDB = async () => {
  try {
    // Log the MongoDB URI (with password masked) for debugging
    const uriForLogging = process.env.MONGODB_URI 
      ? process.env.MONGODB_URI.replace(/:\/\/([^:]+):([^@]+)@/, '://$1:****@')
      : 'mongodb://localhost:27017/notes_mate';
    
    console.log(`Attempting to connect to MongoDB: ${uriForLogging}`);

    // Set more detailed connection options
    const options = {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      serverSelectionTimeoutMS: 5000, // Timeout after 5 seconds
      socketTimeoutMS: 45000, // Close sockets after 45 seconds of inactivity
      family: 4 // Use IPv4, skip trying IPv6
    };

    const conn = await mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/notes_mate', options);

    console.log(`MongoDB Connected: ${conn.connection.host}`);
    return conn;
  } catch (error) {
    console.error('Error connecting to MongoDB:', error);
    
    // More detailed error handling
    if (error.name === 'MongoServerSelectionError') {
      console.error('Could not connect to any MongoDB server. Please check your network connection and MongoDB Atlas status.');
    } else if (error.name === 'MongoParseError') {
      console.error('Invalid MongoDB connection string. Please check your MONGODB_URI environment variable.');
    } else if (error.message && error.message.includes('bad auth')) {
      console.error('Authentication failed. Please check your MongoDB username and password.');
    }
    
    // Don't exit the process immediately in development to allow for debugging
    if (process.env.NODE_ENV === 'production') {
      process.exit(1);
    } else {
      console.error('Application continuing without MongoDB connection. Fix the connection issue and restart the server.');
    }
    
    return null;
  }
};

module.exports = connectDB;