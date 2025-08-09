require('dotenv').config();
const express = require('express');
const cors = require('cors');
const connectDB = require('./config/db');
const notesRoutes = require('./routes/notes');
const authRoutes = require('./routes/auth');
const questionPapersRoutes = require('./routes/questionPapers');
const adminRoutes = require('./routes/admin');
const { dropIndexes } = require('./models/User');

const app = express();

// Connect to MongoDB
connectDB().then(async () => {
  try {
    // Drop existing indexes
    await dropIndexes();
    console.log('Database indexes reset successfully');
  } catch (error) {
    console.error('Error resetting indexes:', error);
  }
});

// Custom CORS middleware for better control over headers
const corsMiddleware = require('./middleware/cors');

// Apply our custom CORS middleware first
app.use(corsMiddleware);

// Keep the standard cors middleware as a fallback
const corsOptions = {
  origin: process.env.NODE_ENV === 'production'
    ? [process.env.FRONTEND_URL, 'https://note-mate.vercel.app', 'https://notes-mate-nine.vercel.app', 'https://notes-mate.vercel.app']
    : ['http://localhost:5173', 'http://localhost:5174', 'http://localhost:3000'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Cache-Control', 'X-Requested-With', 'Accept', 'Origin', 'Pragma', 'Expires'],
  exposedHeaders: ['Content-Length', 'Content-Type'],
  preflightContinue: false,
  optionsSuccessStatus: 204,
  maxAge: 86400 // 24 hours
};

app.use(cors(corsOptions));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', message: 'Server is running' });
});

// Routes
app.use('/api/notes', notesRoutes);
app.use('/api/auth', authRoutes);
app.use('/api/upload', require('./routes/upload'));
app.use('/api/question-papers', questionPapersRoutes);
app.use('/api/admin', adminRoutes);

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    success: false,
    message: err.message || 'Something went wrong!',
    error: process.env.NODE_ENV === 'development' ? err : {}
  });
});

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
}); 