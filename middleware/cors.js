// Custom CORS middleware to ensure all necessary headers are included
const corsMiddleware = (req, res, next) => {
  // Allow requests from the Vercel domain
  const allowedOrigins = [
    'https://notes-mate-nine.vercel.app',
    'https://note-mate.vercel.app',
    'https://notes-mate.vercel.app'
  ];
  
  const origin = req.headers.origin;
  if (allowedOrigins.includes(origin)) {
    res.header('Access-Control-Allow-Origin', origin);
  } else if (process.env.NODE_ENV !== 'production') {
    // In development, allow localhost
    res.header('Access-Control-Allow-Origin', req.headers.origin || '*');
  }
  
  // Allow credentials
  res.header('Access-Control-Allow-Credentials', 'true');
  
  // Allow all necessary methods
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS');
  
  // Allow all necessary headers
  res.header(
    'Access-Control-Allow-Headers',
    'Content-Type, Authorization, Cache-Control, X-Requested-With, Accept, Origin, Pragma, Expires'
  );
  
  // Handle preflight requests
  if (req.method === 'OPTIONS') {
    res.header('Access-Control-Max-Age', '86400'); // 24 hours
    return res.status(204).end();
  }
  
  next();
};

module.exports = corsMiddleware;
