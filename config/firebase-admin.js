const admin = require('firebase-admin');

// Check for required environment variables
const requiredEnvVars = ['FIREBASE_PROJECT_ID', 'FIREBASE_CLIENT_EMAIL'];
const missingEnvVars = requiredEnvVars.filter(envVar => !process.env[envVar]);

if (missingEnvVars.length > 0) {
  console.error('Missing required environment variables:', missingEnvVars.join(', '));
  console.error('Please check your .env file and ensure all required variables are set.');
  process.exit(1);
}

// Initialize Firebase Admin
if (!admin.apps.length) {
  try {
    // Handle the private key - it could be provided in different formats
    let privateKey;
    
    if (process.env.FIREBASE_PRIVATE_KEY) {
      // If the key is provided as an environment variable
      privateKey = process.env.FIREBASE_PRIVATE_KEY;
      
      // Handle different formats of the private key
      if (privateKey.includes('\\n')) {
        // If the key has escaped newlines (\n), replace them with actual newlines
        privateKey = privateKey.replace(/\\n/g, '\n');
      } else if (!privateKey.includes('-----BEGIN PRIVATE KEY-----')) {
        // If the key is base64 encoded (common in some deployment platforms)
        try {
          privateKey = Buffer.from(privateKey, 'base64').toString('utf8');
        } catch (e) {
          console.error('Error decoding private key from base64:', e);
        }
      }
    } else if (process.env.GOOGLE_APPLICATION_CREDENTIALS) {
      // Alternative: use a JSON file if provided
      admin.initializeApp({
        credential: admin.credential.applicationDefault()
      });
      console.log('Firebase Admin initialized with application default credentials');
      return;
    } else {
      console.error('No Firebase credentials provided');
      process.exit(1);
    }
    
    const serviceAccount = {
      projectId: process.env.FIREBASE_PROJECT_ID,
      privateKey: privateKey,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL
    };

    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount)
    });

    console.log('Firebase Admin initialized successfully');
  } catch (error) {
    console.error('Error initializing Firebase Admin:', error);
    console.error('Error details:', error.message);
    if (error.errorInfo) {
      console.error('Firebase error info:', error.errorInfo);
    }
    process.exit(1);
  }
}

module.exports = admin; 