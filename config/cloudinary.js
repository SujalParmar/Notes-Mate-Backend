const { v2: cloudinary } = require('cloudinary');

// Configure using URL format
cloudinary.config({
  cloud_name: 'df9jtqaly',
  api_key: '196627365442557',
  api_secret: '-gp-e25Ch2yqjCWCvwunvrr3tf8'
});

// Test the configuration
cloudinary.api.ping()
  .then(() => console.log('Cloudinary connection successful'))
  .catch(err => console.error('Cloudinary connection error:', err));

module.exports = cloudinary; 