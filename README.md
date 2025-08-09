# NoteMate Backend

This is the backend API for NoteMate, a platform for sharing and accessing study materials.

## Setup Instructions

1. Install dependencies:
   ```bash
   npm install
   ```

2. Run the development server:
   ```bash
   npm run dev
   ```

3. Run in production mode:
   ```bash
   npm start
   ```

## Environment Variables

Create a `.env` file with the following variables:

```
PORT=5000
MONGODB_URI=your_mongodb_connection_string
JWT_SECRET=your_jwt_secret
CLOUDINARY_CLOUD_NAME=your_cloudinary_cloud_name
CLOUDINARY_API_KEY=your_cloudinary_api_key
CLOUDINARY_API_SECRET=your_cloudinary_api_secret
FRONTEND_URL=http://localhost:5173
NODE_ENV=development
```

## API Endpoints

- `/api/auth` - Authentication routes
- `/api/notes` - Notes management
- `/api/question-papers` - Question papers management
- `/api/upload` - File upload handling
- `/api/admin` - Admin-only routes

## Deployment to Render

1. Push your code to a GitHub repository
2. Connect your repository to Render
3. Create a new Web Service with the following settings:
   - Build Command: `npm install`
   - Start Command: `node server.js`
4. Add the environment variables from `.env.production`
5. Deploy!

## Important Notes

- The backend uses Firebase Admin SDK for authentication verification
- CORS is configured to allow requests from the frontend domain
- MongoDB is used as the database
- Cloudinary is used for file storage
