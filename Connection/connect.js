import mongoose from 'mongoose';

const connectDB = async () => {
  const uri = process.env.MONGODB_URI?.trim(); // ✅ Trim whitespace

  if (!uri) {
    console.error('❌ MONGODB_URI is not defined in the environment variables.');
    process.exit(1);
  }

  try {
    console.log('🔌 Connecting to MongoDB...');

    const conn = await mongoose.connect(uri, {
      useNewUrlParser: true,             // ✅ Required for SRV
      useUnifiedTopology: true,          // ✅ Required for stable server discovery
      serverSelectionTimeoutMS: 5000,    // ⏱️ Wait 5s before failing
      socketTimeoutMS: 30000             // ⌛ Timeout for socket inactivity
    });

    console.log(`✅ Connected to: ${conn.connection.host}`);
    console.log(`📁 Database: ${conn.connection.name}`);
  } catch (error) {
    console.error('❌ Connection failed:', error.message);
    console.log('\n🔍 Troubleshooting:');
    console.log('1. Make sure Atlas IP whitelist includes 0.0.0.0/0');
    console.log('2. Ensure the password and username are URL-encoded properly');
    console.log('3. Double-check your MongoDB URI starts with "mongodb+srv://"');
    console.log('4. Ensure the cluster is not paused in the Atlas dashboard');
    console.log('5. Railway: Set NODE_ENV=production and use secrets correctly');
    process.exit(1);
  }
};

export default connectDB;
