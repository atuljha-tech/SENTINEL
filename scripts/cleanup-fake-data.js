// scripts/cleanup-fake-data.js
const { MongoClient } = require('mongodb');

const uri = 'mongodb+srv://hackstorm:hackstorm123@cluster0.gbz3qlp.mongodb.net/?appName=Cluster0';

async function cleanupFakeData() {
  const client = new MongoClient(uri);
  
  try {
    await client.connect();
    console.log('✅ Connected to MongoDB');
    
    const db = client.db('hackstorm');
    
    // Delete ALL simulated traffic
    const result = await db.collection('traffic_logs').deleteMany({
      $or: [
        { ip: /192\.168\./ },
        { ip: /10\.0\./ },
        { ip: /172\.16\./ },
        { userAgent: /Mozilla.*Chrome/ }
      ]
    });
    console.log('🗑️ Deleted', result.deletedCount, 'fake traffic logs');
    
    // Delete fake website scans
    const scanResult = await db.collection('website_security').deleteMany({
      $or: [
        { hasRealThreats: false },
        { threats: 'No threats detected' },
        { threats: [] }
      ]
    });
    console.log('🗑️ Deleted', scanResult.deletedCount, 'fake website scans');
    
    console.log('✅ Cleanup complete!');
    
  } catch (error) {
    console.error('❌ Error:', error);
  } finally {
    await client.close();
    console.log('🔒 Connection closed');
  }
}

cleanupFakeData();