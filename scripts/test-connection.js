#!/usr/bin/env node

// ============================================
// MongoDB Connection Tester
// Use this to verify your database connection
// ============================================

const { MongoClient } = require('mongodb');
const path = require('path');
const fs = require('fs');

// Load .env.local manually from project root
const envPath = path.resolve(__dirname, '../.env.local');
if (fs.existsSync(envPath)) {
    const envContent = fs.readFileSync(envPath, 'utf8');
    const envLines = envContent.split('\n');
    for (const line of envLines) {
        const trimmedLine = line.trim();
        if (trimmedLine && !trimmedLine.startsWith('#')) {
            const [key, ...valueParts] = trimmedLine.split('=');
            const value = valueParts.join('=');
            if (key && value) {
                process.env[key] = value;
            }
        }
    }
    console.log('✅ Loaded .env.local from:', envPath);
} else {
    console.error('❌ .env.local not found at:', envPath);
    process.exit(1);
}

// Colors for console output
const colors = {
    red: '\x1b[31m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m',
    purple: '\x1b[35m',
    cyan: '\x1b[36m',
    white: '\x1b[37m',
    reset: '\x1b[0m'
};

console.log(`
${colors.cyan}╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║     🔌 AI-NMS Database Connection Tester                    ║
║                                                              ║
║     Verifying MongoDB Atlas Connection                      ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝${colors.reset}
`);

// Get connection string from environment
const uri = process.env.MONGODB_URI;
const dbName = process.env.MONGODB_DB;

if (!uri) {
    console.error(`${colors.red}❌ Error: MONGODB_URI not found in .env.local${colors.reset}`);
    console.error(`${colors.yellow}💡 Your .env.local should contain:${colors.reset}`);
    console.error(`   MONGODB_URI=mongodb+srv://hackstorm:hackstorm123@cluster0.gbz3qlp.mongodb.net/?appName=Cluster0`);
    console.error(`   MONGODB_DB=hackstorm`);
    process.exit(1);
}

if (!dbName) {
    console.error(`${colors.red}❌ Error: MONGODB_DB not found in .env.local${colors.reset}`);
    process.exit(1);
}

// Hide password in display
const displayUri = uri.replace(/:[^:@]*@/, ':****@');
console.log(`${colors.blue}📁 Database Name:${colors.reset} ${dbName}`);
console.log(`${colors.blue}🔗 Connection String:${colors.reset} ${displayUri}`);
console.log('');

async function testConnection() {
    let client;
    
    try {
        console.log(`${colors.yellow}🔄 Connecting to MongoDB Atlas...${colors.reset}`);
        
        client = new MongoClient(uri, {
            connectTimeoutMS: 10000,
            serverSelectionTimeoutMS: 10000
        });
        
        await client.connect();
        console.log(`${colors.green}✅ Connected successfully!${colors.reset}`);
        
        const db = client.db(dbName);
        console.log(`${colors.green}📁 Using database: ${dbName}${colors.reset}`);
        
        // Test 1: Create a test collection
        console.log(`\n${colors.blue}📋 Running Tests:${colors.reset}`);
        
        // Test 1: Insert test document
        console.log(`   ${colors.cyan}[1/5]${colors.reset} Testing INSERT...`);
        const testCollection = db.collection('_connection_test');
        const testDoc = {
            message: 'Connection successful!',
            timestamp: new Date(),
            testId: Date.now()
        };
        const insertResult = await testCollection.insertOne(testDoc);
        console.log(`   ${colors.green}✅ Insert successful! ID: ${insertResult.insertedId}${colors.reset}`);
        
        // Test 2: Read test document
        console.log(`   ${colors.cyan}[2/5]${colors.reset} Testing READ...`);
        const readDoc = await testCollection.findOne({ _id: insertResult.insertedId });
        console.log(`   ${colors.green}✅ Read successful! Message: ${readDoc.message}${colors.reset}`);
        
        // Test 3: Update test document
        console.log(`   ${colors.cyan}[3/5]${colors.reset} Testing UPDATE...`);
        await testCollection.updateOne(
            { _id: insertResult.insertedId },
            { $set: { updated: true, updatedAt: new Date() } }
        );
        console.log(`   ${colors.green}✅ Update successful!${colors.reset}`);
        
        // Test 4: Delete test document
        console.log(`   ${colors.cyan}[4/5]${colors.reset} Testing DELETE...`);
        await testCollection.deleteOne({ _id: insertResult.insertedId });
        console.log(`   ${colors.green}✅ Delete successful!${colors.reset}`);
        
        // Test 5: List collections
        console.log(`   ${colors.cyan}[5/5]${colors.reset} Getting collection list...`);
        const collections = await db.listCollections().toArray();
        const collectionNames = collections.map(c => c.name);
        
        console.log(`   ${colors.green}✅ Found ${collectionNames.length} collections:${colors.reset}`);
        if (collectionNames.length > 0) {
            collectionNames.forEach(name => {
                console.log(`      📄 ${name}`);
            });
        } else {
            console.log(`      📄 No collections yet (they will be created automatically)`);
        }
        
        // Summary
        console.log(`\n${colors.green}═══════════════════════════════════════════════════════════════${colors.reset}`);
        console.log(`${colors.green}              ✅ ALL TESTS PASSED!                              ${colors.reset}`);
        console.log(`${colors.green}═══════════════════════════════════════════════════════════════${colors.reset}`);
        console.log(`
${colors.cyan}📊 Connection Summary:${colors.reset}
   • Database: ${dbName}
   • Status: Connected
   • Collections: ${collectionNames.length}
   
${colors.green}✅ Your database is ready to use!${colors.reset}
`);
        
    } catch (error) {
        console.error(`\n${colors.red}❌ Connection FAILED!${colors.reset}`);
        console.error(`${colors.red}Error: ${error.message}${colors.reset}`);
        console.log(`
${colors.yellow}🔧 Troubleshooting Tips:${colors.reset}
   1. Check your username and password in .env.local
   2. Make sure your IP is whitelisted in MongoDB Atlas
      → Go to Atlas → Network Access → Add IP Address
   3. Verify your cluster is active (not paused)
   4. Check your internet connection
`);
        process.exit(1);
    } finally {
        if (client) {
            await client.close();
            console.log(`${colors.blue}🔒 Connection closed${colors.reset}`);
        }
    }
}

// Run the test
testConnection();