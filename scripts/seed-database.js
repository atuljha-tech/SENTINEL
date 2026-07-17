#!/usr/bin/env node

// ============================================
// Database Seeder - Populate with Demo Data
// Use this to seed your database with sample traffic
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

const colors = {
    red: '\x1b[31m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m',
    purple: '\x1b[35m',
    cyan: '\x1b[36m',
    reset: '\x1b[0m'
};

console.log(`
${colors.cyan}╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║     🌱 AI-NMS Database Seeder                               ║
║                                                              ║
║     Seeding database with demo traffic data                 ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝${colors.reset}
`);

const uri = process.env.MONGODB_URI;
const dbName = process.env.MONGODB_DB;

if (!uri || !dbName) {
    console.error(`${colors.red}❌ Error: Missing .env.local configuration${colors.reset}`);
    console.error(`${colors.yellow}💡 Your .env.local should contain:${colors.reset}`);
    console.error(`   MONGODB_URI=mongodb+srv://hackstorm:hackstorm123@cluster0.gbz3qlp.mongodb.net/?appName=Cluster0`);
    console.error(`   MONGODB_DB=hackstorm`);
    process.exit(1);
}

console.log(`${colors.blue}📁 Database:${colors.reset} ${dbName}`);
console.log(`${colors.blue}🔗 URI:${colors.reset} ${uri.replace(/:[^:@]*@/, ':****@')}`);
console.log('');

// Sample data generators
const generateRandomIP = () => {
    const ips = [
        '192.168.1.100', '192.168.1.101', '10.0.0.25', '172.16.0.50',
        '8.8.8.8', '1.1.1.1', '45.33.22.11', '185.130.5.253',
        '94.102.61.78', '193.42.56.78', '203.0.113.5', '198.51.100.17'
    ];
    return ips[Math.floor(Math.random() * ips.length)];
};

const generateRandomPort = () => {
    const ports = [80, 443, 22, 23, 445, 3389, 1433, 3306, 5900, 8080, 8443, 53, 25, 110, 993, 995];
    return ports[Math.floor(Math.random() * ports.length)];
};

const generateRandomProtocol = () => {
    const protocols = ['TCP', 'UDP', 'HTTP', 'HTTPS', 'ICMP', 'SSH', 'FTP', 'SMTP'];
    return protocols[Math.floor(Math.random() * protocols.length)];
};

const generateRandomRequestCount = (attackType) => {
    if (attackType === 'ddos') return Math.floor(Math.random() * 200) + 100;
    if (attackType === 'bruteforce') return Math.floor(Math.random() * 80) + 40;
    if (attackType === 'portscan') return Math.floor(Math.random() * 30) + 5;
    if (attackType === 'bot') return Math.floor(Math.random() * 60) + 20;
    return Math.floor(Math.random() * 30) + 1;
};

const generateRiskScore = (ip, port, requestCount) => {
    let score = 0;
    const maliciousIPs = ['45.33.22.11', '185.130.5.253', '94.102.61.78', '193.42.56.78'];
    const suspiciousPorts = [22, 23, 445, 3389, 1433, 3306, 5900];
    
    if (maliciousIPs.includes(ip)) score += 50;
    if (suspiciousPorts.includes(port)) score += 25;
    if (requestCount > 100) score += 40;
    else if (requestCount > 50) score += 20;
    else if (requestCount > 30) score += 10;
    
    return Math.min(100, score);
};

const getThreatStatus = (riskScore) => {
    if (riskScore >= 70) return 'Attack';
    if (riskScore >= 35) return 'Suspicious';
    return 'Normal';
};

const getAttackType = (riskScore, ip, port, requestCount) => {
    const maliciousIPs = ['45.33.22.11', '185.130.5.253', '94.102.61.78', '193.42.56.78'];
    const suspiciousPorts = [22, 23, 445, 3389, 1433, 3306, 5900];
    
    if (maliciousIPs.includes(ip)) return 'Unknown Intrusion';
    if (requestCount > 100) return 'DDoS';
    if (requestCount > 50 && requestCount <= 100) return 'Brute Force';
    if (suspiciousPorts.includes(port)) return 'Port Scan';
    if (requestCount > 30 && requestCount <= 50) return 'Bot Traffic';
    return 'None';
};

async function seedDatabase() {
    let client;
    
    try {
        console.log(`${colors.yellow}🔄 Connecting to MongoDB Atlas...${colors.reset}`);
        client = new MongoClient(uri);
        await client.connect();
        console.log(`${colors.green}✅ Connected!${colors.reset}`);
        
        const db = client.db(dbName);
        
        // Clear existing data (optional - ask user)
        console.log(`${colors.yellow}🗑️ Clearing existing data...${colors.reset}`);
        await db.collection('traffic_logs').deleteMany({});
        await db.collection('detection_results').deleteMany({});
        await db.collection('response_logs').deleteMany({});
        await db.collection('website_security').deleteMany({});
        console.log(`${colors.green}✅ Cleared existing data${colors.reset}`);
        
        // ============================================
        // Seed 1: Normal Traffic (50 logs)
        // ============================================
        console.log(`${colors.cyan}[1/4]${colors.reset} Generating NORMAL traffic logs...`);
        const normalTraffic = [];
        const normalIPs = ['192.168.1.100', '192.168.1.101', '10.0.0.25', '172.16.0.50', '8.8.8.8', '1.1.1.1'];
        
        for (let i = 0; i < 50; i++) {
            const ip = normalIPs[Math.floor(Math.random() * normalIPs.length)];
            const port = generateRandomPort();
            const requestCount = Math.floor(Math.random() * 30) + 1;
            const riskScore = generateRiskScore(ip, port, requestCount);
            
            normalTraffic.push({
                ip,
                port,
                protocol: generateRandomProtocol(),
                requestCount,
                timestamp: new Date(Date.now() - Math.random() * 3600000),
                userAgent: 'Mozilla/5.0 (Normal Browser)',
                riskScore: Math.min(20, riskScore),
                threatStatus: 'Normal',
                attackType: 'None',
                alertFlag: false,
                analyzedAt: new Date()
            });
        }
        
        await db.collection('traffic_logs').insertMany(normalTraffic);
        console.log(`${colors.green}   ✅ Added 50 normal traffic logs${colors.reset}`);
        
        // ============================================
        // Seed 2: Suspicious Traffic (30 logs)
        // ============================================
        console.log(`${colors.cyan}[2/4]${colors.reset} Generating SUSPICIOUS traffic logs...`);
        const suspiciousTraffic = [];
        
        for (let i = 0; i < 30; i++) {
            const ip = generateRandomIP();
            const port = generateRandomPort();
            const requestCount = generateRandomRequestCount('bruteforce');
            const riskScore = generateRiskScore(ip, port, requestCount);
            
            suspiciousTraffic.push({
                ip,
                port,
                protocol: generateRandomProtocol(),
                requestCount,
                timestamp: new Date(Date.now() - Math.random() * 1800000),
                userAgent: 'Mozilla/5.0 (Suspicious Pattern)',
                riskScore: Math.min(60, Math.max(35, riskScore)),
                threatStatus: 'Suspicious',
                attackType: getAttackType(riskScore, ip, port, requestCount),
                alertFlag: true,
                analyzedAt: new Date()
            });
        }
        
        await db.collection('traffic_logs').insertMany(suspiciousTraffic);
        console.log(`${colors.green}   ✅ Added 30 suspicious traffic logs${colors.reset}`);
        
        // ============================================
        // Seed 3: Attack Traffic (20 logs)
        // ============================================
        console.log(`${colors.cyan}[3/4]${colors.reset} Generating ATTACK traffic logs...`);
        const attackTraffic = [];
        const attackTypes = ['DDoS', 'Brute Force', 'Port Scan', 'Bot Traffic', 'Unknown Intrusion'];
        
        for (let i = 0; i < 20; i++) {
            const ip = generateRandomIP();
            const port = generateRandomPort();
            const attackType = attackTypes[Math.floor(Math.random() * attackTypes.length)];
            let requestCount = 0;
            
            if (attackType === 'DDoS') requestCount = Math.floor(Math.random() * 200) + 100;
            else if (attackType === 'Brute Force') requestCount = Math.floor(Math.random() * 80) + 50;
            else if (attackType === 'Port Scan') requestCount = Math.floor(Math.random() * 30) + 10;
            else requestCount = Math.floor(Math.random() * 100) + 50;
            
            const riskScore = generateRiskScore(ip, port, requestCount);
            
            attackTraffic.push({
                ip,
                port,
                protocol: generateRandomProtocol(),
                requestCount,
                timestamp: new Date(Date.now() - Math.random() * 900000),
                userAgent: attackType === 'Bot Traffic' ? 'AutomatedBot/1.0' : 'Unknown',
                riskScore: Math.min(100, Math.max(70, riskScore)),
                threatStatus: 'Attack',
                attackType: attackType,
                alertFlag: true,
                analyzedAt: new Date()
            });
        }
        
        await db.collection('traffic_logs').insertMany(attackTraffic);
        console.log(`${colors.green}   ✅ Added 20 attack traffic logs${colors.reset}`);
        
        // ============================================
        // Seed 4: Detection Results
        // ============================================
        console.log(`${colors.cyan}[4/4]${colors.reset} Generating detection results...`);
        const allTraffic = [...normalTraffic, ...suspiciousTraffic, ...attackTraffic];
        
        // Get the actual inserted documents to get their _id
        const allInserted = await db.collection('traffic_logs').find({}).toArray();
        
        for (const traffic of allInserted) {
            await db.collection('detection_results').insertOne({
                trafficId: traffic._id,
                riskScore: traffic.riskScore,
                threatStatus: traffic.threatStatus,
                attackType: traffic.attackType,
                alertFlag: traffic.alertFlag,
                reasons: [
                    traffic.riskScore > 70 ? 'High traffic volume detected' : 
                    traffic.riskScore > 35 ? 'Unusual pattern detected' : 'Normal traffic pattern',
                    traffic.attackType !== 'None' ? `${traffic.attackType} characteristics observed` : 'No anomalies'
                ],
                recommendations: traffic.attackType !== 'None' ? 
                    ['Monitor this IP', 'Consider blocking if pattern continues'] : 
                    ['No action needed'],
                analyzedAt: traffic.analyzedAt || new Date(),
                trafficData: traffic
            });
        }
        
        console.log(`${colors.green}   ✅ Added detection results for all traffic${colors.reset}`);
        
        // ============================================
        // Summary
        // ============================================
        const finalCounts = {
            traffic: await db.collection('traffic_logs').countDocuments(),
            detections: await db.collection('detection_results').countDocuments(),
            normal: await db.collection('traffic_logs').countDocuments({ threatStatus: 'Normal' }),
            suspicious: await db.collection('traffic_logs').countDocuments({ threatStatus: 'Suspicious' }),
            attacks: await db.collection('traffic_logs').countDocuments({ threatStatus: 'Attack' })
        };
        
        console.log(`\n${colors.green}═══════════════════════════════════════════════════════════════${colors.reset}`);
        console.log(`${colors.green}              ✅ DATABASE SEEDING COMPLETE!                      ${colors.reset}`);
        console.log(`${colors.green}═══════════════════════════════════════════════════════════════${colors.reset}`);
        console.log(`
${colors.cyan}📊 Seeding Summary:${colors.reset}
   • Total Traffic Logs: ${finalCounts.traffic}
   • Normal Traffic: ${finalCounts.normal}
   • Suspicious Traffic: ${finalCounts.suspicious}
   • Attack Traffic: ${finalCounts.attacks}
   • Detection Results: ${finalCounts.detections}
   
${colors.green}✅ Your database is now ready for demo!${colors.reset}
`);
        
    } catch (error) {
        console.error(`${colors.red}❌ Error seeding database: ${error.message}${colors.reset}`);
        process.exit(1);
    } finally {
        if (client) {
            await client.close();
            console.log(`${colors.blue}🔒 Connection closed${colors.reset}`);
        }
    }
}

// Run the seeder
seedDatabase();