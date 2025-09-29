// YAW NETWORK - AFRICAN BLOCKCHAIN SERVER
// Copy and paste this EXACTLY as is!

const express = require('express');
const http = require('http');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const { Server } = require('socket.io');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'yaw_african_blockchain_secret_2024';

// Simple blockchain simulation
let blockchain = {
  chain: [],
  pendingTransactions: [],
  networkStats: {
    height: 1,
    difficulty: 4,
    tps: 1247.5,
    totalValidators: 122,
    securityScore: 95.7,
    africaRepresentation: { percentage: 87.5 },
    networkHash: { formatted: '15.7 EH/s' }
  }
};

// Create genesis block
blockchain.chain.push({
  height: 0,
  timestamp: Date.now(),
  previousHash: '0'.repeat(64),
  transactions: [],
  hash: 'genesis_african_blockchain_ubuntu_power_2024',
  validator: 'GENESIS-AFRICAN-VALIDATORS',
  message: 'Ubuntu Genesis - African Blockchain Revolution Begins'
});

// Middleware
app.use(helmet());
app.use(cors());
app.use(compression());
app.use(express.json());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 1000,
  message: { error: 'Too many requests - Ubuntu patience please! 🌍' }
});
app.use('/api/', limiter);

// WebSocket connections
const connectedClients = new Set();

io.on('connection', (socket) => {
  console.log(`🔗 Client connected: ${socket.id}`);
  connectedClients.add(socket.id);
  
  socket.emit('welcome', {
    message: '🌍 Welcome to Yaw Network - African Blockchain Revolution!',
    networkStats: blockchain.networkStats,
    ubuntu: 'I am because we are - Ubuntu Technology!'
  });
  
  socket.on('disconnect', () => {
    console.log(`❌ Client disconnected: ${socket.id}`);
    connectedClients.delete(socket.id);
  });
});

// Routes

// Health check
app.get('/health', (req, res) => {
  res.json({
    status: 'Ubuntu Strong! 💪',
    uptime: process.uptime(),
    blockchain: {
      height: blockchain.networkStats.height,
      tps: blockchain.networkStats.tps
    },
    message: '🌍 African blockchain is healthy and strong!',
    ubuntu: 'I am because we are - Ubuntu technology!',
    connectedClients: connectedClients.size
  });
});

// Blockchain info
app.get('/api/blockchain/info', (req, res) => {
  res.json({
    success: true,
    data: {
      ...blockchain.networkStats,
      latestBlock: blockchain.chain[blockchain.chain.length - 1],
      totalBlocks: blockchain.chain.length,
      features: [
        'Ubuntu Byzantine Consensus',
        'Quantum-resistant Encryption', 
        'African Geographic Distribution',
        'Mobile-first Architecture',
        'Real-time WebSocket Updates'
      ],
      message: '🌍 Welcome to African blockchain revolution!',
      ubuntu: 'Ubuntu technology - built with collective wisdom'
    }
  });
});

// Connect wallet
app.post('/api/auth/connect', (req, res) => {
  try {
    const { walletAddress, country = 'nigeria' } = req.body;
    
    if (!walletAddress) {
      return res.status(400).json({
        success: false,
        error: 'Wallet address required',
        message: 'Ubuntu requires identity - please provide wallet address'
      });
    }
    
    const userId = crypto.createHash('sha256').update(walletAddress).digest('hex').slice(0, 16);
    const token = jwt.sign({ userId, country }, JWT_SECRET, { expiresIn: '24h' });
    
    res.json({
      success: true,
      data: {
        token,
        userId,
        country,
        expiresIn: '24h'
      },
      message: `🌍 Ubuntu welcome from ${country}! Connected to African blockchain!`,
      ubuntu: 'I am because we are - Ubuntu connection established!'
    });
    
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Authentication failed',
      message: error.message
    });
  }
});

// Create transaction
app.post('/api/transactions/create', (req, res) => {
  try {
    const { to, amount } = req.body;
    
    if (!to || !amount || amount <= 0) {
      return res.status(400).json({
        success: false,
        error: 'Invalid transaction parameters',
        message: 'Ubuntu requires valid recipient and amount'
      });
    }
    
    const transaction = {
      id: crypto.randomBytes(32).toString('hex'),
      to,
      amount: parseFloat(amount),
      timestamp: Date.now(),
      status: 'pending'
    };
    
    blockchain.pendingTransactions.push(transaction);
    
    // Broadcast to WebSocket clients
    io.emit('newTransaction', { transaction });
    
    res.json({
      success: true,
      data: {
        transactionId: transaction.id,
        amount: transaction.amount,
        status: 'pending',
        estimatedConfirmation: '15-30 seconds'
      },
      message: '💰 Ubuntu transaction created! African speed and efficiency!',
      ubuntu: 'I am because we are - collective transaction success!'
    });
    
  } catch (error) {
    res.status(400).json({
      success: false,
      error: 'Transaction creation failed',
      message: error.message
    });
  }
});

// Get analytics
app.get('/api/analytics', (req, res) => {
  res.json({
    success: true,
    data: {
      blockchain: blockchain.networkStats,
      server: {
        uptime: process.uptime(),
        connectedClients: connectedClients.size,
        memory: process.memoryUsage()
      },
      african: {
        countries: ['Nigeria', 'Kenya', 'Ghana', 'South Africa', 'Egypt', 'Morocco', 'Ethiopia'],
        validators: blockchain.networkStats.totalValidators,
        representation: blockchain.networkStats.africaRepresentation.percentage
      }
    },
    message: '📊 Ubuntu analytics - transparency through technology!',
    ubuntu: 'Collective intelligence for collective progress'
  });
});

// African countries
app.get('/api/countries', (req, res) => {
  const countries = [
    { code: 'NG', name: 'Nigeria', flag: '🇳🇬' },
    { code: 'KE', name: 'Kenya', flag: '🇰🇪' },
    { code: 'GH', name: 'Ghana', flag: '🇬🇭' },
    { code: 'ZA', name: 'South Africa', flag: '🇿🇦' },
    { code: 'EG', name: 'Egypt', flag: '🇪🇬' },
    { code: 'MA', name: 'Morocco', flag: '🇲🇦' },
    { code: 'ET', name: 'Ethiopia', flag: '🇪🇹' }
  ];
  
  res.json({
    success: true,
    data: {
      supportedCountries: countries,
      totalCountries: countries.length,
      networkCoverage: '87.5%'
    },
    message: '🌍 Ubuntu spans across Africa - united blockchain!',
    ubuntu: 'Many countries, one Ubuntu vision!'
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Endpoint not found',
    message: '🌍 Ubuntu wisdom: This path does not exist in our African blockchain',
    availableEndpoints: [
      'GET /health',
      'GET /api/blockchain/info', 
      'POST /api/auth/connect',
      'POST /api/transactions/create',
      'GET /api/analytics',
      'GET /api/countries'
    ],
    ubuntu: 'I am because we are - but this endpoint is not because it should not be'
  });
});

// Error handler
app.use((err, req, res, next) => {
  console.error('🔥 Ubuntu Error:', err);
  res.status(500).json({
    success: false,
    error: 'Ubuntu encountered a challenge',
    message: 'Something went wrong in the African blockchain',
    ubuntu: 'I am because we are - and we learn from our mistakes'
  });
});

// Simulate network activity
setInterval(() => {
  // Update network stats
  blockchain.networkStats.height += 1;
  blockchain.networkStats.tps = Math.random() * 500 + 1000;
  
  // Broadcast analytics update
  io.emit('analyticsUpdate', { analytics: blockchain.networkStats });
  
  // Simulate new block
  if (Math.random() > 0.7) {
    const newBlock = {
      height: blockchain.networkStats.height,
      timestamp: Date.now(),
      transactions: blockchain.pendingTransactions.splice(0, 5),
      validator: 'validator-african-node'
    };
    
    blockchain.chain.push(newBlock);
    io.emit('newBlock', { block: newBlock, chainHeight: blockchain.chain.length });
  }
}, 30000);

// Start server
server.listen(PORT, '0.0.0.0', () => {
  console.log('\n🌍 YAW NETWORK - AFRICAN BLOCKCHAIN SERVER STARTED! 🚀');
  console.log('================================================');
  console.log(`🔥 Server running on port ${PORT}`);
  console.log(`🤝 Ubuntu Consensus: ACTIVE`);
  console.log(`📡 WebSocket: Real-time updates enabled`);
  console.log(`💎 Blockchain Height: ${blockchain.networkStats.height}`);
  console.log('================================================');
  console.log('🌟 UBUNTU MESSAGE: "I am because we are"');
  console.log('🚀 African blockchain revolution is LIVE!');
  console.log('================================================\n');
});

module.exports = app;
