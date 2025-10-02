// YAW NETWORK - ENTERPRISE-GRADE API SERVER
// High-performance REST API with WebSocket real-time updates

const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const cors = require('cors');
const compression = require('compression');
const cluster = require('cluster');
const os = require('os');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { body, validationResult, param } = require('express-validator');

// Import blockchain core
const { YawBlockchain, QuantumResistantCrypto, ZKProofSystem } = require('./yaw-blockchain-core');

// =================== ENTERPRISE CLUSTER SETUP ===================
class YawClusterManager {
    static initializeCluster() {
        const numCPUs = os.cpus().length;
        
        if (cluster.isMaster) {
            console.log(`Master process ${process.pid} started`);
            console.log(`Spawning ${numCPUs} worker processes`);
            
            for (let i = 0; i < numCPUs; i++) {
                cluster.fork();
            }
            
            cluster.on('exit', (worker, code, signal) => {
                console.log(`Worker ${worker.process.pid} died. Respawning...`);
                cluster.fork();
            });
            
            return false;
        }
        
        return true;
    }
}

// =================== REDIS CACHING LAYER ===================
class YawCacheManager {
    constructor() {
        this.enabled = false;
        this.cache = new Map(); // Fallback in-memory cache
        
        console.log('Cache manager initialized (in-memory mode)');
    }
    
    async get(key) {
        return this.cache.get(`yaw:${key}`) || null;
    }
    
    async set(key, value, expireSeconds = 3600) {
        this.cache.set(`yaw:${key}`, value);
        
        // Auto-cleanup after expiration
        setTimeout(() => {
            this.cache.delete(`yaw:${key}`);
        }, expireSeconds * 1000);
        
        return true;
    }
    
    async del(key) {
        this.cache.delete(`yaw:${key}`);
        return true;
    }
}

// =================== ADVANCED AUTHENTICATION ===================
class YawAuthSystem {
    constructor() {
        this.jwtSecret = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
        this.refreshTokens = new Map();
    }
    
    generateTokens(userId, publicKey) {
        const payload = {
            userId,
            publicKey,
            timestamp: Date.now(),
            permissions: this.getUserPermissions(userId)
        };
        
        const accessToken = jwt.sign(payload, this.jwtSecret, { 
            expiresIn: '15m',
            algorithm: 'HS512'
        });
        
        const refreshToken = crypto.randomBytes(64).toString('hex');
        
        this.refreshTokens.set(refreshToken, {
            userId,
            createdAt: Date.now(),
            expiresAt: Date.now() + (7 * 24 * 60 * 60 * 1000)
        });
        
        return { accessToken, refreshToken };
    }
    
    verifyToken(token) {
        try {
            const decoded = jwt.verify(token, this.jwtSecret);
            
            if (decoded.timestamp + (15 * 60 * 1000) < Date.now()) {
                throw new Error('Token expired');
            }
            
            return decoded;
        } catch (error) {
            throw new Error('Invalid token');
        }
    }
    
    refreshAccessToken(refreshToken) {
        const tokenData = this.refreshTokens.get(refreshToken);
        
        if (!tokenData || tokenData.expiresAt < Date.now()) {
            throw new Error('Invalid or expired refresh token');
        }
        
        const newTokens = this.generateTokens(tokenData.userId);
        this.refreshTokens.delete(refreshToken);
        
        return newTokens;
    }
    
    getUserPermissions(userId) {
        return [
            'wallet:read',
            'wallet:write',
            'transactions:create',
            'transactions:read',
            'mining:participate',
            'analytics:basic'
        ];
    }
    
    generateAPIKey(userId) {
        const apiKeyData = {
            userId,
            createdAt: Date.now(),
            permissions: ['api:read', 'api:write']
        };
        
        const apiKey = 'yaw_' + crypto.randomBytes(32).toString('hex');
        const hashedKey = crypto.createHash('sha256').update(apiKey).digest('hex');
        
        return { apiKey, hashedKey, data: apiKeyData };
    }
}

// =================== WEBSOCKET REAL-TIME MANAGER ===================
class YawRealtimeManager {
    constructor(io, blockchain) {
        this.io = io;
        this.blockchain = blockchain;
        this.connectedClients = new Map();
        this.subscriptions = new Map();
        
        this.setupSocketHandlers();
    }
    
    setupSocketHandlers() {
        this.io.on('connection', (socket) => {
            console.log(`Client connected: ${socket.id}`);
            
            this.connectedClients.set(socket.id, {
                connectedAt: Date.now(),
                subscriptions: new Set()
            });
            
            socket.on('subscribe', (data) => {
                this.handleSubscription(socket, data);
            });
            
            socket.on('unsubscribe', (data) => {
                this.handleUnsubscription(socket, data);
            });
            
            socket.on('disconnect', () => {
                console.log(`Client disconnected: ${socket.id}`);
                this.cleanupClient(socket.id);
            });
            
            socket.emit('welcome', {
                message: 'Welcome to Yaw Network',
                networkStats: this.getNetworkStats()
            });
        });
    }
    
    handleSubscription(socket, data) {
        const { channel } = data;
        
        if (!this.subscriptions.has(channel)) {
            this.subscriptions.set(channel, new Set());
        }
        
        this.subscriptions.get(channel).add(socket.id);
        this.connectedClients.get(socket.id).subscriptions.add(channel);
        
        socket.emit('subscribed', { channel, status: 'success' });
        this.sendInitialData(socket, channel);
    }
    
    handleUnsubscription(socket, data) {
        const { channel } = data;
        
        if (this.subscriptions.has(channel)) {
            this.subscriptions.get(channel).delete(socket.id);
        }
        
        if (this.connectedClients.has(socket.id)) {
            this.connectedClients.get(socket.id).subscriptions.delete(channel);
        }
        
        socket.emit('unsubscribed', { channel, status: 'success' });
    }
    
    sendInitialData(socket, channel) {
        switch (channel) {
            case 'blocks':
                socket.emit('blocks', {
                    latestBlock: this.blockchain.getLatestBlock(),
                    chainHeight: this.blockchain.chain.length
                });
                break;
            
            case 'transactions':
                socket.emit('transactions', {
                    pending: this.blockchain.pendingTransactions.slice(-10)
                });
                break;
            
            case 'analytics':
                socket.emit('analytics', this.blockchain.getBlockchainAnalytics());
                break;
        }
    }
    
    broadcastNewBlock(block) {
        this.broadcast('blocks', 'newBlock', {
            block,
            chainHeight: this.blockchain.chain.length,
            timestamp: Date.now()
        });
    }
    
    broadcastNewTransaction(transaction) {
        this.broadcast('transactions', 'newTransaction', {
            transaction,
            pendingCount: this.blockchain.pendingTransactions.length,
            timestamp: Date.now()
        });
    }
    
    broadcastAnalyticsUpdate() {
        this.broadcast('analytics', 'analyticsUpdate', {
            analytics: this.blockchain.getBlockchainAnalytics(),
            timestamp: Date.now()
        });
    }
    
    broadcast(channel, event, data) {
        if (this.subscriptions.has(channel)) {
            for (const socketId of this.subscriptions.get(channel)) {
                const socket = this.io.sockets.sockets.get(socketId);
                if (socket) {
                    socket.emit(event, data);
                }
            }
        }
    }
    
    cleanupClient(socketId) {
        for (const [channel, subscribers] of this.subscriptions) {
            subscribers.delete(socketId);
        }
        this.connectedClients.delete(socketId);
    }
    
    getNetworkStats() {
        return {
            connectedClients: this.connectedClients.size,
            activeSubscriptions: Array.from(this.subscriptions.keys()),
            uptime: process.uptime(),
            timestamp: Date.now()
        };
    }
}

// =================== SMART CONTRACT ENGINE ===================
class YawSmartContractEngine {
    constructor(blockchain) {
        this.blockchain = blockchain;
        this.contracts = new Map();
        this.contractTemplates = new Map();
        
        this.initializeContractTemplates();
    }
    
    initializeContractTemplates() {
        this.contractTemplates.set('YAW-TOKEN', {
            name: 'Yaw Token Contract',
            version: '1.0.0',
            functions: ['transfer', 'approve', 'mint', 'burn', 'balanceOf'],
            storage: ['balances', 'allowances', 'totalSupply', 'owner']
        });
        
        this.contractTemplates.set('YAW-MULTISIG', {
            name: 'Multi-Signature Wallet',
            version: '1.0.0',
            functions: ['submitTransaction', 'confirmTransaction', 'executeTransaction'],
            storage: ['owners', 'required', 'transactions', 'confirmations']
        });
    }
    
    async deployContract(contractType, params, deployerAddress) {
        try {
            if (!this.contractTemplates.has(contractType)) {
                throw new Error(`Contract template ${contractType} not found`);
            }
            
            const template = this.contractTemplates.get(contractType);
            const contractAddress = this.generateContractAddress(deployerAddress, Date.now());
            
            const contract = {
                address: contractAddress,
                type: contractType,
                template: template,
                owner: deployerAddress,
                storage: this.initializeContractStorage(template, params),
                deployedAt: Date.now(),
                version: template.version,
                params: params
            };
            
            this.contracts.set(contractAddress, contract);
            
            console.log(`Contract deployed: ${contractType} at ${contractAddress}`);
            
            return {
                contractAddress,
                contract: contract
            };
            
        } catch (error) {
            throw new Error(`Contract deployment failed: ${error.message}`);
        }
    }
    
    generateContractAddress(deployerAddress, timestamp) {
        const data = `${deployerAddress}-${timestamp}`;
        const hash = crypto.createHash('sha256').update(data).digest('hex');
        return '0x' + hash.slice(0, 40);
    }
    
    initializeContractStorage(template, params) {
        const storage = {};
        
        template.storage.forEach(key => {
            switch (key) {
                case 'balances':
                    storage[key] = {};
                    break;
                case 'totalSupply':
                    storage[key] = params.initialSupply || 0;
                    break;
                case 'owners':
                    storage[key] = params.owners || [];
                    break;
                case 'required':
                    storage[key] = params.required || 2;
                    break;
                default:
                    storage[key] = params[key] || null;
            }
        });
        
        return storage;
    }
    
    getContract(address) {
        return this.contracts.get(address);
    }
    
    getAllContracts() {
        return Array.from(this.contracts.values());
    }
}

// =================== MAIN API SERVER CLASS ===================
class YawAPIServer {
    constructor() {
        this.app = express();
        this.server = http.createServer(this.app);
        this.io = socketIo(this.server, {
            cors: {
                origin: "*",
                methods: ["GET", "POST"]
            }
        });
        
        this.blockchain = new YawBlockchain();
        this.cache = new YawCacheManager();
        this.auth = new YawAuthSystem();
        this.realtime = new YawRealtimeManager(this.io, this.blockchain);
        
        this.port = process.env.PORT || 3000;
        this.setupMiddleware();
        this.setupRoutes();
        this.startPerformanceMonitoring();
    }
    
    setupMiddleware() {
        this.app.use(helmet({
            contentSecurityPolicy: {
                directives: {
                    defaultSrc: ["'self'"],
                    styleSrc: ["'self'", "'unsafe-inline'"],
                    scriptSrc: ["'self'"],
                    imgSrc: ["'self'", "data:", "https:"],
                }
            }
        }));
        
        this.app.use(cors({
            origin: process.env.ALLOWED_ORIGINS?.split(',') || '*',
            credentials: true
        }));
        
        this.app.use(compression());
        this.app.use(express.json({ limit: '10mb' }));
        this.app.use(express.urlencoded({ extended: true, limit: '10mb' }));
        
        const limiter = rateLimit({
            windowMs: 15 * 60 * 1000,
            max: 1000,
            message: {
                error: 'Too many requests, please try again later',
                retryAfter: '15 minutes'
            },
            standardHeaders: true,
            legacyHeaders: false
        });
        
        this.app.use('/api/', limiter);
        
        this.app.use((req, res, next) => {
            const start = Date.now();
            res.on('finish', () => {
                const duration = Date.now() - start;
                console.log(`${req.method} ${req.path} - ${res.statusCode} (${duration}ms)`);
            });
            next();
        });
    }
    
    setupRoutes() {
        this.app.get('/health', (req, res) => {
            res.json({
                status: 'healthy',
                uptime: process.uptime(),
                blockchain: {
                    height: this.blockchain.chain.length,
                    difficulty: this.blockchain.difficulty,
                    pending: this.blockchain.pendingTransactions.length
                },
                server: {
                    memory: process.memoryUsage(),
                    cpu: process.cpuUsage(),
                    version: '1.0.0'
                }
            });
        });
        
        this.app.get('/api/blockchain/info', async (req, res) => {
            try {
                const cacheKey = 'blockchain:info';
                let info = await this.cache.get(cacheKey);
                
                if (!info) {
                    info = {
                        height: this.blockchain.chain.length,
                        difficulty: this.blockchain.difficulty,
                        totalTransactions: this.blockchain.chain.reduce((sum, block) => 
                            sum + block.transactions.length, 0),
                        validators: this.blockchain.validators.size,
                        latestBlock: this.blockchain.getLatestBlock(),
                        features: [
                            'Quantum-resistant cryptography',
                            'Zero-knowledge proofs',
                            'Ubuntu consensus algorithm',
                            'Smart contracts'
                        ]
                    };
                    
                    await this.cache.set(cacheKey, info, 30);
                }
                
                res.json({
                    success: true,
                    data: info
                });
                
            } catch (error) {
                res.status(500).json({
                    error: 'Failed to fetch blockchain info',
                    message: error.message
                });
            }
        });
        
        this.app.post('/api/auth/register', [
            body('publicKey').isLength({ min: 64 }).withMessage('Valid public key required'),
            body('country').isIn(['nigeria', 'kenya', 'ghana', 'south-africa', 'egypt', 'morocco', 'ethiopia'])
        ], async (req, res) => {
            try {
                const errors = validationResult(req);
                if (!errors.isEmpty()) {
                    return res.status(400).json({ errors: errors.array() });
                }
                
                const { publicKey, country } = req.body;
                const userId = crypto.createHash('sha256').update(publicKey).digest('hex').slice(0, 16);
                const tokens = this.auth.generateTokens(userId, publicKey);
                
                await this.cache.set(`user:${userId}`, {
                    publicKey,
                    country,
                    registeredAt: Date.now()
                }, 86400);
                
                res.json({
                    success: true,
                    userId,
                    tokens,
                    country
                });
                
            } catch (error) {
                res.status(500).json({
                    error: 'Registration failed',
                    message: error.message
                });
            }
        });
        
        this.app.use('*', (req, res) => {
            res.status(404).json({
                error: 'Endpoint not found',
                availableEndpoints: [
                    'GET /health',
                    'GET /api/blockchain/info',
                    'POST /api/auth/register'
                ]
            });
        });
        
        this.app.use((err, req, res, next) => {
            console.error('Server error:', err);
            
            res.status(err.status || 500).json({
                error: 'Internal server error',
                message: process.env.NODE_ENV === 'development' ? err.message : 'Something went wrong',
                timestamp: Date.now()
            });
        });
    }
    
    authenticateToken(req, res, next) {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];
        
        if (!token) {
            return res.status(401).json({
                error: 'Access token required'
            });
        }
        
        try {
            const user = this.auth.verifyToken(token);
            req.user = user;
            next();
        } catch (error) {
            return res.status(403).json({
                error: 'Invalid token',
                message: error.message
            });
        }
    }
    
    startPerformanceMonitoring() {
        setInterval(() => {
            const stats = {
                timestamp: Date.now(),
                memory: process.memoryUsage(),
                blockchain: {
                    height: this.blockchain.chain.length,
                    pending: this.blockchain.pendingTransactions.length
                }
            };
            
            this.cache.set('performance:latest', stats, 300);
            
            const memUsage = stats.memory.heapUsed / stats.memory.heapTotal;
            if (memUsage > 0.9) {
                console.warn('High memory usage:', (memUsage * 100).toFixed(1) + '%');
            }
            
        }, 30000);
        
        setInterval(() => {
            this.realtime.broadcastAnalyticsUpdate();
        }, 60000);
    }
    
    start() {
        this.server.listen(this.port, () => {
            console.log('\nYAW NETWORK API SERVER STARTED');
            console.log('================================================');
            console.log(`Server running on port ${this.port}`);
            console.log(`Process ID: ${process.pid}`);
            console.log(`Validators: ${this.blockchain.validators.size} nodes`);
            console.log('Ready to serve requests');
            console.log('================================================\n');
        });
        
        process.on('SIGTERM', () => {
            console.log('SIGTERM received, shutting down gracefully...');
            this.server.close(() => {
                console.log('Server shut down complete');
                process.exit(0);
            });
        });
        
        process.on('SIGINT', () => {
            console.log('\nSIGINT received, shutting down gracefully...');
            this.server.close(() => {
                console.log('Server shut down complete');
                process.exit(0);
            });
        });
    }
}

// =================== DEMONSTRATION FUNCTION (FIXED) ===================
async function demonstrateYawBlockchain(yawChain) {
    console.log('\n📊 BLOCKCHAIN PERFORMANCE DEMONSTRATION\n');
    
    try {
        // Generate keys
        const aliceKeys = yawChain.generateECDSAKeys();
        const bobKeys = yawChain.generateECDSAKeys();
        const charlieKeys = yawChain.generateECDSAKeys();
        
        const aliceAddr = aliceKeys.publicKey.slice(0, 40);
        const bobAddr = bobKeys.publicKey.slice(0, 40);
        const charlieAddr = charlieKeys.publicKey.slice(0, 40);
        
        console.log('Creating initial transactions...');
        
        // Create transactions with proper balance parameter
        for (let i = 0; i < 5; i++) {
            const amount = 100 + (i * 50);
            
            await yawChain.createTransaction(
                aliceAddr,
                bobAddr,
                amount,
                aliceKeys.privateKey,
                {
                    private: i % 2 === 0,
                    fee: amount * 0.002,
                    balance: 10000 // Provide balance for validation
                }
            );
        }
        
        console.log('Mining first block...');
        const block1 = await yawChain.mineBlock('validator-lagos');
        console.log(`Block #${block1.height} mined successfully`);
        
        // Create more transactions
        for (let i = 0; i < 3; i++) {
            const amount = 50 + (i * 25);
            
            await yawChain.createTransaction(
                bobAddr,
                charlieAddr,
                amount,
                bobKeys.privateKey,
                {
                    fee: amount * 0.002,
                    balance: 5000
                }
            );
        }
        
        console.log('Mining second block...');
        const block2 = await yawChain.mineBlock('validator-nairobi');
        console.log(`Block #${block2.height} mined successfully`);
        
        // Display analytics
        const analytics = yawChain.getBlockchainAnalytics();
        console.log('\n📈 DEMONSTRATION COMPLETE');
        console.log(`   Blocks: ${analytics.chainHeight}`);
        console.log(`   TPS: ${analytics.tps.toFixed(2)}`);
        console.log(`   Security Score: ${analytics.securityScore.toFixed(1)}/100`);
        
    } catch (error) {
        console.error('Demonstration error (non-critical):', error.message);
        console.log('Server will continue without demonstration');
    }
}

// =================== MAIN APPLICATION ===================
const shouldCluster = process.env.ENABLE_CLUSTER === 'true';

if (!shouldCluster || YawClusterManager.initializeCluster()) {
    try {
        const yawServer = new YawAPIServer();
        const contractEngine = new YawSmartContractEngine(yawServer.blockchain);
        
        // Add contract deployment endpoint
        yawServer.app.post('/api/contracts/deploy', [
            yawServer.authenticateToken.bind(yawServer),
            body('contractType').isIn(['YAW-TOKEN', 'YAW-MULTISIG']),
            body('params').isObject()
        ], async (req, res) => {
            try {
                const errors = validationResult(req);
                if (!errors.isEmpty()) {
                    return res.status(400).json({ errors: errors.array() });
                }
                
                const { contractType, params } = req.body;
                const deployerAddress = req.user.publicKey.slice(0, 20);
                
                const deployment = await contractEngine.deployContract(
                    contractType,
                    params,
                    deployerAddress
                );
                
                res.json({
                    success: true,
                    data: deployment
                });
                
            } catch (error) {
                res.status(400).json({
                    error: 'Contract deployment failed',
                    message: error.message
                });
            }
        });
        
        // Add contract info endpoint
        yawServer.app.get('/api/contracts/:address', (req, res) => {
            try {
                const { address } = req.params;
                const contract = contractEngine.getContract(address);
                
                if (!contract) {
                    return res.status(404).json({
                        error: 'Contract not found'
                    });
                }
                
                res.json({
                    success: true,
                    data: contract
                });
                
            } catch (error) {
                res.status(500).json({
                    error: 'Failed to fetch contract',
                    message: error.message
                });
            }
        });
        
        // START SERVER FIRST
        yawServer.start();
        
        // Run demonstration AFTER server starts (optional, wrapped in try-catch)
        if (process.env.SKIP_DEMO !== 'true') {
            setTimeout(() => {
                demonstrateYawBlockchain(yawServer.blockchain)
                    .then(() => console.log('Demonstration completed successfully'))
                    .catch(err => console.log('Demo skipped:', err.message));
            }, 3000); // Wait 3 seconds after server starts
        }
        
        console.log('YAW NETWORK - COMPLETE BLOCKCHAIN ECOSYSTEM READY');
        
    } catch (error) {
        console.error('Failed to start server:', error);
        process.exit(1);
    }
}

module.exports = {
    YawAPIServer,
    YawSmartContractEngine,
    YawCacheManager,
    YawAuthSystem,
    YawRealtimeManager
};
