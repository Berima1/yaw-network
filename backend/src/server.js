// YAW NETWORK - ENTERPRISE-GRADE API SERVER
// "When they said it couldn't be built in Africa, we said watch us"
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
const redis = require('redis');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { body, validationResult, param } = require('express-validator');

// Import our revolutionary blockchain
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
        this.client = null;
        
        try {
            if (process.env.REDIS_URL || process.env.REDIS_HOST) {
                this.client = redis.createClient({
                    url: process.env.REDIS_URL,
                    host: process.env.REDIS_HOST || 'localhost',
                    port: process.env.REDIS_PORT || 6379,
                    password: process.env.REDIS_PASSWORD,
                    db: 0,
                    lazyConnect: true
                });
                
                this.client.on('connect', () => {
                    console.log('Redis cache connected');
                    this.enabled = true;
                });
                
                this.client.on('error', (err) => {
                    console.warn('Redis error (running without cache):', err.message);
                    this.enabled = false;
                });
                
                this.client.connect().catch(() => {
                    console.warn('Redis unavailable - running without cache');
                    this.enabled = false;
                });
            } else {
                console.log('Redis not configured - running without cache');
            }
        } catch (error) {
            console.warn('Redis initialization failed - running without cache');
            this.enabled = false;
        }
    }
    
    async get(key) {
        if (!this.enabled || !this.client) return null;
        
        try {
            const data = await this.client.get(`yaw:${key}`);
            return data ? JSON.parse(data) : null;
        } catch (error) {
            return null;
        }
    }
    
    async set(key, value, expireSeconds = 3600) {
        if (!this.enabled || !this.client) return false;
        
        try {
            await this.client.setEx(`yaw:${key}`, expireSeconds, JSON.stringify(value));
            return true;
        } catch (error) {
            return false;
        }
    }
    
    async del(key) {
        if (!this.enabled || !this.client) return false;
        
        try {
            await this.client.del(`yaw:${key}`);
            return true;
        } catch (error) {
            return false;
        }
    }
}

// =================== ADVANCED AUTHENTICATION ===================
class YawAuthSystem {
    constructor() {
        this.jwtSecret = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
        this.refreshTokens = new Map();
        this.quantumCrypto = new QuantumResistantCrypto();
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
                message: 'Welcome to Yaw Network Real-time Feed',
                networkStats: this.getNetworkStats()
            });
        });
    }
    
    handleSubscription(socket, data) {
        const { channel, params } = data;
        
        if (!this.subscriptions.has(channel)) {
            this.subscriptions.set(channel, new Set());
        }
        
        this.subscriptions.get(channel).add(socket.id);
        this.connectedClients.get(socket.id).subscriptions.add(channel);
        
        socket.emit('subscribed', { channel, status: 'success' });
        this.sendInitialData(socket, channel, params);
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
    
    sendInitialData(socket, channel, params) {
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
            const originalSend = res.send;
            
            res.send = function(data) {
                const duration = Date.now() - start;
                console.log(`${req.method} ${req.path} - ${res.statusCode} (${duration}ms)`);
                originalSend.call(this, data);
            };
            
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
                        totalTransactions: this.blockchain.chain.reduce((sum, block) => sum + block.transactions.length, 0),
                        validators: this.blockchain.validators.size,
                        latestBlock: this.blockchain.getLatestBlock()
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
        
        this.app.use('*', (req, res) => {
            res.status(404).json({
                error: 'Endpoint not found',
                availableEndpoints: [
                    'GET /health',
                    'GET /api/blockchain/info'
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

// =================== MAIN APPLICATION ===================
// Skip cluster mode for simplicity in deployment
const shouldCluster = process.env.ENABLE_CLUSTER === 'true';

if (!shouldCluster || YawClusterManager.initializeCluster()) {
    try {
        const yawServer = new YawAPIServer();
        yawServer.start();
        
        console.log('YAW NETWORK - BLOCKCHAIN ECOSYSTEM READY');
    } catch (error) {
        console.error('Failed to start server:', error);
        process.exit(1);
    }
}

module.exports = {
    YawAPIServer,
    YawCacheManager,
    YawAuthSystem,
    YawRealtimeManager
};
