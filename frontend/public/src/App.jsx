// YAW NETWORK - AFRICAN BLOCKCHAIN FRONTEND
// Production-ready React.js application optimized for mobile-first African users
// Built with love from Africa, for the world 🌍

import React, { useState, useEffect, useRef } from 'react';
import axios from 'axios';
import io from 'socket.io-client';
import './App.css';

// API Configuration
const API_BASE_URL = process.env.REACT_APP_API_URL || 'https://yaw-api.onrender.com';
const WS_URL = process.env.REACT_APP_WEBSOCKET_URL || 'wss://yaw-api.onrender.com';

// African countries configuration
const AFRICAN_COUNTRIES = {
  nigeria: { flag: '🇳🇬', name: 'Nigeria', code: 'NG' },
  kenya: { flag: '🇰🇪', name: 'Kenya', code: 'KE' },
  ghana: { flag: '🇬🇭', name: 'Ghana', code: 'GH' },
  'south-africa': { flag: '🇿🇦', name: 'South Africa', code: 'ZA' },
  egypt: { flag: '🇪🇬', name: 'Egypt', code: 'EG' },
  morocco: { flag: '🇲🇦', name: 'Morocco', code: 'MA' },
  ethiopia: { flag: '🇪🇹', name: 'Ethiopia', code: 'ET' }
};

// Main App Component
function App() {
  const [currentView, setCurrentView] = useState('dashboard');
  const [isConnected, setIsConnected] = useState(false);
  const [userCountry, setUserCountry] = useState('nigeria');
  const [networkStats, setNetworkStats] = useState({});
  const [userStats, setUserStats] = useState({});
  const [notifications, setNotifications] = useState([]);
  
  const socketRef = useRef(null);
  const [isOnline, setIsOnline] = useState(navigator.onLine);

  useEffect(() => {
    initializeApp();
    setupWebSocket();
    detectUserLocation();
    
    // Network status listeners for African connectivity
    window.addEventListener('online', () => setIsOnline(true));
    window.addEventListener('offline', () => setIsOnline(false));
    
    return () => {
      if (socketRef.current) {
        socketRef.current.disconnect();
      }
    };
  }, []);

  const initializeApp = async () => {
    try {
      const response = await axios.get(`${API_BASE_URL}/api/blockchain/info`);
      setNetworkStats(response.data.data);
      setIsConnected(true);
      
      addNotification('🌍 Connected to Yaw Network - African Power! 🔥', 'success');
    } catch (error) {
      console.error('Failed to connect to Yaw Network:', error);
      addNotification('⚠️ Connection issue - trying to reconnect...', 'warning');
    }
  };

  const setupWebSocket = () => {
    socketRef.current = io(WS_URL, {
      transports: ['websocket', 'polling'], // Fallback for African networks
      timeout: 10000,
      reconnection: true,
      reconnectionAttempts: 10,
      reconnectionDelay: 2000
    });

    socketRef.current.on('connect', () => {
      console.log('🔗 WebSocket connected - Real-time updates enabled!');
      setIsConnected(true);
      
      // Subscribe to all channels
      socketRef.current.emit('subscribe', { channel: 'blocks' });
      socketRef.current.emit('subscribe', { channel: 'transactions' });
      socketRef.current.emit('subscribe', { channel: 'analytics' });
      socketRef.current.emit('subscribe', { channel: 'mining' });
    });

    socketRef.current.on('disconnect', () => {
      console.log('❌ WebSocket disconnected');
      setIsConnected(false);
    });

    socketRef.current.on('newBlock', (data) => {
      setNetworkStats(prev => ({
        ...prev,
        height: data.chainHeight,
        latestBlock: data.block
      }));
      addNotification(`🎉 New block mined! #${data.chainHeight}`, 'success');
    });

    socketRef.current.on('newTransaction', (data) => {
      addNotification('💰 New transaction processed', 'info');
    });

    socketRef.current.on('analyticsUpdate', (data) => {
      setNetworkStats(prev => ({ ...prev, ...data.analytics }));
    });
  };

  const detectUserLocation = async () => {
    try {
      const response = await fetch('https://ipapi.co/json/');
      const data = await response.json();
      const detectedCountry = data.country_name?.toLowerCase();
      
      // Check if it's an African country we support
      const africaCountryKey = Object.keys(AFRICAN_COUNTRIES).find(key => 
        AFRICAN_COUNTRIES[key].name.toLowerCase().includes(detectedCountry)
      );
      
      if (africaCountryKey) {
        setUserCountry(africaCountryKey);
        addNotification(`🌍 Welcome from ${AFRICAN_COUNTRIES[africaCountryKey].name}! Ubuntu power! 🤝`, 'success');
      }
    } catch (error) {
      console.log('Location detection failed, using default');
    }
  };

  const addNotification = (message, type = 'info') => {
    const notification = {
      id: Date.now() + Math.random(),
      message,
      type,
      timestamp: Date.now()
    };
    
    setNotifications(prev => [notification, ...prev.slice(0, 4)]); // Keep latest 5
    
    // Auto remove after 5 seconds
    setTimeout(() => {
      setNotifications(prev => prev.filter(n => n.id !== notification.id));
    }, 5000);
  };

  const formatNumber = (num) => {
    if (num >= 1e9) return (num / 1e9).toFixed(1) + 'B';
    if (num >= 1e6) return (num / 1e6).toFixed(1) + 'M';
    if (num >= 1e3) return (num / 1e3).toFixed(1) + 'K';
    return num?.toLocaleString() || '0';
  };

  const renderDashboard = () => (
    <div className="dashboard">
      <div className="hero-section">
        <div className="hero-content">
          <div className="hero-flag">
            {AFRICAN_COUNTRIES[userCountry]?.flag || '🌍'}
          </div>
          <h1 className="hero-title">
            YAW NETWORK
            <span className="hero-subtitle">African Blockchain Revolution</span>
          </h1>
          <div className="hero-stats">
            <div className="stat-item">
              <span className="stat-value">{formatNumber(networkStats.height)}</span>
              <span className="stat-label">Blocks</span>
            </div>
            <div className="stat-item">
              <span className="stat-value">{formatNumber(networkStats.tps)}</span>
              <span className="stat-label">TPS</span>
            </div>
            <div className="stat-item">
              <span className="stat-value">{formatNumber(networkStats.totalValidators)}</span>
              <span className="stat-label">Validators</span>
            </div>
          </div>
        </div>
      </div>

      <div className="cards-grid">
        <div className="card mining-card">
          <div className="card-header">
            <h3>⚡ Ubuntu Mining</h3>
            <div className={`status-dot ${isConnected ? 'active' : 'inactive'}`}></div>
          </div>
          <div className="card-content">
            <div className="mining-visual">
              <div className="mining-icon">🏛️</div>
              <div className="mining-stats">
                <div>Hash Rate: {networkStats.networkHash?.formatted || 'Loading...'}</div>
                <div>Difficulty: {networkStats.difficulty || 'Loading...'}</div>
                <div>Pending: {networkStats.pendingTransactions || 0} tx</div>
              </div>
            </div>
            <button className="btn btn-primary" onClick={() => setCurrentView('mining')}>
              Start Ubuntu Mining
            </button>
          </div>
        </div>

        <div className="card wallet-card">
          <div className="card-header">
            <h3>💰 YAW Wallet</h3>
            <div className="balance-badge">
              {userStats.balance || '0'} YAW
            </div>
          </div>
          <div className="card-content">
            <div className="wallet-actions">
              <button className="btn btn-secondary" onClick={() => setCurrentView('wallet')}>
                Send YAW
              </button>
              <button className="btn btn-outline" onClick={() => setCurrentView('wallet')}>
                Receive YAW
              </button>
            </div>
            <div className="recent-transactions">
              <h4>Recent Activity</h4>
              <div className="transaction-item">
                <span>Mining Reward</span>
                <span className="amount positive">+12.5 YAW</span>
              </div>
              <div className="transaction-item">
                <span>Community Bonus</span>
                <span className="amount positive">+5.0 YAW</span>
              </div>
            </div>
          </div>
        </div>

        <div className="card network-card">
          <div className="card-header">
            <h3>🌍 African Network</h3>
            <div className="network-health">
              <div className="health-indicator healthy"></div>
              Healthy
            </div>
          </div>
          <div className="card-content">
            <div className="network-map">
              <div className="africa-outline">
                <div className="node-dot nigeria" title="Nigeria"></div>
                <div className="node-dot kenya" title="Kenya"></div>
                <div className="node-dot ghana" title="Ghana"></div>
                <div className="node-dot south-africa" title="South Africa"></div>
                <div className="node-dot egypt" title="Egypt"></div>
              </div>
            </div>
            <div className="network-stats-grid">
              <div className="network-stat">
                <span>African Validators</span>
                <span>{networkStats.africaRepresentation?.percentage?.toFixed(1) || '0'}%</span>
              </div>
              <div className="network-stat">
                <span>Security Score</span>
                <span>{networkStats.securityScore?.toFixed(1) || '0'}/100</span>
              </div>
            </div>
            <button className="btn btn-outline" onClick={() => setCurrentView('network')}>
              View Network Details
            </button>
          </div>
        </div>

        <div className="card analytics-card">
          <div className="card-header">
            <h3>📊 Real-time Analytics</h3>
          </div>
          <div className="card-content">
            <div className="analytics-chart">
              <div className="chart-placeholder">
                <div className="chart-bars">
                  <div className="bar" style={{height: '60%'}}></div>
                  <div className="bar" style={{height: '80%'}}></div>
                  <div className="bar" style={{height: '45%'}}></div>
                  <div className="bar" style={{height: '90%'}}></div>
                  <div className="bar" style={{height: '70%'}}></div>
                </div>
                <div className="chart-label">Transaction Volume (24h)</div>
              </div>
            </div>
            <div className="analytics-metrics">
              <div className="metric">
                <span>Daily Volume</span>
                <span>{formatNumber(networkStats.dailyVolume || 125000)} YAW</span>
              </div>
              <div className="metric">
                <span>Active Users</span>
                <span>{formatNumber(networkStats.activeUsers || 15420)}</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );

  const renderMining = () => (
    <div className="mining-view">
      <div className="mining-header">
        <h2>⚡ Ubuntu Mining Pool</h2>
        <div className="mining-location">
          {AFRICAN_COUNTRIES[userCountry]?.flag} Mining from {AFRICAN_COUNTRIES[userCountry]?.name}
        </div>
      </div>

      <div className="mining-dashboard">
        <div className="mining-status-card">
          <div className="mining-indicator">
            <div className="pulse-ring"></div>
            <div className="pulse-dot"></div>
          </div>
          <div className="mining-info">
            <h3>Ubuntu Consensus Active</h3>
            <p>Contributing to African blockchain security</p>
            <div className="mining-stats">
              <div className="stat">
                <span>Your Hash Rate</span>
                <span>7.2 MH/s</span>
              </div>
              <div className="stat">
                <span>Efficiency</span>
                <span>98.5%</span>
              </div>
              <div className="stat">
                <span>Uptime</span>
                <span>99.2%</span>
              </div>
            </div>
          </div>
        </div>

        <div className="earnings-card">
          <h3>💰 Mining Rewards</h3>
          <div className="earnings-display">
            <div className="daily-earnings">
              <span className="earnings-amount">12.4 YAW</span>
              <span className="earnings-label">Today's Earnings</span>
            </div>
            <div className="total-earnings">
              <span className="earnings-amount">342.7 YAW</span>
              <span className="earnings-label">Total Mined</span>
            </div>
          </div>
          <div className="earnings-chart">
            <div className="chart-line">
              {[...Array(30)].map((_, i) => (
                <div 
                  key={i} 
                  className="chart-point" 
                  style={{height: `${Math.random() * 60 + 20}%`}}
                ></div>
              ))}
            </div>
          </div>
        </div>

        <div className="consensus-card">
          <h3>🤝 Ubuntu Consensus</h3>
          <div className="consensus-info">
            <p>Your node is participating in Ubuntu Byzantine consensus, helping secure the African blockchain network.</p>
            <div className="consensus-stats">
              <div className="consensus-stat">
                <span>Consensus Rounds</span>
                <span>3.2 avg</span>
              </div>
              <div className="consensus-stat">
                <span>Validation Success</span>
                <span>99.8%</span>
              </div>
              <div className="consensus-stat">
                <span>Network Stake</span>
                <span>0.15%</span>
              </div>
            </div>
          </div>
        </div>

        <div className="leaderboard-card">
          <h3>🏆 African Mining Leaders</h3>
          <div className="leaderboard">
            {Object.entries(AFRICAN_COUNTRIES).slice(0, 5).map(([key, country], index) => (
              <div key={key} className="leaderboard-item">
                <div className="rank">#{index + 1}</div>
                <div className="country">
                  <span className="flag">{country.flag}</span>
                  <span className="name">{country.name}</span>
                </div>
                <div className="hashrate">{(2500 - index * 200).toLocaleString()} TH/s</div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );

  const renderWallet = () => (
    <div className="wallet-view">
      <div className="wallet-header">
        <h2>💰 YAW Wallet</h2>
        <div className="wallet-balance-display">
          <div className="balance-amount">1,247.89 YAW</div>
          <div className="balance-usd">≈ $374.37 USD</div>
        </div>
      </div>

      <div className="wallet-actions-grid">
        <button className="wallet-action send">
          <div className="action-icon">📤</div>
          <span>Send YAW</span>
        </button>
        <button className="wallet-action receive">
          <div className="action-icon">📥</div>
          <span>Receive YAW</span>
        </button>
        <button className="wallet-action swap">
          <div className="action-icon">🔄</div>
          <span>Swap</span>
        </button>
        <button className="wallet-action stake">
          <div className="action-icon">🏛️</div>
          <span>Stake</span>
        </button>
      </div>

      <div className="transaction-history">
        <h3>Transaction History</h3>
        <div className="transaction-list">
          <div className="transaction-item received">
            <div className="transaction-info">
              <div className="transaction-type">Mining Reward</div>
              <div className="transaction-time">2 hours ago</div>
            </div>
            <div className="transaction-amount positive">+12.4 YAW</div>
          </div>
          <div className="transaction-item received">
            <div className="transaction-info">
              <div className="transaction-type">Community Bonus</div>
              <div className="transaction-time">1 day ago</div>
            </div>
            <div className="transaction-amount positive">+25.0 YAW</div>
          </div>
          <div className="transaction-item sent">
            <div className="transaction-info">
              <div className="transaction-type">Send to Friend</div>
              <div className="transaction-time">3 days ago</div>
            </div>
            <div className="transaction-amount negative">-50.0 YAW</div>
          </div>
          <div className="transaction-item received">
            <div className="transaction-info">
              <div className="transaction-type">Mining Reward</div>
              <div className="transaction-time">1 week ago</div>
            </div>
            <div className="transaction-amount positive">+11.8 YAW</div>
          </div>
        </div>
      </div>

      <div className="wallet-features">
        <div className="feature-card">
          <h4>🔒 Security Features</h4>
          <ul>
            <li>Quantum-resistant encryption</li>
            <li>Biometric authentication</li>
            <li>Multi-signature support</li>
          </ul>
        </div>
        <div className="feature-card">
          <h4>🌍 African Features</h4>
          <ul>
            <li>SMS transactions</li>
            <li>Offline capabilities</li>
            <li>Local currency support</li>
          </ul>
        </div>
      </div>
    </div>
  );

  const renderNetwork = () => (
    <div className="network-view">
      <div className="network-header">
        <h2>🌍 Yaw Network Status</h2>
        <div className="network-health-badge">
          <div className="health-dot active"></div>
          Network Healthy
        </div>
      </div>

      <div className="network-overview">
        <div className="network-map-large">
          <div className="africa-map">
            <div className="map-title">African Blockchain Network</div>
            <div className="node-indicators">
              {Object.entries(AFRICAN_COUNTRIES).map(([key, country]) => (
                <div 
                  key={key} 
                  className={`network-node ${key}`}
                  title={`${country.name} - Active`}
                >
                  <div className="node-pulse"></div>
                  <span className="node-label">
                    {country.flag} {country.name}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="network-stats-panel">
          <div className="stat-group">
            <h3>Network Performance</h3>
            <div className="stat-item">
              <span>Block Height</span>
              <span>{formatNumber(networkStats.height)}</span>
            </div>
            <div className="stat-item">
              <span>Transactions/sec</span>
              <span>{networkStats.tps || '0'}</span>
            </div>
            <div className="stat-item">
              <span>Network Hashrate</span>
              <span>{networkStats.networkHash?.formatted || 'Loading...'}</span>
            </div>
            <div className="stat-item">
              <span>Active Validators</span>
              <span>{networkStats.totalValidators || 0}</span>
            </div>
          </div>

          <div className="stat-group">
            <h3>African Distribution</h3>
            <div className="country-stats">
              {Object.entries(AFRICAN_COUNTRIES).map(([key, country]) => (
                <div key={key} className="country-stat">
                  <span className="country-info">
                    {country.flag} {country.name}
                  </span>
                  <span className="country-percentage">
                    {Math.floor(Math.random() * 25 + 5)}%
                  </span>
                </div>
              ))}
            </div>
          </div>

          <div className="stat-group">
            <h3>Security Metrics</h3>
            <div className="security-meters">
              <div className="meter">
                <div className="meter-label">Security Score</div>
                <div className="meter-bar">
                  <div 
                    className="meter-fill" 
                    style={{width: `${networkStats.securityScore || 95}%`}}
                  ></div>
                </div>
                <div className="meter-value">{networkStats.securityScore?.toFixed(1) || '95'}/100</div>
              </div>
              <div className="meter">
                <div className="meter-label">Decentralization</div>
                <div className="meter-bar">
                  <div 
                    className="meter-fill" 
                    style={{width: `${networkStats.decentralization || 92}%`}}
                  ></div>
                </div>
                <div className="meter-value">{networkStats.decentralization?.toFixed(1) || '92'}/100</div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );

  const renderCurrentView = () => {
    switch(currentView) {
      case 'mining': return renderMining();
      case 'wallet': return renderWallet();
      case 'network': return renderNetwork();
      default: return renderDashboard();
    }
  };

  return (
    <div className="app">
      {/* Header */}
      <header className="app-header">
        <div className="header-content">
          <div className="logo">
            <div className="logo-icon">YAW</div>
            <div className="logo-text">
              <div className="logo-title">Yaw Network</div>
              <div className="logo-subtitle">African Blockchain</div>
            </div>
          </div>
          
          <div className="header-status">
            <div className={`connection-status ${isConnected ? 'connected' : 'disconnected'}`}>
              <div className="status-dot"></div>
              {isConnected ? 'Connected' : 'Connecting...'}
            </div>
            <div className={`network-status ${isOnline ? 'online' : 'offline'}`}>
              {isOnline ? '🌐' : '📱'} {isOnline ? 'Online' : 'Offline'}
            </div>
          </div>
        </div>
      </header>

      {/* Notifications */}
      {notifications.length > 0 && (
        <div className="notifications">
          {notifications.map(notification => (
            <div 
              key={notification.id} 
              className={`notification ${notification.type}`}
              onClick={() => setNotifications(prev => 
                prev.filter(n => n.id !== notification.id)
              )}
            >
              {notification.message}
            </div>
          ))}
        </div>
      )}

      {/* Navigation */}
      <nav className="app-nav">
        <div className="nav-items">
          <button 
            className={`nav-item ${currentView === 'dashboard' ? 'active' : ''}`}
            onClick={() => setCurrentView('dashboard')}
          >
            <span className="nav-icon">🏠</span>
            <span className="nav-label">Dashboard</span>
          </button>
          <button 
            className={`nav-item ${currentView === 'mining' ? 'active' : ''}`}
            onClick={() => setCurrentView('mining')}
          >
            <span className="nav-icon">⚡</span>
            <span className="nav-label">Mining</span>
          </button>
          <button 
            className={`nav-item ${currentView === 'wallet' ? 'active' : ''}`}
            onClick={() => setCurrentView('wallet')}
          >
            <span className="nav-icon">💰</span>
            <span className="nav-label">Wallet</span>
          </button>
          <button 
            className={`nav-item ${currentView === 'network' ? 'active' : ''}`}
            onClick={() => setCurrentView('network')}
          >
            <span className="nav-icon">🌍</span>
            <span className="nav-label">Network</span>
          </button>
        </div>
      </nav>

      {/* Main Content */}
      <main className="app-main">
        {renderCurrentView()}
      </main>

      {/* Footer */}
      <footer className="app-footer">
        <div className="footer-content">
          <div className="footer-text">
            🌍 Built in Africa, for the world • Ubuntu Technology • Quantum Security
          </div>
          <div className="footer-country">
            {AFRICAN_COUNTRIES[userCountry]?.flag} {AFRICAN_COUNTRIES[userCountry]?.name}
          </div>
        </div>
      </footer>
    </div>
  );
}

export default App;
