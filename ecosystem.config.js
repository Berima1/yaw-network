// YAW NETWORK - PM2 ECOSYSTEM CONFIGURATION
// Ubuntu-powered process management

module.exports = {
  apps: [{
    name: 'yaw-network-api',
    script: 'server.js',
    instances: 'max', // Use all CPU cores
    exec_mode: 'cluster',
    
    // Ubuntu environment
    env: {
      NODE_ENV: 'production',
      PORT: 3000,
      BLOCKCHAIN_NETWORK: 'african-mainnet',
      CONSENSUS_ALGORITHM: 'ubuntu-byzantine',
      UBUNTU_MESSAGE: 'I am because we are',
      LOG_LEVEL: 'info'
    },
    
    // Performance monitoring
    monitoring: true,
    pmx: true,
    
    // Auto restart configuration
    autorestart: true,
    watch: false,
    max_memory_restart: '1G',
    restart_delay: 4000,
    
    // Logging
    log_file: './logs/yaw-network.log',
    out_file: './logs/yaw-network-out.log',
    error_file: './logs/yaw-network-error.log',
    log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
    merge_logs: true,
    
    // Process management
    kill_timeout: 5000,
    wait_ready: true,
    listen_timeout: 10000,
    
    // Ubuntu-specific settings
    node_args: '--max-old-space-size=1024',
    
    // Health monitoring
    health_check_grace_period: 10000,
    health_check_fatal_exceptions: false
  }],

  // Deployment configuration
  deploy: {
    production: {
      user: 'ubuntu',
      host: 'your-server.com',
      ref: 'origin/main',
      repo: 'https://github.com/your-username/yaw-network.git',
      path: '/var/www/yaw-network',
      'pre-deploy-local': '',
      'post-deploy': 'npm install && pm2 reload ecosystem.config.js --env production',
      'pre-setup': '',
      'ssh_options': 'ForwardAgent=yes'
    }
  }
};