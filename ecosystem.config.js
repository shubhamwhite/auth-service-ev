module.exports = {
  apps: [
    {
      name: 'auth-service', // Name of the app in PM2
      script: './index.js', // Path to your entry point script (server.js)
      instances: 1, // Number of instances to run (use 'max' to run as many as CPU cores)
      exec_mode: 'fork', // Cluster mode for better performance (recommended for production)
      watch: false, // Watch for file changes (set to true if you want to restart on file change)
      env: {
        NODE_ENV: 'development', // Environment variables for development
        PORT: 3004 // Example environment variable
      },
      env_production: {
        NODE_ENV: 'production', // Environment variables for production
        PORT: 3004
      }
    }
  ]
}
