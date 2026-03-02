#!/usr/bin/env python3
"""
Quick Setup Script for Malware Detector Full Stack
Automates React app setup with API integration
Run: python setup_react_app.py
"""

import os
import subprocess
import sys
import json
from pathlib import Path

class ReactAppSetup:
    def __init__(self):
        self.project_dir = Path.cwd()
        self.components_dir = self.project_dir / "src" / "components"
        self.api_url = "http://localhost:8000"
        
    def print_header(self, msg):
        print("\n" + "="*60)
        print(f"  {msg}")
        print("="*60 + "\n")
    
    def run_command(self, cmd, error_msg="Command failed"):
        """Execute shell command"""
        try:
            subprocess.run(cmd, shell=True, check=True)
            return True
        except subprocess.CalledProcessError as e:
            print(f"❌ {error_msg}: {e}")
            return False
    
    def create_env_file(self):
        """Create .env file with API configuration"""
        self.print_header("Creating Environment Configuration")
        
        env_content = f"""# API Configuration
REACT_APP_API_URL={self.api_url}
REACT_APP_API_TIMEOUT=30000
REACT_APP_ENABLE_DEBUG=false

# Feature flags
REACT_APP_SHOW_ADVANCED_STATS=true
REACT_APP_MAX_BATCH_SIZE=10000
REACT_APP_AUTO_REFRESH_RESULTS=true
"""
        
        env_file = self.project_dir / ".env"
        with open(env_file, 'w') as f:
            f.write(env_content)
        
        print(f"✓ Created {env_file}")
        print(f"✓ API URL: {self.api_url}")
    
    def create_app_jsx(self):
        """Create updated App.jsx"""
        self.print_header("Creating App Component")
        
        app_content = '''import React from 'react';
import MalwareDetector from './components/MalwareDetector';
import './App.css';

function App() {
  return (
    <div className="app-container">
      <MalwareDetector />
    </div>
  );
}

export default App;
'''
        
        app_file = self.project_dir / "src" / "App.jsx"
        with open(app_file, 'w') as f:
            f.write(app_content)
        
        print(f"✓ Created {app_file}")
    
    def create_app_css(self):
        """Create updated App.css"""
        self.print_header("Creating App Styles")
        
        css_content = '''.app-container {
  min-height: 100vh;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  padding: 20px;
}

* {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
}

body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Oxygen',
    'Ubuntu', 'Cantarell', 'Fira Sans', 'Droid Sans', 'Helvetica Neue',
    sans-serif;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
}

code {
  font-family: source-code-pro, Menlo, Monaco, Consolas, 'Courier New', monospace;
}
'''
        
        css_file = self.project_dir / "src" / "App.css"
        with open(css_file, 'w') as f:
            f.write(css_content)
        
        print(f"✓ Created {css_file}")
    
    def create_axios_config(self):
        """Create Axios API client configuration"""
        self.print_header("Creating API Client Configuration")
        
        config_content = '''import axios from 'axios';

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';
const API_TIMEOUT = parseInt(process.env.REACT_APP_API_TIMEOUT) || 30000;

const apiClient = axios.create({
  baseURL: API_BASE_URL,
  timeout: API_TIMEOUT,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor
apiClient.interceptors.request.use(
  (config) => {
    console.log(`[API] ${config.method.toUpperCase()} ${config.url}`);
    return config;
  },
  (error) => Promise.reject(error)
);

// Response interceptor
apiClient.interceptors.response.use(
  (response) => {
    console.log(`[API] Response:`, response.data);
    return response.data;
  },
  (error) => {
    console.error(`[API] Error:`, error.response?.data || error.message);
    return Promise.reject(error);
  }
);

export default apiClient;
'''
        
        config_dir = self.project_dir / "src" / "api"
        config_dir.mkdir(exist_ok=True)
        
        config_file = config_dir / "client.js"
        with open(config_file, 'w') as f:
            f.write(config_content)
        
        print(f"✓ Created API client at {config_file}")
    
    def create_services(self):
        """Create API service functions"""
        self.print_header("Creating API Services")
        
        services_content = '''import apiClient from './client';

export const malwareAPI = {
  // Check if API is healthy
  health: async () => {
    return apiClient.get('/health');
  },

  // Get model information
  modelInfo: async () => {
    return apiClient.get('/model-info');
  },

  // Upload and scan PE file
  predictFile: async (file) => {
    const formData = new FormData();
    formData.append('file', file);
    
    return apiClient.post('/predict-file', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
  },
};

export default malwareAPI;
'''
        
        services_dir = self.project_dir / "src" / "api"
        services_dir.mkdir(exist_ok=True)
        
        services_file = services_dir / "services.js"
        with open(services_file, 'w') as f:
            f.write(services_content)
        
        print(f"✓ Created API services at {services_file}")
    
    def setup(self):
        """Run complete setup"""
        self.print_header("🚀 React App Setup for Malware Detector")
        
        print("Step 1/5: Creating environment configuration...")
        self.create_env_file()
        
        print("\nStep 2/5: Creating app components...")
        self.create_app_jsx()
        
        print("\nStep 3/5: Creating app styles...")
        self.create_app_css()
        
        print("\nStep 4/5: Creating API client...")
        self.create_axios_config()
        
        print("\nStep 5/5: Creating API services...")
        self.create_services()
        
        self.print_header("✅ Setup Complete!")
        
        print(f"""
Next steps:

1. Install dependencies:
   npm install axios

2. (Optional) Copy frontend component if not already present:
   cp ../frontend/MalwareDetector.jsx src/components/
   cp ../frontend/MalwareDetector.css src/components/

3. Start the development server:
   npm start

4. Open browser:
   http://localhost:3000

Your React app is now configured to work with the XGBoost API!

API is available at: {self.api_url}
Check /docs for API documentation

To verify everything is working:
curl {self.api_url}/health
""")

if __name__ == "__main__":
    try:
        setup = ReactAppSetup()
        setup.setup()
    except Exception as e:
        print(f"❌ Setup failed: {e}")
        sys.exit(1)
