import React, { useState, useEffect } from 'react';
import { Shield, LayoutDashboard, Search, History, FileText, Wifi, WifiOff } from 'lucide-react';
import { checkHealth } from '../../api/guardianApi';

const Sidebar = ({ activeTab, setActiveTab }) => {
  const [apiConnected, setApiConnected] = useState(null);

  // Monitor backend connectivity status
  useEffect(() => {
    const verifyConnection = async () => {
      const isConnected = await checkHealth();
      setApiConnected(isConnected);
    };

    // Run immediately and then every 10 seconds
    verifyConnection();
    const interval = setInterval(verifyConnection, 10000);

    return () => clearInterval(interval);
  }, []);

  const navItems = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { id: 'analyzer', label: 'URL Analyzer', icon: Search },
    { id: 'history', label: 'Scan History', icon: History },
    { id: 'reports', label: 'Reports', icon: FileText }
  ];

  return (
    <aside className="sidebar">
      <div className="sidebar-logo">
        <Shield className="sidebar-logo-icon" size={24} />
        <span className="sidebar-logo-text">URL GUARDIAN</span>
      </div>

      <nav className="sidebar-menu">
        {navItems.map((item) => {
          const IconComponent = item.icon;
          return (
            <button
              key={item.id}
              onClick={() => setActiveTab(item.id)}
              className={`sidebar-link ${activeTab === item.id ? 'active' : ''}`}
            >
              <IconComponent className="sidebar-link-icon" />
              <span>{item.label}</span>
            </button>
          );
        })}
      </nav>

      <div className="sidebar-footer">
        <div className="api-status">
          {apiConnected === null ? (
            <>
              <div className="status-indicator" style={{ backgroundColor: '#6b7280' }} />
              <span>Checking API...</span>
            </>
          ) : apiConnected ? (
            <>
              <Wifi size={14} className="status-indicator-icon" style={{ color: '#10b981' }} />
              <div className="status-indicator connected" />
              <span>API Connected</span>
            </>
          ) : (
            <>
              <WifiOff size={14} className="status-indicator-icon" style={{ color: '#ef4444' }} />
              <div className="status-indicator disconnected" />
              <span>API Offline</span>
            </>
          )}
        </div>
      </div>
    </aside>
  );
};

export default Sidebar;
