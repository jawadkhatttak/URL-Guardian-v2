import React, { useState } from 'react';
import Sidebar from './components/Navigation/Sidebar';
import DashboardPage from './pages/DashboardPage';
import AnalyzerPage from './pages/AnalyzerPage';
import HistoryPage from './pages/HistoryPage';
import ReportsPage from './pages/ReportsPage';
import { useScanHistory } from './hooks/useScanHistory';

function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [analyzerPrefillUrl, setAnalyzerPrefillUrl] = useState('');
  const [openedScan, setOpenedScan] = useState(null);

  // Hook for localStorage scan persistence
  const {
    history,
    addScan,
    toggleFavorite,
    deleteScan,
    clearHistory
  } = useScanHistory();

  // Load a historical scan report inside the Analyzer tab
  const handleReopenScan = (scanItem) => {
    setOpenedScan(scanItem);
    setAnalyzerPrefillUrl(''); // Clear any prefilled input URL
    setActiveTab('analyzer');
  };

  // Prefill a URL and trigger a scan in the Analyzer tab
  const handleNavigateToAnalyzer = (url) => {
    setAnalyzerPrefillUrl(url);
    setOpenedScan(null); // Clear any currently opened static scan report
    setActiveTab('analyzer');
  };

  const renderActivePage = () => {
    switch (activeTab) {
      case 'dashboard':
        return (
          <DashboardPage
            history={history}
            onReopenScan={handleReopenScan}
            onNavigateToAnalyzer={handleNavigateToAnalyzer}
          />
        );
      case 'analyzer':
        return (
          <AnalyzerPage
            initialUrl={analyzerPrefillUrl}
            openedScan={openedScan}
            onClearOpenedScan={() => {
              setOpenedScan(null);
              setAnalyzerPrefillUrl('');
            }}
            history={history}
            onAddScan={addScan}
            onToggleFavorite={toggleFavorite}
          />
        );
      case 'history':
        return (
          <HistoryPage
            history={history}
            onReopenScan={handleReopenScan}
            onToggleFavorite={toggleFavorite}
            onDeleteScan={deleteScan}
            onClearHistory={clearHistory}
          />
        );
      case 'reports':
        return (
          <ReportsPage
            history={history}
            onReopenScan={handleReopenScan}
          />
        );
      default:
        return (
          <DashboardPage
            history={history}
            onReopenScan={handleReopenScan}
            onNavigateToAnalyzer={handleNavigateToAnalyzer}
          />
        );
    }
  };

  return (
    <div className="app-container">
      {/* Navigation Sidebar */}
      <Sidebar activeTab={activeTab} setActiveTab={setActiveTab} />
      
      {/* Content panel */}
      <main className="main-content">
        {renderActivePage()}
      </main>
    </div>
  );
}

export default App;
