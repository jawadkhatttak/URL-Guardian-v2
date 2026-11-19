import { useState, useEffect } from 'react';

const HISTORY_KEY = 'url_guardian_scan_history';

export const useScanHistory = () => {
  const [history, setHistory] = useState([]);

  // Load history on mount
  useEffect(() => {
    const stored = localStorage.getItem(HISTORY_KEY);
    if (stored) {
      try {
        setHistory(JSON.parse(stored));
      } catch (e) {
        console.error('Failed to parse scan history', e);
        setHistory([]);
      }
    }
  }, []);

  // Save history helper
  const saveHistory = (newHistory) => {
    setHistory(newHistory);
    localStorage.setItem(HISTORY_KEY, JSON.stringify(newHistory));
  };

  /**
   * Add a new scan to history. If the URL already exists, we can either
   * replace the old scan with this new one (bringing it to the top) or keep both.
   * We will update the existing entry if it's the same URL to prevent clutter,
   * but preserve its "isFavorite" status.
   */
  const addScan = (scanData) => {
    const cleanUrl = scanData.url.trim().toLowerCase();
    
    // Check if URL already exists
    const existingIndex = history.findIndex(
      (item) => item.url.trim().toLowerCase() === cleanUrl
    );

    let isFavorite = false;
    let newHistory = [...history];

    if (existingIndex !== -1) {
      // Preserve favorite status
      isFavorite = history[existingIndex].isFavorite || false;
      // Remove the old one to move it to the top
      newHistory.splice(existingIndex, 1);
    }

    const newEntry = {
      id: `${scanData.url}_${Date.now()}`,
      url: scanData.url,
      timestamp: scanData.timestamp || new Date().toISOString(),
      score: scanData.score,
      risk: scanData.risk,
      isFavorite,
      fullData: scanData
    };

    newHistory.unshift(newEntry); // Add to the top
    saveHistory(newHistory);
    return newEntry;
  };

  /**
   * Toggle the favorite status of a scan by ID.
   */
  const toggleFavorite = (id) => {
    const newHistory = history.map((item) => {
      if (item.id === id) {
        return { ...item, isFavorite: !item.isFavorite };
      }
      return item;
    });
    saveHistory(newHistory);
  };

  /**
   * Delete an individual scan by ID.
   */
  const deleteScan = (id) => {
    const newHistory = history.filter((item) => item.id !== id);
    saveHistory(newHistory);
  };

  /**
   * Clear the entire history.
   */
  const clearHistory = () => {
    saveHistory([]);
  };

  return {
    history,
    addScan,
    toggleFavorite,
    deleteScan,
    clearHistory
  };
};
