import React, { useState, useEffect, useRef } from 'react';
import { Shield, AlertTriangle, CheckCircle, XCircle, Terminal, Activity, Lock, Globe, Server, Folder } from 'lucide-react';

function App() {
  const [domain, setDomain] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [logs, setLogs] = useState([]);
  const [results, setResults] = useState(null);
  const logsEndRef = useRef(null);
  const wsRef = useRef(null);

  const startScan = () => {
    if (!domain) return;
    
    setIsScanning(true);
    setLogs([]);
    setResults(null);
    
    // Connect to WebSocket directly to backend to avoid proxy issues
    const wsUrl = `ws://localhost:8000/ws/scan/${domain}`;
    
    console.log(`Connecting to WebSocket: ${wsUrl}`);
    
    const ws = new WebSocket(wsUrl);
    wsRef.current = ws;

    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      
      if (data.type === 'log') {
        setLogs(prev => [...prev, data]);
      } else if (data.type === 'complete') {
        setResults(data.results);
        setIsScanning(false);
        ws.close();
      } else if (data.type === 'error') {
        setLogs(prev => [...prev, { message: `Error: ${data.message}`, level: 'ERROR' }]);
        setIsScanning(false);
        ws.close();
      }
    };

    ws.onclose = () => {
      if (isScanning) {
        // If closed unexpectedly
        // setIsScanning(false);
      }
    };

    ws.onerror = (error) => {
      console.error('WebSocket error:', error);
      setLogs(prev => [...prev, { message: `Ошибка подключения к ${wsUrl}`, level: 'ERROR' }]);
      setIsScanning(false);
    };
  };

  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  return (
    <div className="min-h-screen bg-dark text-gray-200 p-8">
      <div className="max-w-6xl mx-auto space-y-8">
        
        {/* Header */}
        <div className="text-center space-y-4">
          <h1 className="text-5xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-cyan to-primary tracking-tight">
            Ultimate Security Analyzer
          </h1>
          <p className="text-gray-400 text-lg">Advanced vulnerability scanning and security assessment tool</p>
        </div>

        {/* Search Bar */}
        <div className="flex gap-4 max-w-2xl mx-auto">
          <input
            type="text"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            placeholder="Enter domain (e.g., example.com)"
            className="flex-1 bg-darker border border-gray-700 rounded-lg px-6 py-4 text-lg focus:outline-none focus:border-cyan transition-colors"
            onKeyDown={(e) => e.key === 'Enter' && startScan()}
            disabled={isScanning}
          />
          <button
            onClick={startScan}
            disabled={isScanning || !domain}
            className={`px-8 py-4 rounded-lg font-bold text-lg transition-all transform hover:scale-105 ${
              isScanning 
                ? 'bg-gray-700 cursor-not-allowed' 
                : 'bg-gradient-to-r from-primary to-cyan text-white hover:shadow-lg hover:shadow-cyan/20'
            }`}
          >
            {isScanning ? 'Сканирование...' : 'Начать сканирование'}
          </button>
        </div>

        {/* Dashboard Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          
          {/* Left Column: Live Logs */}
          <div className="lg:col-span-2 bg-darker border border-gray-800 rounded-xl p-6 h-[600px] flex flex-col">
            <div className="flex items-center gap-2 mb-4 text-cyan border-b border-gray-800 pb-4">
              <Terminal size={20} />
              <h2 className="font-mono text-lg">Журнал выполнения</h2>
            </div>
            <div className="flex-1 overflow-y-auto font-mono text-sm space-y-2 pr-2">
              {logs.length === 0 && !isScanning && (
                <div className="text-gray-600 text-center mt-20">
                  Готов к сканированию. Введите домен для начала.
                </div>
              )}
              {logs.map((log, index) => (
                <div key={index} className={`break-words ${
                  log.level === 'ERROR' ? 'text-danger' :
                  log.level === 'WARNING' ? 'text-warning' :
                  log.level === 'SUCCESS' ? 'text-success' :
                  log.level === 'DEBUG' ? 'text-gray-500' :
                  'text-gray-300'
                }`}>
                  <span className="opacity-50 mr-2">[{new Date().toLocaleTimeString()}]</span>
                  {log.message}
                </div>
              ))}
              <div ref={logsEndRef} />
            </div>
          </div>

          {/* Right Column: Results Summary */}
          <div className="space-y-6">
            
            {/* Security Score Card */}
            <div className="bg-darker border border-gray-800 rounded-xl p-6 relative overflow-hidden">
              <div className="absolute top-0 right-0 p-4 opacity-10">
                <Shield size={100} />
              </div>
              <h2 className="text-gray-400 mb-2">Оценка безопасности</h2>
              <div className="flex items-end gap-2">
                <span className={`text-6xl font-bold ${
                  !results ? 'text-gray-600' :
                  results.security_score >= 90 ? 'text-success' :
                  results.security_score >= 70 ? 'text-warning' :
                  'text-danger'
                }`}>
                  {results ? results.security_score : '--'}
                </span>
                <span className="text-xl text-gray-500 mb-2">/100</span>
              </div>
              {results && (
                <div className={`mt-4 inline-block px-3 py-1 rounded-full text-sm font-bold ${
                  results.risk_level === 'SECURE' || results.risk_level === 'LOW' ? 'bg-success/20 text-success' :
                  results.risk_level === 'MEDIUM' ? 'bg-warning/20 text-warning' :
                  'bg-danger/20 text-danger'
                }`}>
                  {results.risk_level} RISK
                </div>
              )}
            </div>

            {/* Stats Grid */}
            <div className="grid grid-cols-2 gap-4">
              <div className="bg-darker border border-gray-800 rounded-xl p-4">
                <div className="text-gray-400 text-sm mb-1 flex items-center gap-2">
                  <AlertTriangle size={14} /> Critical
                </div>
                <div className="text-2xl font-bold text-danger">
                  {results ? results.critical_vulns.length : '-'}
                </div>
              </div>
              <div className="bg-darker border border-gray-800 rounded-xl p-4">
                <div className="text-gray-400 text-sm mb-1 flex items-center gap-2">
                  <Activity size={14} /> Проблемы
                </div>
                <div className="text-2xl font-bold text-warning">
                  {results ? results.vulnerabilities.length : '-'}
                </div>
              </div>
              <div className="bg-darker border border-gray-800 rounded-xl p-4">
                <div className="text-gray-400 text-sm mb-1 flex items-center gap-2">
                  <Server size={14} /> Порты
                </div>
                <div className="text-2xl font-bold text-cyan">
                  {results ? results.ports.filter(p => p.state === 'open').length : '-'}
                </div>
              </div>
              <div className="bg-darker border border-gray-800 rounded-xl p-4">
                <div className="text-gray-400 text-sm mb-1 flex items-center gap-2">
                  <Globe size={14} /> Поддомены
                </div>
                <div className="text-2xl font-bold text-primary">
                  {results ? results.subdomains.length : '-'}
                </div>
              </div>
            </div>

            {/* Vulnerability List (Mini) */}
            {results && results.critical_vulns.length > 0 && (
              <div className="bg-darker border border-gray-800 rounded-xl p-6">
                <h3 className="text-danger font-bold mb-4 flex items-center gap-2">
                  <AlertTriangle size={18} />
                  Critical Findings
                </h3>
                <ul className="space-y-2">
                  {results.critical_vulns.map((vuln, i) => (
                    <li key={i} className="text-sm text-gray-300 flex items-start gap-2">
                      <span className="text-danger mt-1">•</span>
                      {vuln}
                    </li>
                  ))}
                </ul>
              </div>
            )}

          </div>
        </div>

      </div>
    </div>
  );
}

export default App;
