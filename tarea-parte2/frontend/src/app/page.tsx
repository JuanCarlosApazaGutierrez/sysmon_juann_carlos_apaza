"use client";

import React, { useState, useCallback, useMemo, useEffect } from 'react';
import { Upload, AlertTriangle, ShieldAlert, Activity, FileJson, X, Download, Moon, Sun, CheckCircle, Database, FileUp, Save, Search, ChevronLeft, ChevronRight, Eye, LayoutDashboard } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, Legend, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';
import { analyzeEvents, SysmonEvent, Alert } from '@/lib/sysmonParser';

const SEVERITY_COLORS = {
  Critical: '#ef4444', 
  High: '#f97316',     
  Medium: '#eab308',   
  Low: '#3b82f6',      
};

const CHART_COLORS = ['#3b82f6', '#f97316', '#10b981', '#8b5cf6', '#ec4899'];

const EVENT_ID_NAMES: Record<number, string> = {
  1: "ProcessCreate",
  2: "FileCreationTimeChanged",
  3: "NetworkConnect",
  4: "SysmonServiceState",
  5: "ProcessTerminated",
  7: "ImageLoaded",
  10: "ProcessAccess",
  11: "FileCreate",
  12: "RegistryCreate/Delete",
  13: "RegistryValueSet",
  14: "RegistryRename",
  15: "FileCreateStreamHash",
  22: "DNSEvent",
  25: "ProcessTampering"
};

export default function Dashboard() {
  const [events, setEvents] = useState<SysmonEvent[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [selectedRawJson, setSelectedRawJson] = useState<any>(null);

  const [theme, setTheme] = useState<'dark' | 'light'>('dark');
  const [filterSeverity, setFilterSeverity] = useState<string>('All');
  const [filterCategory, setFilterCategory] = useState<string>('All');
  
  // Tabs: 'dashboard' (Principal), 'upload' (Cargado de JSON) o 'informes' (Lista Histórica)
  const [activeTab, setActiveTab] = useState<'dashboard' | 'upload' | 'informes'>('dashboard');
  
  const [localObs, setLocalObs] = useState('');
  const [currentFileName, setCurrentFileName] = useState('');

  // Estados de paginación y búsqueda
  const [searchTerm, setSearchTerm] = useState('');
  const [currentPage, setCurrentPage] = useState(1);
  const itemsPerPage = 10;

  const [historyItems, setHistoryItems] = useState<any[]>([]);

  const toggleTheme = () => {
    const newTheme = theme === 'dark' ? 'light' : 'dark';
    setTheme(newTheme);
    document.documentElement.classList.toggle('dark');
  };

  useEffect(() => {
    const loadDefaultFile = async () => {
      try {
        setLoading(true);
        const res = await fetch('/sysmon_enriquecido.json');
        if (res.ok) {
          let json = await res.json();
          if (json && json.Events && Array.isArray(json.Events)) {
            json = json.Events;
          }
          if (Array.isArray(json) && json.length > 0) {
            setEvents(json);
            setCurrentFileName("sysmon_enriquecido.json (Por Defecto)");
            setTimeout(() => {
              const generatedAlerts = analyzeEvents(json);
              setAlerts(generatedAlerts);
              setLoading(false);
            }, 100);
          } else {
            setLoading(false);
          }
        } else {
          setLoading(false);
        }
      } catch (err) {
        console.error("Error cargando default:", err);
        setLoading(false);
      }
    };

    if (events.length === 0) {
      loadDefaultFile();
    }
  }, []);

  useEffect(() => {
    if (activeTab === 'informes') {
      loadHistoryList();
    }
  }, [activeTab]);

  const loadHistoryList = async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await fetch('http://localhost:5000/api/history');
      if (!res.ok) throw new Error("Backend no disponible");
      const historyList = await res.json();
      setHistoryItems(historyList);
      setLoading(false);
    } catch (err: any) {
      setLoading(false);
      setError("Error conectando con el backend: " + err.message);
    }
  };

  const loadReportToDashboard = async (id: number) => {
    try {
      setLoading(true);
      const resDetail = await fetch(`http://localhost:5000/api/history/${id}`);
      if (!resDetail.ok) throw new Error("Error obteniendo detalles del análisis");
      const detail = await resDetail.json();
      
      let json = detail.data;
      if (json.Events && Array.isArray(json.Events)) json = json.Events;
      
      setLocalObs(detail.observations || '');
      setCurrentFileName(detail.filename || 'Archivo Histórico');
      setEvents(json);
      
      setTimeout(() => {
        const generatedAlerts = analyzeEvents(json);
        setAlerts(generatedAlerts);
        setLoading(false);
        setActiveTab('dashboard');
      }, 100);
    } catch (err: any) {
      setLoading(false);
      setError("Error cargando detalle al dashboard: " + err.message);
    }
  };

  const showRawJsonModal = async (id: number) => {
    try {
      setLoading(true);
      const resDetail = await fetch(`http://localhost:5000/api/history/${id}`);
      if (!resDetail.ok) throw new Error("Error obteniendo detalles del análisis");
      const detail = await resDetail.json();
      
      setSelectedRawJson(detail);
      setLoading(false);
    } catch (err: any) {
      setLoading(false);
      alert("Error obteniendo JSON crudo: " + err.message);
    }
  };

  const processFile = (file: File) => {
    if (file.size > 50 * 1024 * 1024) {
      setError("El archivo es demasiado grande (Máximo 50MB).");
      return;
    }
    setLoading(true);
    setError(null);
    setCurrentFileName(file.name);
    setLocalObs('');
    
    const reader = new FileReader();
    reader.onload = (e) => {
      try {
        let json = JSON.parse(e.target?.result as string);
        
        if (json && json.Events && Array.isArray(json.Events)) {
          json = json.Events;
        }

        if (!Array.isArray(json)) throw new Error("JSON debe ser un array de eventos o contener una propiedad 'Events'.");
        
        if (json.length > 0 && (!('EventID' in json[0] || 'Id' in json[0]) || !('TimeCreated' in json[0]))) {
           throw new Error("El JSON no tiene el formato esperado de Sysmon.");
        }
        
        setEvents(json);
        
        setTimeout(() => {
          const generatedAlerts = analyzeEvents(json);
          setAlerts(generatedAlerts);
          setLoading(false);
          setActiveTab('dashboard'); // Redirigir al dashboard al cargar
        }, 100);

      } catch (err: any) {
        setError("Error procesando el archivo JSON: " + err.message);
        setLoading(false);
      }
    };
    reader.onerror = () => {
      setError("Error leyendo el archivo.");
      setLoading(false);
    };
    reader.readAsText(file);
  };

  const handleDrop = useCallback((e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      processFile(e.dataTransfer.files[0]);
    }
  }, []);

  const downloadReport = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(alerts, null, 2));
    const downloadAnchorNode = document.createElement('a');
    downloadAnchorNode.setAttribute("href", dataStr);
    downloadAnchorNode.setAttribute("download", "reporte_alertas_sysmon.json");
    document.body.appendChild(downloadAnchorNode);
    downloadAnchorNode.click();
    downloadAnchorNode.remove();
  };

  const saveToBackend = async () => {
    try {
      setLoading(true);
      const payload = {
        filename: currentFileName,
        total_events: events.length,
        total_alerts: alerts.length,
        observations: localObs,
        raw_json: events
      };
      
      const res = await fetch('http://localhost:5000/api/history', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      
      if (!res.ok) throw new Error("Error al guardar en el servidor");
      alert("Análisis guardado exitosamente en el servidor.");
    } catch(err: any) {
      alert("Error al guardar: " + err.message);
    } finally {
      setLoading(false);
    }
  };

  // Cálculos estadísticos
  const severityCount = useMemo(() => {
    const counts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
    alerts.forEach(a => counts[a.severity]++);
    return [
      { name: 'Critical', value: counts.Critical, color: SEVERITY_COLORS.Critical },
      { name: 'High', value: counts.High, color: SEVERITY_COLORS.High },
      { name: 'Medium', value: counts.Medium, color: SEVERITY_COLORS.Medium },
      { name: 'Low', value: counts.Low, color: SEVERITY_COLORS.Low },
    ].filter(v => v.value > 0);
  }, [alerts]);

  const eventIdCount = useMemo(() => {
    const counts: Record<number, number> = {};
    events.forEach(e => {
      const id = (e as any).EventID || e.Id || 0;
      counts[id] = (counts[id] || 0) + 1;
    });
    return Object.entries(counts).map(([id, count]) => {
      const numId = Number(id);
      const name = EVENT_ID_NAMES[numId] || "Unknown";
      return { EventID: `${id} - ${name}`, Count: count };
    }).sort((a, b) => b.Count - a.Count).slice(0, 10);
  }, [events]);

  const mitreCount = useMemo(() => {
    const counts: Record<string, number> = {};
    alerts.forEach(a => {
      if(a.mitre && a.mitre !== 'N/A') {
         const parts = a.mitre.split('/').map(p => p.trim());
         parts.forEach(p => { counts[p] = (counts[p] || 0) + 1; });
      }
    });
    return Object.entries(counts).map(([name, count]) => ({ name, Count: count })).sort((a,b) => b.Count - a.Count).slice(0, 5);
  }, [alerts]);

  const owaspCount = useMemo(() => {
    const counts: Record<string, number> = {};
    alerts.forEach(a => {
      if(a.owasp && a.owasp !== 'N/A') {
         counts[a.owasp] = (counts[a.owasp] || 0) + 1;
      }
    });
    return Object.entries(counts).map(([name, count]) => ({ name, Count: count })).sort((a,b) => b.Count - a.Count).slice(0, 5);
  }, [alerts]);

  // Filtrado y paginación
  const filteredAlerts = useMemo(() => {
    return alerts.filter(a => {
      const passSeverity = filterSeverity === 'All' || a.severity === filterSeverity;
      let passCategory = true;
      if (filterCategory !== 'All') {
        const rule = a.ruleName.toLowerCase();
        if (filterCategory === 'RDP') passCategory = rule.includes('rdp');
        else if (filterCategory === 'PowerShell') passCategory = rule.includes('powershell');
        else if (filterCategory === 'Registry') passCategory = rule.includes('registry') || rule.includes('service') || rule.includes('ifeo');
      }
      
      const term = searchTerm.toLowerCase();
      const passSearch = term === '' || 
                         a.ruleName.toLowerCase().includes(term) ||
                         a.indicator.toLowerCase().includes(term) ||
                         a.mitre.toLowerCase().includes(term) ||
                         a.owasp.toLowerCase().includes(term);

      return passSeverity && passCategory && passSearch;
    });
  }, [alerts, filterSeverity, filterCategory, searchTerm]);

  const totalPages = Math.max(1, Math.ceil(filteredAlerts.length / itemsPerPage));
  
  const paginatedAlerts = useMemo(() => {
    const start = (currentPage - 1) * itemsPerPage;
    return filteredAlerts.slice(start, start + itemsPerPage);
  }, [filteredAlerts, currentPage]);

  useEffect(() => {
    setCurrentPage(1); // Reset al cambiar filtros
  }, [filterSeverity, filterCategory, searchTerm]);

  return (
    <div className={`min-h-screen bg-background text-foreground transition-colors`}>
      <header className="border-b border-border bg-white dark:bg-slate-950 p-4 flex justify-between items-center sticky top-0 z-[100] shadow-sm">
        <div className="flex items-center gap-3">
          <ShieldAlert className="w-8 h-8 text-blue-500" />
          <h1 className="text-2xl font-bold hidden md:block">Sysmon MITRE & OWASP Analyzer</h1>
          <h1 className="text-xl font-bold md:hidden">Sysmon Analyzer</h1>
        </div>
        
        <div className="flex bg-gray-100 dark:bg-slate-900 border border-border rounded-lg p-1">
          <button 
            className={`flex items-center gap-2 px-3 py-1.5 md:px-4 md:py-2 rounded-md font-medium text-xs md:text-sm transition ${activeTab === 'dashboard' ? 'bg-blue-600 text-white shadow-md' : 'text-gray-500 dark:text-gray-400 hover:text-foreground'}`}
            onClick={() => setActiveTab('dashboard')}
          >
            <Activity className="w-4 h-4" />
            <span className="hidden sm:inline">Dashboard Principal</span>
          </button>
          <button 
            className={`flex items-center gap-2 px-3 py-1.5 md:px-4 md:py-2 rounded-md font-medium text-xs md:text-sm transition ${activeTab === 'upload' ? 'bg-blue-600 text-white shadow-md' : 'text-gray-500 dark:text-gray-400 hover:text-foreground'}`}
            onClick={() => setActiveTab('upload')}
          >
            <FileUp className="w-4 h-4" />
            <span className="hidden sm:inline">Cargado de JSON</span>
          </button>
          <button 
            className={`flex items-center gap-2 px-3 py-1.5 md:px-4 md:py-2 rounded-md font-medium text-xs md:text-sm transition ${activeTab === 'informes' ? 'bg-blue-600 text-white shadow-md' : 'text-gray-500 dark:text-gray-400 hover:text-foreground'}`}
            onClick={() => setActiveTab('informes')}
          >
            <Database className="w-4 h-4" />
            <span className="hidden sm:inline">Informes</span>
          </button>
        </div>

        <button onClick={toggleTheme} className="p-2 rounded-full hover:bg-border transition bg-background border border-border">
          {theme === 'dark' ? <Sun className="w-5 h-5 text-yellow-400" /> : <Moon className="w-5 h-5 text-blue-600" />}
        </button>
      </header>

      {/* Cabecera del Programa */}
      <div className="bg-blue-50 dark:bg-slate-800/80 border-b border-blue-100 dark:border-slate-700 px-6 py-3 text-center md:text-left flex flex-col md:flex-row justify-between items-center text-xs md:text-sm shadow-inner">
         <div className="font-medium text-blue-900 dark:text-blue-300">
           <span className="font-bold">Programa:</span> Maestría en Informática Forense, Ciberseguridad y Auditoría con Aplicación de IA
           <span className="mx-2 hidden xl:inline">|</span>
           <span className="block xl:inline mt-1 xl:mt-0"><span className="font-bold">Módulo:</span> IV - Fundamentos de Ciberseguridad y Protección con IA (UMSA)</span>
         </div>
         <div className="font-medium text-indigo-700 dark:text-indigo-300 mt-2 md:mt-0 bg-white/50 dark:bg-slate-900/50 px-3 py-1 rounded-full border border-indigo-100 dark:border-slate-700 shadow-sm">
           <span className="font-bold">Maestrante:</span> Juan Carlos Apaza Gutierrez
         </div>
      </div>

      <main className="p-4 md:p-6 max-w-7xl mx-auto space-y-6">
        
        {loading && (
          <div className="flex flex-col items-center justify-center py-32 animate-in fade-in">
            <div className="animate-spin rounded-full h-16 w-16 border-b-4 border-blue-500 mb-6"></div>
            <p className="text-lg font-medium animate-pulse text-gray-600 dark:text-gray-300 text-center px-4">
              Procesando datos...
            </p>
          </div>
        )}

        {/* VISTA DE INFORMES HISTÓRICOS */}
        {activeTab === 'informes' && !loading && (
           <div className="animate-in fade-in slide-in-from-bottom-4 duration-500">
             <div className="bg-white dark:bg-slate-900 border border-border rounded-xl shadow-sm overflow-hidden">
                <div className="p-5 border-b border-border flex justify-between items-center bg-gray-50/50 dark:bg-slate-800/50">
                  <h2 className="text-xl font-bold flex items-center gap-2 text-gray-800 dark:text-gray-200">
                    <Database className="w-5 h-5 text-blue-500" />
                    Registro Histórico de Análisis Guardados
                  </h2>
                </div>
                
                {error ? (
                  <div className="p-8 text-center text-red-500 font-medium">Error: {error}</div>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-sm">
                      <thead className="bg-gray-100 dark:bg-slate-800 text-gray-600 dark:text-gray-400">
                        <tr>
                          <th className="px-6 py-4 font-semibold">ID</th>
                          <th className="px-6 py-4 font-semibold">Archivo</th>
                          <th className="px-6 py-4 font-semibold">Fecha de Análisis</th>
                          <th className="px-6 py-4 font-semibold text-center">Eventos / Alertas</th>
                          <th className="px-6 py-4 font-semibold">Observaciones</th>
                          <th className="px-6 py-4 font-semibold text-right">Acciones</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-border">
                        {historyItems.length === 0 ? (
                          <tr><td colSpan={6} className="text-center py-16 text-gray-500 font-medium">No hay informes guardados en la base de datos.</td></tr>
                        ) : historyItems.map(item => (
                          <tr key={item.id} className="hover:bg-gray-50 dark:hover:bg-slate-800/50 transition">
                            <td className="px-6 py-4 font-bold text-gray-500">#{item.id}</td>
                            <td className="px-6 py-4 font-medium text-blue-600 dark:text-blue-400 break-all max-w-xs">{item.filename}</td>
                            <td className="px-6 py-4 text-gray-600 dark:text-gray-300">{new Date(item.created_at).toLocaleString()}</td>
                            <td className="px-6 py-4 text-center">
                              <span className="font-bold text-gray-700 dark:text-gray-200">{item.total_events}</span> / <span className="font-bold text-red-500">{item.total_alerts}</span>
                            </td>
                            <td className="px-6 py-4 text-gray-600 dark:text-gray-400 max-w-xs truncate">{item.observations || '-'}</td>
                            <td className="px-6 py-4 text-right">
                              <div className="flex items-center justify-end gap-2">
                                <button 
                                  onClick={() => showRawJsonModal(item.id)}
                                  className="text-xs bg-gray-100 hover:bg-gray-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-gray-700 dark:text-gray-300 px-3 py-1.5 rounded-md font-semibold transition flex items-center gap-1 border border-border"
                                >
                                  <FileJson className="w-3 h-3" /> Ver JSON
                                </button>
                                <button 
                                  onClick={() => loadReportToDashboard(item.id)}
                                  className="text-xs bg-blue-100 hover:bg-blue-200 dark:bg-blue-900/30 dark:hover:bg-blue-800/50 text-blue-700 dark:text-blue-300 px-3 py-1.5 rounded-md font-semibold transition flex items-center gap-1 border border-blue-200 dark:border-blue-800"
                                >
                                  <LayoutDashboard className="w-3 h-3" /> Ver Dashboard
                                </button>
                              </div>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
             </div>
           </div>
        )}

        {/* VISTA DE CARGA DE JSON */}
        {activeTab === 'upload' && !loading && (
          <div className="animate-in fade-in slide-in-from-bottom-4">
            <div 
              onDragOver={(e) => e.preventDefault()}
              onDrop={handleDrop}
              className="border-2 border-dashed border-border rounded-xl p-8 md:p-12 flex flex-col items-center justify-center text-center hover:bg-gray-50 dark:hover:bg-slate-900/50 transition cursor-pointer mt-4 bg-white dark:bg-slate-900 shadow-sm"
            >
              <Upload className="w-16 h-16 mb-4 text-blue-500" />
              <h2 className="text-2xl font-bold mb-2 text-gray-800 dark:text-gray-200">Cargar archivo JSON de Sysmon</h2>
              <p className="text-gray-500 mb-6 max-w-md">Arrastra tu archivo exportado de Sysmon (ej. sysmon_enriquecido.json) o haz clic para seleccionar. Todo el procesamiento se realiza localmente.</p>
              <input 
                type="file" 
                accept=".json" 
                className="hidden" 
                id="file-upload"
                onChange={(e) => e.target.files && processFile(e.target.files[0])}
              />
              <label htmlFor="file-upload" className="bg-blue-600 hover:bg-blue-700 text-white px-8 py-3 rounded-md cursor-pointer transition font-medium shadow-lg shadow-blue-500/20 text-lg">
                Seleccionar Archivo JSON
              </label>
            </div>
            {error && <p className="text-red-500 mt-6 bg-red-50 dark:bg-red-900/20 p-4 rounded-lg font-medium border border-red-200 dark:border-red-800/50 max-w-2xl mx-auto text-center">{error}</p>}
          </div>
        )}

        {/* VISTA DE DASHBOARD */}
        {activeTab === 'dashboard' && events.length === 0 && !loading && (
          <div className="flex flex-col items-center justify-center py-32 text-gray-500">
            <Activity className="w-16 h-16 mb-4 text-gray-300 dark:text-gray-700" />
            <p className="text-lg">No hay datos cargados en el Dashboard.</p>
            <button onClick={() => setActiveTab('upload')} className="mt-4 text-blue-500 hover:underline">Ir a cargar JSON</button>
          </div>
        )}

        {activeTab === 'dashboard' && events.length > 0 && !loading && (
          <div className="animate-in fade-in slide-in-from-bottom-4 duration-500 space-y-6">
            
            <div className="bg-white dark:bg-slate-900 border border-border p-5 rounded-xl shadow-sm flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
               <div>
                 <h2 className="text-xl font-bold text-blue-600 dark:text-blue-400">Dashboard Activo</h2>
                 <p className="text-gray-500 text-sm mt-1">Archivo procesado: <span className="font-mono text-gray-800 dark:text-gray-200 font-semibold break-all">{currentFileName}</span></p>
               </div>
               
               <div className="flex flex-col sm:flex-row gap-2 items-stretch sm:items-center w-full md:w-auto">
                 <input 
                   type="text" 
                   placeholder="Observaciones para el reporte..." 
                   className="bg-white dark:bg-slate-800 text-gray-900 dark:text-gray-100 border border-border rounded-md px-3 py-2 text-sm w-full sm:w-64 focus:border-blue-500 outline-none transition shadow-sm"
                   value={localObs}
                   onChange={(e) => setLocalObs(e.target.value)}
                 />
                 <button 
                   onClick={saveToBackend}
                   className="bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded-md flex items-center justify-center gap-2 text-sm font-medium transition shadow-md"
                 >
                   <Save className="w-4 h-4" /> Guardar Informe
                 </button>
                 <button 
                   onClick={() => { setEvents([]); setAlerts([]); }}
                   className="bg-gray-200 hover:bg-gray-300 dark:bg-slate-700 dark:hover:bg-slate-600 text-gray-800 dark:text-gray-200 px-4 py-2 rounded-md flex items-center justify-center gap-2 text-sm font-medium transition shadow-sm border border-border"
                 >
                   <X className="w-4 h-4" /> Cerrar
                 </button>
               </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4">
              <div className="bg-white dark:bg-slate-900 border border-border p-5 rounded-xl shadow-sm flex items-center gap-4 hover:shadow-md transition">
                <div className="p-3 bg-blue-100 dark:bg-blue-900/30 rounded-lg text-blue-600 dark:text-blue-400">
                  <Activity className="w-6 h-6" />
                </div>
                <div>
                  <p className="text-sm text-gray-500 font-medium">Total Eventos</p>
                  <p className="text-3xl font-bold">{events.length}</p>
                </div>
              </div>
              <div className="bg-white dark:bg-slate-900 border border-border p-5 rounded-xl shadow-sm flex items-center gap-4 hover:shadow-md transition">
                <div className="p-3 bg-red-100 dark:bg-red-900/30 rounded-lg text-red-600 dark:text-red-400">
                  <AlertTriangle className="w-6 h-6" />
                </div>
                <div>
                  <p className="text-sm text-gray-500 font-medium">Total Alertas</p>
                  <p className="text-3xl font-bold">{alerts.length}</p>
                </div>
              </div>
              <div className="bg-white dark:bg-slate-900 border border-border p-5 rounded-xl shadow-sm flex items-center gap-4 hover:shadow-md transition">
                <div className="p-3 bg-green-100 dark:bg-green-900/30 rounded-lg text-green-600 dark:text-green-400">
                  <CheckCircle className="w-6 h-6" />
                </div>
                <div>
                  <p className="text-sm text-gray-500 font-medium">Tasa de Detección</p>
                  <p className="text-3xl font-bold">{((alerts.length / Math.max(1, events.length)) * 100).toFixed(1)}%</p>
                </div>
              </div>
              <div className="bg-white dark:bg-slate-900 border border-border p-5 rounded-xl shadow-sm flex items-center gap-4 cursor-pointer hover:bg-indigo-50 dark:hover:bg-indigo-900/10 transition group" onClick={downloadReport}>
                <div className="p-3 bg-indigo-100 dark:bg-indigo-900/30 rounded-lg text-indigo-600 dark:text-indigo-400 group-hover:scale-110 transition">
                  <Download className="w-6 h-6" />
                </div>
                <div>
                  <p className="text-sm text-gray-500 font-medium">Exportar Reporte</p>
                  <p className="text-sm font-bold text-indigo-500 group-hover:text-indigo-600">Descargar JSON</p>
                </div>
              </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Gráfico de Severidad */}
              <div className="bg-white dark:bg-slate-900 border border-border p-5 rounded-xl shadow-sm h-80 flex flex-col">
                <h3 className="font-bold mb-4 text-lg text-gray-800 dark:text-gray-200">Distribución por Severidad</h3>
                <div className="flex-1 min-h-0">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie data={severityCount} cx="50%" cy="50%" innerRadius={70} outerRadius={90} paddingAngle={5} dataKey="value" label>
                        {severityCount.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.color} />
                        ))}
                      </Pie>
                      <RechartsTooltip contentStyle={{ backgroundColor: 'var(--card)', borderColor: 'var(--border)', borderRadius: '8px' }} />
                      <Legend verticalAlign="bottom" height={36} />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
              </div>

              {/* Gráfico de Event IDs */}
              <div className="bg-white dark:bg-slate-900 border border-border p-5 rounded-xl shadow-sm h-80 flex flex-col">
                <h3 className="font-bold mb-4 text-lg text-gray-800 dark:text-gray-200">Top 10 Event IDs Observados</h3>
                <div className="flex-1 min-h-0">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={eventIdCount} margin={{ top: 10, right: 10, left: -20, bottom: 20 }}>
                      <CartesianGrid strokeDasharray="3 3" opacity={0.1} vertical={false} />
                      <XAxis dataKey="EventID" axisLine={false} tickLine={false} tick={{ fontSize: 11 }} angle={-25} textAnchor="end" />
                      <YAxis axisLine={false} tickLine={false} tick={{ fontSize: 12 }} />
                      <RechartsTooltip cursor={{fill: 'rgba(255, 255, 255, 0.05)'}} contentStyle={{ backgroundColor: 'var(--card)', borderColor: 'var(--border)', borderRadius: '8px' }} />
                      <Bar dataKey="Count" fill="#3b82f6" radius={[4, 4, 0, 0]} barSize={30} />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </div>
              
              {/* Gráfico de Tácticas MITRE */}
              <div className="bg-white dark:bg-slate-900 border border-border p-5 rounded-xl shadow-sm h-80 flex flex-col">
                <h3 className="font-bold mb-4 text-lg text-gray-800 dark:text-gray-200">Top 5 Tácticas MITRE ATT&CK</h3>
                <div className="flex-1 min-h-0">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={mitreCount} layout="vertical" margin={{ top: 0, right: 20, left: 20, bottom: 0 }}>
                      <CartesianGrid strokeDasharray="3 3" opacity={0.1} horizontal={false} />
                      <XAxis type="number" axisLine={false} tickLine={false} />
                      <YAxis type="category" dataKey="name" axisLine={false} tickLine={false} tick={{ fontSize: 12 }} width={80} />
                      <RechartsTooltip cursor={{fill: 'rgba(255, 255, 255, 0.05)'}} contentStyle={{ backgroundColor: 'var(--card)', borderColor: 'var(--border)', borderRadius: '8px' }} />
                      <Bar dataKey="Count" radius={[0, 4, 4, 0]} barSize={20}>
                        {mitreCount.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={CHART_COLORS[index % CHART_COLORS.length]} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </div>

              {/* Gráfico de Categorías OWASP */}
              <div className="bg-white dark:bg-slate-900 border border-border p-5 rounded-xl shadow-sm h-80 flex flex-col">
                <h3 className="font-bold mb-4 text-lg text-gray-800 dark:text-gray-200">Top Categorías OWASP</h3>
                <div className="flex-1 min-h-0">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie data={owaspCount} cx="50%" cy="50%" innerRadius={40} outerRadius={80} paddingAngle={2} dataKey="Count" label={({name, percent}) => `${name.split(':')[0]} (${(percent * 100).toFixed(0)}%)`} labelLine={false}>
                        {owaspCount.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={CHART_COLORS[(index + 2) % CHART_COLORS.length]} />
                        ))}
                      </Pie>
                      <RechartsTooltip contentStyle={{ backgroundColor: 'var(--card)', borderColor: 'var(--border)', borderRadius: '8px' }} />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
              </div>
            </div>

            {/* TABLA DE ALERTAS */}
            <div className="bg-white dark:bg-slate-900 border border-border rounded-xl shadow-sm overflow-hidden">
              <div className="p-4 md:p-5 border-b border-border flex flex-col xl:flex-row justify-between items-start xl:items-center gap-4 bg-gray-50/50 dark:bg-slate-800/50">
                <h3 className="font-bold text-lg flex items-center gap-2 text-gray-800 dark:text-gray-200 shrink-0">
                  <ShieldAlert className="w-5 h-5 text-red-500" />
                  Registro de Detecciones
                </h3>
                <div className="flex flex-col md:flex-row flex-wrap gap-3 w-full xl:w-auto">
                  
                  {/* Buscador */}
                  <div className="relative w-full md:w-auto flex-1 md:flex-none">
                    <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                      <Search className="h-4 w-4 text-gray-400" />
                    </div>
                    <input
                      type="text"
                      className="bg-white dark:bg-slate-800 border border-border text-gray-900 dark:text-gray-100 rounded-md pl-10 pr-3 py-1.5 text-sm w-full md:w-64 focus:border-blue-500 outline-none transition shadow-sm"
                      placeholder="Buscar por regla, técnica, IoC..."
                      value={searchTerm}
                      onChange={(e) => setSearchTerm(e.target.value)}
                    />
                  </div>

                  <div className="flex items-center gap-2">
                    <span className="text-sm font-medium text-gray-500 hidden sm:inline">Severidad:</span>
                    <select 
                      className="bg-white dark:bg-slate-800 text-gray-900 dark:text-gray-100 border border-border rounded-md px-3 py-1.5 text-sm font-medium outline-none focus:border-blue-500 transition w-full sm:w-auto shadow-sm cursor-pointer"
                      value={filterSeverity}
                      onChange={(e) => setFilterSeverity(e.target.value)}
                    >
                      <option value="All" className="bg-white dark:bg-slate-800 text-gray-900 dark:text-gray-100">Todas</option>
                      <option value="Critical" className="bg-white dark:bg-slate-800 text-gray-900 dark:text-gray-100">Critical</option>
                      <option value="High" className="bg-white dark:bg-slate-800 text-gray-900 dark:text-gray-100">High</option>
                      <option value="Medium" className="bg-white dark:bg-slate-800 text-gray-900 dark:text-gray-100">Medium</option>
                      <option value="Low" className="bg-white dark:bg-slate-800 text-gray-900 dark:text-gray-100">Low</option>
                    </select>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-medium text-gray-500 hidden sm:inline">Categoría:</span>
                    <select 
                      className="bg-white dark:bg-slate-800 text-gray-900 dark:text-gray-100 border border-border rounded-md px-3 py-1.5 text-sm font-medium outline-none focus:border-blue-500 transition w-full sm:w-auto shadow-sm cursor-pointer"
                      value={filterCategory}
                      onChange={(e) => setFilterCategory(e.target.value)}
                    >
                      <option value="All" className="bg-white dark:bg-slate-800 text-gray-900 dark:text-gray-100">Todas</option>
                      <option value="RDP" className="bg-white dark:bg-slate-800 text-gray-900 dark:text-gray-100">RDP</option>
                      <option value="PowerShell" className="bg-white dark:bg-slate-800 text-gray-900 dark:text-gray-100">PowerShell</option>
                      <option value="Registry" className="bg-white dark:bg-slate-800 text-gray-900 dark:text-gray-100">Registry / Services</option>
                    </select>
                  </div>
                </div>
              </div>
              <div className="overflow-x-auto min-h-[400px]">
                <table className="w-full text-left text-sm">
                  <thead className="bg-gray-100 dark:bg-slate-800 text-gray-600 dark:text-gray-400">
                    <tr>
                      <th className="px-6 py-4 font-semibold">Timestamp</th>
                      <th className="px-6 py-4 font-semibold">Severidad</th>
                      <th className="px-6 py-4 font-semibold">Regla / Detección</th>
                      <th className="px-6 py-4 font-semibold">MITRE ATT&CK</th>
                      <th className="px-6 py-4 font-semibold">OWASP</th>
                      <th className="px-6 py-4 font-semibold text-right">Acción</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border">
                    {paginatedAlerts.length === 0 ? (
                      <tr><td colSpan={6} className="text-center py-16 text-gray-500 text-lg font-medium">No se encontraron alertas para los filtros seleccionados.</td></tr>
                    ) : paginatedAlerts.map(alert => (
                      <tr key={alert.id} className="hover:bg-gray-50 dark:hover:bg-slate-800/50 transition">
                        <td className="px-6 py-4 whitespace-nowrap text-gray-600 dark:text-gray-300">{new Date(alert.timestamp).toLocaleString()}</td>
                        <td className="px-6 py-4">
                          <span className={`inline-flex items-center px-2.5 py-1 rounded-md text-xs font-bold border shadow-sm
                            ${alert.severity === 'Critical' ? 'bg-red-100 text-red-800 border-red-200 dark:bg-red-900/30 dark:border-red-900/50 dark:text-red-400' :
                              alert.severity === 'High' ? 'bg-orange-100 text-orange-800 border-orange-200 dark:bg-orange-900/30 dark:border-orange-900/50 dark:text-orange-400' :
                              alert.severity === 'Medium' ? 'bg-yellow-100 text-yellow-800 border-yellow-200 dark:bg-yellow-900/30 dark:border-yellow-900/50 dark:text-yellow-400' :
                              'bg-blue-100 text-blue-800 border-blue-200 dark:bg-blue-900/30 dark:border-blue-900/50 dark:text-blue-400'
                            }`}>
                            {alert.severity}
                          </span>
                        </td>
                        <td className="px-6 py-4 font-semibold text-gray-900 dark:text-gray-100">{alert.ruleName}</td>
                        <td className="px-6 py-4 text-indigo-600 dark:text-indigo-400 font-mono text-xs font-bold">{alert.mitre}</td>
                        <td className="px-6 py-4 text-purple-600 dark:text-purple-400 font-mono text-xs font-bold">{alert.owasp}</td>
                        <td className="px-6 py-4 text-right">
                          <button onClick={() => setSelectedAlert(alert)} className="text-blue-600 dark:text-blue-400 hover:text-blue-800 dark:hover:text-blue-300 hover:underline font-bold transition">Detalles</button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              
              {/* Paginación */}
              {totalPages > 1 && (
                <div className="flex flex-col sm:flex-row justify-between items-center p-4 border-t border-border bg-gray-50/50 dark:bg-slate-800/50 gap-4">
                  <span className="text-sm text-gray-500 font-medium">
                    Mostrando {(currentPage - 1) * itemsPerPage + 1} - {Math.min(currentPage * itemsPerPage, filteredAlerts.length)} de {filteredAlerts.length} alertas
                  </span>
                  <div className="flex items-center gap-2">
                    <button 
                      onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                      disabled={currentPage === 1}
                      className="p-1.5 rounded-md border border-border bg-white dark:bg-slate-800 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-slate-700 disabled:opacity-50 disabled:cursor-not-allowed transition shadow-sm"
                    >
                      <ChevronLeft className="w-5 h-5" />
                    </button>
                    <span className="text-sm font-semibold px-2 text-gray-700 dark:text-gray-300">
                      Página {currentPage} de {totalPages}
                    </span>
                    <button 
                      onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
                      disabled={currentPage === totalPages}
                      className="p-1.5 rounded-md border border-border bg-white dark:bg-slate-800 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-slate-700 disabled:opacity-50 disabled:cursor-not-allowed transition shadow-sm"
                    >
                      <ChevronRight className="w-5 h-5" />
                    </button>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}
      </main>

      {/* MODAL DETALLES DE ALERTA */}
      {selectedAlert && (
        <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/60 backdrop-blur-sm p-4 animate-in fade-in duration-200">
          <div className="bg-white dark:bg-slate-900 border border-border w-full max-w-4xl rounded-2xl shadow-2xl flex flex-col max-h-[90vh] animate-in zoom-in-95 duration-200">
            <div className="p-6 border-b border-border flex justify-between items-start bg-gray-50 dark:bg-slate-800 rounded-t-2xl">
              <div>
                <h3 className="text-2xl font-bold flex items-center gap-3 text-gray-900 dark:text-gray-100">
                  <AlertTriangle className={`w-8 h-8 ${selectedAlert.severity === 'Critical' ? 'text-red-500' : 'text-orange-500'}`} />
                  Detalle de Detección
                </h3>
                <p className="text-base text-gray-600 dark:text-gray-400 mt-2 font-medium">{selectedAlert.ruleName}</p>
              </div>
              <button onClick={() => setSelectedAlert(null)} className="p-2 hover:bg-gray-200 dark:hover:bg-slate-700 rounded-full transition bg-white dark:bg-slate-900 shadow-sm border border-border text-gray-700 dark:text-gray-300">
                <X className="w-5 h-5" />
              </button>
            </div>
            
            <div className="p-6 overflow-y-auto flex-1 space-y-6">
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <div className="bg-white dark:bg-slate-800 border border-border p-4 rounded-xl shadow-sm">
                  <p className="text-xs text-gray-500 dark:text-gray-400 uppercase font-bold mb-1 tracking-wider">Severidad</p>
                  <p className={`font-bold text-lg ${selectedAlert.severity === 'Critical' ? 'text-red-500' : 'text-orange-500'}`}>{selectedAlert.severity}</p>
                </div>
                <div className="bg-white dark:bg-slate-800 border border-border p-4 rounded-xl shadow-sm">
                  <p className="text-xs text-gray-500 dark:text-gray-400 uppercase font-bold mb-1 tracking-wider">Táctica MITRE ATT&CK</p>
                  <p className="font-bold text-lg text-indigo-600 dark:text-indigo-400">{selectedAlert.mitre}</p>
                </div>
                <div className="bg-white dark:bg-slate-800 border border-border p-4 rounded-xl shadow-sm">
                  <p className="text-xs text-gray-500 dark:text-gray-400 uppercase font-bold mb-1 tracking-wider">Mapeo OWASP</p>
                  <p className="font-bold text-lg text-purple-600 dark:text-purple-400">{selectedAlert.owasp}</p>
                </div>
              </div>

              <div>
                <h4 className="font-bold mb-3 flex items-center gap-2 text-lg text-gray-900 dark:text-gray-100">
                  <Activity className="w-5 h-5 text-gray-500" />
                  Indicador de Compromiso (IoC)
                </h4>
                <div className="bg-gray-100 dark:bg-slate-950 p-4 rounded-xl font-mono text-sm break-all border border-border shadow-inner text-red-600 dark:text-red-400 font-medium">
                  {selectedAlert.indicator}
                </div>
              </div>

              <div>
                <h4 className="font-bold mb-3 flex items-center gap-2 text-lg text-gray-900 dark:text-gray-100">
                  <FileJson className="w-5 h-5 text-gray-500" />
                  Payload Original de Sysmon (JSON)
                </h4>
                <pre className="bg-gray-100 dark:bg-slate-950 p-5 rounded-xl overflow-x-auto text-sm text-gray-800 dark:text-gray-300 font-mono border border-border shadow-inner">
                  {JSON.stringify(selectedAlert.rawEvent, null, 2)}
                </pre>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* MODAL VER JSON HISTÓRICO */}
      {selectedRawJson && (
        <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/60 backdrop-blur-sm p-4 animate-in fade-in duration-200">
          <div className="bg-white dark:bg-slate-900 border border-border w-full max-w-5xl rounded-2xl shadow-2xl flex flex-col max-h-[90vh] animate-in zoom-in-95 duration-200">
            <div className="p-6 border-b border-border flex justify-between items-start bg-gray-50 dark:bg-slate-800 rounded-t-2xl">
              <div>
                <h3 className="text-2xl font-bold flex items-center gap-3 text-gray-900 dark:text-gray-100">
                  <FileJson className="w-8 h-8 text-blue-500" />
                  Archivo JSON: {selectedRawJson.filename}
                </h3>
                <p className="text-sm text-gray-600 dark:text-gray-400 mt-1 font-medium">Reporte generado el {new Date(selectedRawJson.created_at).toLocaleString()}</p>
              </div>
              <button onClick={() => setSelectedRawJson(null)} className="p-2 hover:bg-gray-200 dark:hover:bg-slate-700 rounded-full transition bg-white dark:bg-slate-900 shadow-sm border border-border text-gray-700 dark:text-gray-300">
                <X className="w-5 h-5" />
              </button>
            </div>
            
            <div className="p-6 overflow-y-auto flex-1 bg-gray-50 dark:bg-slate-950">
                <pre className="text-sm text-gray-800 dark:text-gray-300 font-mono">
                  {JSON.stringify(selectedRawJson.data, null, 2)}
                </pre>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}
