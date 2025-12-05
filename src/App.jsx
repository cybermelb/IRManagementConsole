import React, { useState, useEffect, useCallback } from 'react';
import { 
  Shield, Book, ListChecks, Target, Users, X, CheckCircle, Clock, Search, FolderOpen, 
  AlertTriangle, Cpu, Globe, Zap, Megaphone, Calendar, Phone, Grip, TrendingUp, 
  FilePlus, ClipboardList, Database, Cog, Settings, LayoutDashboard, Menu, GitFork, FileText,
  Plus, Trash2, Edit2, BarChart3, Server, Hash, Layers, ListTodo
} from 'lucide-react';

// --- CONFIG & UTILS ---

// Global variables for Firebase access (Mandatory use)
const appId = typeof __app_id !== 'undefined' ? __app_id : 'default-app-id';
const firebaseConfig = typeof __firebase_config !== 'undefined' ? JSON.parse(__firebase_config) : null;
const initialAuthToken = typeof __initial_auth_token !== 'undefined' ? __initial_auth_token : null;

// Mock Firebase Setup for Persistence Demonstration
const useFirebase = () => {
  const [userId, setUserId] = useState(null);

  useEffect(() => {
    // Mock Initialization
    if (firebaseConfig) {
      console.log("Mock Firebase: Initializing...");
      const mockUser = { uid: `user-${Math.random().toString(36).substr(2, 9)}` };
      setUserId(mockUser.uid);
      console.log("Mock Firebase: Signed in successfully.");
    }
  }, []);

  // Return userId only, as actual DB/Auth objects are mocked/omitted for brevity
  return { userId, isAuthReady: !!userId };
};

// --- MOCK DATA STRUCTURES ---
const initialScenarios = [
  { id: 1, title: 'Ransomware Attack (Production)', status: 'Containment', severity: 'Critical', updated: '10:30 AM' },
  { id: 2, title: 'Phishing Attempt (Low Volume)', status: 'Identified', severity: 'Low', updated: 'Yesterday' },
  { id: 3, title: 'Insider Data Exfiltration', status: 'Eradication', severity: 'High', updated: '9:00 AM' },
];

const initialChecklists = {
  identification: [
    { id: 1, text: "Verify the alert's veracity and scope (Passive Monitoring).", checked: false, source: "SANS 504" },
    { id: 2, text: "Establish Chain of Custody (CoC) for all collected evidence (ISO/IEC 27037).", checked: false, source: "SANS 504" },
  ],
  containment: [
    { id: 5, text: "Notify Management / Legal Counsel (Use OOB Comms).", checked: false, source: "SANS 504" },
    { id: 6, text: "Implement Short-Term Containment (Isolate System/VLAN).", checked: false, source: "SANS 504" },
  ],
};

const initialAssets = [
  { id: 101, name: 'Prod-DB-01', criticality: 'High', owner: 'DevOps', logs: 'Enabled (Full)', controls: 'E8 Compliant' },
  { id: 102, name: 'Marketing Web Srv', criticality: 'Medium', owner: 'Marketing', logs: 'Disabled', controls: 'Partial' },
  { id: 103, name: 'Executive Laptops', criticality: 'Critical', owner: 'IT Support', logs: 'Enabled (Endpoint)', controls: 'E8 Compliant' },
];

const initialRemediationTasks = [
  { id: 201, title: 'Implement MFA for Marketing Web Srv', source: 'Post-Incident 2 Review', status: 'In Progress', priority: 'High' },
  { id: 202, title: 'Schedule forensic training for Tier 1 SOC', source: 'Lessons Learned 1', status: 'Pending', priority: 'Medium' },
];


// --- COMPONENT: Sidebar Navigation ---
const Sidebar = ({ activeTab, setActiveTab, isSidebarOpen, toggleSidebar }) => {
  const tabs = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { id: 'risk', label: 'Risk Dashboard', icon: TrendingUp },
    { id: 'builder', label: 'Incident Builder', icon: FilePlus },
    { id: 'asset_builder', label: 'Asset Builder', icon: Database },
    { id: 'remediation', label: 'Remediation Tasks', icon: ClipboardList },
    { id: 'ir_playbooks', label: 'IR Playbooks', icon: Book },
    { id: 'hunting', label: 'Threat Hunting', icon: Target },
    { id: 'dfir_guides', label: 'DFIR Guides', icon: FolderOpen },
    { id: 'checklists', label: 'PICERL Checklists', icon: ListChecks },
    { id: 'timeline', label: 'Timeline', icon: Calendar },
    { id: 'reports', label: 'Reports', icon: Megaphone },
    { id: 'admin', label: 'Admin Dashboard', icon: Shield },
    { id: 'settings', label: 'Settings', icon: Cog },
  ];

  const handleTabClick = (id) => {
    setActiveTab(id);
    if (window.innerWidth < 768) { 
      toggleSidebar();
    }
  };

  return (
    <>
      {/* Mobile Menu Button */}
      <button
        onClick={toggleSidebar}
        className="md:hidden fixed top-4 left-4 z-50 p-2 bg-indigo-600 text-white rounded-lg shadow-xl hover:bg-indigo-700 transition"
      >
        <Menu className="w-6 h-6" />
      </button>

      {/* Sidebar - Desktop and Mobile Overlay */}
      <div 
        className={`fixed top-0 left-0 h-full bg-gray-900 text-white z-40 transition-all duration-300 md:relative md:translate-x-0 md:w-64 flex-shrink-0 ${
          isSidebarOpen ? 'translate-x-0 w-64 shadow-2xl' : '-translate-x-full w-0 md:w-64'
        }`}
      >
        <div className="p-4 pt-6 flex flex-col h-full">
          <h1 className="text-2xl font-bold font-mono tracking-tighter text-indigo-400 mb-6 flex items-center">
            <Zap className="inline-block h-6 w-6 mr-2" />
            IR Console
          </h1>
          <nav className="flex-grow space-y-2 overflow-y-auto">
            {tabs.map(tab => {
              const Icon = tab.icon;
              const isActive = activeTab === tab.id;
              return (
                <button
                  key={tab.id}
                  onClick={() => handleTabClick(tab.id)}
                  className={`flex items-center w-full space-x-3 p-3 rounded-xl text-sm transition duration-200 ease-in-out ${
                    isActive
                      ? 'bg-indigo-600 text-white font-semibold shadow-md'
                      : 'text-gray-300 hover:bg-gray-800 hover:text-indigo-400'
                  }`}
                >
                  <Icon className="h-5 w-5" />
                  <span>{tab.label}</span>
                </button>
              );
            })}
          </nav>
        </div>
      </div>
      
      {/* Mobile Overlay Backdrop */}
      {isSidebarOpen && window.innerWidth < 768 && (
        <div className="fixed inset-0 bg-black bg-opacity-50 z-30" onClick={toggleSidebar}></div>
      )}
    </>
  );
};

// --- CORE DASHBOARD PAGES ---

// Dashboard Page (Scenario Selector & Metrics)
const DashboardPage = ({ onSelectIncident, currentIncident }) => {
  const metricCards = [
    { title: "Time to Contain (TTC)", value: "3.2 Hours", change: "+5%", icon: Clock, color: "red" },
    { title: "Time to Remediate (TTR)", value: "2 Days", change: "-15%", icon: CheckCircle, color: "green" },
    { title: "IR Coverage Score", value: "92%", change: "+2%", icon: Shield, color: "indigo" },
  ];

  const getSeverityColor = (severity) => {
    switch(severity) {
      case 'Critical': return 'border-red-500 bg-red-50 text-red-800';
      case 'High': return 'border-orange-500 bg-orange-50 text-orange-800';
      case 'Low': return 'border-green-500 bg-green-50 text-green-800';
      default: return 'border-gray-300 bg-gray-50 text-gray-800';
    }
  }

  return (
    <div className="p-4 space-y-8">
      <h2 className="text-3xl font-bold text-gray-800 border-b pb-2">Active Incident Dashboard</h2>
      
      {/* Metrics Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-6">
        {metricCards.map(card => {
          const Icon = card.icon;
          return (
            <div key={card.title} className={`p-5 rounded-xl shadow-lg bg-white border-t-4 border-${card.color}-500`}>
              <div className="flex justify-between items-center">
                <p className="text-sm font-medium text-gray-500">{card.title}</p>
                <Icon className={`w-5 h-5 text-${card.color}-500`} />
              </div>
              <p className="text-3xl font-extrabold text-gray-900 mt-1">{card.value}</p>
              <div className={`mt-2 text-xs font-semibold text-green-600 flex items-center`}>
                 <span className={`text-${card.color}-600`}>{card.change}</span> vs Last Quarter
              </div>
            </div>
          );
        })}
      </div>
      
      {/* Current Incident Banner */}
      <div className={`p-5 rounded-xl border-l-4 ${getSeverityColor(currentIncident.severity)} shadow-md`}>
        <p className="font-semibold flex items-center mb-1"><AlertTriangle className="w-5 h-5 mr-2" /> Active Incident:</p>
        <p className="text-2xl font-bold">{currentIncident.title}</p>
        <p className="text-sm">Status: <span className="font-semibold">{currentIncident.status}</span> | Severity: <span className="font-semibold">{currentIncident.severity}</span></p>
      </div>

      <h3 className="text-2xl font-semibold text-gray-700 mt-6">Open Incidents Overview</h3>
      <div className="space-y-3">
        {initialScenarios.map(incident => (
          <div
            key={incident.id}
            className={`flex justify-between items-center p-4 rounded-lg shadow-md transition ${
              incident.id === currentIncident.id ? 'bg-indigo-100 ring-2 ring-indigo-500' : 'bg-white hover:bg-gray-50 cursor-pointer'
            }`}
            onClick={() => onSelectIncident(incident)}
          >
            <div>
              <p className="font-bold text-lg">{incident.title}</p>
              <p className="text-sm text-gray-500">Last Updated: {incident.updated}</p>
            </div>
            <div className="text-right">
              <span className={`px-3 py-1 text-xs font-semibold rounded-full ${incident.severity === 'Critical' ? 'bg-red-200 text-red-800' : 'bg-green-200 text-green-800'}`}>{incident.severity}</span>
              <p className="text-sm font-medium mt-1">{incident.status}</p>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

// Timeline Page
const TimelinePage = ({ currentIncident, incomingEvents }) => {
  const [events, setEvents] = useState(() => {
    // Prefer props if provided; otherwise load from localStorage; fallback to mock
    if (incomingEvents && Array.isArray(incomingEvents) && incomingEvents.length > 0) return incomingEvents;
    try {
      const saved = localStorage.getItem("timelineEvents");
      if (saved) {
        const parsed = JSON.parse(saved);
        if (Array.isArray(parsed) && parsed.length > 0) return parsed;
      }
    } catch {
      // ignore
    }
    // Fallback mock data
    return [
      {
        timestamp: "10:00 AM (D-0)",
        incidentTitle: "Prod-Server-01 Ransomware",
        action: "Alert Received: EDR flagged potential ransomware activity.",
        phase: "Identification",
        user: "SOC Analyst 1",
      },
      {
        timestamp: "10:15 AM (D-0)",
        incidentTitle: "Prod-Server-01 Ransomware",
        action: "Containment Action: Isolated VLAN; blocked external C2 IPs.",
        phase: "Containment",
        user: "IRH John D.",
      },
      {
        timestamp: "11:00 AM (D-0)",
        incidentTitle: "Prod-Server-01 Ransomware",
        action: "Legal Counsel notified and engaged.",
        phase: "Containment",
        user: "PIH Sarah K.",
      },
    ];
  });

  // Listen for broadcasted updates from IncidentBuilderPage
  useEffect(() => {
    const handler = (ev) => {
      const detail = ev.detail;
      if (detail && detail.timestamp && detail.action) {
        setEvents((prev) => [...prev, detail]);
      }
    };
    window.addEventListener("timeline:updated", handler);
    return () => window.removeEventListener("timeline:updated", handler);
  }, []);

  const getPhaseColor = (phase) => {
    switch (phase) {
      case "Identification":
        return "bg-yellow-500";
      case "Containment":
        return "bg-red-500";
      case "Eradication":
        return "bg-orange-500";
      case "Recovery":
        return "bg-blue-500";
      case "Lessons Learned":
        return "bg-green-500";
      default:
        return "bg-gray-400";
    }
  };

  return (
    <div className="p-4 space-y-6">
      <h2 className="text-3xl font-bold text-gray-800 border-b pb-2">
        Timeline for: {currentIncident?.title || "Current Incident"}
      </h2>
      <div className="space-y-8 relative before:absolute before:inset-y-0 before:w-1 before:bg-gray-200 before:left-3">
        {events.map((event, index) => (
          <div key={index} className="ml-8 relative">
            <span
              className={`absolute -left-10 top-1 w-6 h-6 rounded-full ${getPhaseColor(
                event.phase
              )} ring-4 ring-white`}
            ></span>
            <div className="p-4 bg-white rounded-lg shadow-md border-l-4 border-gray-300">
              <p className="text-xs font-semibold uppercase tracking-wider text-gray-500">
                {event.timestamp} | {event.phase}
              </p>
              <p className="font-bold mt-1 text-gray-800">
                {event.incidentTitle ? `${event.incidentTitle}: ${event.action}` : event.action}
              </p>
              <p className="text-xs text-gray-400 mt-1">Logged by: {event.user}</p>
            </div>
          </div>
        ))}
        {events.length === 0 && (
          <div className="ml-8 p-4 bg-white rounded-lg shadow-md border">
            <p className="text-sm text-gray-600">
              No timeline events yet. Add actions from the Incident Builder.
            </p>
          </div>
        )}
      </div>
    </div>
  );
};




// PICERL Checklists Page
const ChecklistsPage = () => {
  const [checklists, setChecklists] = useState(initialChecklists);
  const toggleCheck = (category, id) => {
    setChecklists(prev => ({
      ...prev,
      [category]: prev[category].map(item =>
        item.id === id ? { ...item, checked: !item.checked } : item
      )
    }));
  };
  const getCategoryIcon = (category) => {
    switch (category) {
      case 'identification': return <Search className="w-5 h-5 mr-2 text-yellow-500" />;
      case 'containment': return <X className="w-5 h-5 mr-2 text-red-500" />;
      default: return <ListChecks className="w-5 h-5 mr-2 text-indigo-500" />;
    }
  };

  return (
    <div className="space-y-8 p-4">
      <h2 className="text-3xl font-bold text-gray-800 border-b pb-2">PICERL Checklists</h2>
      <div className="bg-yellow-50 border-l-4 border-yellow-500 p-4 rounded-xl">
        <h3 className="text-lg font-semibold text-yellow-800 flex items-center"><Clock className="w-5 h-5 mr-2" /> PICERL Framework</h3>
        <p className="text-sm text-yellow-700">Checklists for active phases (Identification, Containment, Eradication). </p>
      </div>
      {Object.entries(checklists).map(([category, items]) => (
        <div key={category} className="bg-white p-6 rounded-xl shadow-lg border-t-4 border-indigo-500">
          <h3 className="flex items-center text-xl font-semibold mb-4 capitalize text-indigo-600">
            {getCategoryIcon(category)}{category} Phase
          </h3>
          <ul className="space-y-3">
            {items.map(item => (
              <li key={item.id} className="flex items-start">
                <input type="checkbox" checked={item.checked} onChange={() => toggleCheck(category, item.id)} className="mt-1 h-5 w-5 rounded border-gray-300 text-indigo-600 focus:ring-indigo-500" />
                <label className="ml-3 text-gray-700 select-none">{item.text} <span className="text-xs ml-2 text-gray-500">({item.source})</span></label>
              </li>
            ))}
          </ul>
        </div>
      ))}
    </div>
  );
};


// Reports & NDB Page (Stakeholders)
const ReportsPage = () => {
  const externalStakeholders = [
    { entity: "ACSC", contact: "1300 CYBER1", trigger: "National/economic interests" },
    { entity: "OAIC (NDB)", contact: "NDB Portal", trigger: "Likely serious harm" },
  ];
  return (
    <div className="space-y-8 p-4">
      <h2 className="text-3xl font-bold text-gray-800 border-b pb-2 flex items-center">
        <Megaphone className="w-7 h-7 mr-2 text-red-600" />
        Reporting & Regulatory Obligations (ACSC, NDB)
      </h2>
      <div className="bg-white p-6 rounded-xl shadow-lg border-t-4 border-red-500">
        <h3 className="text-2xl font-semibold mb-4 text-red-600 border-b pb-2">External Entities & Mandatory Reporting</h3>
        <p className="text-sm text-gray-600 mb-4">Mandatory reporting is driven by the Notifiable Data Breach (NDB) Scheme and ACSC Guidance. The severity of the cyber incident informs the type and nature of incident response. </p>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {externalStakeholders.map((s, index) => (
            <div key={index} className="border p-4 rounded-lg bg-red-50 hover:shadow-md transition">
              <p className="font-bold text-lg text-red-800 flex items-center"><Globe className="w-4 h-4 mr-2" />{s.entity}</p>
              <p className="text-xs mt-2 text-gray-600"><span className="font-semibold text-red-600">Trigger:</span> {s.trigger}</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};


// Contacts Directory Page (Moved from old ContactsPage)
const ContactsPage = () => {
  const mockContacts = [
    { type: 'Internal', role: 'CISO', name: 'Jane S.', phone: '+61 400 111 222', email: 'jane.s@corp.com', priority: 'High' },
    { type: 'External', role: 'ACSC Hotline', name: '1300 CYBER1', phone: '1300 292 371', priority: 'Critical' },
  ];

  return (
    <div className="p-4 space-y-6">
      <h2 className="text-3xl font-bold text-gray-800 border-b pb-2">Incident Contact Directory</h2>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {mockContacts.map((contact, index) => (
          <div key={index} className="bg-white p-4 rounded-xl shadow-md border-t-4 border-indigo-600">
            <h3 className="font-bold text-lg text-indigo-800">{contact.name} ({contact.type})</h3>
            <p className="text-sm text-gray-600 mt-1">{contact.role}</p>
            <p className="flex items-center text-gray-700"><Phone className="w-4 h-4 mr-2 text-green-500" /> {contact.phone}</p>
          </div>
        ))}
      </div>
    </div>
  );
};


// --- KNOWLEDGE BASE PAGES (ENHANCED) ---

// IR Playbooks Page

const IRPlaybooksPage = () => (
  <div className="p-4 space-y-6">
    <h2 className="text-3xl font-bold text-gray-800 border-b pb-2">
      IR Playbooks: Ransomware & Phishing
    </h2>

    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
      {/* Ransomware Playbook */}
      <div className="bg-white p-6 rounded-xl shadow-lg border-t-4 border-red-500">
        <h3 className="text-2xl font-bold text-red-700 flex items-center mb-3">
          <AlertTriangle className="w-6 h-6 mr-2" /> Ransomware Playbook
        </h3>

        <div className="space-y-4">
          <div className="border-l-4 border-yellow-500 pl-3">
            <h4 className="font-semibold text-lg text-yellow-800">
              1. Identification & Initial Triage
            </h4>
            <ul className="list-disc list-inside text-gray-700 text-sm ml-2">
              <li>Confirm encryption (check file extensions, ransom note presence).</li>
              <li>Identify patient zero / initial access vector.</li>
            </ul>
          </div>
          <div className="border-l-4 border-red-500 pl-3">
            <h4 className="font-semibold text-lg text-red-800">
              2. Containment (Stop the Bleeding)
            </h4>
            <ul className="list-disc list-inside text-gray-700 text-sm ml-2">
              <li><strong>Short-Term:</strong> Isolate affected host/VLAN from all networks.</li>
              <li><strong>Forensic Image:</strong> Create a memory capture and disk image <em>before</em> shutdown.</li>
              <li><strong>Account Lockout:</strong> Disable/reset credentials potentially compromised.</li>
            </ul>
          </div>
        </div>
      </div>

      {/* High-impact defense strategies with table */}
      <div className="bg-white p-6 rounded-xl shadow-lg border-t-4 border-red-500">
        <h3 className="text-2xl font-bold text-red-700 flex items-center mb-3">
          <AlertTriangle className="w-6 h-6 mr-2" /> The high-impact defense strategies
        </h3>
        <div className="space-y-4">
          <div className="border-l-4 border-yellow-500 pl-3 overflow-x-auto">
            <table style={{ width: "100%" }} className="table-auto border-collapse border border-gray-300 text-sm">
              <tbody>
                <tr>
                  <td style={{ width: "136px" }}><strong>Malware Name</strong></td>
                  <td style={{ width: "63px" }}><strong>Type &amp; Primary Goal</strong></td>
                  <td style={{ width: "143px" }}><strong>Compromise Flow (TTPs)</strong></td>
                  <td style={{ width: "151px" }}><strong>Critical Mitigation &amp; SOC Strategy</strong></td>
                </tr>

                {/* BRICKSTORM */}
                <tr>
                  <td>1. BRICKSTORM</td>
                  <td>RAT / Backdoor / SOCKS Proxy</td>
                  <td>
                    <p>1. Initial Access: Vulnerability → Web Shell.</p>
                    <p>2. Lateral Movement: RDP/SMB with service creds.</p>
                    <p>3. Credential Theft: Copied AD database.</p>
                    <p>4. Persistence: Init file executes payload.</p>
                  </td>
                  <td>
                    <p>1. Harden DMZ.</p>
                    <p>2. Enforce MFA.</p>
                    <p>3. Restrict AD access.</p>
                    <p>4. File Integrity Monitoring.</p>
                  </td>
                </tr>

                {/* Emotet */}
                <tr>
                  <td>2. Emotet</td>
                  <td>Botnet / Banking Trojan</td>
                  <td>
                    <p>1. Delivery: Malspam attachments.</p>
                    <p>2. Execution: Macros → PowerShell.</p>
                    <p>3. Persistence: Registry/scheduled tasks.</p>
                    <p>4. Lateral Movement: Drops TrickBot.</p>
                  </td>
                  <td>
                    <p>1. Email Filtering.</p>
                    <p>2. Disable macros.</p>
                    <p>3. Restrict SMB traffic.</p>
                  </td>
                </tr>

                {/* NotPetya */}
                <tr>
                  <td>3. NotPetya</td>
                  <td>Wiper Malware</td>
                  <td>
                    <p>1. Supply chain compromise.</p>
                    <p>2. EternalBlue + stolen creds.</p>
                    <p>3. MBR/MFT encryption.</p>
                    <p>4. Permanent destruction.</p>
                  </td>
                  <td>
                    <p>1. Patch MS17-010.</p>
                    <p>2. Immutable backups.</p>
                    <p>3. Segment networks.</p>
                  </td>
                </tr>

                {/* WannaCry */}
                <tr>
                  <td>4. WannaCry</td>
                  <td>Worm / Ransomware</td>
                  <td>
                    <p>1. Exploits EternalBlue.</p>
                    <p>2. Worm propagation.</p>
                    <p>3. Encrypts files, ransom demand.</p>
                    <p>4. Kill switch domain halts.</p>
                  </td>
                  <td>
                    <p>1. Patch MS17-010.</p>
                    <p>2. Block SMB exposure.</p>
                    <p>3. Update AV.</p>
                  </td>
                </tr>

                {/* TrickBot */}
                <tr>
                  <td>5. TrickBot</td>
                  <td>Banking Trojan</td>
                  <td>
                    <p>1. Delivered via Emotet/phishing.</p>
                    <p>2. Browser injection.</p>
                    <p>3. Lateral movement with stolen creds.</p>
                    <p>4. Leads to ransomware.</p>
                  </td>
                  <td>
                    <p>1. Least Privilege.</p>
                    <p>2. Credential Guard.</p>
                    <p>3. User training.</p>
                  </td>
                </tr>

                {/* Stuxnet */}
                <tr>
                  <td>6. Stuxnet</td>
                  <td>Worm / OT Sabotage</td>
                  <td>
                    <p>1. Delivery: USB/network shares.</p>
                    <p>2. Targeting: Siemens Step7/WinCC.</p>
                    <p>3. Execution: Reprograms PLC controllers.</p>
                    <p>4. Masking: Rootkit feeds false sensor data.</p>
                  </td>
                  <td>
                    <p>1. OT Segmentation.</p>
                    <p>2. USB control policies.</p>
                    <p>3. Asset inventory & patching.</p>
                    <p>4. SCADA protocol monitoring.</p>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* Phishing Playbook */}
      <div className="bg-white p-6 rounded-xl shadow-lg border-t-4 border-blue-500">
        <h3 className="text-2xl font-bold text-blue-700 flex items-center mb-3">
          <Search className="w-6 h-6 mr-2" /> Phishing/Credential Theft Playbook
        </h3>

        <div className="space-y-4">
          <div className="border-l-4 border-yellow-500 pl-3">
            <h4 className="font-semibold text-lg text-yellow-800">
              1. Identification & Analysis
            </h4>
            <ul className="list-disc list-inside text-gray-700 text-sm ml-2">
              <li>Check email headers (Sender IP, SPF/DKIM status, return path).</li>
              <li>Analyze malicious attachment/link payload.</li>
            </ul>
          </div>
          <div className="border-l-4 border-red-500 pl-3">
            <h4 className="font-semibold text-lg text-red-800">
              2. Containment & Eradication
            </h4>
            <ul className="list-disc list-inside text-gray-700 text-sm ml-2">
              <li><strong>Quarantine:</strong> Remove email from all affected inboxes.</li>
              <li><strong>Reset:</strong> Force password reset and MFA re-enrollment.</li>
              <li>**Log Hunt:** Search logs for successful logon events from unusual IPs/geos.</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  </div>
);

// DFIR Guides Page

const DFIRGuidesPage = () => (
  <div className="p-4 space-y-6">
    <h2 className="text-3xl font-bold text-gray-800 border-b pb-2 flex items-center">
      DFIR Triage & Artifact Guides (SANS FOR508 / FOR504)
    </h2>
    <p className="text-sm text-gray-600">
      Guidance on key forensic data points and their purpose during triage. Includes host execution artifacts and network communications checks.
    </p>

    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
      {/* Host Artifacts */}
      <div className="bg-white p-5 rounded-xl shadow-md border-t-4 border-purple-500">
        <p className="font-bold text-xl text-purple-700 flex items-center mb-3">
          <Cpu className="w-5 h-5 mr-2" /> Host & Execution Artifacts
        </p>
        <div className="space-y-3">
          <div className="bg-gray-50 p-3 rounded-lg">
            <p className="font-semibold text-gray-800">Windows Event Logs (4688, 7045, 4624, 4625)</p>
            <p className="text-xs text-gray-600">
              Tracks process creation, service installs, and logon successes/failures. Useful for detecting persistence and brute-force attempts.
            </p>
          </div>
          <div className="bg-gray-50 p-3 rounded-lg">
            <p className="font-semibold text-gray-800">ShimCache / Prefetch / Amcache</p>
            <p className="text-xs text-gray-600">
              Execution history showing first/last run times. Amcache provides metadata about installed executables.
            </p>
          </div>
          <div className="bg-gray-50 p-3 rounded-lg">
            <p className="font-semibold text-gray-800">Scheduled Tasks & Services</p>
            <p className="text-xs text-gray-600">
              Check for malicious persistence via new tasks (schtasks) or unusual services (Event ID 4697).
            </p>
          </div>
          <div className="bg-gray-50 p-3 rounded-lg">
            <p className="font-semibold text-gray-800">Registry Keys (Run/RunOnce, UserInit, Winlogon)</p>
            <p className="text-xs text-gray-600">
              Common persistence locations. Look for executables outside standard paths (Program Files, System32).
            </p>
          </div>
          <div className="bg-gray-50 p-3 rounded-lg">
            <p className="font-semibold text-gray-800">Browser Artifacts (History, Cache, Downloads)</p>
            <p className="text-xs text-gray-600">
              Identify phishing lure execution, malicious downloads, or suspicious domains accessed by the user.
            </p>
          </div>
          <div className="bg-gray-50 p-3 rounded-lg">
            <p className="font-semibold text-gray-800">Memory Captures</p>
            <p className="text-xs text-gray-600">
              Volatile evidence: running processes, injected code, network sockets, command history, and crypto keys.
            </p>
          </div>
        </div>
      </div>

      {/* Network Artifacts */}
      <div className="bg-white p-5 rounded-xl shadow-md border-t-4 border-teal-500">
        <p className="font-bold text-xl text-teal-700 flex items-center mb-3">
          <Globe className="w-5 h-5 mr-2" /> Network & External Comms
        </p>
        <div className="space-y-3">
          <div className="bg-gray-50 p-3 rounded-lg">
            <p className="font-semibold text-gray-800">Web Proxies / Firewall Logs</p>
            <p className="text-xs text-gray-600">
              Detect suspicious outbound traffic, long URLs, or outdated User-Agent strings indicative of C2 activity.
            </p>
          </div>
          <div className="bg-gray-50 p-3 rounded-lg">
            <p className="font-semibold text-gray-800">Netflow / PCAP Analysis</p>
            <p className="text-xs text-gray-600">
              Look for beaconing (regular intervals), large outbound transfers, or connections to rare geolocations.
            </p>
          </div>
          <div className="bg-gray-50 p-3 rounded-lg">
            <p className="font-semibold text-gray-800">DNS Cache & Logs</p>
            <p className="text-xs text-gray-600">
              Identify lookups to known malicious domains. Cross-reference with OSINT feeds (VirusTotal, AbuseIPDB).
            </p>
          </div>
          <div className="bg-gray-50 p-3 rounded-lg">
            <p className="font-semibold text-gray-800">Proxy Auto-Config (PAC) & WPAD</p>
            <p className="text-xs text-gray-600">
              Malicious PAC/WPAD files can redirect traffic to attacker-controlled proxies. Check system proxy settings.
            </p>
          </div>
          <div className="bg-gray-50 p-3 rounded-lg">
            <p className="font-semibold text-gray-800">Email Gateway Logs</p>
            <p className="text-xs text-gray-600">
              Review for phishing attempts, spoofed sender domains, or malicious attachments. Correlate with SIEM alerts.
            </p>
          </div>
          <div className="bg-gray-50 p-3 rounded-lg">
            <p className="font-semibold text-gray-800">External Threat Feeds (OSINT)</p>
            <p className="text-xs text-gray-600">
              Use feeds like AlienVault OTX, MISP, and SANS ISC Storm Center to enrich indicators and validate suspicious traffic.
            </p>
          </div>
        </div>
      </div>
    </div>
  </div>
);




// Threat Hunting Page

const ThreatHuntingPage = () => (
  <div className="p-4 space-y-6">
    <h2 className="text-3xl font-bold text-gray-800 border-b pb-2 flex items-center">
      Threat Hunting Queries (Persistence & Lateral Movement)
    </h2>

    {/* Hunting Queries */}
    <div className="bg-white p-6 rounded-xl shadow-md border-t-2 border-green-400">
      <h4 className="font-bold text-lg text-gray-800 mb-3 flex items-center">
        <Clock className="w-4 h-4 mr-2" /> Persistence Artifacts (Autostart Mechanisms)
      </h4>
      <p className="text-sm text-gray-600 mb-3">
        Focus on registry keys that launch processes on user login or system boot outside of standard paths.
      </p>
      <p className="text-sm font-mono bg-gray-100 p-3 rounded-md text-red-700 overflow-x-auto">
        Registry: Run | Path !contains 'Program Files' OR Path !contains 'System32'
      </p>

      <h4 className="font-bold text-lg text-gray-800 mb-3 mt-6 flex items-center">
        <Users className="w-4 h-4 mr-2" /> Lateral Movement (Credential Use)
      </h4>
      <p className="text-sm text-gray-600 mb-3">
        Explicit logon events are often used in credential theft scenarios like Pass-the-Hash (PtH).
      </p>
      <p className="text-sm font-mono bg-gray-100 p-3 rounded-md text-red-700 overflow-x-auto">
        EventCode=4648 (A logon was attempted using explicit credentials)
      </p>
    </div>

    {/* Threat Intelligence Report Section */}
    <div className="bg-white p-6 rounded-xl shadow-md border-t-2 border-blue-400">
      <h3 className="text-2xl font-bold text-blue-700 flex items-center mb-4">
        <FileText className="w-6 h-6 mr-2" /> Threat & Adversary Mitigation Report
      </h3>

      <h4 className="font-semibold text-lg text-gray-800 mb-2">Executive Summary</h4>
      <p className="text-sm text-gray-700 mb-4">
        Recent intelligence indicates that APT groups (e.g., OceanLotus/APT32) are targeting Australian financial institutions
        using phishing campaigns and exploiting web application vulnerabilities. Recommended mitigations include enhanced email
        filtering, vulnerability patching, EDR deployment, and improved network monitoring.
      </p>

      <h4 className="font-semibold text-lg text-gray-800 mb-2">Priority Intelligence Requirements (PIR)</h4>
      <table className="table-auto border-collapse border border-gray-300 text-sm mb-4 w-full">
        <tbody>
          <tr className="bg-gray-100">
            <td className="border px-2 py-1 font-bold">PIR ID</td>
            <td className="border px-2 py-1 font-bold">Intelligence Question</td>
            <td className="border px-2 py-1 font-bold">Relevance</td>
          </tr>
          <tr>
            <td className="border px-2 py-1">PIR-001</td>
            <td className="border px-2 py-1">Latest TTPs used by APT groups targeting banking?</td>
            <td className="border px-2 py-1">Critical for proactive defense.</td>
          </tr>
          <tr>
            <td className="border px-2 py-1">PIR-002</td>
            <td className="border px-2 py-1">New ransomware campaigns targeting financial institutions?</td>
            <td className="border px-2 py-1">Essential for risk mitigation.</td>
          </tr>
          <tr>
            <td className="border px-2 py-1">PIR-003</td>
            <td className="border px-2 py-1">Emerging vulnerabilities in external-facing applications?</td>
            <td className="border px-2 py-1">Key for patching and reducing attack surface.</td>
          </tr>
        </tbody>
      </table>

      <h4 className="font-semibold text-lg text-gray-800 mb-2">Internal Intelligence Collection</h4>
      <ul className="list-disc list-inside text-sm text-gray-700 mb-4">
        <li><strong>SIEM Alerts:</strong> 15 phishing emails detected; blocked and rules updated.</li>
        <li><strong>EDR Telemetry:</strong> PowerShell execution observed on 3 endpoints; isolated successfully.</li>
        <li><strong>Email Gateway:</strong> 10% increase in phishing attempts; employee training conducted.</li>
      </ul>

      <h4 className="font-semibold text-lg text-gray-800 mb-2">External Intelligence Collection</h4>
      <ul className="list-disc list-inside text-sm text-gray-700 mb-4">
        <li><strong>Microsoft Defender:</strong> New Locky 2.0 ransomware variant detected.</li>
        <li><strong>Cisco AIGS:</strong> APT38 (Lazarus) using COVID-19 phishing lures.</li>
        <li><strong>Dark Web Monitoring:</strong> Planned DDoS attack on banking sector discussed.</li>
      </ul>

      <h4 className="font-semibold text-lg text-gray-800 mb-2">Recommendations</h4>
      <ul className="list-disc list-inside text-sm text-gray-700">
        <li>Enhance email filtering rules to block malicious attachments and URLs.</li>
        <li>Conduct employee awareness training on phishing and ransomware prevention.</li>
        <li>Patch external-facing applications to mitigate exploitation risks.</li>
        <li>Update SIEM/EDR detection rules for new TTPs (e.g., Locky 2.0).</li>
      </ul>
    </div>
  </div>
);



// --- NEW FUNCTIONAL PAGES ---

// Risk Dashboard Page
const RiskDashboardPage = () => {
  const risks = [
    { name: 'Ransomware', score: 9.5, impact: 'High', likelihood: 'High', color: 'bg-red-500' },
    { name: 'Phishing/BEC', score: 6.0, impact: 'Medium', likelihood: 'High', color: 'bg-orange-500' },
    { name: 'Cloud Misconfig', score: 4.0, impact: 'Medium', likelihood: 'Medium', color: 'bg-yellow-500' },
    { name: 'Insider Threat', score: 2.5, impact: 'Low', likelihood: 'Low', color: 'bg-green-500' },
  ];
  return (
    <div className="p-4 space-y-8">
      <h2 className="text-3xl font-bold text-gray-800 border-b pb-2 flex items-center"><BarChart3 className="w-7 h-7 mr-2 text-blue-600" /> Risk Dashboard</h2>
      
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="md:col-span-2 bg-white p-6 rounded-xl shadow-lg border-t-4 border-indigo-500">
          <h3 className="text-xl font-semibold mb-4 text-indigo-700">Risk Heatmap (Simulated)</h3>
          <p className="text-sm text-gray-500 mb-4">Current residual risks based on control maturity and threat intelligence.</p>
          {/* Mock Heatmap Grid */}
          <div className="grid grid-cols-4 grid-rows-4 h-64 border border-gray-200">
            {/* Legend Y-Axis (Likelihood) */}
            <div className="col-span-1 flex flex-col justify-around text-xs font-semibold text-gray-600">
              <span className="text-right pr-2 h-1/4 pt-2">High</span>
              <span className="text-right pr-2 h-1/4 pt-2">Medium</span>
              <span className="text-right pr-2 h-1/4 pt-2">Low</span>
              <span className="text-right pr-2 h-1/4 pt-2">Very Low</span>
            </div>
            {/* Risk Cells */}
            <div className="col-span-3 grid grid-cols-3 grid-rows-4">
              <div className="bg-red-600 text-white flex items-center justify-center font-bold text-xs" style={{ gridRow: 1, gridColumn: 3 }}>Ransomware</div>
              <div className="bg-yellow-400 text-black flex items-center justify-center font-bold text-xs" style={{ gridRow: 2, gridColumn: 2 }}>Phishing</div>
              <div className="bg-green-500 flex items-center justify-center text-xs" style={{ gridRow: 3, gridColumn: 1 }}>Insider</div>
              <div className="bg-orange-400 flex items-center justify-center text-xs" style={{ gridRow: 2, gridColumn: 3 }}>DDoS</div>
            </div>
            {/* Legend X-Axis (Impact) */}
            <div className="col-span-1"></div>
            <div className="col-span-3 flex justify-around text-xs font-semibold text-gray-600 border-t pt-1">
              <span>Low</span>
              <span>Medium</span>
              <span>High</span>
            </div>
          </div>
        </div>
        
        {/* Risk Scores Summary */}
        <div className="bg-white p-6 rounded-xl shadow-lg border-t-4 border-pink-500">
          <h3 className="text-xl font-semibold mb-4 text-pink-700">Top 4 Risk Scores</h3>
          <div className="space-y-4">
            {risks.map((r, i) => (
              <div key={i} className="flex justify-between items-center">
                <span className="text-gray-700">{r.name}</span>
                <div className="flex items-center space-x-2">
                  <span className={`px-3 py-1 text-xs font-bold rounded-full text-white ${r.color}`}>{r.score.toFixed(1)}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

// Incident Builder Page
const IncidentBuilderPage = ({ assets = [] }) => {
  const [newIncident, setNewIncident] = useState({ title: '', severity: 'Medium', asset: '' });
  const [incidentLog, setIncidentLog] = useState(initialScenarios);

  const [timelineEvents, setTimelineEvents] = useState(() => {
    try {
      const saved = localStorage.getItem('timelineEvents');
      return saved ? JSON.parse(saved) : [];
    } catch {
      return [];
    }
  });

  const [newEvent, setNewEvent] = useState({
    incidentId: '',
    action: '',
    details: '',
    phase: 'Identification',
    user: 'SOC Analyst 1',
  });

  // Handle incident intake
  const handleChange = (e) => {
    const { name, value } = e.target;
    setNewIncident(prev => ({ ...prev, [name]: value }));
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    if (newIncident.title.trim()) {
      const newEntry = {
        id: incidentLog.length + 1,
        title: newIncident.title.trim(),
        status: 'Identified',
        severity: newIncident.severity,
        updated: new Date().toLocaleTimeString(),
        asset: newIncident.asset || 'N/A',
      };
      setIncidentLog(prev => [newEntry, ...prev]);
      setNewIncident({ title: '', severity: 'Medium', asset: '' });
    }
  };

  // Handle event form
  const handleEventFieldChange = (e) => {
    const { name, value } = e.target;
    setNewEvent(prev => ({ ...prev, [name]: value }));
  };

  const handleAddEvent = (e) => {
    e.preventDefault();
    if (!newEvent.action || !newEvent.incidentId) return;

    const incident = incidentLog.find(i => i.id === parseInt(newEvent.incidentId));
    if (!incident) return;

    const entry = {
      timestamp: new Date().toLocaleTimeString(),
      incidentTitle: incident.title,
      action: newEvent.details ? `${newEvent.action}: ${newEvent.details}` : newEvent.action,
      phase: newEvent.phase,
      user: newEvent.user,
    };

    const updated = [...timelineEvents, entry];
    setTimelineEvents(updated);
    localStorage.setItem('timelineEvents', JSON.stringify(updated));
    window.dispatchEvent(new CustomEvent('timeline:updated', { detail: entry }));

    setNewEvent({ incidentId: '', action: '', details: '', phase: 'Identification', user: 'SOC Analyst 1' });
  };

  return (
    <div className="p-4 space-y-8">
      <h2 className="text-3xl font-bold text-gray-800 border-b pb-2 flex items-center">
        <FilePlus className="w-7 h-7 mr-2 text-green-600" /> Incident Builder
      </h2>

      {/* Incident Intake Form */}
      <div className="bg-white p-6 rounded-xl shadow-lg border-t-4 border-green-500">
        <h3 className="text-xl font-semibold mb-4">Log New Incident</h3>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700">Incident Title</label>
            <input
              type="text"
              name="title"
              value={newIncident.title}
              onChange={handleChange}
              placeholder="e.g., EDR Alert: Suspicious file execution"
              required
              className="mt-1 block w-full rounded-md border-gray-300 shadow-sm p-2 border"
            />
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700">Severity</label>
              <select
                name="severity"
                value={newIncident.severity}
                onChange={handleChange}
                className="mt-1 block w-full rounded-md border-gray-300 shadow-sm p-2 border"
              >
                <option>Low</option>
                <option>Medium</option>
                <option>High</option>
                <option>Critical</option>
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700">Affected Asset</label>
              <select
                name="asset"
                value={newIncident.asset}
                onChange={handleChange}
                className="mt-1 block w-full rounded-md border-gray-300 shadow-sm p-2 border"
              >
                <option value="">Select from Asset Builder</option>
                {assets.map((a, idx) => (
                  <option key={idx} value={a}>{a}</option>
                ))}
              </select>
              <input
                type="text"
                name="asset"
                value={newIncident.asset}
                onChange={handleChange}
                placeholder="Or enter manually"
                className="mt-2 block w-full rounded-md border-gray-300 shadow-sm p-2 border"
              />
            </div>
          </div>
          <button type="submit" className="px-4 py-2 bg-green-600 text-white rounded-lg">Start Incident</button>
        </form>
      </div>

      {/* Add Incident Response Action */}
      <div className="bg-white p-6 rounded-xl shadow-lg border-t-4 border-blue-500">
        <h3 className="text-xl font-semibold mb-4">Add Incident Response Action</h3>
        <form onSubmit={handleAddEvent} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700">Select Incident</label>
            <select
              name="incidentId"
              value={newEvent.incidentId}
              onChange={handleEventFieldChange}
              className="mt-1 block w-full rounded-md border-gray-300 shadow-sm p-2 border"
            >
              <option value="">Choose Incident</option>
              {incidentLog.map(inc => (
                <option key={inc.id} value={inc.id}>{inc.title}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700">Action</label>
            <select
              name="action"
              value={newEvent.action}
              onChange={handleEventFieldChange}
              className="mt-1 block w-full rounded-md border-gray-300 shadow-sm p-2 border"
            >
              <option value="">Select Action</option>
              <option>Alert Received</option>
              <option>Triage Initiated</option>
              <option>Incident Declared</option>
              <option>Technology Team Notified</option>
              <option>Cyber Manager Notified</option>
              <option>Containment Action</option>
              <option>Recovery Action</option>
              <option>Legal Counsel Notified</option>
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700">Details</label>
            <input
              type="text"
              name="details"
              value={newEvent.details}
              onChange={handleEventFieldChange}
              placeholder="Optional details"
              className="mt-1 block w-full rounded-md border-gray-300 shadow-sm p-2 border"
            />
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700">Phase</label>
              <select
                name="phase"
                value={newEvent.phase}
                onChange={handleEventFieldChange}
                className="mt-1 block w-full rounded-md border-gray-300 shadow-sm p-2 border"
              >
                <option>Identification</option>
                <option>Containment</option>
                <option>Eradication</option>
                <option>Recovery</option>
                <option>Lessons Learned</option>
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700">Logged By</label>
              <input
                type="text"
                name="user"
                value={newEvent.user}
                onChange={handleEventFieldChange}
                className="mt-1 block w-full rounded-md border-gray-300 shadow-sm p-2 border"
              />
            </div>
          </div>
          <button type="submit" className="px-4 py-2 bg-blue-600 text-white rounded-lg">Add to Timeline</button>
        </form>
      </div>
    </div>
  );
};


// Asset Builder Page
const AssetBuilderPage = () => {
  const [assets, setAssets] = useState(initialAssets);
  const [newAsset, setNewAsset] = useState({ name: '', criticality: 'Medium', owner: '', logs: 'Disabled' });

  const handleChange = (e) => {
    const { name, value } = e.target;
    setNewAsset(prev => ({ ...prev, [name]: value }));
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    if (newAsset.name && newAsset.owner) {
      const newEntry = {
        id: assets.length + 101,
        ...newAsset,
        controls: 'Pending Review',
      };
      setAssets(prev => [newEntry, ...prev]);
      setNewAsset({ name: '', criticality: 'Medium', owner: '', logs: 'Disabled' });
    }
  };

  const getLogStatusStyle = (status) => {
    if (status.includes('Enabled')) return 'bg-green-100 text-green-800';
    if (status.includes('Disabled')) return 'bg-red-100 text-red-800';
    return 'bg-yellow-100 text-yellow-800';
  };

  return (
    <div className="p-4 space-y-8">
      <h2 className="text-3xl font-bold text-gray-800 border-b pb-2 flex items-center"><Database className="w-7 h-7 mr-2 text-teal-600" /> Asset Builder & Inventory</h2>
      
      {/* Asset Intake Form */}
      <div className="bg-white p-6 rounded-xl shadow-lg border-t-4 border-teal-500">
        <h3 className="text-xl font-semibold mb-4">Add New Critical Asset</h3>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700">Asset Name (Hostname/Service)</label>
              <input type="text" name="name" value={newAsset.name} onChange={handleChange} required className="mt-1 block w-full rounded-md border-gray-300 shadow-sm p-2 border" />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700">Owner / Custodian</label>
              <input type="text" name="owner" value={newAsset.owner} onChange={handleChange} required className="mt-1 block w-full rounded-md border-gray-300 shadow-sm p-2 border" />
            </div>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700">Business Criticality</label>
              <select name="criticality" value={newAsset.criticality} onChange={handleChange} className="mt-1 block w-full rounded-md border-gray-300 shadow-sm p-2 border">
                <option value="Low">Low</option>
                <option value="Medium">Medium</option>
                <option value="High">High</option>
                <option value="Critical">Critical</option>
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700">Log Onboarding Status (IR Control)</label>
              <select name="logs" value={newAsset.logs} onChange={handleChange} className="mt-1 block w-full rounded-md border-gray-300 shadow-sm p-2 border">
                <option value="Disabled">Disabled</option>
                <option value="Enabled (Minimal)">Enabled (Minimal)</option>
                <option value="Enabled (Full)">Enabled (Full)</option>
              </select>
            </div>
          </div>
          <button
            type="submit"
            className="px-4 py-2 bg-teal-600 text-white font-semibold rounded-lg shadow-md hover:bg-teal-700 transition flex items-center"
          >
            <Plus className="w-5 h-5 mr-2" /> Add Asset
          </button>
        </form>
      </div>

      {/* Asset Inventory Table */}
      <h3 className="text-2xl font-semibold text-gray-700 mt-6">Critical Asset Inventory ({assets.length} items)</h3>
      <div className="overflow-x-auto bg-white rounded-xl shadow-lg">
        <table className="min-w-full divide-y divide-gray-200">
          <thead className="bg-gray-50">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Asset Name</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Criticality</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Owner</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Log Status</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">IR Controls</th>
            </tr>
          </thead>
          <tbody className="bg-white divide-y divide-gray-200">
            {assets.map((asset) => (
              <tr key={asset.id}>
                <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900 flex items-center"><Server className="w-4 h-4 mr-2 text-gray-400"/> {asset.name}</td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{asset.criticality}</td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{asset.owner}</td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${getLogStatusStyle(asset.logs)}`}>
                    {asset.logs}
                  </span>
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{asset.controls}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

// Remediation Tasks Page
const RemediationTasksPage = () => {
  const [tasks, setTasks] = useState(initialRemediationTasks);

  const getPriorityStyle = (priority) => {
    if (priority === 'High') return 'text-red-600 bg-red-100';
    if (priority === 'Medium') return 'text-orange-600 bg-orange-100';
    return 'text-green-600 bg-green-100';
  };

  const getStatusStyle = (status) => {
    if (status === 'In Progress') return 'text-blue-600 bg-blue-100';
    if (status === 'Pending') return 'text-gray-600 bg-gray-100';
    return 'text-green-600 bg-green-100';
  };

  return (
    <div className="p-4 space-y-8">
      <h2 className="text-3xl font-bold text-gray-800 border-b pb-2 flex items-center"><ListTodo className="w-7 h-7 mr-2 text-orange-600" /> Remediation Tasks (Lessons Learned Phase)</h2>
      <div className="bg-white p-6 rounded-xl shadow-lg border-t-4 border-orange-500">
        <h3 className="text-xl font-semibold mb-4">Open Remediation Items</h3>
        <p className="text-sm text-gray-600 mb-4">Security gaps identified during or after incident handling must be tracked here to ensure system resilience.</p>
        
        <div className="space-y-4">
          {tasks.map(task => (
            <div key={task.id} className="flex justify-between items-center p-3 border rounded-lg hover:bg-gray-50 transition">
              <div className="flex-grow">
                <p className="font-semibold text-gray-800">{task.title}</p>
                <p className="text-xs text-gray-500 mt-1">Source: {task.source}</p>
              </div>
              <div className="flex items-center space-x-3">
                <span className={`px-3 py-1 text-xs font-medium rounded-full ${getPriorityStyle(task.priority)}`}>{task.priority}</span>
                <span className={`px-3 py-1 text-xs font-medium rounded-full ${getStatusStyle(task.status)}`}>{task.status}</span>
                <button className="text-gray-400 hover:text-red-500 transition"><Trash2 className="w-4 h-4" /></button>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

// Admin Dashboard Page (Placeholder Enhanced)
const AdminDashboardPage = () => {
  const metrics = [
    { title: "Active Users", value: "24", icon: Users, color: "blue" },
    { title: "Rules Updated (30D)", value: "18", icon: Edit2, color: "yellow" },
    { title: "Storage Usage", value: "72%", icon: Database, color: "purple" },
  ];
  return (
    <div className="p-4 space-y-8">
      <h2 className="text-3xl font-bold text-gray-800 border-b pb-2 flex items-center"><Shield className="w-7 h-7 mr-2 text-gray-600" /> Admin Dashboard</h2>
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-6">
        {metrics.map(card => {
          const Icon = card.icon;
          return (
            <div key={card.title} className={`p-5 rounded-xl shadow-lg bg-white border-b-4 border-${card.color}-500`}>
              <div className="flex justify-between items-center">
                <p className="text-sm font-medium text-gray-500">{card.title}</p>
                <Icon className={`w-5 h-5 text-${card.color}-500`} />
              </div>
              <p className="text-3xl font-extrabold text-gray-900 mt-1">{card.value}</p>
            </div>
          );
        })}
      </div>
      <div className="bg-white p-6 rounded-xl shadow-lg border-t-4 border-gray-400">
        <h3 className="text-xl font-semibold mb-4 text-gray-700">Audit Log Summary</h3>
        <p className="text-sm font-mono bg-gray-100 p-3 rounded-lg text-gray-700">
          [10:05] User Jane S. updated 'Containment' checklist.<br/>
          [09:30] System initiated new incident: ID-004.
        </p>
      </div>
    </div>
  );
};

// Settings Page (Placeholder Enhanced)
const SettingsPage = () => (
  <div className="p-4 space-y-8">
    <h2 className="text-3xl font-bold text-gray-800 border-b pb-2 flex items-center"><Cog className="w-7 h-7 mr-2 text-gray-600" /> Application Settings</h2>
    <div className="bg-white p-6 rounded-xl shadow-lg border-t-4 border-gray-400 space-y-4">
      <h3 className="text-xl font-semibold text-gray-700">API & Integration Keys</h3>
      <div className="flex justify-between items-center border-b pb-2">
        <label className="text-sm font-medium text-gray-700">Threat Intel Feed API Key</label>
        <input type="password" value="**************" readOnly className="p-1 rounded-md bg-gray-100 text-sm" />
      </div>
      <div className="flex justify-between items-center border-b pb-2">
        <label className="text-sm font-medium text-gray-700">SIEM Connection Status</label>
        <span className="px-3 py-1 text-xs font-semibold rounded-full bg-green-100 text-green-800">Connected</span>
      </div>
      <button className="px-4 py-2 bg-indigo-600 text-white font-semibold rounded-lg shadow-md hover:bg-indigo-700 transition flex items-center">
        Save Changes
      </button>
    </div>
  </div>
);


// --- MAIN APP COMPONENT ---
const App = () => {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [currentIncident, setCurrentIncident] = useState(initialScenarios[0]);
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);
  const { userId } = useFirebase();

  const handleSelectIncident = useCallback((incident) => {
    setCurrentIncident(incident);
    setActiveTab('timeline'); 
  }, []);

  const toggleSidebar = () => {
    setIsSidebarOpen(prev => !prev);
  };

  // Close sidebar on desktop size change
  useEffect(() => {
    const handleResize = () => {
      if (window.innerWidth >= 768 && isSidebarOpen) {
        setIsSidebarOpen(false);
      }
    };
    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, [isSidebarOpen]);


  const renderContent = () => {
    switch (activeTab) {
      case 'dashboard':
        return <DashboardPage onSelectIncident={handleSelectIncident} currentIncident={currentIncident} />;
      case 'timeline':
        return <TimelinePage currentIncident={currentIncident} />;
      case 'contacts':
        return <ContactsPage />;
      case 'checklists':
        return <ChecklistsPage />;
      case 'ir_playbooks':
        return <IRPlaybooksPage />;
      case 'dfir_guides':
        return <DFIRGuidesPage />;
      case 'hunting':
        return <ThreatHuntingPage />;
      case 'reports':
        return <ReportsPage />;
      case 'risk':
        return <RiskDashboardPage />;
      case 'builder':
        return <IncidentBuilderPage />;
      case 'remediation':
        return <RemediationTasksPage />;
      case 'asset_builder':
        return <AssetBuilderPage />;
      case 'admin':
        return <AdminDashboardPage />;
      case 'settings':
        return <SettingsPage />;
      default:
        return <DashboardPage onSelectIncident={handleSelectIncident} currentIncident={currentIncident} />;
    }
  };

  return (
    <div className="min-h-screen bg-gray-100 font-sans antialiased flex">
      <Sidebar activeTab={activeTab} setActiveTab={setActiveTab} isSidebarOpen={isSidebarOpen} toggleSidebar={toggleSidebar} />
      
      <div className="flex-grow min-h-screen overflow-hidden">
        <header className="bg-white shadow-lg p-3 md:p-4 sticky top-0 z-20">
          <div className="max-w-7xl mx-auto flex justify-between items-center">
            <h1 className="text-xl md:text-2xl font-bold text-gray-800 hidden md:block">{activeTab.replace(/_/g, ' ').toUpperCase()}</h1>
            <div className="bg-gray-100 text-xs rounded-lg p-2 text-gray-600 font-mono">
              User ID: <span className="text-indigo-600 break-all">{userId || 'Loading...'}</span>
            </div>
          </div>
        </header>

        <main className="max-w-7xl mx-auto py-6 px-4 sm:px-6 lg:px-8">
          {renderContent()}
        </main>
      </div>
    </div>
  );
};

export default App;
