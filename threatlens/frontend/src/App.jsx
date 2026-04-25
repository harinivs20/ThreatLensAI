import React from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import Navbar    from './components/Navbar.jsx';
import Scanner   from './pages/Scanner.jsx';
import BulkScan  from './pages/BulkScan.jsx';
import Dashboard from './pages/Dashboard.jsx';
import Campaigns from './pages/Campaigns.jsx';
import './App.css';

export default function App() {
  return (
    <BrowserRouter>
      <Navbar/>
      <main className="app-main">
        <Routes>
          <Route path="/"          element={<Scanner/>}/>
          <Route path="/bulk"      element={<BulkScan/>}/>
          <Route path="/dashboard" element={<Dashboard/>}/>
          <Route path="/campaigns" element={<Campaigns/>}/>
        </Routes>
      </main>
    </BrowserRouter>
  );
}
