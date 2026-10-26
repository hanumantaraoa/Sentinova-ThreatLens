"use client";

import React, { useState, useEffect } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";

interface AlertPayload {
  event: string;
  indicator_id: string;
  value: string;
  type: string;
  severity_score: number;
  tlp: string;
  status: string;
}

export default function SOCAnalystDashboard() {
  const queryClient = useQueryClient();
  const [liveAlerts, setLiveAlerts] = useState<AlertPayload[]>([]);
  const [connectionStatus, setConnectionStatus] = useState<"connecting" | "online" | "offline">("connecting");

  // 1. TanStack Query for REST API Hydration (NFR-01: Sub-2 Second Page Load)
  const { data: indicators, isLoading } = useQuery({
    queryKey: ["indicators"],
    queryFn: async () => {
      const token = localStorage.getItem("threatlens_token") || "MOCK_TOKEN";
      const res = await fetch("http://localhost:8000/api/v1/indicators", {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) throw new Error("Failed to sync structural indicator queues.");
      return res.json();
    },
    refetchOnWindowFocus: false,
  });

  // 2. WebSocket Channel Broker Integration (NFR-02: Sub-5 Second Alert Delivery)
  useEffect(() => {
    const token = localStorage.getItem("threatlens_token") || "MOCK_TOKEN";
    const socket = new WebSocket(`ws://localhost:8000/api/v1/ws/alerts/stream?token=${token}`);

    socket.onopen = () => setConnectionStatus("online");
    socket.onclose = () => setConnectionStatus("offline");

    socket.onmessage = (event) => {
      const payload: AlertPayload = JSON.parse(event.data);
      if (payload.event === "NEW_HIGH_SEVERITY_ALERT") {
        // Prepend fresh incoming threat parameters natively into the triage surface
        setLiveAlerts((prev) => [payload, ...prev]);
        // Invalidate stale data trees to force asynchronous cache updating
        queryClient.invalidateQueries({ queryKey: ["indicators"] });
      }
    };

    return () => socket.close();
  }, [queryClient]);

  // Helper calculation to apply consistent semantic colors matching Section 12.6
  const getSeverityBadgeClass = (score: number) => {
    if (score >= 80) return "bg-red-950 text-red-400 border-red-800";
    if (score >= 60) return "bg-orange-950 text-orange-400 border-orange-800";
    return "bg-yellow-950 text-yellow-400 border-yellow-800";
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 font-sans p-6 selection:bg-cyan-500 selection:text-slate-900">
      {/* GLOBAL APPLICATION SHELL HEADER */}
      <header className="flex justify-between items-center border-b border-slate-800 pb-4 mb-6">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
            🛡️ ThreatLens <span className="text-xs font-mono font-normal px-2 py-0.5 rounded bg-slate-900 text-slate-400 border border-slate-800">Enterprise Core</span>
          </h1>
          <p className="text-sm text-slate-400 mt-1">Security Operations Centre Triage Interface — Persona: Priya Nair</p>
        </div>

        {/* NETWORK LIVE TELEMETRY ANCHOR */}
        <div className="flex items-center gap-2 font-mono text-xs">
          <span className={`h-2.5 w-2.5 rounded-full ${connectionStatus === "online" ? "bg-emerald-500 animate-pulse" : "bg-rose-500"}`} />
          <span className="text-slate-400">WebSocket: {connectionStatus.toUpperCase()}</span>
        </div>
      </header>

      {/* THREE-COLUMN RISKPosture SUMMARY OVERVIEWS */}
      <section className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
        <div className="bg-slate-900 p-4 rounded-xl border border-slate-800 shadow-xl">
          <p className="text-xs font-mono uppercase tracking-wider text-slate-400">Ecosystem Throughput</p>
          <p className="text-3xl font-extrabold text-white mt-2">≥ 50,000 <span className="text-sm font-normal text-slate-500">/ hr</span></p>
        </div>
        <div className="bg-slate-900 p-4 rounded-xl border border-slate-800 shadow-xl">
          <p className="text-xs font-mono uppercase tracking-wider text-slate-400">Deduplicated Indicators</p>
          <p className="text-3xl font-extrabold text-cyan-400 mt-2">{indicators ? indicators.length : "..."}</p>
        </div>
        <div className="bg-slate-900 p-4 rounded-xl border border-slate-800 shadow-xl">
          <p className="text-xs font-mono uppercase tracking-wider text-slate-400">Live Streaming Incidents</p>
          <p className="text-3xl font-extrabold text-rose-500 mt-2">{liveAlerts.length}</p>
        </div>
      </section>

      {/* CORE OPERATIONAL DATA LAYOUT SPLIT PANEL */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">

        {/* LEFT COLUMN: LIVE STREAM REAL-TIME BROKER TOASTS */}
        <div className="bg-slate-900 rounded-xl border border-slate-800 p-5 shadow-2xl">
          <h2 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
            📡 Live WebSocket Stream <span className="text-xs bg-rose-950 text-rose-400 border border-rose-800 px-2 py-0.5 rounded font-mono">Real-Time</span>
          </h2>

          <div className="space-y-3 max-h-[500px] overflow-y-auto pr-2 custom-scrollbar">
            {liveAlerts.length === 0 ? (
              <div className="text-center py-12 border border-dashed border-slate-800 rounded-lg text-slate-500 font-mono text-sm">
                Awaiting asynchronous data packet injections...
              </div>
            ) : (
              liveAlerts.map((alert, index) => (
                <div key={index} className="p-4 rounded-lg bg-slate-950 border border-slate-800 hover:border-slate-700 transition flex items-center justify-between shadow-md">
                  <div>
                    <span className="text-xs font-mono text-cyan-400 bg-cyan-950/40 px-2 py-0.5 rounded border border-cyan-900/50">{alert.type.toUpperCase()}</span>
                    <p className="font-mono text-sm font-bold text-slate-200 mt-2 selection:bg-amber-400 selection:text-slate-900 break-all">{alert.value}</p>
                  </div>
                  <div className={`px-2.5 py-1 text-xs font-mono font-bold rounded border ${getSeverityBadgeClass(alert.severity_score)}`}>
                    CRIT-{alert.severity_score}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* RIGHT COLUMN: RECONCILED DEDUPLICATED HISTORICAL GRID */}
        <div className="bg-slate-900 rounded-xl border border-slate-800 p-5 shadow-2xl">
          <h2 className="text-lg font-bold text-white mb-4">🗃️ Canonical IOC Triage Ledger</h2>

          <div className="space-y-3 max-h-[500px] overflow-y-auto pr-2 custom-scrollbar">
            {isLoading ? (
              <div className="space-y-3 animate-pulse">
                {[...Array(4)].map((_, i) => <div key={i} className="h-16 bg-slate-800 rounded-lg" />)}
              </div>
            ) : indicators?.length === 0 ? (
              <div className="text-center py-12 text-slate-500 font-mono text-sm">No canonical trace documents found.</div>
            ) : (
              indicators?.map((ioc: any) => (
                <div key={ioc.id} className="p-4 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-mono text-slate-400 bg-slate-900 px-1.5 py-0.5 rounded border border-slate-800">{ioc.type.toUpperCase()}</span>
                      <span className="text-xs font-mono text-amber-400 bg-amber-950/40 px-1.5 py-0.5 rounded border border-amber-900/50">TLP:{ioc.tlp.toUpperCase()}</span>
                    </div>
                    <p className="font-mono text-sm font-semibold text-slate-300 mt-2 break-all">{ioc.value}</p>
                  </div>
                  <div className={`px-2.5 py-1 text-xs font-mono font-bold rounded border ${getSeverityBadgeClass(ioc.severity_score)}`}>
                    SCORE-{ioc.severity_score}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

      </div>
    </div>
  );
}
