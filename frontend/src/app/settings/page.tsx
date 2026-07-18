"use client";

import { useState, useEffect } from "react";
import { Save, Shield, Key, Sliders, Eye } from "lucide-react";
import { useFocusMode } from "@/contexts/FocusModeContext";
import toast from "react-hot-toast";

export default function SettingsPage() {
    const [apiKey, setApiKey] = useState("");
    const { isFocusMode, setFocusMode } = useFocusMode();
    const [theme, setTheme] = useState<"immersive" | "focus">(isFocusMode ? "focus" : "immersive");

    useEffect(() => {
        // Load from localStorage or env default (masked)
        const stored = localStorage.getItem("adv_api_key");
        if (stored) setApiKey(stored);

        // Sync theme with focus mode
        setTheme(isFocusMode ? "focus" : "immersive");
    }, [isFocusMode]);

    const handleSaveApiKey = () => {
        if (apiKey) {
            localStorage.setItem("adv_api_key", apiKey);
            toast.success("API Key saved successfully!");
        } else {
            toast.error("API Key cannot be empty");
        }
    };

    const handleThemeChange = (newTheme: "immersive" | "focus") => {
        setTheme(newTheme);
        setFocusMode(newTheme === "focus");
        toast.success(`Switched to ${newTheme === "focus" ? "Focus" : "Immersive"} Mode`);
    };

    return (
        <div className="space-y-12 animate-fade-in-up max-w-4xl">
            <div>
                <h1 className="text-3xl font-black italic tracking-tighter text-white mb-2">SYSTEM CONFIGURATION</h1>
                <p className="text-primaryMuted text-sm uppercase tracking-widest font-bold">
                    Global Parameters // Node X-7728
                </p>
            </div>

            <div className="grid gap-8">
                {/* API Security Section */}
                <section className="bg-surface/30 border border-white/5 rounded-2xl p-8 backdrop-blur-sm">
                    <div className="flex items-center gap-4 mb-6">
                        <div className="p-3 bg-accentBlue/10 rounded-lg text-accentBlue">
                            <Key className="w-6 h-6" />
                        </div>
                        <div>
                            <h2 className="text-xl font-bold text-white tracking-tight">API Credentials</h2>
                            <p className="text-xs text-primaryMuted uppercase tracking-wider">Access Control & Auth</p>
                        </div>
                    </div>

                    <div className="space-y-4">
                        <label className="block text-xs font-bold text-white/60 uppercase tracking-widest">
                            Adversum API Key
                        </label>
                        <div className="flex gap-4">
                            <input
                                type="password"
                                value={apiKey}
                                onChange={(e) => setApiKey(e.target.value)}
                                placeholder="adv-..."
                                className="flex-1 bg-black/50 border border-white/10 rounded-lg px-4 py-3 text-white font-mono text-sm focus:border-accentBlue focus:outline-none transition-colors"
                            />
                            <button
                                onClick={handleSaveApiKey}
                                className="bg-white text-black px-6 rounded-lg font-bold text-xs uppercase tracking-wider hover:bg-white/90 transition-colors flex items-center gap-2"
                            >
                                <Save className="w-4 h-4" />
                                Save
                            </button>
                        </div>
                        <p className="text-[10px] text-white/30">
                            Key is stored locally in your browser's secure storage. Ensure strict CORS policies on the backend.
                        </p>
                    </div>
                </section>

                {/* Engine Parameters */}
                <section className="bg-surface/30 border border-white/5 rounded-2xl p-8 backdrop-blur-sm opacity-60">
                    <div className="flex items-center gap-4 mb-6">
                        <div className="p-3 bg-accentPurple/10 rounded-lg text-accentPurple">
                            <Sliders className="w-6 h-6" />
                        </div>
                        <div>
                            <h2 className="text-xl font-bold text-white tracking-tight">Engine Parameters</h2>
                            <p className="text-xs text-primaryMuted uppercase tracking-wider">Scan Heuristics (Managed by Orchestrator)</p>
                        </div>
                    </div>

                    <div className="grid grid-cols-2 gap-4">
                        <div className="p-4 bg-black/30 rounded-lg border border-white/5 flex items-center justify-between">
                            <span className="text-sm font-bold text-white/80">Deterministic Mode</span>
                            <div className="w-8 h-4 bg-accentMint rounded-full relative cursor-not-allowed">
                                <div className="absolute right-0.5 top-0.5 w-3 h-3 bg-black rounded-full" />
                            </div>
                        </div>
                        <div className="p-4 bg-black/30 rounded-lg border border-white/5 flex items-center justify-between">
                            <span className="text-sm font-bold text-white/80">LLM Reasoning (G-ASR)</span>
                            <div className="w-8 h-4 bg-accentMint rounded-full relative cursor-not-allowed">
                                <div className="absolute right-0.5 top-0.5 w-3 h-3 bg-black rounded-full" />
                            </div>
                        </div>
                    </div>
                </section>

                {/* Display Preferences */}
                <section className="bg-surface/30 border border-white/5 rounded-2xl p-8 backdrop-blur-sm">
                    <div className="flex items-center gap-4 mb-6">
                        <div className="p-3 bg-emerald-500/10 rounded-lg text-emerald-500">
                            <Eye className="w-6 h-6" />
                        </div>
                        <div>
                            <h2 className="text-xl font-bold text-white tracking-tight">Interface Mode</h2>
                            <p className="text-xs text-primaryMuted uppercase tracking-wider">Visual Fidelity</p>
                        </div>
                    </div>

                    <div className="flex gap-4">
                        <button
                            onClick={() => handleThemeChange("immersive")}
                            className={`flex-1 p-6 rounded-xl border transition-all text-left ${theme === 'immersive' ? 'bg-white/10 border-white text-white' : 'bg-black/30 border-white/5 text-white/40 hover:border-white/20'}`}
                        >
                            <span className="block text-lg font-black italic tracking-tighter mb-2">IMMERSIVE</span>
                            <span className="text-xs">Full 3D WebGL Effects, Particles, Tilt. High GPU usage.</span>
                        </button>
                        <button
                            onClick={() => handleThemeChange("focus")}
                            className={`flex-1 p-6 rounded-xl border transition-all text-left ${theme === 'focus' ? 'bg-white/10 border-white text-white' : 'bg-black/30 border-white/5 text-white/40 hover:border-white/20'}`}
                        >
                            <span className="block text-lg font-black italic tracking-tighter mb-2">FOCUS</span>
                            <span className="text-xs">Reduced motion, high contrast, data-first layout.</span>
                        </button>
                    </div>
                    <p className="text-[10px] text-white/30 mt-4">
                        Mode preference is saved automatically and persists across sessions.
                    </p>
                </section>
            </div>
        </div>
    );
}
