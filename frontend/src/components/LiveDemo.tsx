"use client";

import { useState } from "react";
import { Code2, Shield, Zap, CheckCircle2, AlertTriangle } from "lucide-react";
import GlowButton from "./GlowButton";

const vulnerableCode = `function processUserInput(data) {
  // Vulnerable: No input validation
  const query = "SELECT * FROM users WHERE id = " + data.userId;
  database.execute(query);
  
  // Vulnerable: XSS risk
  document.innerHTML = data.message;
  
  return true;
}`;

const secureCode = `function processUserInput(data) {
  // ✓ Input validation
  const userId = sanitize(data.userId);
  const query = "SELECT * FROM users WHERE id = ?";
  database.execute(query, [userId]);
  
  // ✓ XSS prevention
  const sanitized = DOMPurify.sanitize(data.message);
  element.textContent = sanitized;
  
  return true;
}`;

export default function LiveDemo() {
    const [isScanning, setIsScanning] = useState(false);
    const [showResults, setShowResults] = useState(false);
    const [progress, setProgress] = useState(0);

    const runDemo = () => {
        setIsScanning(true);
        setShowResults(false);
        setProgress(0);

        const interval = setInterval(() => {
            setProgress((prev) => {
                if (prev >= 100) {
                    clearInterval(interval);
                    setIsScanning(false);
                    setShowResults(true);
                    return 100;
                }
                return prev + 2;
            });
        }, 30);
    };

    return (
        <div className="relative py-32 overflow-hidden">
            {/* Background */}
            <div className="absolute inset-0 bg-gradient-to-b from-background via-surface/30 to-background" />

            <div className="relative z-10 max-w-7xl mx-auto px-6">
                {/* Header */}
                <div className="text-center mb-16">
                    <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-accentPurple/10 border border-accentPurple/20 mb-6">
                        <Zap className="w-4 h-4 text-accentPurple" />
                        <span className="text-sm font-medium text-accentPurple">
                            See It In Action
                        </span>
                    </div>
                    <h2 className="text-5xl font-black text-white mb-4">
                        Watch Adversum Work Its Magic
                    </h2>
                    <p className="text-xl text-primaryMuted max-w-2xl mx-auto">
                        Real-time vulnerability detection and autonomous fixing in seconds
                    </p>
                </div>

                {/* Demo Container */}
                <div className="grid lg:grid-cols-2 gap-8 mb-12">
                    {/* Before - Vulnerable Code */}
                    <div className="relative group">
                        <div className="absolute -inset-1 bg-gradient-to-r from-error/50 to-warning/50 rounded-2xl blur opacity-25 group-hover:opacity-50 transition duration-300" />
                        <div className="relative p-6 rounded-2xl bg-surface border border-surfaceBorder">
                            <div className="flex items-center justify-between mb-4">
                                <div className="flex items-center gap-2">
                                    <AlertTriangle className="w-5 h-5 text-error" />
                                    <span className="font-bold text-white">Vulnerable Code</span>
                                </div>
                                <span className="px-3 py-1 rounded-full bg-error/20 text-error text-xs font-bold">
                                    3 CRITICAL ISSUES
                                </span>
                            </div>
                            <pre className="text-sm text-primaryMuted font-mono overflow-x-auto">
                                <code>{vulnerableCode}</code>
                            </pre>
                        </div>
                    </div>

                    {/* After - Secure Code */}
                    <div className="relative group">
                        <div className="absolute -inset-1 bg-gradient-to-r from-accentMint/50 to-accentBlue/50 rounded-2xl blur opacity-25 group-hover:opacity-50 transition duration-300" />
                        <div className="relative p-6 rounded-2xl bg-surface border border-surfaceBorder">
                            <div className="flex items-center justify-between mb-4">
                                <div className="flex items-center gap-2">
                                    <CheckCircle2 className="w-5 h-5 text-accentMint" />
                                    <span className="font-bold text-white">Adversum Fixed</span>
                                </div>
                                <span className="px-3 py-1 rounded-full bg-accentMint/20 text-accentMint text-xs font-bold">
                                    ALL SECURE
                                </span>
                            </div>
                            <pre className="text-sm text-primaryMuted font-mono overflow-x-auto">
                                <code>{secureCode}</code>
                            </pre>
                        </div>
                    </div>
                </div>

                {/* Scan Button & Progress */}
                <div className="text-center">
                    <GlowButton
                        variant="primary"
                        size="lg"
                        onClick={runDemo}
                        disabled={isScanning}
                    >
                        <Shield className="w-5 h-5" />
                        {isScanning ? "Scanning..." : "Run Live Scan"}
                    </GlowButton>

                    {/* Progress Bar */}
                    {isScanning && (
                        <div className="mt-8 max-w-2xl mx-auto">
                            <div className="flex justify-between text-sm text-primaryMuted mb-2">
                                <span>Analyzing code patterns...</span>
                                <span>{progress}%</span>
                            </div>
                            <div className="h-2 bg-surface rounded-full overflow-hidden">
                                <div
                                    className="h-full bg-gradient-to-r from-accentBlue via-accentPurple to-accentMint transition-all duration-300"
                                    style={{ width: `${progress}%` }}
                                />
                            </div>
                        </div>
                    )}

                    {/* Results */}
                    {showResults && (
                        <div className="mt-12 grid md:grid-cols-3 gap-6 max-w-4xl mx-auto animate-scale-in">
                            {[
                                { icon: Shield, label: "Vulnerabilities Found", value: "3", color: "error" },
                                { icon: Zap, label: "Auto-Fixed", value: "3", color: "accentMint" },
                                { icon: Code2, label: "Time Saved", value: "2.5h", color: "accentBlue" },
                            ].map((stat, i) => (
                                <div
                                    key={i}
                                    className="p-6 rounded-xl bg-surface/80 backdrop-blur-sm border border-surfaceBorder"
                                >
                                    <stat.icon className={`w-8 h-8 text-${stat.color} mb-3 mx-auto`} />
                                    <div className="text-3xl font-black text-white mb-1">{stat.value}</div>
                                    <div className="text-sm text-primaryMuted">{stat.label}</div>
                                </div>
                            ))}
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}
