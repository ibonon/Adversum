"use client";

import { Shield, Zap, Lock, TrendingUp } from "lucide-react";
import AnimatedCounter from "./AnimatedCounter";
import GlowButton from "./GlowButton";

export default function HeroSection() {
    return (
        <div className="relative min-h-screen flex items-center justify-center overflow-hidden">
            {/* Mesh gradient background */}
            <div className="absolute inset-0 bg-mesh-gradient opacity-30" />

            {/* Content */}
            <div className="relative z-10 max-w-7xl mx-auto px-6 py-20 text-center">
                {/* Badge */}
                <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-accentBlue/10 border border-accentBlue/20 mb-8 animate-slide-up">
                    <div className="w-2 h-2 rounded-full bg-accentMint animate-pulse" />
                    <span className="text-sm font-medium text-accentBlue">
                        Trusted by Fortune 500 Companies
                    </span>
                </div>

                {/* Main headline */}
                <h1 className="text-6xl md:text-7xl lg:text-8xl font-black tracking-tight text-white mb-6 animate-fade-in">
                    Security That
                    <br />
                    <span className="bg-clip-text text-transparent bg-cyber-gradient animate-glow-pulse">
                        Thinks Ahead
                    </span>
                </h1>

                {/* Subheadline */}
                <p className="text-xl md:text-2xl text-primaryMuted max-w-3xl mx-auto mb-12 animate-slide-up">
                    Adversum uses deterministic AI to find, fix, and prevent vulnerabilities
                    before they become threats. Autonomous security that never sleeps.
                </p>

                {/* CTA Buttons */}
                <div className="flex flex-col sm:flex-row gap-4 justify-center mb-20 animate-scale-in">
                    <GlowButton variant="primary" size="lg">
                        <Zap className="w-5 h-5" />
                        Start Free Audit
                    </GlowButton>
                    <button className="px-8 py-4 rounded-xl font-bold text-white border-2 border-white/20 hover:border-white/40 hover:bg-white/5 transition-all duration-300">
                        Watch Demo
                    </button>
                </div>

                {/* Stats Grid */}
                <div className="grid grid-cols-2 md:grid-cols-4 gap-8 max-w-5xl mx-auto">
                    {[
                        { icon: Shield, value: 99.9, suffix: "%", label: "Threat Detection Rate", color: "accentBlue" },
                        { icon: Zap, value: 10000, suffix: "+", label: "Vulnerabilities Fixed", color: "accentPurple" },
                        { icon: Lock, value: 24, suffix: "/7", label: "Autonomous Protection", color: "accentMint" },
                        { icon: TrendingUp, value: 85, suffix: "%", label: "Faster Than Manual", color: "accentBlue" },
                    ].map((stat, i) => (
                        <div
                            key={i}
                            className="group relative p-6 rounded-2xl bg-surface/50 backdrop-blur-sm border border-surfaceBorder hover:border-white/20 transition-all duration-300 hover:scale-105 animate-slide-up"
                            style={{ animationDelay: `${i * 100}ms` }}
                        >
                            {/* Glow effect on hover */}
                            <div className={`absolute inset-0 rounded-2xl bg-${stat.color}/5 opacity-0 group-hover:opacity-100 transition-opacity duration-300`} />

                            <div className="relative">
                                <stat.icon className={`w-8 h-8 text-${stat.color} mb-4 mx-auto`} />
                                <div className="text-4xl font-black text-white mb-2">
                                    <AnimatedCounter
                                        value={stat.value}
                                        suffix={stat.suffix}
                                        decimals={stat.suffix === "%" ? 1 : 0}
                                    />
                                </div>
                                <div className="text-sm text-primaryMuted font-medium">
                                    {stat.label}
                                </div>
                            </div>
                        </div>
                    ))}
                </div>

                {/* Trust badges */}
                <div className="mt-16 flex flex-wrap items-center justify-center gap-8 opacity-50">
                    {["SOC 2 Type II", "ISO 27001", "GDPR Compliant", "HIPAA Ready"].map((badge) => (
                        <div key={badge} className="px-4 py-2 rounded-lg bg-white/5 border border-white/10 text-sm font-medium text-white">
                            {badge}
                        </div>
                    ))}
                </div>
            </div>

            {/* Gradient orbs */}
            <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-accentBlue/20 rounded-full blur-3xl animate-float" />
            <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-accentPurple/20 rounded-full blur-3xl animate-float" style={{ animationDelay: "2s" }} />
        </div>
    );
}
