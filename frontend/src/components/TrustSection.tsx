"use client";

import { Star, Building2 } from "lucide-react";

const testimonials = [
    {
        quote: "Adversum found critical vulnerabilities our team missed for months. The autonomous fixes saved us weeks of work.",
        author: "Sarah Chen",
        role: "CISO",
        company: "TechCorp Global",
        rating: 5,
    },
    {
        quote: "The deterministic approach gives us confidence that nothing slips through. It's like having a security team that never sleeps.",
        author: "Michael Rodriguez",
        role: "VP Engineering",
        company: "CloudScale Inc",
        rating: 5,
    },
    {
        quote: "ROI was immediate. We reduced security incidents by 85% in the first quarter.",
        author: "Emily Watson",
        role: "CTO",
        company: "FinTech Solutions",
        rating: 5,
    },
];

const clients = [
    "TechCorp", "CloudScale", "FinTech Solutions", "DataVault", "SecureNet", "CyberShield"
];

export default function TrustSection() {
    return (
        <div className="relative py-32 overflow-hidden">
            {/* Background gradient */}
            <div className="absolute inset-0 bg-gradient-to-b from-background via-surface/50 to-background" />

            <div className="relative z-10 max-w-7xl mx-auto px-6">
                {/* Section header */}
                <div className="text-center mb-16">
                    <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-accentMint/10 border border-accentMint/20 mb-6">
                        <Star className="w-4 h-4 text-accentMint fill-accentMint" />
                        <span className="text-sm font-medium text-accentMint">
                            Trusted by Industry Leaders
                        </span>
                    </div>
                    <h2 className="text-5xl font-black text-white mb-4">
                        Don't Just Take Our Word
                    </h2>
                    <p className="text-xl text-primaryMuted max-w-2xl mx-auto">
                        Join hundreds of companies protecting their infrastructure with Adversum
                    </p>
                </div>

                {/* Testimonials grid */}
                <div className="grid md:grid-cols-3 gap-8 mb-20">
                    {testimonials.map((testimonial, i) => (
                        <div
                            key={i}
                            className="group relative p-8 rounded-2xl bg-surface/80 backdrop-blur-sm border border-surfaceBorder hover:border-white/20 transition-all duration-300 hover:scale-105 animate-slide-up"
                            style={{ animationDelay: `${i * 100}ms` }}
                        >
                            {/* Glow effect */}
                            <div className="absolute inset-0 rounded-2xl bg-accentBlue/5 opacity-0 group-hover:opacity-100 transition-opacity duration-300" />

                            <div className="relative">
                                {/* Rating */}
                                <div className="flex gap-1 mb-4">
                                    {Array.from({ length: testimonial.rating }).map((_, i) => (
                                        <Star key={i} className="w-5 h-5 text-accentMint fill-accentMint" />
                                    ))}
                                </div>

                                {/* Quote */}
                                <p className="text-white mb-6 leading-relaxed">
                                    "{testimonial.quote}"
                                </p>

                                {/* Author */}
                                <div className="flex items-center gap-4">
                                    <div className="w-12 h-12 rounded-full bg-gradient-to-br from-accentBlue to-accentPurple flex items-center justify-center text-white font-bold">
                                        {testimonial.author.split(' ').map(n => n[0]).join('')}
                                    </div>
                                    <div>
                                        <div className="font-bold text-white">{testimonial.author}</div>
                                        <div className="text-sm text-primaryMuted">
                                            {testimonial.role} at {testimonial.company}
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    ))}
                </div>

                {/* Client logos */}
                <div className="text-center">
                    <p className="text-sm text-primaryMuted mb-8 uppercase tracking-wider font-bold">
                        Protecting Infrastructure For
                    </p>
                    <div className="flex flex-wrap items-center justify-center gap-12">
                        {clients.map((client) => (
                            <div
                                key={client}
                                className="px-6 py-3 rounded-lg bg-white/5 border border-white/10 hover:border-white/20 transition-all duration-300 hover:scale-110"
                            >
                                <Building2 className="w-6 h-6 text-white/60 inline-block mr-2" />
                                <span className="text-white/60 font-bold text-lg">{client}</span>
                            </div>
                        ))}
                    </div>
                </div>

                {/* Stats bar */}
                <div className="mt-20 grid grid-cols-3 gap-8 max-w-4xl mx-auto">
                    {[
                        { value: "500+", label: "Enterprise Clients" },
                        { value: "99.9%", label: "Uptime SLA" },
                        { value: "24/7", label: "Expert Support" },
                    ].map((stat, i) => (
                        <div key={i} className="text-center">
                            <div className="text-4xl font-black text-white mb-2">{stat.value}</div>
                            <div className="text-sm text-primaryMuted">{stat.label}</div>
                        </div>
                    ))}
                </div>
            </div>
        </div>
    );
}
