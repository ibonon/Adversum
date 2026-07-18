"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

const navItems = [
    { label: "Dashboard", href: "/", icon: "📊" },
    { label: "Audits", href: "/audits", icon: "🔍" },
    { label: "Immune System", href: "/immune", icon: "🛡️" },
    { label: "Settings", href: "/settings", icon: "⚙️" },
];

export default function Sidebar() {
    const pathname = usePathname();

    return (
        <aside className="w-64 border-r border-surfaceBorder bg-black flex flex-col h-screen sticky top-0">
            <div className="p-8">
                <div className="flex items-center gap-3 mb-12">
                    <div className="w-8 h-8 rounded bg-white flex items-center justify-center">
                        <span className="text-black font-black text-xl">A</span>
                    </div>
                    <span className="text-xl font-bold tracking-tighter text-white">ADVERSUM</span>
                </div>

                <nav className="space-y-1">
                    <div className="tech-label mb-4 px-3">System Navigation</div>
                    {navItems.map((item) => {
                        const isActive = pathname === item.href;
                        return (
                            <Link
                                key={item.href}
                                href={item.href}
                                aria-current={isActive ? "page" : undefined}
                                className={`flex items-center gap-3 px-3 py-2.5 rounded-lg transition-all duration-200 group ${isActive
                                    ? "bg-surface text-white shadow-[0_0_15px_rgba(255,255,255,0.05)]"
                                    : "text-primaryMuted hover:text-white hover:bg-surface/50"
                                    }`}
                            >
                                <span className={`text-lg transition-transform duration-200 ${isActive ? "scale-110" : "group-hover:scale-110"}`}>
                                    {item.icon}
                                </span>
                                <span className="text-sm font-medium tracking-tight">{item.label}</span>
                                {isActive && (
                                    <div className="ml-auto w-1 h-4 rounded-full bg-accentBlue shadow-[0_0_8px_#3B82F6]" />
                                )}
                            </Link>
                        );
                    })}
                </nav>
            </div>

            <div className="mt-auto p-8 border-t border-surfaceBorder">
                <div className="p-4 rounded-xl bg-surface/50 border border-surfaceBorder cursor-pointer hover:border-white/20 transition-all">
                    <div className="tech-label mb-2">Engine Status</div>
                    <div className="flex items-center gap-2">
                        <div className="w-2 h-2 rounded-full bg-accentMint animate-pulse" />
                        <span className="text-xs font-medium text-white">Deterministic Active</span>
                    </div>
                </div>
            </div>
        </aside>
    );
}
