"use client";

import { Search, X } from "lucide-react";
import { useState, useEffect } from "react";

interface SearchBarProps {
    value: string;
    onChange: (value: string) => void;
    placeholder?: string;
    className?: string;
}

export default function SearchBar({ value, onChange, placeholder = "Search audits...", className = "" }: SearchBarProps) {
    const [isFocused, setIsFocused] = useState(false);

    // Keyboard shortcut: "/" to focus search
    useEffect(() => {
        const handleKeyDown = (e: KeyboardEvent) => {
            // Only if not already in an input and user presses "/"
            if (e.key === "/" && document.activeElement?.tagName !== "INPUT") {
                e.preventDefault();
                const searchInput = document.getElementById("audit-search");
                searchInput?.focus();
            }
        };

        document.addEventListener("keydown", handleKeyDown);
        return () => document.removeEventListener("keydown", handleKeyDown);
    }, []);

    return (
        <div className={`relative ${className}`}>
            <div className={`flex items-center gap-3 bg-black/50 border rounded-lg px-4 py-3 transition-all ${isFocused ? 'border-accentBlue' : 'border-white/10'
                }`}>
                <Search className="w-4 h-4 text-white/40" aria-hidden="true" />
                <input
                    id="audit-search"
                    type="text"
                    value={value}
                    onChange={(e) => onChange(e.target.value)}
                    onFocus={() => setIsFocused(true)}
                    onBlur={() => setIsFocused(false)}
                    placeholder={placeholder}
                    className="flex-1 bg-transparent text-white text-sm focus:outline-none placeholder:text-white/30"
                    aria-label="Search audits by ID, status, or date"
                    autoComplete="off"
                />
                {value && (
                    <button
                        onClick={() => onChange("")}
                        className="text-white/40 hover:text-white transition-colors"
                        aria-label="Clear search"
                    >
                        <X className="w-4 h-4" />
                    </button>
                )}
            </div>
            {!value && (
                <div className="absolute right-4 top-1/2 -translate-y-1/2 pointer-events-none">
                    <kbd className="px-2 py-1 text-[10px] font-bold text-white/20 bg-white/5 border border-white/10 rounded">
                        /
                    </kbd>
                </div>
            )}
        </div>
    );
}
