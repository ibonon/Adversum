"use client";

import { useEffect, useState } from "react";
import { ArrowDown } from "lucide-react";

export default function SkipToContent() {
    const [isVisible, setIsVisible] = useState(false);

    const handleFocus = () => setIsVisible(true);
    const handleBlur = () => setIsVisible(false);

    return (
        <a
            href="#main-content"
            onFocus={handleFocus}
            onBlur={handleBlur}
            className={`fixed top-4 left-4 z-[100] bg-accentBlue text-black font-bold px-6 py-3 rounded-lg shadow-lg border-2 border-white transition-transform duration-200 flex items-center gap-2 ${isVisible ? "translate-y-0" : "-translate-y-[200%]"
                }`}
        >
            Skip to content
            <ArrowDown className="w-4 h-4" />
        </a>
    );
}
