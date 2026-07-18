"use client";

import { ButtonHTMLAttributes, ReactNode } from "react";

interface GlowButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
    children: ReactNode;
    variant?: "primary" | "secondary" | "success";
    size?: "sm" | "md" | "lg";
}

export default function GlowButton({
    children,
    variant = "primary",
    size = "md",
    className = "",
    ...props
}: GlowButtonProps) {
    const variants = {
        primary: "bg-accentBlue hover:bg-accentBlue/90 shadow-glow-primary hover:shadow-glow-primary",
        secondary: "bg-accentPurple hover:bg-accentPurple/90 shadow-glow-purple hover:shadow-glow-purple",
        success: "bg-accentMint hover:bg-accentMint/90 shadow-glow-mint hover:shadow-glow-mint",
    };

    const sizes = {
        sm: "px-4 py-2 text-sm",
        md: "px-6 py-3 text-base",
        lg: "px-8 py-4 text-lg",
    };

    return (
        <button
            className={`
                ${variants[variant]}
                ${sizes[size]}
                ${className}
                relative overflow-hidden
                rounded-xl font-bold text-white
                transition-all duration-300
                hover:scale-105 active:scale-95
                group
                animate-pulse-glow
            `}
            {...props}
        >
            {/* Shimmer effect */}
            <div className="absolute inset-0 -translate-x-full group-hover:translate-x-full transition-transform duration-1000 bg-gradient-to-r from-transparent via-white/20 to-transparent" />

            {/* Content */}
            <span className="relative z-10 flex items-center justify-center gap-2">
                {children}
            </span>
        </button>
    );
}
