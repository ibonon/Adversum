"use client";

import React, { createContext, useContext, useState, useEffect, ReactNode } from "react";

interface FocusModeContextType {
    isFocusMode: boolean;
    toggleFocusMode: () => void;
    setFocusMode: (value: boolean) => void;
}

const FocusModeContext = createContext<FocusModeContextType | undefined>(undefined);

export function FocusModeProvider({ children }: { children: ReactNode }) {
    const [isFocusMode, setIsFocusMode] = useState(false);
    const [mounted, setMounted] = useState(false);

    // Load from localStorage on mount
    useEffect(() => {
        const stored = localStorage.getItem("adversum_focus_mode");
        if (stored !== null) {
            setIsFocusMode(stored === "true");
        }
        setMounted(true);
    }, []);

    const toggleFocusMode = () => {
        setIsFocusMode((prev) => {
            const newValue = !prev;
            localStorage.setItem("adversum_focus_mode", String(newValue));
            return newValue;
        });
    };

    const setFocusMode = (value: boolean) => {
        setIsFocusMode(value);
        localStorage.setItem("adversum_focus_mode", String(value));
    };

    return (
        <FocusModeContext.Provider value={{ isFocusMode, toggleFocusMode, setFocusMode }}>
            {children}
        </FocusModeContext.Provider>
    );
}

export function useFocusMode() {
    const context = useContext(FocusModeContext);
    if (context === undefined) {
        throw new Error("useFocusMode must be used within a FocusModeProvider");
    }
    return context;
}
