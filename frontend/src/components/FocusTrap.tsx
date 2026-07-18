"use client";

import { useEffect, useRef } from "react";

interface FocusTrapProps {
    children: React.ReactNode;
    isActive: boolean;
}

export default function FocusTrap({ children, isActive }: FocusTrapProps) {
    const rootRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        if (!isActive) return;

        const root = rootRef.current;
        if (!root) return;

        const focusableElements = root.querySelectorAll(
            'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
        );

        const firstElement = focusableElements[0] as HTMLElement;
        const lastElement = focusableElements[focusableElements.length - 1] as HTMLElement;

        const handleTab = (e: KeyboardEvent) => {
            if (e.key !== "Tab") return;

            if (e.shiftKey) {
                if (document.activeElement === firstElement) {
                    e.preventDefault();
                    lastElement.focus();
                }
            } else {
                if (document.activeElement === lastElement) {
                    e.preventDefault();
                    firstElement.focus();
                }
            }
        };

        root.addEventListener("keydown", handleTab);

        // Focus first element on mount
        if (firstElement) {
            firstElement.focus();
        }

        return () => root.removeEventListener("keydown", handleTab);
    }, [isActive]);

    return <div ref={rootRef}>{children}</div>;
}
