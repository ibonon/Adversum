"use client";

import { useEffect, useRef, useState } from "react";

interface AnimatedCounterProps {
    value: number;
    duration?: number;
    suffix?: string;
    prefix?: string;
    decimals?: number;
    className?: string;
}

export default function AnimatedCounter({
    value,
    duration = 2000,
    suffix = "",
    prefix = "",
    decimals = 0,
    className = ""
}: AnimatedCounterProps) {
    const [count, setCount] = useState(0);
    const countRef = useRef(0);
    const startTimeRef = useRef<number | null>(null);

    useEffect(() => {
        startTimeRef.current = null;

        const animate = (timestamp: number) => {
            if (!startTimeRef.current) startTimeRef.current = timestamp;
            const progress = Math.min((timestamp - startTimeRef.current) / duration, 1);

            // Easing function for smooth animation
            const easeOutQuart = 1 - Math.pow(1 - progress, 4);
            countRef.current = value * easeOutQuart;
            setCount(countRef.current);

            if (progress < 1) {
                requestAnimationFrame(animate);
            }
        };

        requestAnimationFrame(animate);
    }, [value, duration]);

    return (
        <span className={className}>
            {prefix}{count.toFixed(decimals)}{suffix}
        </span>
    );
}
