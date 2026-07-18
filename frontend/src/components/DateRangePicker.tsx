"use client";

import { Calendar, X } from "lucide-react";
import { useState } from "react";
import { DayPicker } from "react-day-picker";
import { format, subDays, startOfMonth, endOfMonth } from "date-fns";
import "react-day-picker/dist/style.css";

interface DateRange {
    from: Date | undefined;
    to: Date | undefined;
}

interface DateRangePickerProps {
    value: DateRange;
    onChange: (range: DateRange) => void;
}

export default function DateRangePicker({ value, onChange }: DateRangePickerProps) {
    const [isOpen, setIsOpen] = useState(false);

    const presets = [
        { label: "Today", getValue: () => ({ from: new Date(), to: new Date() }) },
        { label: "Last 7 days", getValue: () => ({ from: subDays(new Date(), 7), to: new Date() }) },
        { label: "Last 30 days", getValue: () => ({ from: subDays(new Date(), 30), to: new Date() }) },
        { label: "This month", getValue: () => ({ from: startOfMonth(new Date()), to: endOfMonth(new Date()) }) },
    ];

    const handlePresetClick = (preset: typeof presets[0]) => {
        onChange(preset.getValue());
        setIsOpen(false);
    };

    const handleClear = () => {
        onChange({ from: undefined, to: undefined });
    };

    const isActive = value.from || value.to;

    return (
        <div className="relative">
            <button
                onClick={() => setIsOpen(!isOpen)}
                className={`flex items-center gap-2 px-4 py-2 rounded-lg border transition-all text-sm font-bold ${isActive
                        ? 'bg-accentBlue/20 border-accentBlue/30 text-accentBlue'
                        : 'bg-black/50 border-white/10 text-white/60 hover:border-white/20'
                    }`}
                aria-label="Select date range"
                aria-expanded={isOpen}
            >
                <Calendar className="w-4 h-4" />
                {value.from && value.to ? (
                    <span>{format(value.from, "MMM d")} - {format(value.to, "MMM d")}</span>
                ) : (
                    <span>Date Range</span>
                )}
            </button>

            {isOpen && (
                <>
                    {/* Backdrop */}
                    <div
                        className="fixed inset-0 z-40"
                        onClick={() => setIsOpen(false)}
                        aria-hidden="true"
                    />

                    {/* Dropdown */}
                    <div className="absolute top-full mt-2 right-0 z-50 bg-surface border border-white/10 rounded-xl shadow-2xl overflow-hidden backdrop-blur-xl">
                        <div className="p-4 border-b border-white/5">
                            <h3 className="text-xs font-bold text-white/60 uppercase tracking-wider mb-3">Quick Presets</h3>
                            <div className="grid gap-2">
                                {presets.map((preset) => (
                                    <button
                                        key={preset.label}
                                        onClick={() => handlePresetClick(preset)}
                                        className="text-left px-3 py-2 text-sm text-white/80 hover:bg-white/5 rounded-lg transition-colors"
                                    >
                                        {preset.label}
                                    </button>
                                ))}
                            </div>
                        </div>

                        <div className="p-4 date-picker-container">
                            <DayPicker
                                mode="range"
                                selected={value}
                                onSelect={(range) => onChange(range || { from: undefined, to: undefined })}
                                numberOfMonths={1}
                                className="text-white"
                            />
                        </div>

                        {isActive && (
                            <div className="p-4 border-t border-white/5">
                                <button
                                    onClick={handleClear}
                                    className="w-full flex items-center justify-center gap-2 px-4 py-2 text-sm font-bold text-white/60 hover:text-white bg-white/5 hover:bg-white/10 rounded-lg transition-all"
                                >
                                    <X className="w-4 h-4" />
                                    Clear Selection
                                </button>
                            </div>
                        )}
                    </div>
                </>
            )}
        </div>
    );
}
