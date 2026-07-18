"use client";

import { useEffect, useState } from "react";
import { Command } from "cmdk";
import { useRouter } from "next/navigation";
import {
    Home,
    FileText,
    Settings,
    Search,
    Eye,
    EyeOff,
    Zap,
    Download
} from "lucide-react";
import { useFocusMode } from "@/contexts/FocusModeContext";
import toast from "react-hot-toast";

interface CommandPaletteProps {
    open: boolean;
    onOpenChange: (open: boolean) => void;
}

export default function CommandPalette({ open, onOpenChange }: CommandPaletteProps) {
    const router = useRouter();
    const { isFocusMode, toggleFocusMode } = useFocusMode();
    const [search, setSearch] = useState("");

    useEffect(() => {
        const down = (e: KeyboardEvent) => {
            if (e.key === "k" && (e.metaKey || e.ctrlKey)) {
                e.preventDefault();
                onOpenChange(!open);
            }
        };

        document.addEventListener("keydown", down);
        return () => document.removeEventListener("keydown", down);
    }, [open, onOpenChange]);

    const commands = [
        {
            group: "Navigation",
            items: [
                {
                    icon: Home,
                    label: "Go to Dashboard",
                    shortcut: "",
                    action: () => { router.push("/"); onOpenChange(false); }
                },
                {
                    icon: FileText,
                    label: "Go to Audits",
                    shortcut: "",
                    action: () => { router.push("/audits"); onOpenChange(false); }
                },
                {
                    icon: Settings,
                    label: "Go to Settings",
                    shortcut: "",
                    action: () => { router.push("/settings"); onOpenChange(false); }
                },
            ]
        },
        {
            group: "Actions",
            items: [
                {
                    icon: Search,
                    label: "Search Audits",
                    shortcut: "/",
                    action: () => {
                        router.push("/audits");
                        onOpenChange(false);
                        setTimeout(() => {
                            const searchInput = document.getElementById("audit-search");
                            searchInput?.focus();
                        }, 100);
                    }
                },
                {
                    icon: isFocusMode ? EyeOff : Eye,
                    label: `Switch to ${isFocusMode ? "Immersive" : "Focus"} Mode`,
                    shortcut: "",
                    action: () => {
                        toggleFocusMode();
                        toast.success(`Switched to ${!isFocusMode ? "Focus" : "Immersive"} Mode`);
                        onOpenChange(false);
                    }
                },
            ]
        },
    ];

    return (
        <Command.Dialog
            open={open}
            onOpenChange={onOpenChange}
            className="fixed inset-0 z-50"
            label="Command palette"
        >
            {/* Backdrop */}
            <div className="fixed inset-0 bg-black/80 backdrop-blur-sm" aria-hidden="true" />

            {/* Command Palette */}
            <div className="fixed top-[20%] left-1/2 -translate-x-1/2 w-full max-w-2xl">
                <div className="bg-surface border border-white/10 rounded-2xl shadow-2xl overflow-hidden">
                    <Command.Input
                        value={search}
                        onValueChange={setSearch}
                        placeholder="Type a command or search..."
                        className="w-full px-6 py-4 bg-transparent text-white text-lg placeholder:text-white/30 focus:outline-none border-b border-white/5"
                    />

                    <Command.List className="max-h-[400px] overflow-y-auto p-2">
                        <Command.Empty className="text-center py-12 text-white/40 text-sm">
                            No results found.
                        </Command.Empty>

                        {commands.map((group) => (
                            <Command.Group
                                key={group.group}
                                heading={group.group}
                                className="mb-2"
                            >
                                <div className="px-3 py-2 text-[10px] font-bold text-white/40 uppercase tracking-wider">
                                    {group.group}
                                </div>
                                {group.items.map((item) => (
                                    <Command.Item
                                        key={item.label}
                                        onSelect={item.action}
                                        className="flex items-center gap-3 px-3 py-3 rounded-lg cursor-pointer hover:bg-white/5 transition-colors group data-[selected=true]:bg-white/10"
                                    >
                                        <item.icon className="w-4 h-4 text-white/40 group-data-[selected=true]:text-white" />
                                        <span className="flex-1 text-sm text-white">{item.label}</span>
                                        {item.shortcut && (
                                            <kbd className="px-2 py-1 text-[10px] font-bold text-white/40 bg-white/5 border border-white/10 rounded">
                                                {item.shortcut}
                                            </kbd>
                                        )}
                                    </Command.Item>
                                ))}
                            </Command.Group>
                        ))}
                    </Command.List>

                    <div className="px-4 py-3 border-t border-white/5 flex items-center justify-between text-[10px] text-white/40">
                        <div className="flex items-center gap-2">
                            <kbd className="px-2 py-1 bg-white/5 border border-white/10 rounded">↑</kbd>
                            <kbd className="px-2 py-1 bg-white/5 border border-white/10 rounded">↓</kbd>
                            <span>to navigate</span>
                        </div>
                        <div className="flex items-center gap-2">
                            <kbd className="px-2 py-1 bg-white/5 border border-white/10 rounded">↵</kbd>
                            <span>to select</span>
                        </div>
                        <div className="flex items-center gap-2">
                            <kbd className="px-2 py-1 bg-white/5 border border-white/10 rounded">ESC</kbd>
                            <span>to close</span>
                        </div>
                    </div>
                </div>
            </div>
        </Command.Dialog>
    );
}
