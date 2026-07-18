"use client";

import { X } from "lucide-react";

interface ShortcutsHelpProps {
    open: boolean;
    onClose: () => void;
}

export default function ShortcutsHelp({ open, onClose }: ShortcutsHelpProps) {
    if (!open) return null;

    const shortcuts = [
        {
            category: "General",
            items: [
                { keys: ["Ctrl", "K"], description: "Open command palette" },
                { keys: ["?"], description: "Show this help" },
                { keys: ["ESC"], description: "Close dialogs / Clear focus" },
            ]
        },
        {
            category: "Navigation",
            items: [
                { keys: ["/"], description: "Focus search bar" },
                { keys: ["←", "→"], description: "Navigate through items" },
                { keys: ["↑", "↓"], description: "Navigate vertical lists" },
                { keys: ["Enter"], description: "Select / Open" },
            ]
        },
        {
            category: "Audits",
            items: [
                { keys: ["Space"], description: "Select audit for comparison" },
                { keys: ["c"], description: "Compare selected audits" },
                { keys: ["e"], description: "Export audit data" },
            ]
        },
    ];

    return (
        <>
            {/* Backdrop */}
            <div
                className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50"
                onClick={onClose}
                aria-hidden="true"
            />

            {/* Modal */}
            <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
                <div
                    className="bg-surface border border-white/10 rounded-2xl shadow-2xl max-w-2xl w-full max-h-[80vh] overflow-hidden"
                    role="dialog"
                    aria-modal="true"
                    aria-labelledby="shortcuts-title"
                >
                    {/* Header */}
                    <div className="px-8 py-6 border-b border-white/5 flex items-center justify-between">
                        <h2 id="shortcuts-title" className="text-2xl font-black italic tracking-tight text-white">
                            KEYBOARD SHORTCUTS
                        </h2>
                        <button
                            onClick={onClose}
                            className="text-white/40 hover:text-white transition-colors"
                            aria-label="Close shortcuts help"
                        >
                            <X className="w-6 h-6" />
                        </button>
                    </div>

                    {/* Content */}
                    <div className="px-8 py-6 overflow-y-auto max-h-[calc(80vh-5rem)]">
                        <div className="space-y-8">
                            {shortcuts.map((group) => (
                                <div key={group.category}>
                                    <h3 className="text-xs font-bold text-white/40 uppercase tracking-wider mb-4">
                                        {group.category}
                                    </h3>
                                    <div className="space-y-3">
                                        {group.items.map((shortcut, idx) => (
                                            <div key={idx} className="flex items-center justify-between py-2">
                                                <span className="text-sm text-white/80">
                                                    {shortcut.description}
                                                </span>
                                                <div className="flex items-center gap-1">
                                                    {shortcut.keys.map((key, keyIdx) => (
                                                        <>
                                                            <kbd
                                                                key={`${idx}-${keyIdx}`}
                                                                className="px-3 py-1.5 text-xs font-bold text-white bg-white/5 border border-white/10 rounded-lg min-w-[2rem] text-center"
                                                            >
                                                                {key}
                                                            </kbd>
                                                            {keyIdx < shortcut.keys.length - 1 && (
                                                                <span className="text-white/20 mx-1">+</span>
                                                            )}
                                                        </>
                                                    ))}
                                                </div>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>

                    {/* Footer */}
                    <div className="px-8 py-4 border-t border-white/5 text-center">
                        <p className="text-xs text-white/40">
                            Press <kbd className="px-2 py-1 bg-white/5 border border-white/10 rounded">ESC</kbd> to close
                        </p>
                    </div>
                </div>
            </div>
        </>
    );
}
