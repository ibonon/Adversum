"use client";

import { useState } from "react";
import CommandPalette from "@/components/CommandPalette";
import ShortcutsHelp from "@/components/ShortcutsHelp";
import { useKeyboardShortcuts } from "@/lib/useKeyboardShortcuts";

export default function KeyboardShortcutsWrapper({ children }: { children: React.ReactNode }) {
    const [commandPaletteOpen, setCommandPaletteOpen] = useState(false);
    const [shortcutsHelpOpen, setShortcutsHelpOpen] = useState(false);

    useKeyboardShortcuts(
        () => setCommandPaletteOpen(true),
        () => setShortcutsHelpOpen(true)
    );

    return (
        <>
            {children}
            <CommandPalette
                open={commandPaletteOpen}
                onOpenChange={setCommandPaletteOpen}
            />
            <ShortcutsHelp
                open={shortcutsHelpOpen}
                onClose={() => setShortcutsHelpOpen(false)}
            />
        </>
    );
}
