/**
 * Forensics++ (ForensicsPP.com)
 * Local-first browser forensics workbench
 *
 * Copyright (c) 2026 DyNooob. All rights reserved.
 * Author: DyNooob
 * Website: https://www.forensicspp.com
 * Platform: DigiForensics.cn
 * Project: https://github.com/DyNooob/ForensicsPP
 *
 * Forensics++ is an open-source, browser-side toolkit for CTF/MISC,
 * lightweight forensic triage, encoding/decoding, metadata inspection,
 * hashes, archive parsing, and local analysis.
 *
 * Do not use this project for unauthorized access, intrusion,
 * privacy infringement, or unlawful activity.
 *
 * Released under the MIT License.
 * Full source code: https://github.com/DyNooob/ForensicsPP
 */

import React from "react";
import { CloseOutlined } from "@ant-design/icons";
import { AButton } from "./ui";
import type { Translation } from "../i18n";
import type { AppCommand } from "../models";

export function CommandPalette({
  t,
  query,
  commands,
  onQueryChange,
  onClose,
  shouldIgnoreBackdropClose,
  onRun
}: {
  t: Translation;
  query: string;
  commands: AppCommand[];
  onQueryChange: (value: string) => void;
  onClose: () => void;
  shouldIgnoreBackdropClose?: () => boolean;
  onRun: (command: AppCommand) => void;
}) {
  const inputRef = React.useRef<HTMLInputElement | null>(null);
  const resultRef = React.useRef<HTMLDivElement | null>(null);
  const [selectedIndex, setSelectedIndex] = React.useState(0);
  const selectedCommand = commands[Math.min(selectedIndex, Math.max(commands.length - 1, 0))];
  const grouped = commands.reduce<Array<{ group: string; items: AppCommand[] }>>((groups, command) => {
    const current = groups.find((group) => group.group === command.group);
    if (current) current.items.push(command);
    else groups.push({ group: command.group, items: [command] });
    return groups;
  }, []);

  React.useEffect(() => {
    inputRef.current?.focus();
  }, []);
  React.useEffect(() => {
    setSelectedIndex(0);
  }, [query]);
  React.useEffect(() => {
    if (!commands.length) {
      setSelectedIndex(0);
      return;
    }
    setSelectedIndex((value) => Math.min(value, commands.length - 1));
  }, [commands.length]);
  React.useEffect(() => {
    resultRef.current?.querySelector<HTMLElement>(".command-item.active")?.scrollIntoView({ block: "nearest" });
  }, [selectedIndex]);

  return (
    <div
      className="modal-backdrop command-backdrop"
      role="presentation"
      onClick={(event) => {
        if (event.target !== event.currentTarget || shouldIgnoreBackdropClose?.()) return;
        onClose();
      }}
    >
      <div className="modal-panel command-panel" role="dialog" aria-modal="true" aria-labelledby="command-title" onClick={(event) => event.stopPropagation()}>
        <div className="command-title-row">
          <h2 id="command-title">{t.commandPalette}</h2>
          <AButton className="modal-close-button" variant="text" icon={<CloseOutlined aria-hidden="true" />} aria-label={t.close} title={t.close} onClick={onClose} />
        </div>
        <input
          ref={inputRef}
          className="command-search"
          value={query}
          aria-label={t.commandPlaceholder}
          placeholder={t.commandPlaceholder}
          onChange={(event) => onQueryChange(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === "ArrowDown") {
              event.preventDefault();
              setSelectedIndex((value) => commands.length ? (value + 1) % commands.length : 0);
              return;
            }
            if (event.key === "ArrowUp") {
              event.preventDefault();
              setSelectedIndex((value) => commands.length ? (value - 1 + commands.length) % commands.length : 0);
              return;
            }
            if (event.key === "Enter" && selectedCommand) {
              event.preventDefault();
              onRun(selectedCommand);
              return;
            }
            if (event.key === "Escape") {
              event.preventDefault();
              onClose();
            }
          }}
        />
        <div className="command-results" ref={resultRef}>
          {grouped.map((group) => (
            <section key={group.group}>
              <h3>{group.group}</h3>
              {group.items.map((command) => (
                <button
                  className={command.id === selectedCommand?.id ? "command-item active" : "command-item"}
                  key={command.id}
                  type="button"
                  onMouseEnter={() => {
                    const index = commands.findIndex((item) => item.id === command.id);
                    if (index >= 0) setSelectedIndex(index);
                  }}
                  onClick={() => onRun(command)}
                >
                  <div className="command-item-main">
                    <strong>{command.label}</strong>
                    <span>{command.hint}</span>
                  </div>
                </button>
              ))}
            </section>
          ))}
          {!commands.length && <div className="command-empty">{t.commandNoResults}</div>}
        </div>
      </div>
    </div>
  );
}
