/**
 * Forensics++ (ForensicsPP.com)
 * Local-first browser forensics workbench
 *
 * Copyright (c) 2026 DyNooob. All rights reserved.
 * Author: DyNooob
 * Website: https://www.loken.cn
 * Platform: DigiForensics.cn
 * Project: https://git.loken.cn/dynooob/ForensicsPP
 *
 * Forensics++ is an open-source, browser-side toolkit for CTF/MISC,
 * lightweight forensic triage, encoding/decoding, metadata inspection,
 * hashes, archive parsing, and local analysis.
 *
 * Do not use this project for unauthorized access, intrusion,
 * privacy infringement, or unlawful activity.
 *
 * Released under the MIT License.
 * Full source code: https://git.loken.cn/dynooob/ForensicsPP
 */

import { copyText } from "../utils/clipboard";
import React from "react";
import { Button, Checkbox, Input, InputNumber, Progress, Select } from "antd";
import type { ButtonProps, CheckboxProps, InputNumberProps, InputProps, SelectProps } from "antd";

export type AButtonProps = Omit<ButtonProps, "type" | "variant"> & {
  variant?: "filled" | "outlined" | "text" | string;
};

export function AButton({ variant, className, ...props }: AButtonProps) {
  const type: ButtonProps["type"] = variant === "filled" ? "primary" : variant === "text" ? "text" : "default";
  return (
    <Button
      {...props}
      className={["app-button", variant ? `app-button--${variant}` : "", className].filter(Boolean).join(" ")}
      type={type}
    />
  );
}

export function ALinearProgress() {
  return <Progress className="app-linear-progress" percent={100} showInfo={false} status="active" />;
}

type SegmentedContextValue = {
  value?: string;
};

const SegmentedContext = React.createContext<SegmentedContextValue>({});

export function ASegmentedGroup({
  className,
  value,
  children,
  ...props
}: React.HTMLAttributes<HTMLDivElement> & { value?: string; selects?: string }) {
  const { selects, role, ...rest } = props;
  return (
    <SegmentedContext.Provider value={{ value }}>
      <div
        {...rest}
        className={["app-segmented", className].filter(Boolean).join(" ")}
        role={role ?? (selects === "single" ? "radiogroup" : "group")}
      >
        {children}
      </div>
    </SegmentedContext.Provider>
  );
}

export function ASegmentedButton({
  value,
  className,
  children,
  ...props
}: AButtonProps & { value?: string }) {
  const group = React.useContext(SegmentedContext);
  const active = Boolean(value && group.value === value);
  return (
    <AButton
      {...props}
      aria-pressed={active}
      data-selected={active ? "true" : "false"}
      className={["app-segmented-button", active ? "active" : "", className].filter(Boolean).join(" ")}
      variant={active ? "filled" : "outlined"}
    >
      {children}
    </AButton>
  );
}

export function ATextField({
  clearable,
  label: _label,
  variant: _variant,
  onInput,
  ...props
}: InputProps & { clearable?: boolean; label?: string; variant?: string }) {
  return <Input {...props} allowClear={clearable} onInput={onInput} />;
}

export function APasswordField(props: InputProps) {
  return <Input.Password {...props} />;
}

export function ACheckbox({ className, ...props }: CheckboxProps) {
  return <Checkbox {...props} className={["app-checkbox", className].filter(Boolean).join(" ")} />;
}

export function AInputNumber({ className, ...props }: InputNumberProps<number>) {
  return <InputNumber<number> {...props} className={["app-input-number", className].filter(Boolean).join(" ")} />;
}

export function ASelect({ className, ...props }: SelectProps) {
  return (
    <Select
      {...props}
      className={["app-select", className].filter(Boolean).join(" ")}
      popupMatchSelectWidth={props.popupMatchSelectWidth ?? false}
    />
  );
}

export function AList({ className, children }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={["app-list", className].filter(Boolean).join(" ")}>{children}</div>;
}

export function AListSubheader({ children }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className="app-list-subheader">{children}</div>;
}

export function AListItem({
  className,
  active,
  description,
  children,
  onClick,
  title,
  "aria-current": ariaCurrent
}: React.HTMLAttributes<HTMLButtonElement> & {
  active?: boolean;
  rounded?: boolean;
  description?: React.ReactNode;
  "description-line"?: number;
}) {
  return (
    <button
      className={["app-list-item", active ? "active" : "", className].filter(Boolean).join(" ")}
      type="button"
      title={title}
      aria-current={ariaCurrent}
      onClick={onClick}
    >
      <span>{children}</span>
      {description && <small>{description}</small>}
    </button>
  );
}

export function ACard({
  className,
  children
}: React.HTMLAttributes<HTMLDivElement> & { variant?: string }) {
  return <div className={["app-card", className].filter(Boolean).join(" ")}>{children}</div>;
}

export function AChip({
  className,
  selected,
  selectable,
  children,
  onClick,
  style,
  title
}: {
  className?: string;
  selected?: boolean;
  selectable?: boolean;
  variant?: string;
  children?: React.ReactNode;
  onClick?: React.MouseEventHandler<HTMLElement>;
  style?: React.CSSProperties;
  title?: string;
}) {
  const classes = ["app-chip", selected ? "selected" : "", onClick || selectable ? "app-chip-button" : "", className].filter(Boolean).join(" ");
  if (onClick || selectable) {
    return (
      <button
        className={classes}
        type="button"
        aria-pressed={selected}
        onClick={onClick as React.MouseEventHandler<HTMLButtonElement> | undefined}
        style={style}
        title={title}
      >
        {children}
      </button>
    );
  }
  return <span className={classes} style={style} title={title}>{children}</span>;
}

export function PanelTitle({ title }: { title: string }) {
  return <h2 className="panel-title">{title}</h2>;
}

export function ToolPanelHeader({
  title,
  subtitle,
  actions,
  className
}: {
  title: string;
  subtitle?: React.ReactNode;
  actions?: React.ReactNode;
  className?: string;
}) {
  return (
    <div className={["panel-heading-row", "tool-panel-header", className].filter(Boolean).join(" ")}>
      <div className="tool-panel-header-copy">
        <PanelTitle title={title} />
        {subtitle && <span>{subtitle}</span>}
      </div>
      {actions && <div className="button-row compact-buttons tool-panel-header-actions">{actions}</div>}
    </div>
  );
}

export function ToolFactGrid({
  items,
  className
}: {
  items: Array<{ label: string; value: React.ReactNode; copyValue?: string; detail?: React.ReactNode; disabled?: boolean }>;
  className?: string;
}) {
  return (
    <div className={["tool-fact-grid", className].filter(Boolean).join(" ")}>
      {items.map((item) => {
        const disabled = item.disabled ?? item.copyValue === "--";
        return (
          <button
            className="result-copy-card"
            type="button"
            key={item.label}
            disabled={disabled}
            onClick={() => item.copyValue && item.copyValue !== "--" && void copyText(item.copyValue)}
          >
            <span>{item.label}</span>
            <strong>{item.value}</strong>
            {item.detail && <em>{item.detail}</em>}
          </button>
        );
      })}
    </div>
  );
}

export function ToolStageFeatures({
  items
}: {
  items: Array<{ label: string; value: string; detail: string }>;
}) {
  return (
    <div className="tool-stage-meta">
      {items.map((item) => (
        <article className="tool-stage-card" key={`${item.label}-${item.value}`}>
          <span>{item.label}</span>
          <strong>{item.value}</strong>
          <em>{item.detail}</em>
        </article>
      ))}
    </div>
  );
}

export function ToolWorkspaceFrame({ children }: { children: React.ReactNode }) {
  return <div className="tool-page-shell">{children}</div>;
}

export function InfoTable({ rows }: { rows: Array<[string, string]> }) {
  return (
    <table className="info-table">
      <tbody>
        {rows.map(([label, value]) => (
          <tr key={label}>
            <th>{label}</th>
            <td>{value}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
