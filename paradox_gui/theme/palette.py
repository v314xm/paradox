"""Единственный источник правды о цветах и шрифтах Paradox."""
from __future__ import annotations

PALETTE = {
    "bg":           "#1e1e2e",  # основной фон
    "bg_light":     "#282a36",  # панели, карточки, меню
    "bg_lighter":   "#313342",  # поля ввода, подложка кнопок
    "bg_hover":     "#3d4050",  # hover на пунктах меню / строк таблицы
    "text":         "#e0e0e0",
    "text_muted":   "#a0a0b0",
    "accent":       "#5b8cff",
    "accent_hover": "#4a7ae0",
    "border":       "#3a3d4d",
    "danger":       "#ff5555",
    "danger_light": "#ff8888",
    "success":      "#50fa7b",
    "violet":       "#c792ea",
}

# Severity — ключи совпадают со строками severity в dict из run_pipeline.
# Пригодится в contradiction_card.py, summary_grid.py, findings_table.py.
SEVERITY = {
    "critical": "#ff5555",
    "high":     "#ffb86c",
    "medium":   "#f1fa8c",
    "low":      "#50fa7b",
    "info":     "#8be9fd",
}

# Моно-шрифт для полей типа rule, subject, values, MITRE.
MONO_FAMILY = "'Cascadia Code', 'Consolas', 'Courier New', monospace"
UI_FAMILY   = "'Segoe UI', system-ui, sans-serif"
