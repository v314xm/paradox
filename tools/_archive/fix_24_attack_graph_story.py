from pathlib import Path
from fix_utils import patch

FIX_ID = "fix_24"
TITLE = "AttackGraph: use HostStoryDialog on node double-click"


def apply(root: Path) -> bool:
    changed = False
    rel = "paradox_gui/dialogs/attack_graph_dialog.py"

    # 1. Сохраняем полный report в self для истории
    changed |= patch(
        root, rel,
        old=(
            "        self._graph = (report or {}).get(\"attack_graph\", {}) or {}\n"
        ),
        new=(
            "        self._report = report or {}\n"
            "        self._graph = self._report.get(\"attack_graph\", {}) or {}\n"
        )
    )

    # 2. Заменяем самодельный QDialog на вызов HostStoryDialog
    old_story = '''\
    def _open_host_story(self, ip: str):
        """Двойной клик на узле — история хоста."""
        try:
            from paradox.analyzers.story import build_host_story  # noqa: F401
            from paradox_gui.dialogs.host_story_dialog import HostStoryDialog  # noqa: F401
        except ImportError:
            return
        # Восстанавливаем отчёт из того, что есть в диалоге
        # (в графе только nodes/edges/paths — историю построить не из чего,
        # поэтому показываем просто findings этого узла)
        findings = []
        for e in self._edges:
            if ip in (e.get("src"), e.get("dst")):
                findings.append(e)
        if not findings:
            return
        html_parts = [f"<h3>{ip}</h3>", "<p><b>Связанные события:</b></p><ul>"]
        for e in findings:
            types = ", ".join(e.get("finding_types", []))
            direction = "→" if e.get("src") == ip else "←"
            other = e.get("dst") if e.get("src") == ip else e.get("src")
            html_parts.append(
                f"<li>{direction} <code>{other}</code>: {types} "
                f"({e.get('phase')}, {e.get('severity')})</li>"
            )
        html_parts.append("</ul>")
        try:
            from PySide6.QtWidgets import QDialog, QPushButton, QTextBrowser, QVBoxLayout
            dlg = QDialog(self)
            dlg.setWindowTitle(f"Хост: {ip}")
            dlg.resize(600, 500)
            v = QVBoxLayout(dlg)
            tb = QTextBrowser()
            tb.setHtml("".join(html_parts))
            v.addWidget(tb)
            btn = QPushButton("Закрыть")
            btn.clicked.connect(dlg.accept)
            v.addWidget(btn)
            dlg.exec()
        except Exception:
            pass
'''
    new_story = '''\
    def _open_host_story(self, ip: str):
        """Двойной клик на узле — история хоста."""
        try:
            from paradox.analyzers.story import build_host_story
            from paradox_gui.dialogs.host_story_dialog import HostStoryDialog
        except ImportError:
            return

        story = build_host_story(self._report, ip)
        dialog = HostStoryDialog(ip, story, self)
        dialog.exec()
'''
    changed |= patch(root, rel, old=old_story, new=new_story)

    return changed
