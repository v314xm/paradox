"""Absence analysis (анализ отсутствия).

Ищет то, чего не хватает в перехвате:
  - DNS-запросы без ответов.
  - TCP-соединения, где клиент отправил SYN, но сервер не ответил
    (отсутствует обратный flow).
"""
from __future__ import annotations

from paradox.models import CaptureState, FlowKey


def analyze_absence(state: CaptureState, top_n: int = 100) -> dict:
    """Проанализировать CaptureState на предмет отсутствующих ответов.

    Возвращает словарь:
      {
        "dns_unanswered": [{"qname": str, "count": int}],
        "dns_unanswered_total": int,
        "tcp_unanswered": [{"src_ip": str, "dst_ip": str,
                            "dst_port": int, "packets": int}],
        "tcp_unanswered_total": int
      }

    Списки ограничены top_n: на сканирующем захвате «без ответа»
    могут быть сотни тысяч имён, и отчёт не должен раздуваться.
    """
    # 1. DNS-запросы без ответов
    dns_unanswered = [
        {"qname": qname, "count": count}
        for qname, count in state.dns_queries.items()
        if qname not in state.dns_answers_by_name
    ]
    dns_unanswered.sort(key=lambda d: (-d["count"], d["qname"]))
    dns_total = len(dns_unanswered)
    dns_unanswered = dns_unanswered[:top_n]

    # 2. TCP-соединения без ответа
    tcp_unanswered = []
    for key, flow in state.flows.items():
        # Проверяем только TCP, где инициатором был src (initiated_by_src = True)
        if key.proto == "tcp" and flow.initiated_by_src is True:
            # Формируем ожидаемый обратный ключ
            reverse_key = FlowKey(
                proto=key.proto,
                src_ip=key.dst_ip,
                dst_ip=key.src_ip,
                src_port=key.dst_port,
                dst_port=key.src_port
            )
            # Если обратного потока нет, значит сервер не ответил
            if reverse_key not in state.flows:
                tcp_unanswered.append({
                    "src_ip": key.src_ip,
                    "dst_ip": key.dst_ip,
                    "dst_port": key.dst_port,
                    "packets": flow.packets,
                })

    tcp_unanswered.sort(
        key=lambda d: (-d["packets"], d["src_ip"], d["dst_ip"],
                       d["dst_port"] or 0),
    )
    tcp_total = len(tcp_unanswered)

    return {
        "dns_unanswered": dns_unanswered[:top_n],
        "dns_unanswered_total": dns_total,
        "tcp_unanswered": tcp_unanswered[:top_n],
        "tcp_unanswered_total": tcp_total,
    }
