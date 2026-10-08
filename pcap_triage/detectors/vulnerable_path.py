from pcap_triage.config import Config
from pcap_triage.models import CaptureState, Finding


class VulnerablePathDetector:
    """
    Обращения к известным уязвимым путям в HTTP.

    Работает поверх FlowStats.http_uri (заполняется HTTPExtractor).
    Не ловит payload-эксплуатацию — только «обращение к уязвимой точке».

    Два сигнала в одном детекторе:
    - vulnerable_path: URI содержит известный уязвимый путь или скрипт
    - script_download: URI заканчивается на подозрительное расширение

    Сигнал не значит «атака»: обращение к wp-login.php бывает
    и легитимным. Аналитик смотрит контекст.
    """
    name = "vulnerable_path"

    def run(self, state: CaptureState, config: Config) -> list[Finding]:
        findings: list[Finding] = []

        vulnerable_paths = config.vulnerable_paths
        script_exts = config.suspicious_download_extensions

        for key, flow in state.flows.items():
            uri = flow.http_uri
            if not uri:
                continue

            uri_lower = uri.lower()

            # --- vulnerable path ---
            matched: list[tuple[str, str]] = []
            for path, description in vulnerable_paths.items():
                if path in uri_lower:
                    matched.append((path, description))

            if matched:
                findings.append(Finding(
                    type="vulnerable_path",
                    value=uri,
                    confidence=0.5,
                    evidence={
                        "uri": uri,
                        "host": flow.http_host,
                        "method": flow.http_method,
                        "user_agent": flow.http_user_agent,
                        "src_ip": key.src_ip,
                        "dst_ip": key.dst_ip,
                        "dst_port": key.dst_port,
                        "matched_paths": [
                            {"path": p, "description": d} for p, d in matched
                        ],
                    },
                    first_seen=flow.first_ts,
                    last_seen=flow.last_ts,
                ))
                continue  # уже нашли, script_download не нужен

            # --- script download ---
            for ext in script_exts:
                if uri_lower.endswith(ext) or (ext + "?") in uri_lower:
                    findings.append(Finding(
                        type="script_download",
                        value=uri,
                        confidence=0.7,
                        evidence={
                            "uri": uri,
                            "extension": ext,
                            "host": flow.http_host,
                            "user_agent": flow.http_user_agent,
                            "src_ip": key.src_ip,
                            "dst_ip": key.dst_ip,
                        },
                        first_seen=flow.first_ts,
                        last_seen=flow.last_ts,
                    ))
                    break

        # сортировка — детерминизм
        findings.sort(key=lambda f: (f.value, f.type))
        return findings