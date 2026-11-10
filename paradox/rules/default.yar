/*
  Стандартные YARA-правила Paradox.

  Только однозначные маркеры вредоносных инструментов: имя правила
  попадает в отчёт как есть, поэтому правило должно молчать на
  легитимном софте. Сигнатуры веб-шеллов и PHP-кода живут в
  detectors/webshell_markers.py — здесь их нет намеренно, иначе один
  payload даёт два разных finding.

  Свои правила: Настройки → YARA → путь к .yar. Файл пользователя
  полностью заменяет этот.
*/

rule Paradox_Meterpreter_Stage
{
    meta:
        description = "Meterpreter stage markers (Metasploit)"
        author = "Paradox core rules"
    strings:
        $metsrv = "metsrv" ascii wide nocase
        $meterpreter = "meterpreter" ascii wide nocase
    condition:
        any of them
}

rule Paradox_XMRig_Miner
{
    meta:
        description = "XMRig cryptominer markers"
        author = "Paradox core rules"
    strings:
        $xmrig = "xmrig" ascii wide nocase
        $stratum = "stratum+tcp://" ascii wide nocase
    condition:
        any of them
}

rule Paradox_CobaltStrike_Beacon
{
    meta:
        description = "Cobalt Strike beacon markers"
        author = "Paradox core rules"
    strings:
        $beacon = "beacon.dll" ascii wide nocase
        $cs = "cobaltstrike" ascii wide nocase
    condition:
        any of them
}
