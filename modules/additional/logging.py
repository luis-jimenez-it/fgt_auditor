# modules/additional/logging.py
import re

def audit(ctx):
    """
    Auditoría del subsistema de Log y Monitorización (Syslog, FortiAnalyzer, Alertemail)
    conforme a la línea base corporativa SEG-LNB-002.
    """
    checks = []
    raw_content = ctx.get('content', '')
    raw_content = raw_content.replace('\xa0', ' ')

    # 1. Verificar Syslog remoto
    syslog_match = re.search(r'config log syslogd[^\n]*(.*?)(?:\nend|\Z)', raw_content, re.DOTALL | re.IGNORECASE)
    syslog_block = syslog_match.group(1) if syslog_match else ""
    syslog_enabled = False
    syslog_server = ""
    if syslog_block and re.search(r'^\s*set\s+status\s+enable', syslog_block, re.IGNORECASE | re.MULTILINE):
        syslog_enabled = True
        m_srv = re.search(r'^\s*set\s+server\s+"?([^"\n]+)"?', syslog_block, re.IGNORECASE | re.MULTILINE)
        if m_srv:
            syslog_server = m_srv.group(1).strip()

    # 2. Verificar FortiAnalyzer (FAZ)
    faz_match = re.search(r'config log fortianalyzer setting(.*?)(?:\nend|\Z)', raw_content, re.DOTALL | re.IGNORECASE)
    faz_block = faz_match.group(1) if faz_match else ""
    faz_enabled = False
    faz_server = ""
    if faz_block and re.search(r'^\s*set\s+status\s+enable', faz_block, re.IGNORECASE | re.MULTILINE):
        faz_enabled = True
        m_faz = re.search(r'^\s*set\s+server\s+"?([^"\n]+)"?', faz_block, re.IGNORECASE | re.MULTILINE)
        if m_faz:
            faz_server = m_faz.group(1).strip()

    # El almacenamiento centralizado cumple si Syslog O FortiAnalyzer están activos
    centralized_logging_active = syslog_enabled or faz_enabled
    logging_destination = f"FortiAnalyzer ({faz_server})" if faz_enabled else (f"Syslog ({syslog_server})" if syslog_enabled else "No configurado")

    # 3. Verificar Alertas por Correo (Alertemail)
    alert_match = re.search(r'config alertemail setting(.*?)(?:\nend|\Z)', raw_content, re.DOTALL | re.IGNORECASE)
    alert_block = alert_match.group(1) if alert_match else ""
    alert_enabled = False
    if alert_block and re.search(r'^\s*set\s+status\s+enable', alert_block, re.IGNORECASE | re.MULTILINE):
        alert_enabled = True

    # =========================================================================
    # CHECK 1: Envío de Logs a FortiAnalyzer / Syslog Externo (SEG-LNB-002 Num 6.8)
    # =========================================================================
    checks.append({
        'id': 'CHK-LOG-CENTRALIZED',
        'vdom': 'global',
        'cat': 'System Hardening',
        'mod': 'Log and Monitoring - Centralized Logging',
        'hallazgo': f"Configuración de Logs: {'El reenvío centralizado de registros está activo a través de ' + logging_destination if centralized_logging_active else 'No se encuentra habilitado el envío de registros a FortiAnalyzer ni a Syslog externo'}",
        'estado': 'PASS' if centralized_logging_active else 'WARNING',
        'sev': 'Alta',
        'peso': 8,
        'afectados': f"Global -> Centralized Logging: {logging_destination}",
        'evidencia': f"FortiAnalyzer activo: {faz_enabled} ({faz_server}), Syslog activo: {syslog_enabled} ({syslog_server})",
        'rec': 'Los logs deberán enviarse a FortiAnalyzer o plataforma equivalente de forma centralizada conforme a SEG-LNB-002[cite: 1].',
        'rem': 'config log fortianalyzer setting\n  set status enable\n  set server "IP_DEL_FORTIANALYZER"\nend',
        'tipo': 'Arquitectura',
        'ref': 'SEG-LNB-002 Num 6.8[cite: 1]'
    })

    # =========================================================================
    # CHECK 2: Alertas ante Eventos Críticos (SEG-LNB-002 Num 6.8)
    # =========================================================================
    checks.append({
        'id': 'CHK-LOG-ALERTEMAIL',
        'vdom': 'global',
        'cat': 'System Hardening',
        'mod': 'Log and Monitoring - Critical Alerts',
        'hallazgo': f"Configuración de Alertas: Las alertas automáticas por correo ante eventos críticos se encuentran {'habilitadas' if alert_enabled else 'deshabilitadas'}",
        'estado': 'PASS' if alert_enabled else 'WARNING',
        'sev': 'Media',
        'peso': 5,
        'afectados': f"Global -> alertemail status: {'Habilitado' if alert_enabled else 'Deshabilitado'}",
        'evidencia': f"Alertemail habilitado: {alert_enabled}",
        'rec': 'Se deberán configurar alertas para eventos críticos de seguridad y sistema conforme a SEG-LNB-002[cite: 1].',
        'rem': 'config alertemail setting\n  set status enable\n  set mailto "soc@empresa.local"\nend',
        'tipo': 'Técnico',
        'ref': 'SEG-LNB-002 Num 6.8[cite: 1]'
    })

    return checks
