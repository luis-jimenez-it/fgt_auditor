# modules/additional/change_management.py
import re

def audit(ctx):
    """
    Auditoría del subsistema de Control de Cambios y Trazabilidad Administrativa
    conforme a la línea base corporativa SEG-LNB-002 (Sección 6.4 y Anexo A).
    """
    checks = []
    raw_content = ctx.get('content', '')
    raw_content = raw_content.replace('\xa0', ' ')

    # Verificar si el equipo cuenta con descripciones o nombres corporativos identificatorios (ej. hostnames formales)
    global_match = re.search(r'config system global(.*?)(?:\nend|\Z)', raw_content, re.DOTALL | re.IGNORECASE)
    global_block = global_match.group(1) if global_match else ""

    hostname = "Unknown"
    if global_block:
        m_host = re.search(r'set\s+hostname\s+"?([^"\n]+)"?', global_block, re.IGNORECASE)
        if m_host:
            hostname = m_host.group(1).strip()

    # Validar si existe una descripción de sistema corporativa o contacto
    has_description = False
    if global_block and re.search(r'set\s+user-friendly-name|set\s+admin-staff', global_block, re.IGNORECASE):
        has_description = True

    # =========================================================================
    # CHECK 1: Identificación y Trazabilidad del Dispositivo (SEG-LNB-002 Num 6.4)
    # =========================================================================
    checks.append({
        'id': 'CHK-CHANGE-HOSTNAME',
        'vdom': 'global',
        'cat': 'System Hardening',
        'mod': 'Change Management - Asset Identification',
        'hallazgo': f"Gestión de Cambios: El dispositivo posee un hostname asignado ('{hostname}'), permitiendo su correcta trazabilidad en inventarios corporativos[cite: 1]",
        'estado': 'PASS' if hostname != "FortiGate" and hostname != "Unknown" else 'WARNING',
        'sev': 'Baja',
        'peso': 3,
        'afectados': f"Global -> Hostname: {hostname}",
        'evidencia': f"Hostname detectado: {hostname}",
        'rec': 'Mantener una nomenclatura estandarizada y formal en el hostname para garantizar una correcta trazabilidad en los cambios y gestión de activos conforme a SEG-LNB-002[cite: 1].',
        'rem': 'config system global\n  set hostname "FGT-SEDE-CORPORATIVA"\nend',
        'tipo': 'Gobernanza',
        'ref': 'SEG-LNB-002 Num 6.4[cite: 1]'
    })

    return checks
