# modules/system/fortiguard.py
import re

def audit(ctx):
    """
    Auditoría del subsistema FortiGuard (config system fortiguard) basada en los
    parámetros reales de FortiOS conforme a SEG-LNB-002.
    """
    checks = []
    raw_content = ctx.get('content', '')
    raw_content = raw_content.replace('\xa0', ' ')

    # Extraer bloque config system fortiguard
    fg_match = re.search(r'config system fortiguard(.*?)(?:\nend|\Z)', raw_content, re.DOTALL)
    fg_block = fg_match.group(1) if fg_match else ""

    # Valores por defecto y detección real
    anycast_enabled = True
    port_val = 8888
    auto_upgrade_enabled = False

    if fg_block:
        # 1. fortiguard-anycast
        m_anycast = re.search(r'^\s*set\s+fortiguard-anycast\s+(enable|disable)', fg_block, re.IGNORECASE | re.MULTILINE)
        if m_anycast:
            anycast_enabled = (m_anycast.group(1).lower() == 'enable')

        # 2. port (443 es seguro/HTTPS, 8888 o 53 son legacy/UDP)
        m_port = re.search(r'^\s*set\s+port\s+(\d+)', fg_block, re.IGNORECASE | re.MULTILINE)
        if m_port:
            port_val = int(m_port.group(1))

        # 3. auto-firmware-upgrade
        m_upg = re.search(r'^\s*set\s+auto-firmware-upgrade\s+(enable|disable)', fg_block, re.IGNORECASE | re.MULTILINE)
        if m_upg:
            auto_upgrade_enabled = (m_upg.group(1).lower() == 'enable')

    # =========================================================================
    # CHECK 1: Puerto y Cifrado de Comunicación con FortiGuard
    # =========================================================================
    # El puerto 443 utiliza HTTPS cifrado; 8888 o 53 usan protocolos menos seguros
    secure_port = (port_val == 443)
    checks.append({
        'id': 'CHK-FG-PORT',
        'vdom': 'global',
        'cat': 'System Hardening',
        'mod': 'FortiGuard Communication Port',
        'hallazgo': f"Configuración FortiGuard: El servicio utiliza el puerto '{port_val}' (se recomienda el puerto 443 para tráfico HTTPS cifrado)",
        'estado': 'PASS' if secure_port else 'WARNING',
        'sev': 'Media',
        'peso': 6,
        'afectados': f"Global -> FortiGuard port: {port_val}",
        'evidencia': f"Puerto configurado: {port_val} ({'HTTPS Cifrado' if secure_port else 'Legacy/Inseguro'})",
        'rec': 'Configurar el puerto de FortiGuard en 443 con protocolo HTTPS para cifrar la telemetría corporativa conforme a SEG-LNB-002.',
        'rem': 'config system fortiguard\n  set protocol https\n  set port 443\nend',
        'tipo': 'Técnico',
        'ref': 'SEG-LNB-002 Num 6.12'
    })

    # =========================================================================
    # CHECK 2: Anycast Routing de FortiGuard
    # =========================================================================
    checks.append({
        'id': 'CHK-FG-ANYCAST',
        'vdom': 'global',
        'cat': 'System Hardening',
        'mod': 'FortiGuard Anycast Routing',
        'hallazgo': f"Configuración FortiGuard: El enrutamiento Anycast se encuentra deshabilitado (fortiguard-anycast disable)",
        'estado': 'WARNING' if not anycast_enabled else 'PASS',
        'sev': 'Baja',
        'peso': 3,
        'afectados': f"Global -> fortiguard-anycast: {'Habilitado' if anycast_enabled else 'Deshabilitado'}",
        'evidencia': f"Fortiguard-anycast habilitado: {anycast_enabled}",
        'rec': 'Habilitar fortiguard-anycast para optimizar la latencia en las consultas de reputación y filtrado conforme a SEG-LNB-002.',
        'rem': 'config system fortiguard\n  set fortiguard-anycast enable\nend',
        'tipo': 'Técnico',
        'ref': 'SEG-LNB-002 Num 6.12'
    })

    # =========================================================================
    # CHECK 3: Actualización Automática de Firmware
    # =========================================================================
    # Lo ideal corporativamente es que esté deshabilitado para evitar despliegues sin control (PASS si está disable)
    checks.append({
        'id': 'CHK-FG-AUTOUPGRADE',
        'vdom': 'global',
        'cat': 'System Hardening',
        'mod': 'FortiGuard Auto Firmware Upgrade',
        'hallazgo': f"Configuración FortiGuard: Las actualizaciones automáticas de firmware están {'habilitadas' if auto_upgrade_enabled else 'deshabilitadas'}",
        'estado': 'PASS' if not auto_upgrade_enabled else 'WARNING',
        'sev': 'Media',
        'peso': 5,
        'afectados': f"Global -> auto-firmware-upgrade: {'Habilitado' if auto_upgrade_enabled else 'Deshabilitado'}",
        'evidencia': f"Auto-firmware-upgrade: {auto_upgrade_enabled}",
        'rec': 'Mantener auto-firmware-upgrade deshabilitado para prevenir actualizaciones no programadas que puedan comprometer la estabilidad operativa conforme a SEG-LNB-002.',
        'rem': 'config system fortiguard\n  set auto-firmware-upgrade disable\nend',
        'tipo': 'Técnico',
        'ref': 'SEG-LNB-002 Num 6.2'
    })

    return checks

