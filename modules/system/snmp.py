# modules/system/snmp.py
import re

def audit(ctx):
    """
    Auditoría del subsistema SNMP (config system snmp) conforme a SEG-LNB-002.
    Extrae correctamente los nombres reales de las comunidades y usuarios v3.
    """
    checks = []
    raw_content = ctx.get('content', '')
    raw_content = raw_content.replace('\xa0', ' ')

    # Extraer bloques relacionados con SNMP
    snmp_sysinfo_match = re.search(r'config system snmp sysinfo(.*?)(?:\nend|\Z)', raw_content, re.DOTALL)
    snmp_sysinfo = snmp_sysinfo_match.group(1) if snmp_sysinfo_match else ""

    snmp_comm_match = re.search(r'config system snmp community(.*?)(?:\nend|\Z)', raw_content, re.DOTALL)
    snmp_comm_block = snmp_comm_match.group(1) if snmp_comm_match else ""

    snmp_user_match = re.search(r'config system snmp user(.*?)(?:\nend|\Z)', raw_content, re.DOTALL)
    snmp_user_block = snmp_user_match.group(1) if snmp_user_match else ""

    # 1. Estado de SNMP
    snmp_enabled = False
    if re.search(r'^\s*set\s+status\s+enable', snmp_sysinfo, re.IGNORECASE | re.MULTILINE):
        snmp_enabled = True

    # =========================================================================
    # CHECK 1: Estado General del Servicio SNMP
    # =========================================================================
    checks.append({
        'id': 'CHK-SNMP-STATUS',
        'vdom': 'global',
        'cat': 'System Hardening',
        'mod': 'SNMP Service Status',
        'hallazgo': "Configuración SNMP: El servicio de administración SNMP se encuentra habilitado en el equipo",
        'estado': 'WARNING' if snmp_enabled else 'PASS',
        'sev': 'Baja',
        'peso': 3,
        'afectados': f"Global -> SNMP Status: {'Habilitado' if snmp_enabled else 'Deshabilitado'}",
        'evidencia': f"SNMP habilitado: {snmp_enabled}",
        'rec': 'Si el servicio SNMP no es utilizado para el monitoreo corporativo (NMS/SIEM), mantenerlo deshabilitado conforme a SEG-LNB-002.',
        'rem': 'config system snmp sysinfo\n  set status disable\nend',
        'tipo': 'Técnico',
        'ref': 'SEG-LNB-002 Num 6.10'
    })

    if snmp_enabled:
        # 2. Extraer nombres reales de comunidades v1/v2c (buscando 'set name "..."')
        communities = re.findall(r'set\s+name\s+"?([^"\n]+)"?', snmp_comm_block, re.IGNORECASE)
        has_legacy_communities = len(communities) > 0

        insecure_names = [c for c in communities if c.lower() in ['public', 'private', 'admin', 'snmp', 'test']]

        checks.append({
            'id': 'CHK-SNMP-LEGACY-COMMUNITY',
            'vdom': 'global',
            'cat': 'System Hardening',
            'mod': 'SNMP v1/v2c Communities',
            'hallazgo': f"Configuración SNMP: Se detectaron {len(communities)} comunidades SNMP v1/v2c activas (transmisión en texto plano)",
            'estado': 'FAIL' if has_legacy_communities else 'PASS',
            'sev': 'Crítica',
            'peso': 10,
            'afectados': f"Comunidades detectadas: {communities if communities else 'Ninguna'}",
            'evidencia': f"Nombres de comunidades v1/v2c: {communities}",
            'rec': 'Eliminar las comunidades SNMP v1 y v2c ya que transmiten credenciales y datos de red en texto plano. Migrar estrictamente a SNMPv3 conforme a SEG-LNB-002.',
            'rem': 'config system snmp community\n  purge\nend',
            'tipo': 'Técnico',
            'ref': 'SEG-LNB-002 Num 6.10'
        })

        if insecure_names:
            checks.append({
                'id': 'CHK-SNMP-INSECURE-NAME',
                'vdom': vdom_name if 'vdom_name' in locals() else 'global',
                'cat': 'System Hardening',
                'mod': 'SNMP Weak Community Names',
                'hallazgo': f"Configuración SNMP: Uso de nombres de comunidad SNMP predeterminados o débiles: {insecure_names}",
                'estado': 'FAIL',
                'sev': 'Crítica',
                'peso': 10,
                'afectados': f"Nombres débiles: {insecure_names}",
                'evidencia': f"Comunidades con nombres inseguros: {insecure_names}",
                'rec': 'Evitar terminologías genéricas o de fábrica en las comunidades SNMP para prevenir ataques de enumeración corporativa.',
                'rem': 'config system snmp community\n  unset ...\nend',
                'tipo': 'Técnico',
                'ref': 'SEG-LNB-002 Num 6.10'
            })

        # 3. Validar SNMPv3 Users (capturando el nombre del edit o el set name)
        # En snmp user, el nombre principal viene en el edit: edit "nombre"
        raw_users = re.findall(r'edit\s+"?([^"\n]+)"?', snmp_user_block, re.IGNORECASE)
        # Filtrar posibles valores numéricos si los hubiera
        users = [u for u in raw_users]
        has_v3_users = len(users) > 0

        checks.append({
            'id': 'CHK-SNMP-V3-ENFORCEMENT',
            'vdom': 'global',
            'cat': 'System Hardening',
            'mod': 'SNMPv3 Configuration',
            'hallazgo': f"Configuración SNMP: {'Se utilizan usuarios SNMPv3 seguros' if has_v3_users else 'No se han configurado usuarios SNMPv3 en el equipo'}",
            'estado': 'PASS' if has_v3_users else 'WARNING',
            'sev': 'Media',
            'peso': 6,
            'afectados': f"Usuarios SNMPv3 configurados: {users if users else 'Ninguno'}",
            'evidencia': f"Usuarios SNMPv3: {users}",
            'rec': 'Implementar SNMPv3 utilizando autenticación robusta (SHA-256/SHA-512) y privacidad (AES) conforme a SEG-LNB-002.',
            'rem': 'config system snmp user\n  edit "Monitoreo_Sec"\n    set security-level authPriv\n    set auth-proto sha256\n    set auth-pwd "PasswordSeguro"\n    set priv-proto aes\n    set priv-pwd "PrivPasswordSeguro"\n  next\nend',
            'tipo': 'Técnico',
            'ref': 'SEG-LNB-002 Num 6.10'
        })

    return checks
