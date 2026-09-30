# modules/system/ha.py
import re

def audit(ctx):
    """
    Auditoría completa del subsistema de High Availability (config system ha)
    conforme a la línea base corporativa SEG-LNB-002.
    """
    checks = []
    raw_content = ctx.get('content', '')

    # Normalizar espacios
    raw_content = raw_content.replace('\xa0', ' ')

    # Extraer bloque config system ha
    ha_block_match = re.search(r'config system ha(.*?)(?:\nend|\Z)', raw_content, re.DOTALL)
    ha_block = ha_block_match.group(1) if ha_block_match else ""

    # Valores por defecto y detección
    ha_mode = "standalone"
    session_pickup = False
    memory_failover = False
    hbdevs = []
    monitored_ifs = []

    if ha_block:
        # 1. Modo HA (standalone, a-p, a-a)
        m_mode = re.search(r'^\s*set\s+mode\s+(\S+)', ha_block, re.IGNORECASE | re.MULTILINE)
        if m_mode:
            ha_mode = m_mode.group(1).lower()

        # 2. Session Pickup
        m_pickup = re.search(r'^\s*set\s+session-pickup\s+(enable|disable)', ha_block, re.IGNORECASE | re.MULTILINE)
        if m_pickup:
            session_pickup = (m_pickup.group(1).lower() == 'enable')

        # 3. Memory-based failover
        m_mem = re.search(r'^\s*set\s+memory-based-failover\s+(enable|disable)', ha_block, re.IGNORECASE | re.MULTILINE)
        if m_mem:
            memory_failover = (m_mem.group(1).lower() == 'enable')

        # 4. Heartbeat interfaces (hbdev)
        m_hb = re.search(r'^\s*set\s+hbdev\s+([^\n]+)', ha_block, re.IGNORECASE | re.MULTILINE)
        if m_hb:
            hbdevs = m_hb.group(1).strip().strip('"').split()

        # 5. Monitored interfaces (monitor)
        m_mon = re.search(r'^\s*set\s+monitor\s+([^\n]+)', ha_block, re.IGNORECASE | re.MULTILINE)
        if m_mon:
            monitored_ifs = m_mon.group(1).strip().strip('"').split()

    # =========================================================================
    # CHECK 1: Estado y Modo de Alta Disponibilidad (HA Mode)
    # =========================================================================
    is_standalone = (ha_mode == "standalone" or not ha_block)
    checks.append({
        'id': 'CHK-SYSHA-MODE',
        'vdom': 'global',
        'cat': 'System Hardening',
        'mod': 'HA Deployment Mode',
        'hallazgo': f"Configuración HA: El equipo opera en modo '{ha_mode.upper()}', careciendo de redundancia de nodo",
        'estado': 'WARNING' if is_standalone else 'PASS',
        'sev': 'Alta',
        'peso': 10,
        'afectados': f"Global -> HA Mode: {ha_mode.upper()}",
        'evidencia': f"Modo HA detectado: {ha_mode.upper()}",
        'rec': 'Implementar topología de Alta Disponibilidad en modo Active-Passive (A-P) para garantizar continuidad de negocio conforme a SEG-LNB-002.',
        'rem': 'config system ha\n  set mode a-p\n  set group-name "Corp-Cluster"\nend',
        'tipo': 'Arquitectura',
        'ref': 'SEG-LNB-002 Num 6.14'
    })

    # =========================================================================
    # CHECK 2: Sincronización de Sesiones (Session Pickup)
    # =========================================================================
    checks.append({
        'id': 'CHK-SYSHA-SESSIONPICKUP',
        'vdom': 'global',
        'cat': 'System Hardening',
        'mod': 'HA Session Pickup',
        'hallazgo': "Configuración HA: La sincronización de sesiones activas (session-pickup) se encuentra deshabilitada",
        'estado': 'PASS' if session_pickup else 'WARNING',
        'sev': 'Media',
        'peso': 7,
        'afectados': f"Global -> session-pickup: {'Habilitado' if session_pickup else 'Deshabilitado'}",
        'evidencia': f"Session-pickup habilitado: {session_pickup}",
        'rec': 'Habilitar session-pickup en el clúster HA para mantener las conexiones TCP activas ante un failover y evitar interrupción percibida por los usuarios conforme a SEG-LNB-002.',
        'rem': 'config system ha\n  set session-pickup enable\nend',
        'tipo': 'Técnico',
        'ref': 'SEG-LNB-002 Num 6.14'
    })

    # =========================================================================
    # CHECK 3: Failover Basado en Memoria (Memory-Based Failover)
    # =========================================================================
    checks.append({
        'id': 'CHK-SYSHA-MEMFAILOVER',
        'vdom': 'global',
        'cat': 'System Hardening',
        'mod': 'HA Memory-Based Failover',
        'hallazgo': "Configuración HA: El failover basado en saturación de memoria (memory-based-failover) no está activo",
        'estado': 'PASS' if memory_failover else 'WARNING',
        'sev': 'Media',
        'peso': 6,
        'afectados': f"Global -> memory-based-failover: {'Habilitado' if memory_failover else 'Deshabilitado'}",
        'evidencia': f"Memory-based failover habilitado: {memory_failover}",
        'rec': 'Habilitar memory-based-failover para permitir que el clúster realice conmutación preventiva de nodo ante agotamiento severo de memoria (modo conservativo) conforme a SEG-LNB-002.',
        'rem': 'config system ha\n  set memory-based-failover enable\nend',
        'tipo': 'Técnico',
        'ref': 'SEG-LNB-002 Num 6.14'
    })

    # =========================================================================
    # CHECK 4: Interfaces de Latido (Heartbeat - hbdev) y Monitoreo
    # =========================================================================
    has_hb = len(hbdevs) > 0
    has_monitor = len(monitored_ifs) > 0
    hb_status_pass = (has_hb and (has_monitor or is_standalone))

    checks.append({
        'id': 'CHK-SYSHA-INTERFACES',
        'vdom': 'global',
        'cat': 'System Hardening',
        'mod': 'HA Heartbeat and Monitored Interfaces',
        'hallazgo': "Configuración HA: Interfaces de latido (hbdev) o interfaces críticas monitoreadas insuficientes o ausentes",
        'estado': 'PASS' if hb_status_pass else 'WARNING',
        'sev': 'Alta',
        'peso': 8,
        'afectados': f"Global -> hbdev: {hbdevs if hbdevs else 'Ninguna'}, Monitoreadas: {monitored_ifs if monitored_ifs else 'Ninguna'}",
        'evidencia': f"Heartbeat interfaces: {hbdevs}, Monitored interfaces: {monitored_ifs}",
        'rec': 'Configurar múltiples interfaces dedicadas de heartbeat redundantes (hbdev) y declarar las interfaces WAN/LAN críticas en el parámetro monitor conforme a SEG-LNB-002.',
        'rem': 'config system ha\n  set hbdev "port3" "port4"\n  set monitor "port1" "port2"\nend',
        'tipo': 'Técnico',
        'ref': 'SEG-LNB-002 Num 6.14'
    })

    return checks
