# modules/network/interfaces.py
import re

PROTOCOL_RULES = {
    'prohibited': {
        'http': {'name': 'HTTP (Texto Claro)', 'sev': 'Alta'},
        'telnet': {'name': 'Telnet (Texto Claro)', 'sev': 'Crítica'}
    },
    'restricted': {
        'ssh': {'name': 'SSH (Gestión Consola)', 'sev': 'Alta'},
        'snmp': {'name': 'SNMP (Monitoreo)', 'sev': 'Media'},
        'ftm': {'name': 'FortiToken Mobile Push', 'sev': 'Baja'}
    },
    'allowed': {
        'https': {'name': 'HTTPS (Gestión Cifrada)', 'estado': 'PASS'},
        'ping': {'name': 'ICMP Ping (Diagnóstico)', 'estado': 'PASS'},
        'fabric': {'name': 'Security Fabric Telemetry', 'estado': 'PASS'}
    }
}

def audit(ctx):
    checks = []
    metadata = ctx.get('metadata', {})
    parsed_ifaces = ctx.get('parsed_interfaces', [])
    vdom_list = metadata.get('VDOM_List', ['root'])

    for vdom in vdom_list:
        vdom_ifaces = [i for i in parsed_ifaces if i['vdom'] == vdom]
        if not vdom_ifaces:
            continue

        # 1. TELNET
        telnet_ifaces = [i['name'] for i in vdom_ifaces if 'telnet' in i['access']]
        if telnet_ifaces:
            checks.append({
                'id': f'CHK-PROT-TELNET-{vdom}',
                'vdom': vdom,
                'cat': 'Acceso al Dispositivo',
                'mod': 'Interfaces de Red & Gestión',
                'hallazgo': f"Protocolo TELNET (texto plano) habilitado en interfaces de VDOM '{vdom}'",
                'estado': 'FAIL',
                'sev': 'Crítica',
                'peso': 15,
                'afectados': f"Interfaces: {', '.join(telnet_ifaces)}",
                'evidencia': f"allowaccess incluye 'telnet' en: {telnet_ifaces}",
                'rec': 'Deshabilitar Telnet de inmediato en todas las interfaces',
                'rem': f'config system interface\nedit "<interfaz>"\n  unset allowaccess\nnext\nend',
                'tipo': 'Técnico',
                'ref': 'SEG-LNB-002 Num 6.1 / NIST SC-8 / CIS 1.3'
            })
        else:
            checks.append({
                'id': f'CHK-PROT-TELNET-{vdom}',
                'vdom': vdom,
                'cat': 'Acceso al Dispositivo',
                'mod': 'Interfaces de Red & Gestión',
                'hallazgo': f"Protocolo obsoleto TELNET deshabilitado en VDOM '{vdom}'",
                'estado': 'PASS',
                'sev': 'Crítica',
                'peso': 10,
                'afectados': f"VDOM {vdom}",
                'evidencia': 'Telnet ausente en todas las interfaces',
                'rec': 'Mantener Telnet permanentemente deshabilitado',
                'rem': 'N/A - Cumple',
                'tipo': 'Técnico',
                'ref': 'SEG-LNB-002 Num 6.1 / NIST SC-8'
            })

        # 2. HTTP
        http_ifaces = [f"{i['name']}" + (f" (VLAN {i['vlan']})" if i['vlan'] else "") for i in vdom_ifaces if 'http' in i['access']]
        if http_ifaces:
            checks.append({
                'id': f'CHK-PROT-HTTP-{vdom}',
                'vdom': vdom,
                'cat': 'Acceso al Dispositivo',
                'mod': 'Interfaces de Red & Gestión',
                'hallazgo': f"Protocolo HTTP no cifrado expuesto en {len(http_ifaces)} interfaces/VLANs de VDOM '{vdom}'",
                'estado': 'FAIL',
                'sev': 'Alta',
                'peso': 10,
                'afectados': f"Interfaces: {', '.join(http_ifaces[:5])}",
                'evidencia': f"allowaccess incluye 'http' en: {'; '.join(http_ifaces)}",
                'rec': 'Deshabilitar HTTP y forzar únicamente el uso de HTTPS seguro',
                'rem': f'config system interface\nedit "<interfaz>"\n  set allowaccess ping https ssh\nnext\nend',
                'tipo': 'Técnico',
                'ref': 'SEG-LNB-002 Num 6.1 / ISO 27001 A.13.1.1 / CIS 1.3 / NIST SC-8'
            })
        else:
            checks.append({
                'id': f'CHK-PROT-HTTP-{vdom}',
                'vdom': vdom,
                'cat': 'Acceso al Dispositivo',
                'mod': 'Interfaces de Red & Gestión',
                'hallazgo': f"Protocolo HTTP deshabilitado en todas las interfaces de VDOM '{vdom}'",
                'estado': 'PASS',
                'sev': 'Alta',
                'peso': 10,
                'afectados': f"VDOM {vdom}",
                'evidencia': 'HTTP ausente en allowaccess de interfaces',
                'rec': 'Mantener acceso web cifrado exclusivo mediante HTTPS',
                'rem': 'N/A - Cumple',
                'tipo': 'Técnico',
                'ref': 'SEG-LNB-002 Num 6.1 / ISO 27001 A.13.1.1'
            })

        # 3. SSH
        ssh_expuestos = []
        for i in vdom_ifaces:
            if 'ssh' in i['access']:
                es_mgmt_dedicado = (i['name'] in ['mgmt', 'management'] or 'MGT' in i['name']) and i['status'] != 'down'
                if not es_mgmt_dedicado:
                    ssh_expuestos.append(f"{i['name']} (status: {i['status']})")

        if ssh_expuestos:
            checks.append({
                'id': f'CHK-PROT-SSH-{vdom}',
                'vdom': vdom,
                'cat': 'Acceso al Dispositivo',
                'mod': 'Interfaces de Red & Gestión',
                'hallazgo': f"Servicio SSH expuesto fuera del segmento de gestión en {len(ssh_expuestos)} interfaces de VDOM '{vdom}'",
                'estado': 'FAIL',
                'sev': 'Alta',
                'peso': 10,
                'afectados': f"Puertos: {', '.join([s.split()[0] for s in ssh_expuestos[:6]])}...",
                'evidencia': f"allowaccess ssh activo en puertos no dedicados a mgmt: {'; '.join(ssh_expuestos[:6])}",
                'rec': 'Deshabilitar SSH en puertos de usuario, enlaces inactivos y túneles VPN',
                'rem': f'config system interface\nedit "<puerto>"\n  unset allowaccess\nnext\nend',
                'tipo': 'Técnico',
                'ref': 'SEG-LNB-002 Num 6.1 / CIS Controls 1.4 / NIST AC-3'
            })
        else:
            checks.append({
                'id': f'CHK-PROT-SSH-{vdom}',
                'vdom': vdom,
                'cat': 'Acceso al Dispositivo',
                'mod': 'Interfaces de Red & Gestión',
                'hallazgo': f"Servicio SSH estrictamente acotado y protegido en VDOM '{vdom}'",
                'estado': 'PASS',
                'sev': 'Alta',
                'peso': 10,
                'afectados': f"VDOM {vdom}",
                'evidencia': 'SSH no se encuentra expuesto en puertos de datos de usuario ni enlaces inactivos',
                'rec': 'Mantener SSH restringido a subredes de administración',
                'rem': 'N/A - Cumple',
                'tipo': 'Técnico',
                'ref': 'SEG-LNB-002 Num 6.1 / CIS 1.4'
            })

        # 4. SNMP
        snmp_ifaces = [i['name'] for i in vdom_ifaces if 'snmp' in i['access'] and i['name'] not in ['mgmt', 'management'] and not i['name'].startswith('MGT')]
        if snmp_ifaces:
            checks.append({
                'id': f'CHK-PROT-SNMP-{vdom}',
                'vdom': vdom,
                'cat': 'Logs y Monitorización',
                'mod': 'Interfaces de Red & Gestión',
                'hallazgo': f"Consultas SNMP habilitadas en interfaces de red de usuario/datos ({len(snmp_ifaces)} interfaces en VDOM '{vdom}')",
                'estado': 'FAIL',
                'sev': 'Media',
                'peso': 5,
                'afectados': f"Interfaces: {', '.join(snmp_ifaces)}",
                'evidencia': f"allowaccess incluye 'snmp' en redes de producción: {snmp_ifaces}",
                'rec': 'Remover SNMP de las interfaces de usuarios y limitarlo a la interfaz de gestión dedicada',
                'rem': f'config system interface\nedit "<interfaz>"\n  set allowaccess ping https\nnext\nend',
                'tipo': 'Técnico',
                'ref': 'SEG-LNB-002 Num 6.8 / CIS Controls 2.1 / NIST IA-2'
            })
        else:
            checks.append({
                'id': f'CHK-PROT-SNMP-{vdom}',
                'vdom': vdom,
                'cat': 'Logs y Monitorización',
                'mod': 'Interfaces de Red & Gestión',
                'hallazgo': f"Servicio SNMP protegido sin exposición en redes de usuario de VDOM '{vdom}'",
                'estado': 'PASS',
                'sev': 'Media',
                'peso': 5,
                'afectados': f"VDOM {vdom}",
                'evidencia': 'SNMP ausente en puertos de datos de usuario',
                'rec': 'Mantener SNMP aislado en el segmento de monitoreo dedicado',
                'rem': 'N/A - Cumple',
                'tipo': 'Técnico',
                'ref': 'SEG-LNB-002 Num 6.8 / CIS 2.1'
            })

        # 5. PING EN WAN
        wan_ping = [i['name'] for i in vdom_ifaces if (i['role'] == 'wan' or i['name'].startswith('wan')) and 'ping' in i['access']]
        if wan_ping:
            checks.append({
                'id': f'CHK-PROT-PING-WAN-{vdom}',
                'vdom': vdom,
                'cat': 'Hardening Adicional del Sistema',
                'mod': 'Interfaces de Red & Gestión',
                'hallazgo': f"ICMP Ping habilitado en interfaces WAN públicas ({', '.join(wan_ping)}) en VDOM '{vdom}'",
                'estado': 'WARNING',
                'sev': 'Baja',
                'peso': 5,
                'afectados': f"Interfaces WAN: {', '.join(wan_ping)}",
                'evidencia': f"allowaccess ping activo en interface WAN pública: {wan_ping}",
                'rec': 'Evaluar deshabilitar ping en interfaces WAN o restringirlo mediante Local-In Policy',
                'rem': f'config system interface\nedit "{wan_ping[0]}"\n  unset allowaccess\nnext\nend',
                'tipo': 'Técnico',
                'ref': 'SEG-LNB-002 Num 6.10 / NIST SC-7'
            })
        else:
            checks.append({
                'id': f'CHK-PROT-PING-WAN-{vdom}',
                'vdom': vdom,
                'cat': 'Hardening Adicional del Sistema',
                'mod': 'Interfaces de Red & Gestión',
                'hallazgo': f"Interfaces WAN sin exposición innecesaria de ICMP Ping en VDOM '{vdom}'",
                'estado': 'PASS',
                'sev': 'Baja',
                'peso': 5,
                'afectados': f"WANs VDOM {vdom}",
                'evidencia': 'Ping deshabilitado o no expuesto en WAN',
                'rec': 'Mantener las interfaces externas protegidas contra reconocimiento',
                'rem': 'N/A - Cumple',
                'tipo': 'Técnico',
                'ref': 'SEG-LNB-002 Num 6.10'
            })

    return checks
