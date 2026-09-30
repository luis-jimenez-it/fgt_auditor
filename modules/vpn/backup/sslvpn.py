# modules/vpn/sslvpn.py
import re

def extract_nested_block(text, block_header):
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        if line == block_header:
            block_lines = []
            i += 1
            nesting = 1
            while i < len(lines):
                sub_s = lines[i].strip()
                if sub_s.startswith("config ") or sub_s.startswith("edit "):
                    nesting += 1
                elif sub_s in ["end", "next"]:
                    nesting -= 1
                    if nesting == 0:
                        break
                block_lines.append(lines[i])
                i += 1
            return "\n".join(block_lines)
        i += 1
    return None

def audit(ctx):
    """
    Auditoría exhaustiva de SSL-VPN (global settings, portales, timeouts y marcadores) VDOM por VDOM.
    Retorna 3 líneas resumen alineadas a la línea base SEG-LNB-002.
    """
    checks = []
    vdom_blocks = ctx.get('vdom_blocks', {})
    raw_content = ctx.get('content', '')

    if not vdom_blocks:
        vdom_blocks = {'root': raw_content}

    for vdom_name, vdom_content in vdom_blocks.items():
        vdom_prefix = vdom_name.upper().replace('-', '_')

        # =====================================================================
        # FASE 1: CONFIGURACIÓN GLOBAL DE SSL-VPN (config vpn ssl settings)
        # =====================================================================
        ssl_settings_block = extract_nested_block(vdom_content, "config vpn ssl settings")
        
        insecure_settings = []
        if ssl_settings_block:
            # 1. Versión de TLS obsoleto
            if re.search(r'set ssl-min-proto-version\s+(tls1|tls1-0|tls1-1)', ssl_settings_block, re.IGNORECASE):
                insecure_settings.append("TLS obsoleto (1.0/1.1)")

            # 2. Split-Tunneling habilitado
            if "set split-tunnel enable" in ssl_settings_block.lower():
                insecure_settings.append("Split-Tunneling habilitado")

            # 3. Idle timeout excesivo o no configurado
            idle_m = re.search(r'set idle-timeout\s+(\d+)', ssl_settings_block)
            if idle_m:
                val = int(idle_m.group(1))
                if val > 28800: # Más de 8 horas
                    insecure_settings.append(f"Idle timeout muy alto ({val}s)")
            else:
                insecure_settings.append("Idle timeout por defecto")

        settings_summary = f"Deficiencias globales: {', '.join(insecure_settings)}" if insecure_settings else "Configuración global de SSL-VPN conforme a baseline"
        checks.append({
            'id': f'CHK-SSLVPN-SUMMARY-{vdom_prefix}-SETTINGS',
            'vdom': vdom_name,
            'cat': 'VPN Hardening',
            'mod': 'SSL-VPN Global Settings',
            'hallazgo': f"VDOM '{vdom_name}': Configuración global de SSL-VPN con parámetros débiles o split-tunneling (Total: {len(insecure_settings)})",
            'estado': 'WARNING' if insecure_settings else 'PASS',
            'sev': 'Alta',
            'peso': 10,
            'afectados': f"VDOM {vdom_name} -> Parámetros débiles: {len(insecure_settings)}",
            'evidencia': settings_summary[:250],
            'rec': 'Exigir TLS 1.2+, deshabilitar split-tunneling y ajustar idle-timeout conforme a SEG-LNB-002 Num 9.3.',
            'rem': 'config vpn ssl settings\n  set ssl-min-proto-version tls1-2\n  set split-tunnel disable\n  set idle-timeout 1800\nend',
            'tipo': 'Técnico',
            'ref': 'SEG-LNB-002 Num 9.3'
        })

        # =====================================================================
        # FASE 2: AUDITORÍA DE PORTALES SSL-VPN (Modos y Descargas)
        # =====================================================================
        portal_block = extract_nested_block(vdom_content, "config vpn ssl web portal")
        portals_raw = re.findall(r'edit "([^"]+)"(.*?)(?=\n\s*edit |\Z)', portal_block, re.DOTALL) if portal_block else []

        insecure_portals = []
        risky_bookmarks = []
        portal_names = set()

        for p_name, p_body in portals_raw:
            portal_names.add(p_name)
            
            # Validar modo web + modo túnel simultáneo o descarga de cliente habilitada en login
            portal_issues = []
            if "set tunnel-mode enable" in p_body.lower() and "set web-mode enable" in p_body.lower():
                portal_issues.append("Modo Web y Túnel activos")

            if "set client-download-enable enable" in p_body.lower():
                portal_issues.append("Descarga de cliente en portal web activa")

            if portal_issues:
                insecure_portals.append(f"{p_name} ({', '.join(portal_issues)})")

            # =================================================================
            # FASE 3: MARCADORES DE RIESGO EN PORTALES WEB (RDP, VNC, SMB, HTTP)
            # =================================================================
            if "config bookmark" in p_body.lower():
                bm_block = extract_nested_block(p_body, "config bookmark")
                if bm_block and any(proto in bm_block.lower() for proto in ['rdp', 'vnc', 'cifs', 'smb', 'http://']):
                    risky_bookmarks.append(p_name)

        # Reporte 2: Portales con modos inseguros / descarga
        portal_summary = f"Portales con observaciones: {', '.join(insecure_portals[:10])}" if insecure_portals else "Portales SSL-VPN seguros"
        checks.append({
            'id': f'CHK-SSLVPN-SUMMARY-{vdom_prefix}-PORTALS',
            'vdom': vdom_name,
            'cat': 'VPN Hardening',
            'mod': 'SSL-VPN Portals Restriction',
            'hallazgo': f"VDOM '{vdom_name}': Portales SSL-VPN con modo web y descarga de agentes habilitados (Total: {len(insecure_portals)})",
            'estado': 'WARNING' if insecure_portals else 'PASS',
            'sev': 'Media',
            'peso': 7,
            'afectados': f"VDOM {vdom_name} -> Portales con observaciones: {len(insecure_portals)}",
            'evidencia': portal_summary[:250],
            'rec': 'Deshabilitar modo web y descarga directa de clientes en portales expuestos conforme a SEG-LNB-002 Num 9.4.',
            'rem': 'config vpn ssl web portal\n  edit "<Portal>"\n    set web-mode disable\n    set client-download-enable disable\n  next\nend',
            'tipo': 'Técnico',
            'ref': 'SEG-LNB-002 Num 9.4'
        })

        # Reporte 3: Marcadores de riesgo (RDP/SMB/VNC)
        bm_summary = f"Portales con marcadores de riesgo: {', '.join(risky_bookmarks[:10])}" if risky_bookmarks else "Sin marcadores web de protocolos inseguros"
        checks.append({
            'id': f'CHK-SSLVPN-SUMMARY-{vdom_prefix}-BOOKMARKS',
            'vdom': vdom_name,
            'cat': 'VPN Hardening',
            'mod': 'SSL-VPN Risky Bookmarks',
            'hallazgo': f"VDOM '{vdom_name}': Portales que contienen marcadores web hacia protocolos vulnerables (RDP/VNC/SMB/HTTP) (Total: {len(risky_bookmarks)})",
            'estado': 'WARNING' if risky_bookmarks else 'PASS',
            'sev': 'Alta',
            'peso': 9,
            'afectados': f"VDOM {vdom_name} -> Portales con riesgo: {len(risky_bookmarks)}",
            'evidencia': bm_summary[:250],
            'rec': 'Evitar exponer accesos directos web (bookmarks) a servicios internos sensibles (RDP, SMB, VNC) sin tunelización estricta.',
            'rem': 'config vpn ssl web portal\n  edit "<Portal>"\n    config bookmark\n      delete "<Marcador_Inseguro>"\n    end\n  next\nend',
            'tipo': 'Técnico',
            'ref': 'SEG-LNB-002 Num 9.4.1'
        })

    return checks
