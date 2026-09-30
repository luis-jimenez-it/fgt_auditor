# modules/vpn/sslvpn_settings.py
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
    Auditoría detallada y desglosada por parámetro de Configuración Global de SSL-VPN 
    (config vpn ssl settings y authentication-rule) VDOM por VDOM.
    Retorna múltiples líneas independientes por VDOM para máxima visibilidad.
    """
    checks = []
    vdom_blocks = ctx.get('vdom_blocks', {})
    raw_content = ctx.get('content', '')

    if not vdom_blocks:
        vdom_blocks = {'root': raw_content}

    for vdom_name, vdom_content in vdom_blocks.items():
        vdom_prefix = vdom_name.upper().replace('-', '_')

        ssl_settings_block = extract_nested_block(vdom_content, "config vpn ssl settings")
        
        # Variables de estado individuales
        has_factory_cert = False
        cert_name = "N/A"
        has_old_tls = False
        tls_version = "Desconocido"
        has_split_tunnel = False
        insecure_auth_rule = False
        auth_details = "Ninguna regla general con exceso de privilegios"

        if ssl_settings_block:
            # 1. Certificado del Servidor
            cert_m = re.search(r'set server-cert\s+"?([^"\n]+)"?', ssl_settings_block)
            if cert_m:
                cert_name = cert_m.group(1)
                if "fortinet_factory" in cert_name.lower():
                    has_factory_cert = True

            # 2. Versión Mínima de TLS
            tls_m = re.search(r'set ssl-min-proto-version\s+([^\n]+)', ssl_settings_block)
            if tls_m:
                tls_version = tls_m.group(1).strip()
                if any(v in tls_version.lower() for v in ['tls1', 'tls1-0', 'tls1-1']):
                    has_old_tls = True

            # 3. Split-Tunneling
            if "set split-tunnel enable" in ssl_settings_block.lower():
                has_split_tunnel = True

            # 4. Reglas de Autenticación (All Other Users / all)
            auth_rules_block = extract_nested_block(ssl_settings_block, "config authentication-rule")
            if auth_rules_block:
                rules_raw = re.findall(r'edit\s+(\d+)(.*?)(?=\n\s*edit |\Z)', auth_rules_block, re.DOTALL)
                for r_id, r_body in rules_raw:
                    if re.search(r'set groups\s+.*("all"|All_Users)', r_body, re.IGNORECASE):
                        portal_m = re.search(r'set portal\s+"?([^"\n]+)"?', r_body)
                        if portal_m:
                            assigned_portal = portal_m.group(1).lower()
                            if assigned_portal in ['full-access', 'web-access']:
                                insecure_auth_rule = True
                                auth_details = f"Grupo 'all/All_Users' apunta al portal no restrictivo '{assigned_portal}'"

        # =====================================================================
        # CHECK 1: Certificado del Servidor SSL-VPN
        # =====================================================================
        checks.append({
            'id': f'CHK-SSLSET-{vdom_prefix}-CERT',
            'vdom': vdom_name,
            'cat': 'VPN Hardening',
            'mod': 'SSL-VPN Server Certificate',
            'hallazgo': f"VDOM '{vdom_name}': Uso de certificado autofirmado predeterminado de fábrica ({cert_name})",
            'estado': 'WARNING' if has_factory_cert else 'PASS',
            'sev': 'Alta',
            'peso': 10,
            'afectados': f"VDOM {vdom_name} -> Certificado actual: {cert_name}",
            'evidencia': f"Certificado configurado: {cert_name}",
            'rec': 'Implementar un certificado SSL válido emitido por una CA corporativa o confiable conforme a SEG-LNB-002.',
            'rem': 'config vpn ssl settings\n  set server-cert "<Certificado_Corporativo>"\nend',
            'tipo': 'Técnico',
            'ref': 'SEG-LNB-002 Num 9.3'
        })

        # =====================================================================
        # CHECK 2: Versión Mínima de Protocolo TLS
        # =====================================================================
        checks.append({
            'id': f'CHK-SSLSET-{vdom_prefix}-TLS',
            'vdom': vdom_name,
            'cat': 'VPN Hardening',
            'mod': 'SSL-VPN TLS Version',
            'hallazgo': f"VDOM '{vdom_name}': Versión mínima de protocolo TLS configurada ({tls_version})",
            'estado': 'WARNING' if has_old_tls else 'PASS',
            'sev': 'Alta',
            'peso': 10,
            'afectados': f"VDOM {vdom_name} -> Protocolo actual: {tls_version}",
            'evidencia': f"Versión mínima TLS: {tls_version}",
            'rec': 'Exigir el uso estricto de TLS 1.2 o TLS 1.3 (tls1-2 o tls1-3) conforme a SEG-LNB-002.',
            'rem': 'config vpn ssl settings\n  set ssl-min-proto-version tls1-2\nend',
            'tipo': 'Técnico',
            'ref': 'SEG-LNB-002 Num 9.3.1'
        })

        # =====================================================================
        # CHECK 3: Control de Split-Tunneling Global
        # =====================================================================
        checks.append({
            'id': f'CHK-SSLSET-{vdom_prefix}-SPLITTUNNEL',
            'vdom': vdom_name,
            'cat': 'VPN Hardening',
            'mod': 'SSL-VPN Split-Tunneling',
            'hallazgo': f"VDOM '{vdom_name}': Estado de Split-Tunneling global en SSL-VPN",
            'estado': 'WARNING' if has_split_tunnel else 'PASS',
            'sev': 'Media',
            'peso': 8,
            'afectados': f"VDOM {vdom_name} -> Split-Tunnel: {'Habilitado' if has_split_tunnel else 'Deshabilitado'}",
            'evidencia': f"Split-Tunnel habilitado: {has_split_tunnel}",
            'rec': 'Deshabilitar el split-tunneling global para asegurar que todo el tráfico pase por los controles corporativos de seguridad.',
            'rem': 'config vpn ssl settings\n  set split-tunnel disable\nend',
            'tipo': 'Técnico',
            'ref': 'SEG-LNB-002 Num 9.3.2'
        })

        # =====================================================================
        # CHECK 4: Principio de Mínimo Privilegio (All Users / Authentication Rules)
        # =====================================================================
        checks.append({
            'id': f'CHK-SSLSET-{vdom_prefix}-AUTHRULES',
            'vdom': vdom_name,
            'cat': 'VPN Hardening',
            'mod': 'SSL-VPN Auth Rules & Min Privilege',
            'hallazgo': f"VDOM '{vdom_name}': Mapeo de grupos genéricos (All Users) a portales con privilegios elevados",
            'estado': 'WARNING' if insecure_auth_rule else 'PASS',
            'sev': 'Alta',
            'peso': 10,
            'afectados': f"VDOM {vdom_name} -> Detalle: {auth_details}",
            'evidencia': auth_details,
            'rec': 'Asegurar que los usuarios genéricos o no catalogados (All_Users) apunten al portal más restrictivo posible.',
            'rem': 'config vpn ssl settings\n  config authentication-rule\n    edit <ID>\n      set portal "tunnel-access"\n    next\n  end\nend',
            'tipo': 'Técnico',
            'ref': 'SEG-LNB-002 Num 9.3.3'
        })

    return checks
