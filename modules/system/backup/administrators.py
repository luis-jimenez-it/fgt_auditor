# modules/system/administrators.py
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
    Auditoría estricta de cuentas de administrador (config system admin) VDOM por VDOM,
    marcando como vulnerabilidad si el trusted-host está ausente o configurado en 0.0.0.0 (abierto a internet).
    """
    checks = []
    vdom_blocks = ctx.get('vdom_blocks', {})
    raw_content = ctx.get('content', '')

    if not vdom_blocks:
        vdom_blocks = {'root': raw_content}

    for vdom_name, vdom_content in vdom_blocks.items():
        vdom_prefix = vdom_name.upper().replace('-', '_')

        admin_block = extract_nested_block(vdom_content, "config system admin")
        admins_raw = re.findall(r'edit "([^"]+)"(.*?)(?=\n\s*edit |\Z)', admin_block, re.DOTALL) if admin_block else []

        untrusted_admins = []
        no_2fa_admins = []
        default_admin_issues = []

        for adm_name, adm_body in admins_raw:
            # 1. Validación estricta de trusted-host (Inseguro si no está o si tiene 0.0.0.0)
            has_valid_trusted_host = True
            trusted_m = re.search(r'set trusted-host\s+([^\n]+)', adm_body, re.IGNORECASE)
            
            if not trusted_m:
                has_valid_trusted_host = False
            else:
                ip_value = trusted_m.group(1).strip()
                if '0.0.0.0' in ip_value:
                    has_valid_trusted_host = False

            if not has_valid_trusted_host:
                untrusted_admins.append(adm_name)

            # 2. Validar Two-Factor (2FA)
            has_2fa = False
            if "set two-factor" in adm_body.lower() and not "set two-factor disable" in adm_body.lower():
                has_2fa = True

            if not has_2fa:
                no_2fa_admins.append(adm_name)

            # 3. Validar cuenta 'admin' por defecto
            if adm_name.lower() == "admin" and not has_valid_trusted_host:
                default_admin_issues.append("Cuenta por defecto 'admin' abierta a internet (0.0.0.0)")

        # =====================================================================
        # CHECK 1: Administradores sin Host de Confianza Estricto
        # =====================================================================
        trusted_summary = f"Admins sin IP corporativa restringida: {', '.join(untrusted_admins[:10])}" if untrusted_admins else "Todas las cuentas de administrador tienen IPs de confianza restringidas"
        checks.append({
            'id': f'CHK-SYSADMIN-{vdom_prefix}-TRUSTEDHOSTS',
            'vdom': vdom_name,
            'cat': 'System Hardening',
            'mod': 'Administrator Trusted Hosts',
            'hallazgo': f"VDOM '{vdom_name}': Cuentas de administrador con trusted-host ausente o abierto a internet (0.0.0.0) (Total: {len(untrusted_admins)})",
            'estado': 'WARNING' if untrusted_admins else 'PASS',
            'sev': 'Alta',
            'peso': 10,
            'afectados': f"VDOM {vdom_name} -> Abiertos/Sin restricción: {len(untrusted_admins)}",
            'evidencia': trusted_summary[:250],
            'rec': 'Configurar subredes corporativas específicas en trusted-host, prohibiendo el uso de 0.0.0.0 conforme a SEG-LNB-002.',
            'rem': 'config system admin\n  edit "<Admin>"\n    set trusted-host <IP_Corp> <Netmask>\n  next\nend',
            'tipo': 'Técnico',
            'ref': 'SEG-LNB-002 Num 8.1'
        })

        # =====================================================================
        # CHECK 2: Administradores sin Doble Factor de Autenticación (2FA)
        # =====================================================================
        twofa_summary = f"Admins sin 2FA: {', '.join(no_2fa_admins[:10])}" if no_2fa_admins else "Todas las cuentas de administrador cuentan con 2FA"
        checks.append({
            'id': f'CHK-SYSADMIN-{vdom_prefix}-2FA',
            'vdom': vdom_name,
            'cat': 'System Hardening',
            'mod': 'Administrator Two-Factor Auth',
            'hallazgo': f"VDOM '{vdom_name}': Cuentas de administrador sin autenticación de doble factor (2FA) habilitada (Total: {len(no_2fa_admins)})",
            'estado': 'WARNING' if no_2fa_admins else 'PASS',
            'sev': 'Alta',
            'peso': 10,
            'afectados': f"VDOM {vdom_name} -> Sin 2FA: {len(no_2fa_admins)}",
            'evidencia': twofa_summary[:250],
            'rec': 'Exigir el uso de doble factor de autenticación (FortiToken o email) en todas las cuentas de administración conforme a SEG-LNB-002.',
            'rem': 'config system admin\n  edit "<Admin>"\n    set two-factor fortitoken\n  next\nend',
            'tipo': 'Técnico',
            'ref': 'SEG-LNB-002 Num 8.1.1'
        })

        # =====================================================================
        # CHECK 3: Exposición de la Cuenta por Defecto 'admin'
        # =====================================================================
        def_summary = f"Observaciones en cuenta admin: {', '.join(default_admin_issues)}" if default_admin_issues else "Cuenta 'admin' debidamente acotada o renombrada"
        checks.append({
            'id': f'CHK-SYSADMIN-{vdom_prefix}-DEFAULTACCOUNT',
            'vdom': vdom_name,
            'cat': 'System Hardening',
            'mod': 'Default Administrator Account',
            'hallazgo': f"VDOM '{vdom_name}': Exposición o falta de endurecimiento en la cuenta de administración predeterminada 'admin'",
            'estado': 'WARNING' if default_admin_issues else 'PASS',
            'sev': 'Media',
            'peso': 7,
            'afectados': f"VDOM {vdom_name} -> Estado cuenta admin",
            'evidencia': def_summary[:250],
            'rec': 'Renombrar la cuenta por defecto "admin" o restringirla estrictamente por IP y doble factor conforme a SEG-LNB-002.',
            'rem': 'config system admin\n  rename admin to <Admin_Personalizado>\nend',
            'tipo': 'Técnico',
            'ref': 'SEG-LNB-002 Num 8.2'
        })

    return checks
