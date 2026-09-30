# modules/user_auth/user_groups.py
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
    Auditoría de grupos de usuarios (config user group) buscando referencias explícitamente
    en políticas de firewall y configuración de SSL-VPN VDOM por VDOM, excluyendo grupos del sistema y SSO.
    """
    checks = []
    vdom_blocks = ctx.get('vdom_blocks', {})
    raw_content = ctx.get('content', '')

    # Grupos estándar del sistema y excepciones corporativas que deben omitirse
    SYSTEM_DEFAULT_GROUPS = {'guest-group', 'ssl-vpn users', 'all_users', 'all', 'sso_guest_users'}

    if not vdom_blocks:
        vdom_blocks = {'root': raw_content}

    for vdom_name, vdom_content in vdom_blocks.items():
        vdom_prefix = vdom_name.upper().replace('-', '_')

        group_block = extract_nested_block(vdom_content, "config user group")
        groups_raw = re.findall(r'edit "([^"]+)"(.*?)(?=\n\s*edit |\Z)', group_block, re.DOTALL) if group_block else []

        # Extraer bloques específicos de referencia para este VDOM
        policy_block = extract_nested_block(vdom_content, "config firewall policy") or ""
        ssl_settings_block = extract_nested_block(vdom_content, "config vpn ssl settings") or ""

        unreferenced_groups = []

        for g_name, g_body in groups_raw:
            if g_name.lower() in SYSTEM_DEFAULT_GROUPS:
                continue

            group_pattern = re.compile(rf'\b{re.escape(g_name)}\b', re.IGNORECASE)

            # Verificar si está referenciado explícitamente en Firewall Policies o SSL-VPN Settings
            referenced_in_policy = bool(group_pattern.search(policy_block))
            referenced_in_sslvpn = bool(group_pattern.search(ssl_settings_block))

            if not referenced_in_policy and not referenced_in_sslvpn:
                unreferenced_groups.append(g_name)

        # =====================================================================
        # CHECK: Grupos de Usuarios sin Referencia Explícita
        # =====================================================================
        group_summary = f"Grupos huérfanos sin uso en Firewall/SSL-VPN: {', '.join(unreferenced_groups[:10])}" if unreferenced_groups else "Todos los grupos están referenciados en políticas o SSL-VPN"
        checks.append({
            'id': f'CHK-USERGRP-{vdom_prefix}-ORPHANS',
            'vdom': vdom_name,
            'cat': 'User & Authentication',
            'mod': 'User Groups Reference Tracking',
            'hallazgo': f"VDOM '{vdom_name}': Grupos de usuarios sin referencia en políticas de firewall o configuración SSL-VPN (Total: {len(unreferenced_groups)})",
            'estado': 'WARNING' if unreferenced_groups else 'PASS',
            'sev': 'Baja',
            'peso': 4,
            'afectados': f"VDOM {vdom_name} -> Grupos sin uso: {len(unreferenced_groups)}",
            'evidencia': group_summary[:250],
            'rec': 'Eliminar grupos de usuarios que no tengan uso activo en políticas de seguridad o perfiles VPN conforme a SEG-LNB-002.',
            'rem': 'config user group\n  delete "<Grupo>"\nend',
            'tipo': 'Técnico',
            'ref': 'SEG-LNB-002 Num 6.1'
        })

    return checks

