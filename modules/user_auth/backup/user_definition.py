# modules/user_auth/user_definition.py
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
    Auditoría completa de definiciones de usuarios locales (config user local) VDOM por VDOM.
    Retorna 3 líneas resumen orientadas a 2FA, cuentas deshabilitadas y usuarios no referenciados.
    """
    checks = []
    vdom_blocks = ctx.get('vdom_blocks', {})
    raw_content = ctx.get('content', '')

    if not vdom_blocks:
        vdom_blocks = {'root': raw_content}

    for vdom_name, vdom_content in vdom_blocks.items():
        vdom_prefix = vdom_name.upper().replace('-', '_')

        user_block = extract_nested_block(vdom_content, "config user local")
        users_raw = re.findall(r'edit "([^"]+)"(.*?)(?=\n\s*edit |\Z)', user_block, re.DOTALL) if user_block else []

        no_2fa_users = []
        disabled_users = []
        unreferenced_users = []

        for u_name, u_body in users_raw:
            # 1. Validar si el usuario está deshabilitado
            if "set status disable" in u_body.lower():
                disabled_users.append(u_name)
                continue

            # 2. Validar si tiene 2FA configurado
            has_2fa = False
            if "set two-factor" in u_body.lower() and not "set two-factor disable" in u_body.lower():
                has_2fa = True

            if not has_2fa:
                no_2fa_users.append(u_name)

            # 3. Validar si el usuario está referenciado en el VDOM
            # Buscamos menciones del nombre del usuario en todo el contenido del VDOM (excepto en su propia definición)
            # Ej: grupos, políticas, admins, etc.
            user_pattern = re.compile(rf'\b{re.escape(u_name)}\b', re.IGNORECASE)
            # Contamos cuántas veces aparece el nombre del usuario en el texto del VDOM
            matches = user_pattern.findall(vdom_content)
            # Si aparece solo 1 vez (su propia definición en 'config user local') o 0 veces
            if len(matches) <= 1:
                unreferenced_users.append(u_name)

        # =====================================================================
        # CHECK 1: Usuarios Activos sin Doble Factor de Autenticación (2FA)
        # =====================================================================
        no_2fa_summary = f"Usuarios sin 2FA: {', '.join(no_2fa_users[:10])}" if no_2fa_users else "Todos los usuarios locales activos cuentan con 2FA"
        checks.append({
            'id': f'CHK-USERDEF-{vdom_prefix}-2FA',
            'vdom': vdom_name,
            'cat': 'User & Authentication',
            'mod': 'Local Users Two-Factor Auth',
            'hallazgo': f"VDOM '{vdom_name}': Usuarios locales activos sin autenticación de doble factor (2FA) (Total: {len(no_2fa_users)})",
            'estado': 'WARNING' if no_2fa_users else 'PASS',
            'sev': 'Alta',
            'peso': 10,
            'afectados': f"VDOM {vdom_name} -> Sin 2FA: {len(no_2fa_users)}",
            'evidencia': no_2fa_summary[:250],
            'rec': 'Habilitar autenticación de doble factor (FortiToken, email o SMS) para todos los usuarios locales conforme a SEG-LNB-002.',
            'rem': 'config user local\n  edit "<Usuario>"\n    set two-factor fortitoken\n  next\nend',
            'tipo': 'Técnico',
            'ref': 'SEG-LNB-002 Num 6.1 / ISO 27001 A.9.4.2 / NIST IA-2'
        })

        # =====================================================================
        # CHECK 2: Cuentas Locales Deshabilitadas / Inactivas
        # =====================================================================
        disabled_summary = f"Usuarios desactivados: {', '.join(disabled_users[:10])}" if disabled_users else "No existen usuarios locales deshabilitados"
        checks.append({
            'id': f'CHK-USERDEF-{vdom_prefix}-DISABLED',
            'vdom': vdom_name,
            'cat': 'User & Authentication',
            'mod': 'Local Users Status',
            'hallazgo': f"VDOM '{vdom_name}': Cuentas de usuarios locales deshabilitadas presentes en configuración (Total: {len(disabled_users)})",
            'estado': 'WARNING' if disabled_users else 'PASS',
            'sev': 'Baja',
            'peso': 3,
            'afectados': f"VDOM {vdom_name} -> Inactivos: {len(disabled_users)}",
            'evidencia': disabled_summary[:250],
            'rec': 'Eliminar cuentas de usuario locales obsoletas o deshabilitadas para cumplir estrictamente con el principio de mínimo privilegio.',
            'rem': 'config user local\n  delete "<Usuario>"\nend',
            'tipo': 'Técnico',
            'ref': 'SEG-LNB-002 Num 6.1 / ISO 27001 A.9.2 / NIST AC-6'
        })

        # =====================================================================
        # CHECK 3: Cuentas Locales No Referenciadas (Huérfanas)
        # =====================================================================
        unref_summary = f"Usuarios huérfanos: {', '.join(unreferenced_users[:10])}" if unreferenced_users else "Todos los usuarios locales están referenciados"
        checks.append({
            'id': f'CHK-USERDEF-{vdom_prefix}-ORPHANS',
            'vdom': vdom_name,
            'cat': 'User & Authentication',
            'mod': 'Local Users Reference Tracking',
            'hallazgo': f"VDOM '{vdom_name}': Cuentas de usuarios locales que no se encuentran referenciadas en grupos o políticas (Total: {len(unreferenced_users)})",
            'estado': 'WARNING' if unreferenced_users else 'PASS',
            'sev': 'Media',
            'peso': 5,
            'afectados': f"VDOM {vdom_name} -> Sin referencia: {len(unreferenced_users)}",
            'evidencia': unref_summary[:250],
            'rec': 'Eliminar o asociar cuentas de usuario local que no posean referencias activas en grupos de seguridad o políticas de acceso.',
            'rem': 'config user local\n  delete "<Usuario>"\nend',
            'tipo': 'Técnico',
            'ref': 'SEG-LNB-002 Num 6.1'
        })

    return checks
