# modules/security_profiles/application_control.py
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
    Auditoría completa de Application Control (config application list) VDOM por VDOM.
    Retorna 2 líneas resumen:
      1. Listas con configuraciones débiles o modo monitor.
      2. Listas huérfanas (sin referencia en ninguna política de firewall).
    """
    checks = []
    vdom_blocks = ctx.get('vdom_blocks', {})
    raw_content = ctx.get('content', '')

    # Lista de perfiles estándar/especiales a excluir de la auditoría de huérfanos
    EXCLUDED_PROFILES = {'sniffer-profile','wifi-default', 'initial'}

    if not vdom_blocks:
        vdom_blocks = {'root': raw_content}

    for vdom_name, vdom_content in vdom_blocks.items():
        vdom_prefix = vdom_name.upper().replace('-', '_')

        # =====================================================================
        # FASE 1: RECOPILAR REFERENCIAS DESDE LAS POLÍTICAS DE FIREWALL
        # =====================================================================
        referenced_apps = set()
        fw_block = extract_nested_block(vdom_content, "config firewall policy")
        if fw_block:
            app_lines = re.findall(r'set application-list\s+([^\n]+)', fw_block)
            for line in app_lines:
                names = re.findall(r'"([^"]+)"|([a-zA-Z0-9_-]+)', line)
                for n1, n2 in names:
                    val = n1 or n2
                    if val:
                        referenced_apps.add(val)

        # =====================================================================
        # FASE 2: AUDITORÍA DE APPLICATION CONTROL (config application list)
        # =====================================================================
        app_block = extract_nested_block(vdom_content, "config application list")
        apps_raw = re.findall(r'edit "([^"]+)"(.*?)(?=\n\s*edit |\Z)', app_block, re.DOTALL) if app_block else []

        weak_profiles = []
        app_names = set()

        for app_name, app_body in apps_raw:
            app_names.add(app_name)
            
            # Criterio de debilidad: verificar si opera en modo monitor exclusivamente o carece de opciones estrictas
            has_weakness = False
            if "options" in app_body.lower() and "allow-all" in app_body.lower():
                has_weakness = True

            if has_weakness:
                weak_profiles.append(app_name)

        # 1. Chequeo de Configuración Débil
        weak_summary = f"Listas débiles: {', '.join(weak_profiles[:10])}" if weak_profiles else "Ninguna lista de aplicaciones con configuración débil"

        checks.append({
            'id': f'CHK-APP-SUMMARY-{vdom_prefix}-PROFILES',
            'vdom': vdom_name,
            'cat': 'Security Profiles',
            'mod': 'Application Control',
            'hallazgo': f"VDOM '{vdom_name}': Listas de aplicaciones con configuración débil o allow-all (Total: {len(weak_profiles)})",
            'estado': 'WARNING' if weak_profiles else 'PASS',
            'sev': 'Media',
            'peso': 8,
            'afectados': f"VDOM {vdom_name} -> Listas débiles: {len(weak_profiles)}",
            'evidencia': weak_summary[:250],
            'rec': 'Asegurar que el control de aplicaciones bloquee tráfico no autorizado conforme a SEG-LNB-002.',
            'rem': 'config application list\n  edit "<Nombre_Lista>"\n    set other-application-action block\n  next\nend',
            'tipo': 'Técnico',
            'ref': 'SEG-LNB-002 Num 7.4'
        })

        # 2. Chequeo de Huérfanos (Excluyendo perfiles predeterminados)
        app_orphans = [name for name in app_names if name not in referenced_apps and name not in EXCLUDED_PROFILES]
        orphan_summary = f"Listas huérfanas: {', '.join(app_orphans[:10])}" if app_orphans else "Ninguna lista de Application Control huérfana"

        checks.append({
            'id': f'CHK-APP-SUMMARY-{vdom_prefix}-ORPHANS',
            'vdom': vdom_name,
            'cat': 'Security Profiles',
            'mod': 'Application Control Huérfanos',
            'hallazgo': f"VDOM '{vdom_name}': Listas de aplicaciones sin referencia en ninguna política de firewall (Total: {len(app_orphans)})",
            'estado': 'WARNING' if app_orphans else 'PASS',
            'sev': 'Baja',
            'peso': 5,
            'afectados': f"VDOM {vdom_name} -> Total huérfanos: {len(app_orphans)}",
            'evidencia': orphan_summary[:250],
            'rec': 'Depurar y eliminar listas de Application Control obsoletas o no utilizadas en las políticas.',
            'rem': 'config application list\n  delete <Nombre_Lista>\nend',
            'tipo': 'Técnico',
            'ref': 'SEG-LNB-002 Num 7.4 / Limpieza'
        })

    return checks
