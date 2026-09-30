# modules/security_profiles/antivirus.py
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
    Auditoría completa de Perfiles de Antivirus (config antivirus profile) VDOM por VDOM.
    Retorna 2 líneas resumen (excluyendo perfiles de sistema/especiales):
      1. Perfiles con configuración débil o modo monitor.
      2. Perfiles huérfanos (sin referencia en ninguna política de firewall).
    """
    checks = []
    vdom_blocks = ctx.get('vdom_blocks', {})
    raw_content = ctx.get('content', '')

    # Lista de perfiles estándar/especiales a excluir de la auditoría de huérfanos
    EXCLUDED_PROFILES = {'wifi-default', 'sniffer-profile', 'default', 'initial'}

    if not vdom_blocks:
        vdom_blocks = {'root': raw_content}

    for vdom_name, vdom_content in vdom_blocks.items():
        vdom_prefix = vdom_name.upper().replace('-', '_')

        # =====================================================================
        # FASE 1: RECOPILAR REFERENCIAS DESDE LAS POLÍTICAS DE FIREWALL
        # =====================================================================
        referenced_av = set()
        fw_block = extract_nested_block(vdom_content, "config firewall policy")
        if fw_block:
            av_lines = re.findall(r'set av-profile\s+([^\n]+)', fw_block)
            for line in av_lines:
                names = re.findall(r'"([^"]+)"|([a-zA-Z0-9_-]+)', line)
                for n1, n2 in names:
                    val = n1 or n2
                    if val:
                        referenced_av.add(val)

        # =====================================================================
        # FASE 2: AUDITORÍA DE PERFILES DE ANTIVIRUS (config antivirus profile)
        # =====================================================================
        av_block = extract_nested_block(vdom_content, "config antivirus profile")
        avs_raw = re.findall(r'edit "([^"]+)"(.*?)(?=\n\s*edit |\Z)', av_block, re.DOTALL) if av_block else []

        weak_profiles = []
        av_names = set()

        for av_name, av_body in avs_raw:
            av_names.add(av_name)
            
            # Validar si tiene configuraciones débiles o modo monitor
            has_weakness = False
            if "option" in av_body.lower() and "monitor" in av_body.lower():
                has_weakness = True

            if has_weakness:
                weak_profiles.append(av_name)

        # 1. Chequeo de Configuración Débil
        weak_summary = f"Perfiles débiles: {', '.join(weak_profiles[:10])}" if weak_profiles else "Ningún perfil con configuración débil"

        checks.append({
            'id': f'CHK-AV-SUMMARY-{vdom_prefix}-PROFILES',
            'vdom': vdom_name,
            'cat': 'Security Profiles',
            'mod': 'Antivirus Inspection',
            'hallazgo': f"VDOM '{vdom_name}': Perfiles de antivirus con configuración débil o modo monitor (Total: {len(weak_profiles)})",
            'estado': 'WARNING' if weak_profiles else 'PASS',
            'sev': 'Media',
            'peso': 8,
            'afectados': f"VDOM {vdom_name} -> Perfiles débiles: {len(weak_profiles)}",
            'evidencia': weak_summary[:250],
            'rec': 'Asegurar que los perfiles de antivirus actúen en modo bloqueo y apliquen inspección profunda conforme a SEG-LNB-002.',
            'rem': 'config antivirus profile\n  edit "<Nombre_Perfil>"\n    set inspection-mode full\n  next\nend',
            'tipo': 'Técnico',
            'ref': 'SEG-LNB-002 Num 7.1'
        })

        # 2. Chequeo de Huérfanos (Excluyendo los perfiles de sistema/especiales)
        av_orphans = [name for name in av_names if name not in referenced_av and name not in EXCLUDED_PROFILES]
        orphan_summary = f"Perfiles huérfanos: {', '.join(av_orphans[:10])}" if av_orphans else "Ningún perfil de antivirus huérfano"

        checks.append({
            'id': f'CHK-AV-SUMMARY-{vdom_prefix}-ORPHANS',
            'vdom': vdom_name,
            'cat': 'Security Profiles',
            'mod': 'Antivirus Huérfanos',
            'hallazgo': f"VDOM '{vdom_name}': Perfiles de antivirus sin referencia en ninguna política de firewall (Total: {len(av_orphans)})",
            'estado': 'WARNING' if av_orphans else 'PASS',
            'sev': 'Baja',
            'peso': 5,
            'afectados': f"VDOM {vdom_name} -> Total huérfanos: {len(av_orphans)}",
            'evidencia': orphan_summary[:250],
            'rec': 'Depurar y eliminar perfiles de antivirus obsoletos o que no estén siendo aplicados en las políticas.',
            'rem': 'config antivirus profile\n  delete <Nombre_Perfil>\nend',
            'tipo': 'Técnico',
            'ref': 'SEG-LNB-002 Num 7.1 / Limpieza'
        })

    return checks
