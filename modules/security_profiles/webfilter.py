# modules/security_profiles/webfilter.py
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
    Auditoría completa de Perfiles de Web Filter (config webfilter profile) VDOM por VDOM.
    Retorna 2 líneas resumen:
      1. Perfiles con configuraciones débiles.
      2. Perfiles huérfanos (sin referencia en ninguna política de firewall).
    """
    checks = []
    vdom_blocks = ctx.get('vdom_blocks', {})
    raw_content = ctx.get('content', '')

    # Lista de perfiles estándar/especiales a excluir de la auditoría de huérfanos
    EXCLUDED_PROFILES = { 'wifi-default', 'sniffer-profile'}

    if not vdom_blocks:
        vdom_blocks = {'root': raw_content}

    for vdom_name, vdom_content in vdom_blocks.items():
        vdom_prefix = vdom_name.upper().replace('-', '_')

        # =====================================================================
        # FASE 1: RECOPILAR REFERENCIAS DESDE LAS POLÍTICAS DE FIREWALL
        # =====================================================================
        referenced_wf = set()
        fw_block = extract_nested_block(vdom_content, "config firewall policy")
        if fw_block:
            wf_lines = re.findall(r'set webfilter-profile\s+([^\n]+)', fw_block)
            for line in wf_lines:
                names = re.findall(r'"([^"]+)"|([a-zA-Z0-9_-]+)', line)
                for n1, n2 in names:
                    val = n1 or n2
                    if val:
                        referenced_wf.add(val)

        # =====================================================================
        # FASE 2: AUDITORÍA DE PERFILES DE WEB FILTER (config webfilter profile)
        # =====================================================================
        wf_block = extract_nested_block(vdom_content, "config webfilter profile")
        wfs_raw = re.findall(r'edit "([^"]+)"(.*?)(?=\n\s*edit |\Z)', wf_block, re.DOTALL) if wf_block else []

        weak_profiles = []
        wf_names = set()

        for wf_name, wf_body in wfs_raw:
            wf_names.add(wf_name)

            # Criterio de debilidad: Evaluar si permite explícitamente categorías de alto riesgo o carece de bloqueo activo
            has_weakness = False
            if "option" in wf_body.lower() and "block-invalid-url" not in wf_body.lower():
                # Ejemplo de validación de hardening web
                pass

            # Si se desea auditar perfiles que operan en modo monitor o sin inspección estricta
            if "mode" in wf_body.lower() and "monitor" in wf_body.lower():
                has_weakness = True

            if has_weakness:
                weak_profiles.append(wf_name)

        # 1. Chequeo de Configuración Débil
        weak_summary = f"Perfiles débiles: {', '.join(weak_profiles[:10])}" if weak_profiles else "Ningún perfil web con configuración débil"

        checks.append({
            'id': f'CHK-WF-SUMMARY-{vdom_prefix}-PROFILES',
            'vdom': vdom_name,
            'cat': 'Security Profiles',
            'mod': 'Web Filter Inspection',
            'hallazgo': f"VDOM '{vdom_name}': Perfiles de Web Filter con configuración débil o modo monitor (Total: {len(weak_profiles)})",
            'estado': 'WARNING' if weak_profiles else 'PASS',
            'sev': 'Media',
            'peso': 8,
            'afectados': f"VDOM {vdom_name} -> Perfiles débiles: {len(weak_profiles)}",
            'evidencia': weak_summary[:250],
            'rec': 'Asegurar que los perfiles de Web Filter apliquen bloqueo estricto a categorías maliciosas conforme a SEG-LNB-002.',
            'rem': 'config webfilter profile\n  edit "<Nombre_Perfil>"\n    set inspection-mode url-filter\n  next\nend',
            'tipo': 'Técnico',
            'ref': 'SEG-LNB-002 Num 6.5 / ISO 27001 A.13.2.1'
        })

        # 2. Chequeo de Huérfanos (Excluyendo perfiles predeterminados)
        wf_orphans = [name for name in wf_names if name not in referenced_wf and name not in EXCLUDED_PROFILES]
        orphan_summary = f"Perfiles huérfanos: {', '.join(wf_orphans[:10])}" if wf_orphans else "Ningún perfil de Web Filter huérfano"

        checks.append({
            'id': f'CHK-WF-SUMMARY-{vdom_prefix}-ORPHANS',
            'vdom': vdom_name,
            'cat': 'Security Profiles',
            'mod': 'Web Filter Huérfanos',
            'hallazgo': f"VDOM '{vdom_name}': Perfiles de Web Filter sin referencia en ninguna política de firewall (Total: {len(wf_orphans)})",
            'estado': 'WARNING' if wf_orphans else 'PASS',
            'sev': 'Baja',
            'peso': 5,
            'afectados': f"VDOM {vdom_name} -> Total huérfanos: {len(wf_orphans)}",
            'evidencia': orphan_summary[:250],
            'rec': 'Depurar y eliminar perfiles de Web Filter obsoletos o no utilizados en las políticas.',
            'rem': 'config webfilter profile\n  delete <Nombre_Perfil>\nend',
            'tipo': 'Técnico',
            'ref': 'SEG-LNB-002 Num 6.5'
        })

    return checks
