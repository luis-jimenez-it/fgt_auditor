# modules/policy_objects/services.py
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
    Auditoría precisa de Objetos de Servicio y Grupos VDOM por VDOM.
    Retorna 3 líneas resumen:
      1. Servicios personalizados duplicados (por puertos/protocolo).
      2. Servicios personalizados huérfanos (sin uso en políticas ni grupos).
      3. Grupos de servicios huérfanos (sin uso en políticas ni otros grupos).
    """
    checks = []
    vdom_blocks = ctx.get('vdom_blocks', {})
    raw_content = ctx.get('content', '')

    if not vdom_blocks:
        vdom_blocks = {'root': raw_content}

    for vdom_name, vdom_content in vdom_blocks.items():
        vdom_prefix = vdom_name.upper().replace('-', '_')

        # =====================================================================
        # FASE 1: RECOPILAR TODAS LAS REFERENCIAS REALES DE SERVICIOS EN EL VDOM
        # =====================================================================
        referenced_services = set()

        # 1. Desde las Políticas de Firewall (config firewall policy -> set service)
        fw_block = extract_nested_block(vdom_content, "config firewall policy")
        if fw_block:
            service_lines = re.findall(r'set service\s+([^\n]+)', fw_block)
            for line in service_lines:
                # Extraer nombres entre comillas o palabras simples
                names = re.findall(r'"([^"]+)"|([a-zA-Z0-9_-]+)', line)
                for n1, n2 in names:
                    val = n1 or n2
                    if val and val.lower() != 'all':
                        referenced_services.add(val)

        # 2. Desde los Grupos de Servicios (config firewall service group -> set member)
        group_block = extract_nested_block(vdom_content, "config firewall service group")
        groups_raw = []
        if group_block:
            groups_parsed = re.findall(r'edit "([^"]+)"(.*?)(?=\n\s*edit |\Z)', group_block, re.DOTALL)
            for gname, gbody in groups_parsed:
                groups_raw.append(gname)
                member_m = re.search(r'set member\s+([^\n]+)', gbody)
                if member_m:
                    members = re.findall(r'"([^"]+)"|([a-zA-Z0-9_-]+)', member_m.group(1))
                    for m1, m2 in members:
                        m_val = m1 or m2
                        if m_val:
                            referenced_services.add(m_val)

        # =====================================================================
        # FASE 2: AUDITORÍA DE SERVICIOS PERSONALIZADOS (Custom Services)
        # =====================================================================
        svc_block = extract_nested_block(vdom_content, "config firewall service custom")
        svcs_raw = re.findall(r'edit "([^"]+)"(.*?)(?=\n\s*edit |\Z)', svc_block, re.DOTALL) if svc_block else []

        port_map = {}
        svc_names = set()

        for svc_name, svc_body in svcs_raw:
            svc_names.add(svc_name)
            proto_m = re.search(r'set protocol\s+([a-zA-Z0-9_-]+)', svc_body)
            port_m = re.search(r'set tcp-portrange\s+([^\n]+)|set udp-portrange\s+([^\n]+)', svc_body)
            
            proto = proto_m.group(1).strip() if proto_m else "TCP/UDP"
            ports = "N/A"
            if port_m:
                ports = (port_m.group(1) or port_m.group(2)).strip().replace('"', '')

            signature = f"{proto}:{ports}"
            if signature != "TCP/UDP:N/A":
                if signature not in port_map:
                    port_map[signature] = []
                port_map[signature].append(svc_name)

        # 1. Duplicados
        duplicates = {sig: names for sig, names in port_map.items() if len(names) > 1}
        dup_tags = [f"Firma '{sig}': {names}" for sig, names in duplicates.items()]

        checks.append({
            'id': f'CHK-SVC-SUMMARY-{vdom_prefix}-DUPLICATES',
            'vdom': vdom_name,
            'cat': 'Políticas y Objetos',
            'mod': 'Service Objects (Duplicados)',
            'hallazgo': f"VDOM '{vdom_name}': Servicios personalizados con puertos duplicados (Total: {len(duplicates)})",
            'estado': 'WARNING' if duplicates else 'PASS',
            'sev': 'Baja',
            'peso': 5,
            'afectados': f"VDOM {vdom_name} -> Duplicados: {len(duplicates)}",
            'evidencia': ' | '.join(dup_tags) if dup_tags else 'Ningún servicio duplicado',
            'rec': 'Consolidar objetos de servicio redundantes.',
            'rem': 'config firewall service custom\n  delete <Servicio>\nend',
            'tipo': 'Técnico',
            'ref': 'SEG-LNB-002 Num 6.5'
        })

        # 2. Huérfanos de Servicios Personalizados
        svc_orphans = [name for name in svc_names if name not in referenced_services]
        svc_orphan_summary = f"Huérfanos: {', '.join(svc_orphans[:15])}" if svc_orphans else "Ningún servicio huérfano"
        
        checks.append({
            'id': f'CHK-SVC-SUMMARY-{vdom_prefix}-ORPHANS',
            'vdom': vdom_name,
            'cat': 'Políticas y Objetos',
            'mod': 'Service Objects (Huérfanos)',
            'hallazgo': f"VDOM '{vdom_name}': Servicios personalizados sin referencia (Total: {len(svc_orphans)})",
            'estado': 'WARNING' if svc_orphans else 'PASS',
            'sev': 'Baja',
            'peso': 5,
            'afectados': f"VDOM {vdom_name} -> Total huérfanos: {len(svc_orphans)}",
            'evidencia': svc_orphan_summary[:250],
            'rec': 'Depurar y eliminar servicios huérfanos o no utilizados.',
            'rem': 'config firewall service custom\n  delete <Servicio>\nend',
            'tipo': 'Técnico',
            'ref': 'SEG-LNB-002 Num 6.5'
        })

        # =====================================================================
        # FASE 3: AUDITORÍA DE GRUPOS DE SERVICIOS (Service Groups)
        # =====================================================================
        group_orphans = [gname for gname in groups_raw if gname not in referenced_services]
        group_orphan_summary = f"Grupos huérfanos: {', '.join(group_orphans[:15])}" if group_orphans else "Ningún grupo de servicio huérfano"

        checks.append({
            'id': f'CHK-SVCGRP-SUMMARY-{vdom_prefix}-ORPHANS',
            'vdom': vdom_name,
            'cat': 'Políticas y Objetos',
            'mod': 'Service Groups (Huérfanos)',
            'hallazgo': f"VDOM '{vdom_name}': Grupos de servicios sin referencia alguna (Total: {len(group_orphans)})",
            'estado': 'WARNING' if group_orphans else 'PASS',
            'sev': 'Baja',
            'peso': 5,
            'afectados': f"VDOM {vdom_name} -> Total grupos huérfanos: {len(group_orphans)}",
            'evidencia': group_orphan_summary[:250],
            'rec': 'Depurar grupos de servicios obsoletos o no utilizados.',
            'rem': 'config firewall service group\n  delete <Grupo>\nend',
            'tipo': 'Técnico',
            'ref': 'SEG-LNB-002 Num 6.5'
        })

    return checks
