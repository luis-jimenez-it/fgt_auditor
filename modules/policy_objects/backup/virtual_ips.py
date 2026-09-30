# modules/policy_objects/virtual_ips.py
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
    Auditoría optimizada de Virtual IPs, VIP Groups y resolución en Address Groups VDOM por VDOM.
    Retorna 2 líneas resumen:
      1. VIPs huérfanos (sin referencia en políticas, grupos VIP ni address groups).
      2. Grupos de VIPs huérfanos (sin referencia en políticas).
    """
    checks = []
    vdom_blocks = ctx.get('vdom_blocks', {})
    raw_content = ctx.get('content', '')

    if not vdom_blocks:
        vdom_blocks = {'root': raw_content}

    for vdom_name, vdom_content in vdom_blocks.items():
        vdom_prefix = vdom_name.upper().replace('-', '_')

        # =====================================================================
        # FASE 1: RECOPILAR REFERENCIAS DESDE LAS POLÍTICAS DE FIREWALL
        # =====================================================================
        referenced_tokens = set()
        fw_block = extract_nested_block(vdom_content, "config firewall policy")
        if fw_block:
            dst_lines = re.findall(r'set dstaddr\s+([^\n]+)', fw_block)
            for line in dst_lines:
                names = re.findall(r'"([^"]+)"|([a-zA-Z0-9_-]+)', line)
                for n1, n2 in names:
                    val = n1 or n2
                    if val and val.lower() != 'all':
                        referenced_tokens.add(val)

        # =====================================================================
        # FASE 2: RESOLVER MIEMBROS DE GRUPOS DE VIPs (config firewall vipgrp)
        # =====================================================================
        vipgrp_block = extract_nested_block(vdom_content, "config firewall vipgrp")
        vipgrps_raw = []
        vipgrp_members = {}

        if vipgrp_block:
            parsed_groups = re.findall(r'edit "([^"]+)"(.*?)(?=\n\s*edit |\Z)', vipgrp_block, re.DOTALL)
            for gname, gbody in parsed_groups:
                vipgrps_raw.append(gname)
                member_m = re.search(r'set member\s+([^\n]+)', gbody)
                if member_m:
                    members = re.findall(r'"([^"]+)"|([a-zA-Z0-9_-]+)', member_m.group(1))
                    vipgrp_members[gname] = [m1 or m2 for m1, m2 in members if (m1 or m2)]

        # Expandir referencias de vipgrp si el grupo está en políticas
        active_vipgrps = [g for g in vipgrps_raw if g in referenced_tokens]
        for g in active_vipgrps:
            if g in vipgrp_members:
                for member in vipgrp_members[g]:
                    referenced_tokens.add(member)

        # =====================================================================
        # FASE 3: RESOLVER MIEMBROS DE GRUPOS DE DIRECCIONES (config firewall addrgrp)
        # =====================================================================
        addrgrp_block = extract_nested_block(vdom_content, "config firewall addrgrp")
        if addrgrp_block:
            parsed_addrgrps = re.findall(r'edit "([^"]+)"(.*?)(?=\n\s*edit |\Z)', addrgrp_block, re.DOTALL)
            for agname, agbody in parsed_addrgrps:
                # Si el grupo de direcciones está en las políticas, expandimos sus miembros
                if agname in referenced_tokens:
                    member_m = re.search(r'set member\s+([^\n]+)', agbody)
                    if member_m:
                        members = re.findall(r'"([^"]+)"|([a-zA-Z0-9_-]+)', member_m.group(1))
                        for m1, m2 in members:
                            m_val = m1 or m2
                            if m_val:
                                referenced_tokens.add(m_val)

        # =====================================================================
        # FASE 4: EVALUACIÓN FINAL DE HUÉRFANOS
        # =====================================================================
        group_orphans = [g for g in vipgrps_raw if g not in referenced_tokens]
        group_orphan_summary = f"Grupos VIP huérfanos: {', '.join(group_orphans[:15])}" if group_orphans else "Ningún grupo VIP huérfano"

        checks.append({
            'id': f'CHK-VIPGRP-SUMMARY-{vdom_prefix}-ORPHANS',
            'vdom': vdom_name,
            'cat': 'Políticas y Objetos',
            'mod': 'VIP Groups (Huérfanos)',
            'hallazgo': f"VDOM '{vdom_name}': Grupos de VIPs sin referencia alguna (Total: {len(group_orphans)})",
            'estado': 'WARNING' if group_orphans else 'PASS',
            'sev': 'Baja',
            'peso': 5,
            'afectados': f"VDOM {vdom_name} -> Total grupos VIP huérfanos: {len(group_orphans)}",
            'evidencia': group_orphan_summary[:250],
            'rec': 'Depurar y eliminar grupos de VIPs obsoletos o no utilizados.',
            'rem': 'config firewall vipgrp\n  delete <Grupo_VIP>\nend',
            'tipo': 'Técnico',
            'ref': 'SEG-LNB-002 Num 6.5'
        })

        vip_block = extract_nested_block(vdom_content, "config firewall vip")
        vips_raw = re.findall(r'edit "([^"]+)"', vip_block) if vip_block else []

        vip_orphans = [v for v in vips_raw if v not in referenced_tokens]
        vip_orphan_summary = f"VIPs huérfanos: {', '.join(vip_orphans[:15])}" if vip_orphans else "Ninguna Virtual IP huérfana"

        checks.append({
            'id': f'CHK-VIP-SUMMARY-{vdom_prefix}-ORPHANS',
            'vdom': vdom_name,
            'cat': 'Políticas y Objetos',
            'mod': 'Virtual IPs (Huérfanos)',
            'hallazgo': f"VDOM '{vdom_name}': Virtual IPs sin referencia en políticas o grupos (Total: {len(vip_orphans)})",
            'estado': 'WARNING' if vip_orphans else 'PASS',
            'sev': 'Baja',
            'peso': 5,
            'afectados': f"VDOM {vdom_name} -> Total VIPs huérfanas: {len(vip_orphans)}",
            'evidencia': vip_orphan_summary[:250],
            'rec': 'Depurar y eliminar Virtual IPs obsoletas o no utilizadas.',
            'rem': 'config firewall vip\n  delete <Nombre_VIP>\nend',
            'tipo': 'Técnico',
            'ref': 'SEG-LNB-002 Num 6.5'
        })

    return checks
