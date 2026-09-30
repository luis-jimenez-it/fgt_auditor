# modules/network/sdwan_zones.py
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
    Auditoría Dinámica de Zonas SD-WAN VDOM por VDOM.
    Evalúa:
    - Estado de activación (set status enable).
    - Zonas configuradas en config zone.
    - Miembros asignados en config members y su estado físico.
    Normativa: SEG-LNB-002 (Num 6.14 Alta Disponibilidad y SD-WAN), ISO 27001 A.17.2.1, NIST CP-2
    """
    checks = []
    vdom_blocks = ctx.get('vdom_blocks', {})
    if not vdom_blocks:
        vdom_blocks = {'root': ctx.get('content', '')}

    parsed_ifaces = ctx.get('parsed_interfaces', [])

    for vdom_name, vdom_content in vdom_blocks.items():
        vdom_iface_status = {i['name']: i['status'] for i in parsed_ifaces if i['vdom'] == vdom_name}

        # Extraer el bloque config system sdwan del VDOM actual
        sdwan_body = extract_nested_block(vdom_content, "config system sdwan")
        if not sdwan_body:
            checks.append({
                'id': f'CHK-SDWAN-STATUS-{vdom_name.upper().replace("-", "_")}',
                'vdom': vdom_name,
                'cat': 'Red y Segmentación',
                'mod': 'Alta Disponibilidad y SD-WAN',
                'hallazgo': f"VDOM '{vdom_name}': SD-WAN no configurado ni utilizado",
                'estado': 'INFO',
                'sev': 'Baja',
                'peso': 0,
                'afectados': f"VDOM {vdom_name}",
                'evidencia': 'config system sdwan no presente en este VDOM',
                'rec': 'Implementar SD-WAN únicamente si este VDOM administra enlaces WAN externos',
                'rem': 'N/A - Informativo',
                'tipo': 'Técnico',
                'ref': 'SEG-LNB-002 Num 6.14'
            })
            continue

        status_m = re.search(r'set status\s+([a-z]+)', sdwan_body)
        is_enabled = (status_m.group(1) == "enable") if status_m else False

        if not is_enabled:
            checks.append({
                'id': f'CHK-SDWAN-STATUS-{vdom_name.upper().replace("-", "_")}',
                'vdom': vdom_name,
                'cat': 'Red y Segmentación',
                'mod': 'Alta Disponibilidad y SD-WAN',
                'hallazgo': f"VDOM '{vdom_name}': Servicio SD-WAN deshabilitado administrativamente",
                'estado': 'INFO',
                'sev': 'Baja',
                'peso': 0,
                'afectados': f"VDOM {vdom_name} -> config system sdwan",
                'evidencia': 'set status disable (o default)',
                'rec': 'Habilitar el servicio si se requiere balanceo o redundancia activa en este VDOM',
                'rem': f'config vdom\nedit "{vdom_name}"\nconfig system sdwan\n  set status enable\nend\nnext\nend',
                'tipo': 'Técnico',
                'ref': 'SEG-LNB-002 Num 6.14'
            })
            continue

        # Zonas del VDOM
        zone_block = extract_nested_block(sdwan_body, "config zone")
        zones = re.findall(r'edit "([^"]+)"', zone_block) if zone_block else []
        if not zones:
            zones = ["virtual-wan-link"]

        # Miembros del VDOM
        member_block = extract_nested_block(sdwan_body, "config members")
        members_raw = re.findall(r'edit \d+(.*?)(?=\n\s*edit \d+|\Z)', member_block, re.DOTALL) if member_block else []

        zone_members_map = {z: [] for z in zones}

        for m in members_raw:
            iface_m = re.search(r'set interface\s+"([^"]+)"', m)
            zone_m = re.search(r'set zone\s+"([^"]+)"', m)
            member_st_m = re.search(r'set status\s+([a-z]+)', m)

            iface_name = iface_m.group(1) if iface_m else "desconocida"
            zone_target = zone_m.group(1) if zone_m else "virtual-wan-link"
            member_status = member_st_m.group(1) if member_st_m else "enable"
            phys_status = vdom_iface_status.get(iface_name, "up")

            is_active = (member_status == "enable" and phys_status == "up")

            member_info = {
                'interface': iface_name,
                'zone': zone_target,
                'member_status': member_status,
                'phys_status': phys_status,
                'is_active': is_active
            }

            if zone_target in zone_members_map:
                zone_members_map[zone_target].append(member_info)
            else:
                zone_members_map[zone_target] = [member_info]

        # Evaluación zona por zona
        for zone_name, members in zone_members_map.items():
            check_id = f"CHK-SDWAN-ZONE-{vdom_name.upper().replace('-', '_')}-{zone_name.upper().replace('-', '_')}"

            # Caso A: Sin miembros -> APAGADA / INACTIVA
            if not members:
                checks.append({
                    'id': check_id,
                    'vdom': vdom_name,
                    'cat': 'Red y Segmentación',
                    'mod': 'Alta Disponibilidad y SD-WAN',
                    'hallazgo': f"Zona SD-WAN '{zone_name}' en VDOM '{vdom_name}' APAGADA / INACTIVA: no tiene interfaces miembros asignadas",
                    'estado': 'WARNING',
                    'sev': 'Media',
                    'peso': 5,
                    'afectados': f"VDOM {vdom_name} -> zone '{zone_name}'",
                    'evidencia': f"Zona '{zone_name}' configurada sin interfaces miembros en config members",
                    'rec': f"Asignar interfaces activas a la zona '{zone_name}' o eliminar la zona si no se utiliza",
                    'rem': f'config vdom\nedit "{vdom_name}"\nconfig system sdwan\n  config zone\n    delete "{zone_name}"\n  end\nend\nnext\nend',
                    'tipo': 'Técnico',
                    'ref': 'SEG-LNB-002 Num 6.14'
                })
                continue

            active_members = [m['interface'] for m in members if m['is_active']]
            down_members = [f"{m['interface']} ({'status down' if m['phys_status'] == 'down' else 'member disable'})" for m in members if not m['is_active']]

            # Caso B: Todos los miembros caídos -> LINK DISABLE
            if not active_members:
                checks.append({
                    'id': check_id,
                    'vdom': vdom_name,
                    'cat': 'Red y Segmentación',
                    'mod': 'Alta Disponibilidad y SD-WAN',
                    'hallazgo': f"Zona SD-WAN '{zone_name}' en VDOM '{vdom_name}' APAGADA / LINK DISABLE: todos sus enlaces están inactivos ({', '.join(down_members)})",
                    'estado': 'FAIL',
                    'sev': 'Alta',
                    'peso': 10,
                    'afectados': f"VDOM {vdom_name} -> zona '{zone_name}'",
                    'evidencia': f"Todos los enlaces de la zona inactivos: {', '.join(down_members)}",
                    'rec': f"Habilitar administrativamente las interfaces miembros de la zona '{zone_name}' en VDOM '{vdom_name}'",
                    'rem': f'config vdom\nedit "{vdom_name}"\nconfig system interface\nedit "<interfaz>"\n  set status up\nnext\nend\nnext\nend',
                    'tipo': 'Técnico',
                    'ref': 'SEG-LNB-002 Num 6.14'
                })

            # Caso C: Zona Degradada
            elif down_members:
                checks.append({
                    'id': check_id,
                    'vdom': vdom_name,
                    'cat': 'Red y Segmentación',
                    'mod': 'Alta Disponibilidad y SD-WAN',
                    'hallazgo': f"Zona SD-WAN '{zone_name}' en VDOM '{vdom_name}' DEGRADADA: opera con enlaces caídos (Activos: {', '.join(active_members)} | Inactivos: {', '.join(down_members)})",
                    'estado': 'WARNING',
                    'sev': 'Media',
                    'peso': 5,
                    'afectados': f"VDOM {vdom_name} -> zona '{zone_name}'",
                    'evidencia': f"Miembro caído: {', '.join(down_members)} | Miembro activo: {', '.join(active_members)}",
                    'rec': f"Revisar el estado físico/lógico del enlace inactivo en la zona '{zone_name}' para restaurar la redundancia",
                    'rem': f'Verificar conectividad del enlace {down_members[0].split()[0]} en VDOM {vdom_name}',
                    'tipo': 'Técnico',
                    'ref': 'SEG-LNB-002 Num 6.14'
                })

            # Caso D: Zona Operativa
            else:
                checks.append({
                    'id': check_id,
                    'vdom': vdom_name,
                    'cat': 'Red y Segmentación',
                    'mod': 'Alta Disponibilidad y SD-WAN',
                    'hallazgo': f"Zona SD-WAN '{zone_name}' en VDOM '{vdom_name}' OPERATIVA: todos sus enlaces miembros están activos ({', '.join(active_members)})",
                    'estado': 'PASS',
                    'sev': 'Baja',
                    'peso': 5,
                    'afectados': f"VDOM {vdom_name} -> zona '{zone_name}'",
                    'evidencia': f"Enlaces operativos: {', '.join(active_members)}",
                    'rec': 'Mantener monitoreo de métricas de SLA y rendimiento de enlaces',
                    'rem': 'N/A - Cumple',
                    'tipo': 'Técnico',
                    'ref': 'SEG-LNB-002 Num 6.14'
                })

    return checks
