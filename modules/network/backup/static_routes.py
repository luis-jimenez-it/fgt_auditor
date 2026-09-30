# modules/network/static_routes.py
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
    checks = []
    vdom_blocks = ctx.get('vdom_blocks', {})
    if not vdom_blocks:
        vdom_blocks = {'root': ctx.get('content', '')}

    parsed_ifaces = ctx.get('parsed_interfaces', [])

    for vdom_name, vdom_content in vdom_blocks.items():
        vdom_iface_status = {i['name']: i['status'] for i in parsed_ifaces if i['vdom'] == vdom_name}

        # Verificar si SD-WAN está activo en este VDOM
        sdwan_body = extract_nested_block(vdom_content, "config system sdwan")
        sdwan_enabled = False
        if sdwan_body:
            st_m = re.search(r'set status\s+([a-z]+)', sdwan_body)
            sdwan_enabled = (st_m.group(1) == "enable") if st_m else False

        # Extraer bloque de rutas estáticas
        static_block = extract_nested_block(vdom_content, "config router static")
        if not static_block:
            checks.append({
                'id': f'CHK-ROUTE-STATIC-{vdom_name.upper().replace("-", "_")}-NONE',
                'vdom': vdom_name,
                'cat': 'Red y Enrutamiento',
                'mod': 'Rutas Estáticas',
                'hallazgo': f"VDOM '{vdom_name}': No existen rutas estáticas configuradas",
                'estado': 'INFO',
                'sev': 'Baja',
                'peso': 0,
                'afectados': f"VDOM {vdom_name} -> config router static",
                'evidencia': 'config router static ausente en este VDOM',
                'rec': 'Validar si el enrutamiento se gestiona dinámicamente por BGP/OSPF',
                'rem': 'N/A - Informativo',
                'tipo': 'Técnico',
                'ref': 'SEG-LNB-002 Num 6.1 / NIST SC-7'
            })
            continue

        routes_raw = re.findall(r'edit (\d+)(.*?)(?=\n\s*edit \d+|\Z)', static_block, re.DOTALL)
        if not routes_raw:
            continue

        default_routes = []
        disabled_routes = []
        down_routes = []

        for seq, r_body in routes_raw:
            dst_m = re.search(r'set dst\s+([^\n]+)', r_body)
            dev_m = re.search(r'set device\s+"([^"]+)"', r_body)
            gw_m = re.search(r'set gateway\s+([^\n]+)', r_body)
            dist_m = re.search(r'set distance\s+(\d+)', r_body)
            prio_m = re.search(r'set priority\s+(\d+)', r_body)
            status_m = re.search(r'set status\s+([a-z]+)', r_body)
            comment_m = re.search(r'set comment\s+"([^"]+)"', r_body)

            dst = dst_m.group(1).strip() if dst_m else "0.0.0.0 0.0.0.0"
            device = dev_m.group(1).strip() if dev_m else "desconocido"
            gateway = gw_m.group(1).strip() if gw_m else "N/A"
            distance = dist_m.group(1) if dist_m else "10"
            priority = prio_m.group(1) if prio_m else "0"
            status = status_m.group(1) if status_m else "enable"
            comment = comment_m.group(1) if comment_m else ""

            if status == "disable":
                disabled_routes.append(f"Seq #{seq} (dst: {dst}, dev: {device})")
                continue

            is_default = (dst in ["0.0.0.0 0.0.0.0", "0.0.0.0/0", "0.0.0.0/0.0.0.0"])
            if is_default:
                default_routes.append({
                    'seq': seq,
                    'device': device,
                    'gateway': gateway,
                    'distance': distance,
                    'priority': priority,
                    'comment': comment
                })

            dev_phys_status = vdom_iface_status.get(device, "up")
            if dev_phys_status == "down":
                down_routes.append(f"Seq #{seq} -> red: {dst} apuntando a {device} (status down)")

        def_check_id = f"CHK-ROUTE-DEFAULT-{vdom_name.upper().replace('-', '_')}"

        if not default_routes:
            checks.append({
                'id': def_check_id,
                'vdom': vdom_name,
                'cat': 'Red y Enrutamiento',
                'mod': 'Rutas Estáticas',
                'hallazgo': f"VDOM '{vdom_name}': No se detectó ruta por defecto estática (0.0.0.0/0)",
                'estado': 'WARNING',
                'sev': 'Media',
                'peso': 5,
                'afectados': f"VDOM {vdom_name} -> Tabla de Enrutamiento",
                'evidencia': 'No existe regla con dst 0.0.0.0 0.0.0.0 en config router static',
                'rec': 'Verificar si el VDOM requiere salida externa o si aprende la ruta por defecto vía OSPF/BGP',
                'rem': f'config vdom\nedit "{vdom_name}"\nconfig router static\n  edit 1\n    set dst 0.0.0.0 0.0.0.0\n    set device "sdwan"\n  next\nend\nnext\nend',
                'tipo': 'Técnico',
                'ref': 'SEG-LNB-002 Num 6.1 / NIST SC-7'
            })
        else:
            sdwan_mismatch = []
            if sdwan_enabled:
                for dr in default_routes:
                    if dr['device'] not in ['sdwan', 'virtual-wan-link']:
                        sdwan_mismatch.append(f"Seq #{dr['seq']} -> apunta a {dr['device']} con GW {dr['gateway']}")

            if sdwan_enabled and sdwan_mismatch:
                checks.append({
                    'id': def_check_id,
                    'vdom': vdom_name,
                    'cat': 'Red y Enrutamiento',
                    'mod': 'Rutas Estáticas',
                    'hallazgo': f"VDOM '{vdom_name}': Ruta por defecto estática desviada de SD-WAN ({', '.join(sdwan_mismatch)})",
                    'estado': 'FAIL',
                    'sev': 'Alta',
                    'peso': 10,
                    'afectados': f"VDOM {vdom_name} -> Ruta 0.0.0.0/0",
                    'evidencia': f"SD-WAN habilitado pero ruta 0.0.0.0/0 apunta a interfaces físicas individuales: {'; '.join(sdwan_mismatch)}",
                    'rec': 'Hacer que la ruta 0.0.0.0/0 apunte a la interfaz virtual "sdwan" para permitir failover automático',
                    'rem': f'config vdom\nedit "{vdom_name}"\nconfig router static\n  edit <seq>\n    set device "sdwan"\n    unset gateway\n  next\nend\nnext\nend',
                    'tipo': 'Técnico',
                    'ref': 'SEG-LNB-002 Num 6.14 / Buenas Prácticas Fortinet'
                })
            else:
                gw_info = [f"dev: {d['device']} (GW: {d['gateway']}, dist: {d['distance']}, prio: {d['priority']})" for d in default_routes]
                checks.append({
                    'id': def_check_id,
                    'vdom': vdom_name,
                    'cat': 'Red y Enrutamiento',
                    'mod': 'Rutas Estáticas',
                    'hallazgo': f"VDOM '{vdom_name}': Ruta por defecto 0.0.0.0/0 configurada correctamente ({len(default_routes)} ruta(s))",
                    'estado': 'PASS',
                    'sev': 'Baja',
                    'peso': 5,
                    'afectados': f"VDOM {vdom_name} -> Ruta 0.0.0.0/0",
                    'evidencia': f"Ruta(s) detectadas: {'; '.join(gw_info)}",
                    'rec': 'Mantener monitoreo del gateway por defecto',
                    'rem': 'N/A - Cumple',
                    'tipo': 'Técnico',
                    'ref': 'SEG-LNB-002 Num 6.1 / NIST SC-7'
                })

        orphan_id = f"CHK-ROUTE-ORPHAN-{vdom_name.upper().replace('-', '_')}"
        if down_routes:
            checks.append({
                'id': orphan_id,
                'vdom': vdom_name,
                'cat': 'Red y Enrutamiento',
                'mod': 'Rutas Estáticas',
                'hallazgo': f"VDOM '{vdom_name}': Se detectaron {len(down_routes)} ruta(s) huérfana(s) hacia interfaces inactivas (status down)",
                'estado': 'WARNING',
                'sev': 'Media',
                'peso': 5,
                'afectados': f"VDOM {vdom_name} -> Rutas: {', '.join([d.split('->')[0].strip() for d in down_routes[:4]])}",
                'evidencia': f"Rutas hacia enlaces inactivos: {'; '.join(down_routes[:4])}",
                'rec': 'Eliminar las rutas huérfanas o activar las interfaces correspondientes si están pendientes de entrega',
                'rem': f'config vdom\nedit "{vdom_name}"\nconfig router static\n  delete <seq>\nend\nnext\nend',
                'tipo': 'Técnico',
                'ref': 'SEG-LNB-002 Num 6.1'
            })
        else:
            checks.append({
                'id': orphan_id,
                'vdom': vdom_name,
                'cat': 'Red y Enrutamiento',
                'mod': 'Rutas Estáticas',
                'hallazgo': f"VDOM '{vdom_name}': Todas las rutas estáticas apuntan a interfaces válidas y activas",
                'estado': 'PASS',
                'sev': 'Baja',
                'peso': 5,
                'afectados': f"VDOM {vdom_name} -> Rutas Estáticas",
                'evidencia': 'No se encontraron rutas estáticas apuntando a puertos caídos',
                'rec': 'Mantener limpieza de tablas de enrutamiento',
                'rem': 'N/A - Cumple',
                'tipo': 'Técnico',
                'ref': 'SEG-LNB-002 Num 6.1'
            })

        dis_id = f"CHK-ROUTE-DISABLED-{vdom_name.upper().replace('-', '_')}"
        if disabled_routes:
            checks.append({
                'id': dis_id,
                'vdom': vdom_name,
                'cat': 'Red y Enrutamiento',
                'mod': 'Rutas Estáticas',
                'hallazgo': f"VDOM '{vdom_name}': Existen {len(disabled_routes)} ruta(s) deshabilitada(s) administrativamente",
                'estado': 'WARNING',
                'sev': 'Baja',
                'peso': 5,
                'afectados': f"VDOM {vdom_name} -> {', '.join(disabled_routes[:3])}",
                'evidencia': f"set status disable en: {'; '.join(disabled_routes[:3])}",
                'rec': 'Depurar rutas estáticas obsoletas o en desuso',
                'rem': f'config vdom\nedit "{vdom_name}"\nconfig router static\n  delete <seq>\nend\nnext\nend',
                'tipo': 'Técnico',
                'ref': 'SEG-LNB-002 Num 6.1'
            })
        else:
            checks.append({
                'id': dis_id,
                'vdom': vdom_name,
                'cat': 'Red y Enrutamiento',
                'mod': 'Rutas Estáticas',
                'hallazgo': f"VDOM '{vdom_name}': Sin rutas estáticas deshabilitadas",
                'estado': 'PASS',
                'sev': 'Baja',
                'peso': 5,
                'afectados': f"VDOM {vdom_name} -> config router static",
                'evidencia': 'Todas las rutas configuradas están activas',
                'rec': 'Mantener depuración de rutas temporales',
                'rem': 'N/A - Cumple',
                'tipo': 'Técnico',
                'ref': 'SEG-LNB-002 Num 6.1'
            })

    return checks
