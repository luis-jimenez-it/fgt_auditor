# app.py
import os
from flask import Flask, render_template, request, send_file
from core.parser import parse_config
from core.excel_exporter import export_assessment

# --- Importar Módulos de Sistema ---
from modules.system import updates
from modules.system import administrators
from modules.system import system_settings
from modules.system import ha
from modules.system import snmp
from modules.system import fortiguard

# --- Importar Módulos de Red ---
from modules.network import interfaces
from modules.network import dns
from modules.network import sdwan_zones
from modules.network import sdwan_rules
from modules.network import sdwan_sla
from modules.network import static_routes
from modules.network import policy_routes
from modules.network import routing_protocols

# --- Importar Módulos de Políticas y Objetos ---
from modules.policy_objects import firewall_policy
from modules.policy_objects import addresses
from modules.policy_objects import services
from modules.policy_objects import virtual_ips
from modules.policy_objects import ippools

# --- Importar Módulos de Perfiles de Seguridad ---
from modules.security_profiles import antivirus
from modules.security_profiles import webfilter
from modules.security_profiles import dnsfilter
from modules.security_profiles import application_control
from modules.security_profiles import ips_sensor
from modules.security_profiles import ssl_ssh_inspection

# --- Importar Módulos de VPN ---
from modules.vpn import ipsec_tunnels
from modules.vpn import sslvpn_settings
from modules.vpn import sslvpn_portals

# --- Importar Módulos de User & Authentication ---
from modules.user_auth import user_definition
from modules.user_auth import user_groups
from modules.user_auth import auth_settings

# --- Importar Modulos Adicionales
from modules.additional import logging as additional_logging
from modules.additional import backup as additional_backup
from modules.additional import change_management as additional_change
from modules.additional import certificates as additional_certs
from modules.additional import advanced_threats as additional_adv

# Módulos activos registrados en el pipeline de auditoría
ACTIVE_MODULES = [
    updates,
    administrators,
    system_settings,
    ha,
    snmp,
    fortiguard,
    interfaces,
    dns,
    sdwan_zones,
    sdwan_rules,
    sdwan_sla,
    static_routes,
    policy_routes,
    routing_protocols,
    firewall_policy,
    addresses,
    services,
    virtual_ips,
    ippools,
    antivirus,
    webfilter,
    dnsfilter,
    application_control,
    ips_sensor,
    ssl_ssh_inspection,
    ipsec_tunnels,
    sslvpn_settings,
    sslvpn_portals,
    user_definition,
    user_groups,
    auth_settings,
    additional_logging,
    additional_backup,
    additional_change,
    additional_certs,
    additional_adv,
]

app = Flask(__name__)
LAST_REPORT_PATH = "/tmp/ultimo_reporte_hardening.xlsx"

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html', results=None)

@app.route('/audit', methods=['POST'])
def audit():
    file = request.files.get('backup_file')
    if not file or file.filename == '':
        return "No seleccionó ningún archivo", 400

    raw_content = file.read().decode('utf-8', errors='ignore')
    ctx = parse_config(raw_content)

    checks = []
    for module in ACTIVE_MODULES:
        checks.extend(module.audit(ctx))

    pass_cnt = sum(1 for c in checks if c['estado'] == 'PASS')
    fail_cnt = sum(1 for c in checks if c['estado'] == 'FAIL')
    warn_cnt = sum(1 for c in checks if c['estado'] == 'WARNING')
    
    app_w = sum(c['peso'] for c in checks)
    earned_w = sum(c['peso'] for c in checks if c['estado'] == 'PASS') + (sum(c['peso'] for c in checks if c['estado'] == 'WARNING') * 0.5)
    score = round((earned_w / app_w) * 100, 1) if app_w > 0 else 0
    madurez = "BÁSICA" if score < 70 else "INTERMEDIA" if score < 90 else "AVANZADA"

    stats = {
        'pass_cnt': pass_cnt,
        'fail_cnt': fail_cnt,
        'warn_cnt': warn_cnt,
        'score': score,
        'madurez': madurez
    }

    export_assessment(ctx['metadata'], checks, LAST_REPORT_PATH)
    return render_template('index.html', results=checks, metadata=ctx['metadata'], stats=stats)

@app.route('/download', methods=['GET'])
def download():
    if os.path.exists(LAST_REPORT_PATH):
        return send_file(LAST_REPORT_PATH, as_attachment=True, download_name="FortiGate_Hardening_Assessment.xlsx")
    return "No se ha generado ningún reporte aún", 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

