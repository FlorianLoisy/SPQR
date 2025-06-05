import os
import datetime

def run_test(tool_name, command, result_path):
    print(f"\n[+] Exécution : {tool_name}")
    os.makedirs(result_path, exist_ok=True)
    exit_code = os.system(command)
    if exit_code == 0:
        print(f"[✓] {tool_name} terminé. Résultats dans {result_path}")
    else:
        print(f"[✗] {tool_name} a échoué.")

def get_timestamp():
    return datetime.datetime.now().strftime("%Y%m%d%H%M%S")

def main():
    pcap_file = "MTA.pcap"  # Nom du fichier à tester
    input_pcap_path = f"{os.getcwd()}/input/{pcap_file}"
    rule_path = f"{os.getcwd()}/config/suricata.rules"
    timestamp = get_timestamp()

    output_base = f"{os.getcwd()}/output"

    # 1. Suricata 6.0.15
    suri6_out = f"{output_base}/suricata6/{timestamp}"
    suricata6_cmd = (
        f"docker run --rm -v {os.getcwd()}:/data "
        f"--entrypoint suricata suricata:6.0.15 "
        f"-r /data/input/{pcap_file} -c /data/config/suricata-6.0.15.yaml "
        f"-S /data/config/suricata.rules -l /data/output/suricata6/{timestamp} -v -k none"
    )

    # 2. Suricata 7.0.2
    suri7_out = f"{output_base}/suricata7/{timestamp}"
    suricata7_cmd = (
        f"docker run --rm -v {os.getcwd()}:/data "
        f"--entrypoint suricata suricata:7.0.2 "
        f"-r /data/input/{pcap_file} -c /data/config/suricata-6.0.15.yaml "  # adapter si config différente
        f"-S /data/config/suricata.rules -l /data/output/suricata7/{timestamp} -v -k none"
    )

    # 3. Snort 2.9
    snort2_out = f"{output_base}/snort29/{timestamp}"
    snort2_cmd = (
        f"docker run --rm -v {os.getcwd()}:/data "
        f"snort:2.9 "
        f"snort -r /data/input/{pcap_file} -c /data/config/suricata.rules "
        f"-A console -l /data/output/snort29/{timestamp}"
    )

    # 4. Snort 3
    snort3_out = f"{output_base}/snort3/{timestamp}"
    snort3_cmd = (
        f"docker run --rm -v {os.getcwd()}:/data "
        f"ciscotalos/snort3 "
        f"snort -R /data/config/suricata.rules -r /data/input/{pcap_file} "
        f"-A alert_fast -l /data/output/snort3/{timestamp}"
    )

    tests = [
        ("Suricata 6.0.15", suricata6_cmd, suri6_out),
        ("Suricata 7.0.2", suricata7_cmd, suri7_out),
        ("Snort 2.9", snort2_cmd, snort2_out),
        ("Snort 3", snort3_cmd, snort3_out)
    ]

    for name, cmd, out_dir in tests:
        run_test(name, cmd, out_dir)

if __name__ == "__main__":
    main()
