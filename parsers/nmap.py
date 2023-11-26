from libnmap.parser import NmapParser
import multiprocessing


def parse_scan():
    nmap_info = []
    services_list = []
    nmap_report = NmapParser.parse_fromfile('nmap_results.xml')
    for host in nmap_report.hosts:
        for services in host.services:
            nmap_info.append(f"{services.port}:{services.service}:{services.banner}")

    for nmap_info_list in nmap_info:
        output = nmap_info_list.split(":")
        if output[0] == "80":
            services_list.append(f"{output[0]}")
        if output[0] == "443":
            services_list.append(f"{output[0]}")
        if output[0] == "8843":
            services_list.append(f"{output[0]}")
        if output[0] == "8080":
            services_list.append(f"{output[0]}")

    return "\n".join(map(str, services_list))