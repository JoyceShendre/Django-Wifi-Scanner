from django.shortcuts import render, redirect
import socket
import pywifi
from pywifi import const
import requests


def get_ip_address():
    hostname = socket.gethostname()
    ip_address = socket.gethostbyname(hostname)
    print(ip_address)
    return ip_address


def check_ports(bssid, ip_address):
    target_ip = ip_address
    open_ports = []
    common_ports = [21, 22, 23, 25, 53, 80, 110, 143,
                    443, 445, 3389]  # add more ports as needed

    for port in common_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target_ip, port))
        print("result: ", result)
        if result == 0:
            print(port, 'port is open and vulnerable')
            open_ports.append(port)
            sock.close()
            return open_ports
        else:
            print(result, 'port is not open and vulnerable')
            sock.close()
            return open_ports


def check_wifi_safety():
    try:
        wifi = pywifi.PyWiFi()
        print("Scan Results>>>>", wifi)
        iface = wifi.interfaces()[0]
        print("Checking", iface)
        if len(wifi.interfaces()) == 0:
            print("No WiFi interfaces available.")
            return []
        elif iface.status() != const.IFACE_CONNECTED:
            print("WiFi interface is not connected.")
            return []
        else:
            connected = True
        try:
            scan_results = iface.scan_results()
        except Exception as e:
            print("Error while scanning:", e)
            return []

        scan_results = iface.scan_results()
        print("Scan Results>>>>", scan_results)
        wifi_list = []

        for result in scan_results:
            ssid = result.ssid
            bssid = result.bssid
            signal_strength = result.signal

            encryption_type = result.akm[0]
            secured = (encryption_type ==
                       const.AKM_TYPE_WPA2 or encryption_type == const.AKM_TYPE_WPA2PSK or encryption_type == const.AKM_TYPE_WPAPSK)
            # Check for weak signal strength (adjust the threshold as needed)
            weak_signal = signal_strength < -70

            # Check for open networks (no encryption)
            open_network = encryption_type == const.AKM_TYPE_NONE
            # ip_address
            ip_address = get_ip_address()
            # checking for open ports
            open_ports = check_ports(bssid, ip_address)

            wifi_list.append({
                'connected': connected,
                'ssid': ssid,
                'bssid': bssid,
                'secured': secured,
                'signal_strength': signal_strength,
                'weak_signal': weak_signal,
                'open_network': open_network,
                'open_ports': open_ports,
            })

        print(wifi_list)
        return [wifi_list[0]]
    except Exception as e:
        print("Something went wrong while scanning:", e)
        return []


def check_fake_captive_portal(request):
    if request.method == 'POST':
        login_url = request.POST.get('login_url')
        is_captive_portal = detect_fake_captive_portal(login_url)
        print(is_captive_portal)
        context = {'is_captive_portal': is_captive_portal}

        return render(request, 'safenet/fake_captive_portal.html', context)
    else:
        return render(request, 'safenet/fake_captive_portal.html')


def detect_fake_captive_portal(url):
    try:
        response = requests.get(url)
        html_content = response.text
        # Add more keywords as needed
        keywords = ['login', 'captive', 'portal']

        for keyword in keywords:
            if keyword in html_content.lower():
                return True

        return False
    except Exception as e:
        return False


def get_connected_wifi():
    wifi = pywifi.PyWiFi()
    iface = wifi.interfaces()[0]
    scan_results = iface.scan_results()
    if len(wifi.interfaces()) == 0:
        print("No WiFi interfaces available.")
        return []
    elif iface.status() != const.IFACE_CONNECTED:
        print("WiFi interface is not connected.")
        return []
    try:
        scan_results = iface.scan_results()
    except Exception as e:
        print("Error while scanning:", e)
        return []
    for result in scan_results:
        connected_ssid = result.ssid if scan_results else None
        if connected_ssid:
            connected_bssid = result.bssid if scan_results else None
            return {'ssid': connected_ssid, 'bssid': connected_bssid}
        else:
            return None


def safenet(request):
    error_message = None
    connected_network = None
    try:
        ip_address = get_ip_address()
        wifi_list = check_wifi_safety()
        connected_network = get_connected_wifi()
    except Exception as e:
        error_message = "Wifi is not connected, please connect to the network!"
        wifi_list = []
    if request.method == 'POST':

        if len(wifi_list) == 0 and error_message:
            context = {
                'ip_address': ip_address,
                'wifi_list': wifi_list,
                'error_message': error_message,
                'connected_network': connected_network
            }
        elif len(wifi_list) == 0:
            context = {
                'ip_address': ip_address,
                'wifi_list': wifi_list,
                'error_message': "Wifi is not connected, please connect to the network!",
                'connected_network': connected_network
            }
        else:
            context = {
                'ip_address': ip_address,
                'wifi_list': wifi_list,
                'error_message': error_message,
                'connected_network': connected_network
            }
        return render(request, 'safenet/safenet_results.html', context)
    else:
        context = {
            'ip_address': ip_address,
            'wifi_list': [],
            'error_message': error_message,
            'connected_network': connected_network
        }
        return render(request, 'safenet/safenet_scan.html', context)
