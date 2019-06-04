#!python3
# -*- coding: utf-8 -*-
"""
asa_xauth
"""

import requests
import requests.packages.urllib3
from requests.auth import HTTPBasicAuth
from time import perf_counter as pc

requests.packages.urllib3.disable_warnings()  # Supresses self-signed InsecureRequestWarning


def x_auth_token_generate(firewall_ip, username, password):
    """
    :param firewall_ip: IP/FQDN of the target firewall
    :param username: admin account with priority 15 required
    :param password: admin credentials

    This function will initiate an HTTP-POST to 'https://|firewall_ip|/api/tokenservices'
    using local admin password, and retrieve the X-Auth-Token value from the response headers.
    This token will then be used for API manipulation going forward.
    Pass the associated key 'X-Auth-Token': x_auth_token in to headers of next API call like so--
    headers = {'Content-Type': 'application/json',
               'X-Auth-Token': x_auth_token}
    :return: x_auth_token - a string containing an auth token for the ASA firewall.
    """
    x_auth_session = requests.post(url=(f"https://{firewall_ip}/api/tokenservices"),
                                   verify=False,
                                   auth=HTTPBasicAuth(username,
                                                      password)
                                   )

    #print(x_auth_session)          # Response type
    #print(x_auth_session.headers)  # Response returned headers

    x_auth_token = x_auth_session.headers['X-Auth-Token']
    print(f"X-Auth-Token sent by ASA at {firewall_ip}- {x_auth_token}")
    return x_auth_token


if __name__ == "__main__":
    start_time = pc()
    firewall_ip = input("Firewall IP: ")
    username = input("Username: ")
    password = input("Password: ")
    x_auth_token = x_auth_token_generate(firewall_ip, username, password)   # Get token for ASA Authentication

    duration = pc() - start_time
    runtime = (str(round(duration, 2)))
    print (f"\tTotal runtime: {runtime} seconds")


