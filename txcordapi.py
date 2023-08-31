import os
import socket
import requests
import json
import re
import argparse
from http.server import BaseHTTPRequestHandler, HTTPServer
import configparser
import base64
import datetime
from colorama import Fore, Style, init
import time
import random
import netifaces as ni

init(autoreset=True)  # Initialize colorama
global DEBUG_MODE
DEBUG_MODE = False
config_file = "TXCORDAPI.cfg"

TXASCII='''

ooooooooooooo ooooooo  ooooo   .oooooo.     .oooooo.   ooooooooo.   oooooooooo.   
8'   888   `8  `8888    d8'   d8P'  `Y8b   d8P'  `Y8b  `888   `Y88. `888'   `Y8b  
     888         Y888..8P    888          888      888  888   .d88'  888      888 
     888          `8888'     888          888      888  888ooo88P'   888      888 
     888         .8PY888.    888          888      888  888`88b.     888      888 
     888        d8'  `888b   `88b    ooo  `88b    d88'  888  `88b.   888     d88' 
    o888o     o888o  o88888o  `Y8bood8P'   `Y8bood8P'  o888o  o888o o888bood8P'   
                                                                                  
                                                                                  
                                                                                  

'''

TermF_colour = [Fore.MAGENTA, Fore.BLUE, Fore.CYAN]
SeLected_colour = random.choice(TermF_colour)

for letter in TXASCII:
    print(SeLected_colour + letter + Style.RESET_ALL, end='', flush=True)
    time.sleep(0.0001)  # Adjust the sleep duration to control the typing speed


global ver_str
ver_str = "TXCORDAPI/1.2"

try:
    os.system(f"title {ver_str}")
except Exception:
    pass

print(Fore.GREEN + f"Running {ver_str}" + Style.RESET_ALL)
print("[ATTENTION] you can do txcordapi -h to show all arguements that can be used")

# Check for environment variables or read from the config file
if 'WEBHOOK_URL' in os.environ:
    WEBHOOK_URL = os.environ['WEBHOOK_URL']
else:
    config = configparser.ConfigParser()
    config.read(config_file)
    WEBHOOK_URL = config.get('TXCORDAPI', 'WEBHOOK_URL', fallback='')

if 'AUTH_KEY' in os.environ:
    AUTH_KEY = os.environ['AUTH_KEY']
else:
    config = configparser.ConfigParser()
    config.read(config_file)
    AUTH_KEY = config.get('TXCORDAPI', 'AUTH_KEY', fallback='CHANGE_ME')

if 'PORT' in os.environ:
    PORT = int(os.environ['PORT'])
else:
    config = configparser.ConfigParser()
    config.read(config_file)
    print("using config file")
    PORT = config.getint('TXCORDAPI', 'PORT', fallback=8080)

if 'API_USER' in os.environ:
    API_USER = os.environ['API_USER']
else:
    config = configparser.ConfigParser()
    config.read(config_file)
    API_USER = config.get('TXCORDAPI', 'API_USER', fallback='DEMO')

if 'API_PASS' in os.environ:
    API_PASS = os.environ['API_PASS']
else:
    config = configparser.ConfigParser()
    config.read(config_file)
    API_PASS = config.get('TXCORDAPI', 'API_PASS', fallback='DEMO')

if not all([WEBHOOK_URL, AUTH_KEY, PORT]):
    # Create the config file with default values if it doesn't exist
    if not os.path.exists(config_file):
        config = configparser.ConfigParser()
        config['TXCORDAPI'] = {
            'WEBHOOK_URL': 'https://discord.com/api/webhooks/xxxxxxxxxx',
            'AUTH_KEY': 'CHANGE_ME',
            'PORT': '8080',
            'API_USER': 'DEMO',
            'API_PASS': 'DEMO',
        }
        with open(config_file, 'w') as cfgfile:
            config.write(cfgfile)

payload_data = {}
class CustomRequestHandler(BaseHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.last_auth_time = None  # Initialize the last_auth_time
        super().__init__(*args, **kwargs)
        
    def version_string(self):
        return ver_str
    
    def _set_headers(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()

    def check_basic_auth(self):
        auth_header = self.headers.get('Authorization')
        if auth_header:
            current_time = datetime.datetime.now()
            if self.last_auth_time is None or (current_time - self.last_auth_time).total_seconds() > 3:  # 1 hour in seconds
                credentials = auth_header.split(' ')[1]
                decoded_credentials = base64.b64decode(credentials).decode('utf-8')
                username, password = decoded_credentials.split(':')
                if username == API_USER and password == API_PASS:
                    self.last_auth_time = current_time  # Update the last_auth_time
                    return True
        return False

    def do_GET(self):      
        if self.path == '/':
            if self.check_basic_auth():
                self.handle_default_get()
            else:
                self.send_response(401)
                self.send_header('WWW-Authenticate', 'Basic realm="Authentication required"')
                self.end_headers()
                self.wfile.write(b'Unauthorized')
        elif self.path == '/favicon.ico':
            self.do_favicon()
        elif self.path == '/.htaccess':
            self.send_response(403)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'Nice try but this is a custom http server')
        else:
            self.send_response(404)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'Not Found')


    
    def handle_default_get(self):
        # Access query parameters and other data from self.path
        query_params = self.parse_query_string(self.path)

        # Print the received data
        if DEBUG_MODE == True:
            print(Fore.RED + "[DEBUG] Received data:" + Style.RESET_ALL)
            print(query_params)

        # Get the player count using format_payload and update the global variable
        global payload_data
        default_landing = f'''
        <!DOCTYPE html>
        <html>
        <head>
        <title>TXCORDAPI Landing page</title>
        </head>
        <body>
        <h1>Welcome to TXCORDAPI</h1>
        <p>{format_payload(payload_data)}</p>
        <a>A better User Interface will be made later.</a>
        <button onclick="window.location.href='https://github.com/thexgamelord/txcord'">TXCORD on github</button>
        </body>
        </html>
        '''
        finished_get_response = default_landing.encode('utf-8')
        self.send_response(200)  # Send the response status code
        self.send_header('Content-type', 'text/html')  # Set the correct Content-Type header
        self.end_headers()  # End the headers
        self.wfile.write(finished_get_response)


    def parse_query_string(self, path):
        query_params = {}
        if '?' in path:
            query_string = path.split('?')[1]
            params = query_string.split('&')
            for param in params:
                key, value = param.split('=')
                query_params[key] = value
        return query_params

    def do_favicon(self):
        try:
            with open('favicon.ico', 'rb') as favicon_file:
                favicon = favicon_file.read()

            self.send_response(200)
            self.send_header('Content-type', 'image/x-icon')
            self.send_header('Content-Length', len(favicon))
            self.end_headers()
            self.wfile.write(favicon)
        except FileNotFoundError:
            self.send_fallback_favicon()
            print(Fore.RED + "no favicon.ico file was found so we sent the default one")
            print(Style.RESET_ALL)  # Reset to default style
        except Exception as e:
            self.send_error_response("Internal server error")
            print(e)

    def send_fallback_favicon(self):
        fallback_favicon_url = "https://raw.githubusercontent.com/ThexGameLord/TXCORD/API/favicon.ico"

        try:
            response = requests.get(fallback_favicon_url)
            if response.status_code == 200:
                self.send_response(200)
                self.send_header('Content-type', 'image/x-icon')
                self.send_header('Content-Length', len(response.content))
                self.end_headers()
                self.wfile.write(response.content)
            else:
                self.send_error_response("Fallback favicon not available")
        except Exception as e:
            self.send_error_response("Error fetching fallback favicon")
            print(e)



    def do_POST(self):
        if self.path == '/api/playernames':
            self.handle_playernames_post()
        else:
            self.handle_default_post()

    def handle_default_post(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)

        # Print the received data DEBUG OPTION FOR ARGS
        if DEBUG_MODE == True:
            print(Fore.RED + "[DEBUG] Received data:" + Style.RESET_ALL)
            print(post_data.decode('utf-8'))

        # Check if Authkey matches
        auth_key = self.headers.get('Authkey')
        if auth_key != AUTH_KEY:
            self.send_error_response("Invalid Authkey")
            return

        # Send payload to Discord webhook
        self.send_to_discord_webhook(post_data, WEBHOOK_URL)

        self._set_headers()
        self.wfile.write(b'Received')

    def handle_playernames_post(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)

        # Print the received player names data
        if DEBUG_MODE == True:
            print(Fore.RED + "[DEBUG] Received player names data:" + Style.RESET_ALL)
            print(post_data.decode('utf-8'))

        # Check if Authkey matches
        auth_key = self.headers.get('Authkey')
        if auth_key != AUTH_KEY:
            self.send_error_response("Invalid Authkey")
            return

        # Send payload to Discord webhook for player names
        self.send_player_list_to_discord_webhook(post_data, WEBHOOK_URL)

        self._set_headers()
        self.wfile.write(b'Received')

    def send_to_discord_webhook(self, payload, webhook_url):
        global payload_data
        headers = {'Content-Type': 'application/json'}

        data = {
            'embeds': [{
                'title': 'Server Information:',
                'description': format_payload(payload.decode('utf-8')),
                'color': 65280  # Green color value
            }]
        }

        response = requests.post(webhook_url,
                                 headers=headers,
                                 data=json.dumps(data))

        if response.status_code == 204:
            print('Payload sent to Discord webhook successfully.')
            # Update the global variable with the payload data
            payload_data = json.loads(payload)
        else:
            print('Failed to send payload to Discord webhook. Status code:',
                  response.status_code)

    def send_player_list_to_discord_webhook(self, payload, webhook_url):
        headers = {'Content-Type': 'application/json'}

        data = {
            'embeds': [{
                'title':
                'Player List:',
                'description':
                format_player_list(payload.decode('utf-8')),
                'color':
                65280  # Green color value
            }]
        }

        response = requests.post(webhook_url,
                                 headers=headers,
                                 data=json.dumps(data))

        if response.status_code == 204:
            print('Player list sent to Discord webhook successfully.')
        else:
            print(
                'Failed to send player list to Discord webhook. Status code:',
                response.status_code)

    def send_error_response(self, message):
        self.send_response(403)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(message.encode())


def sanitize_motd(motd):
    # Use regular expression to remove color codes (e.g., §b) and other special characters
    sanitized_motd = re.sub(r'§.', '', motd)
    return sanitized_motd

def format_payload(payload):
    if isinstance(payload, str):
        payload_dict = json.loads(payload)
    else:
        payload_dict = payload

    player_count = payload_dict.get('playerCount', 'N/A')
    max_player_count = payload_dict.get('maxPlayerCount', 'N/A')
    server_motd = payload_dict.get('Motd', 'N/A')

    # Decode the MOTD using the correct encoding (UTF-8) before processing color codes
    decoded_motd = server_motd.encode('latin-1').decode('utf-8')

    # Sanitize the MOTD before displaying
    sanitized_motd = sanitize_motd(decoded_motd)

    formatted_payload = f'''
    Player Count: {player_count} / {max_player_count}
    Server Motd: {sanitized_motd}
    '''
    return formatted_payload


def format_player_list(payload):
    payload_dict = json.loads(payload)
    player_list = payload_dict.get('PlayerNames', [])
    formatted_player_list = "\n".join(player_list)
    return formatted_player_list


def get_public_ip():
    try:
        response = requests.get("https://httpbin.org/ip")
        data = response.json()
        public_ip = data["origin"]
        return public_ip
    except Exception as e:
        print("Error while fetching public IP:", e)
        return None


def get_local_ip():
    try:
        # Get the default gateway interface name
        default_gateway = ni.gateways()['default'][ni.AF_INET][1]

        # Get the local IP address of the default gateway interface
        local_ip = ni.ifaddresses(default_gateway)[ni.AF_INET][0]['addr']
        return local_ip
    except Exception as e:
        print("Error while fetching local IP:", e)
        return None


def run(server_class, handler_class, port):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    #print(f'Starting server on port {port}...')
    # Get and print the public IP address
    public_ip = get_public_ip()
    if public_ip:
        print(Fore.GREEN + f"Starting server on Public IP: {public_ip} : {port}" + Style.RESET_ALL)

    # Get and print the local IP address
    local_ip = get_local_ip()
    if local_ip:
        print(Fore.GREEN + f"Starting server on Local IP: {local_ip} : {port}" + Style.RESET_ALL)
    httpd.serve_forever()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='TXCORDAPI Server')

    parser.add_argument('--debug', '-d', action='store_true', help='Enable debug mode')

    args = parser.parse_args()
    
    if args.debug:
        print(Fore.RED + "Debug mode enabled" + Style.RESET_ALL)
        DEBUG_MODE = True
        
    run(HTTPServer, CustomRequestHandler, PORT)
