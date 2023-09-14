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
import ssl

init(autoreset=True)  # Initialize colorama
global DEBUG_MODE
DEBUG_MODE = False
global HTTPS_MODE
HTTPS_MODE = False
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
ver_str = "TXCORDAPI/1.3"

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

global https_port    
if 'HTTPS_PORT' in os.environ:
    https_port = int(os.environ['HTTPS_PORT'])
else:
    config = configparser.ConfigParser()
    config.read(config_file)
    print("using config file")
    https_port = config.getint('TXCORDAPI', 'HTTPS_PORT', fallback=8443)

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
            'HTTPS_PORT': '8443',
            'API_USER': 'DEMO',
            'API_PASS': 'DEMO',
        }
        with open(config_file, 'w') as cfgfile:
            config.write(cfgfile)

payload_data = {}
global min_player_count
global pmax_player_count
global sanitized_motd
global formatted_player_list
global INT_API_PASS
global INT_API_USER

INT_API_PASS = "TxcCOrrwekm12qm12j491jk9uwijr90ur902iju8r90iui90i2r"
INT_API_USER = "TxcCOrrwekm12qm12j491jk9uwijr90ur902iju8r90iui90i2r"


sanitized_motd = "N/A"
min_player_count = 0
pmax_player_count = 69420
formatted_player_list = "nul"


# # Modified extract_player_count function to get the first and second values from Player Count
# def extract_player_count():
    # global ui_player_count  # Access the global ui_player_count variable
    # global ui_max_player_count  # Access the global ui_max_player_count variable   
    
    # if isinstance(ui_player_count, str) and isinstance(ui_max_player_count, str):
        # # Convert player count and max player count to integers if they are strings
        # min_count = int(ui_player_count) if ui_player_count.isdigit() else 0
        # max_count = int(ui_max_player_count) if ui_max_player_count.isdigit() else 100

        # return min_count, max_count

    # return 999, 2023  # Default values if parsing fails


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
    
    def verify_client_certificate(self):
        # Ensure that the request is using SSL/TLS
        if not self.request.getpeername():
            self.send_error_response("SSL/TLS is not enabled")
            return False

        # Verify the client certificate
        client_cert = self.request.getpeercert()
        if not client_cert:
            return False  # No client certificate provided

        # Path to the expected client certificate file
        expected_cert_file = "client.crt"

        # Check if the presented client certificate matches the expected one
        if os.path.exists(expected_cert_file):
            with open(expected_cert_file, "rb") as f:
                expected_cert_data = f.read()
            if client_cert == expected_cert_data:
                return True  # Certificate matches the expected one

        return False  # Certificate doesn't match the expected one

    
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

    def int_check_basic_auth(self):
        auth_header = self.headers.get('Authorization')
        if auth_header:
            current_time = datetime.datetime.now()
            if self.last_auth_time is None or (current_time - self.last_auth_time).total_seconds() > 3:  # 1 hour in seconds
                credentials = auth_header.split(' ')[1]
                decoded_credentials = base64.b64decode(credentials).decode('utf-8')
                username, password = decoded_credentials.split(':')
                if username == INT_API_USER and password == INT_API_PASS:
                    self.last_auth_time = current_time  # Update the last_auth_time
                    return True
        return False

    def do_GET(self):      
        if self.path == '/':
            self.handle_default_get()
        elif self.path == '/admin':
            if self.check_basic_auth():
                self.handle_default_Admin()
            else:
                self.send_response(401)
                self.send_header('WWW-Authenticate', 'Basic realm="Authentication required"')
                self.end_headers()
                self.wfile.write(b'Unauthorized')
        elif self.path == '/internal/playerlisting':
            if self.check_basic_auth():
                #self.handle_PLIST_Admin()
                self.send_response(500)
                #self.send_header('WWW-Authenticate', 'Basic realm="Authentication required"')
                self.end_headers()
                self.wfile.write(b'Not Implemented')
            else:
                self.send_response(401)
                self.send_header('WWW-Authenticate', 'Basic realm="Authentication required"')
                self.end_headers()
                self.wfile.write(b'Unauthorized')
        elif self.path == '/internal/playercounting':
            if self.int_check_basic_auth():
                self.handle_pc_details_get()
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
        
        # Extract player count values
        #min_player_count, max_player_count = extract_player_count()
        
        default_landing = f'''
<!DOCTYPE html>
<html>
<head>
    <title>TXCORDAPI Landing page</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/raphael/2.3.0/raphael.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/justgage/1.6.1/justgage.min.js"></script>
    <style>
    /* Dark mode styles */
    .dark-mode {{
        background-color: dimgray;
        color: #ffffff;
    }}

    /* Additional dark mode styles for specific elements */
    .dark-mode h1 {{
        color: #ffffff;
    }}
    
    body {{
        height: 200px;
        width: 400px;
        position: fixed;
        top: 20%;
        left: 50%;
        margin-top: -100px;
        margin-left: -200px;
    }}
    </style>
</head>
<body>
    <h1>Welcome to TXCORDAPI</h1>
    <button id="darkModeButton">Toggle Dark Mode</button>
    <div id="playerCountGauge" style="width: 400px; height: 200px;"></div>
    <p id="playerCount">Player Count: {min_player_count} / {pmax_player_count}</p>
    <p id="serverMotd">Server MOTD: {sanitized_motd}</p>
    <a>A better User Interface will be made later.</a>
    <button onclick="window.location.href='https://github.com/thexgamelord/txcord'">TXCORD on github</button>
    <button onclick="window.location.href='/admin'">TXCORD Admin page [WIP]</button>
    
    <script>
        var playerCountGauge = new JustGage({{
            id: "playerCountGauge",
            value: {min_player_count},
            min: 0,
            max: {pmax_player_count},
            title: "Player Count",
            label: "Players"
        }});

        function updateGauge(playerCount) {{
            playerCountGauge.refresh(playerCount);
        }}

        function updatePageContent() {{
        fetch('/internal/playercounting', {{
            method: 'GET',
            headers: {{
                'Authorization': 'Basic ' + btoa("{INT_API_USER}" + ':' + "{INT_API_PASS}")
            }}
        }})
        .then(response => response.json())
        .then(data => {{
            // Update only the gauge value with the received player count
            updateGauge(data.current_player_count);
            document.getElementById("playerCount").innerHTML = "Player Count: " + data.current_player_count + " / " + data.max_player_count;
            document.getElementById("serverMotd").innerHTML = "Server MOTD: " + data.nice_motd;
            console.log("Current players updated to: " + data.current_player_count)
            console.log("Current motd updated to: " + data.nice_motd)
            console.log("Current max players updated to: " + data.max_player_count)
            console.log("Updated Gauge");
        }})
        .catch(error => {{
            console.error("Error fetching data: " + error);
        }});
    }}

    // Initial content update
    updatePageContent();

    // Periodically refresh content every 15 seconds
    setInterval(updatePageContent, 30000);
    </script>
    
    <script>
    // Function to toggle dark mode
    function toggleDarkMode() {{
        const body = document.body;
        body.classList.toggle('dark-mode'); // Toggle a CSS class for dark mode

        // Check if dark mode is active and set a cookie
        const isDarkMode = body.classList.contains('dark-mode');
        const expirationDate = new Date();
        expirationDate.setFullYear(expirationDate.getFullYear() + 1); // Set cookie expiration to 1 year

        // Save the dark mode setting in a cookie
        document.cookie = `TXCORDdarkMode=${{isDarkMode}}; expires=${{expirationDate.toUTCString()}}; path=/`;
    }}

    // Add a click event listener to the dark mode button
    document.getElementById('darkModeButton').addEventListener('click', toggleDarkMode);

    // Function to check if dark mode is enabled from cookies and apply it
    function checkDarkModeFromCookies() {{
        const cookies = document.cookie.split(';');
        for (const cookie of cookies) {{
            const [name, value] = cookie.trim().split('=');
            if (name === 'TXCORDdarkMode') {{
                const body = document.body;
                if (value === 'true') {{
                    body.classList.add('dark-mode');
                }} else {{
                    body.classList.remove('dark-mode');
                }}
            }}
        }}
    }}

    // Call the function to check dark mode from cookies when the page loads
    window.addEventListener('load', checkDarkModeFromCookies);
</script>
</body>
</html>
'''
        finished_get_response = default_landing.encode('utf-8')
        self.send_response(200)  # Send the response status code
        self.send_header('Content-type', 'text/html')  # Set the correct Content-Type header
        self.end_headers()  # End the headers
        self.wfile.write(finished_get_response)


    def handle_default_Admin(self):
        # Access query parameters and other data from self.path
        query_params = self.parse_query_string(self.path)

        # Print the received data
        if DEBUG_MODE == True:
            print(Fore.RED + "[DEBUG] Received data:" + Style.RESET_ALL)
            print(query_params)   
        
        default_landing = f'''
<!DOCTYPE html>
<html>
<head>
    <title>TXCORDAPI Admin page</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
    /* Dark mode styles */
    .dark-mode {{
        background-color: dimgray;
        color: #ffffff;
    }}

    /* Additional dark mode styles for specific elements */
    .dark-mode h1 {{
        color: #ffffff;
    }}
    
    body {{
        height: 200px;
        width: 400px;
        position: fixed;
        top: 20%;
        left: 50%;
        margin-top: -100px;
        margin-left: -200px;
    }}
    </style>
</head>
<body>
    <button onclick="window.location.href='/'">TXCORD HOME</button>
    <h1>Welcome to TXCORDAPI ADMINISTRATOR PAGE</h1>
    <a>A better User Interface will be made later.</a><br>
    <button id="darkModeButton">Toggle Dark Mode</button><br>
    <button onclick="window.location.href='https://github.com/thexgamelord/txcord'">TXCORD on github</button>
    <br>
    {formatted_player_list}
    
    
    
    <script>
    // Function to toggle dark mode
    function toggleDarkMode() {{
        const body = document.body;
        body.classList.toggle('dark-mode'); // Toggle a CSS class for dark mode

        // Check if dark mode is active and set a cookie
        const isDarkMode = body.classList.contains('dark-mode');
        const expirationDate = new Date();
        expirationDate.setFullYear(expirationDate.getFullYear() + 1); // Set cookie expiration to 1 year

        // Save the dark mode setting in a cookie
        document.cookie = `TXCORDdarkMode=${{isDarkMode}}; expires=${{expirationDate.toUTCString()}}; path=/`;
    }}

    // Add a click event listener to the dark mode button
    document.getElementById('darkModeButton').addEventListener('click', toggleDarkMode);

    // Function to check if dark mode is enabled from cookies and apply it
    function checkDarkModeFromCookies() {{
        const cookies = document.cookie.split(';');
        for (const cookie of cookies) {{
            const [name, value] = cookie.trim().split('=');
            if (name === 'TXCORDdarkMode') {{
                const body = document.body;
                if (value === 'true') {{
                    body.classList.add('dark-mode');
                }} else {{
                    body.classList.remove('dark-mode');
                }}
            }}
        }}
    }}

    // Call the function to check dark mode from cookies when the page loads
    window.addEventListener('load', checkDarkModeFromCookies);
</script>
</body>
</html>
'''
        finished_get_response = default_landing.encode('utf-8')
        self.send_response(200)  # Send the response status code
        self.send_header('Content-type', 'text/html')  # Set the correct Content-Type header
        self.end_headers()  # End the headers
        self.wfile.write(finished_get_response)


    def handle_pc_details_get(self):
        # Access query parameters and other data from self.path
        query_params = self.parse_query_string(self.path)

        # Print the received data
        if DEBUG_MODE == True:
            print(Fore.RED + "[DEBUG] Received data:" + Style.RESET_ALL)
            print(query_params)   

        # Assuming you have extracted min_player_count and max_player_count, create a dictionary
        data = {
            "nice_motd": sanitized_motd,
            "max_player_count": pmax_player_count,
            "current_player_count": min_player_count
        }

        # Convert the dictionary to JSON
        json_data = json.dumps(data)

        # Encode the JSON string as bytes
        json_bytes = json_data.encode('utf-8')

        self.send_response(200)  # Send the response status code
        self.send_header('Content-type', 'application/json')  # Set the correct Content-Type header
        self.end_headers()  # End the headers
        self.wfile.write(json_bytes)  # Send the JSON data as the response body

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

        self._set_headers()
        self.wfile.write(b'Received')
    
    def handle_main_post(self):
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

    def do_POST(self):
        if self.path == '/api/playernames':
            self.handle_playernames_post()
        elif self.path == '/api/main':
            self.handle_main_post()
        else:
            self.handle_default_post()
    
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
        if format_player_list(payload.decode('utf-8')) == "s":
            pass

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
    sanitized_motd = re.sub(r'[^\x00-\x7F]+', '', sanitized_motd)  # Removes non-ASCII characters
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
    global sanitized_motd
    sanitized_motd = sanitize_motd(decoded_motd)
    global min_player_count
    global pmax_player_count
    min_player_count = player_count
    pmax_player_count = max_player_count
    if DEBUG_MODE == True:
        print(Fore.RED + f"[DEBUG] Server sent Current player count:{min_player_count}" + Style.RESET_ALL)
        print(Fore.RED + f"[DEBUG] Server sent Max player count:{pmax_player_count}" + Style.RESET_ALL)
    else:
        pass
    formatted_payload = f'''
    Player Count: {player_count} / {max_player_count}
    Server Motd: {sanitized_motd}
    '''
    return formatted_payload


def format_player_list(payload):
    payload_dict = json.loads(payload)
    player_list = payload_dict.get('PlayerNames', [])
    global formatted_player_list
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
    if HTTPS_MODE:
        global https_port
        server_address = ('', https_port)
        port = https_port
        httpd = server_class(server_address, handler_class)
        ca_certfile = "client.crt"
        httpd.socket = ssl.wrap_socket(httpd.socket, keyfile="server.key", certfile="server.crt", server_side=True)
    else:
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
    parser.add_argument('--secure', '-ssl', action='store_true', help='Enable https mode')

    args = parser.parse_args()
    
    if args.debug:
        print(Fore.RED + "Debug mode enabled" + Style.RESET_ALL)
        DEBUG_MODE = True
    
    if args.secure:
        print(Fore.GREEN + "https mode enabled" + Style.RESET_ALL)
        HTTPS_MODE = True
        
    run(HTTPServer, CustomRequestHandler, PORT)
