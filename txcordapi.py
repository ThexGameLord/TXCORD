import os
import socket
import requests
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
import configparser

config_file = "TXCORDAPI.cfg"

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
    PORT = config.getint('TXCORDAPI', 'PORT', fallback=8080)

if not all([WEBHOOK_URL, AUTH_KEY, PORT]):
    # Create the config file with default values if it doesn't exist
    if not os.path.exists(config_file):
        config = configparser.ConfigParser()
        config['TXCORDAPI'] = {
            'WEBHOOK_URL': 'https://discord.com/api/webhooks/xxxxxxxxxx',
            'AUTH_KEY': 'CHANGE_ME',
            'PORT': '8080'
        }
        with open(config_file, 'w') as cfgfile:
            config.write(cfgfile)


class RequestHandler(BaseHTTPRequestHandler):

    
    def _set_headers(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()

    def do_GET(self):
        if self.path == '/':
            self.handle_default_get()

    
    def handle_default_get(self):
        # Access query parameters and other data from self.path
        query_params = self.parse_query_string(self.path)

        # Print the received data
        print("Received data:")
        print(query_params)

        # Get the player count using format_payload and update the global variable
        
        default_landing = f'''
        <!DOCTYPE html>
        <html>
        <head>
        <title>TXCORDAPI Landing page</title>
        </head>
        <body>
        <h1>Welcome to TXCORDAPI</h1>
        <p>UNKNOWN</p>
        <a>The User Interface has not actually been made yet.</a>
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

    def do_POST(self):
        if self.path == '/api/playernames':
            self.handle_playernames_post()
        else:
            self.handle_default_post()

    def handle_default_post(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)

        # Print the received data
        print("Received data:")
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
        print("Received player names data:")
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


def format_payload(payload):
    payload_dict = json.loads(payload)
    player_count = payload_dict.get('playerCount', 'N/A')
    max_player_count = payload_dict.get('maxPlayerCount', 'N/A')
    server_motd = payload_dict.get('Motd', 'N/A')
    formatted_payload = f'''
    Player Count: {player_count} / {max_player_count}
    Server Motd: {server_motd}
    '''
    return formatted_payload


def format_player_list(payload):
    payload_dict = json.loads(payload)
    player_list = payload_dict.get('PlayerNames', [])
    formatted_player_list = "\n".join(player_list)
    return formatted_player_list


def get_public_ip():
    try:
        # Use a public service to determine the public IP address
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("1.1.1.1", 80))
            public_ip = s.getsockname()[0]
        return public_ip
    except Exception as e:
        print("Error while fetching public IP:", e)
        return None


def get_local_ip():
    try:
        # Get the local IP address of the machine
        local_ip = socket.gethostbyname(socket.gethostname())
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
        print(f"Starting server on Public IP: {public_ip} : {port}")

    # Get and print the local IP address
    local_ip = get_local_ip()
    if local_ip:
        print(f"Starting server on Local IP: {local_ip} : {port}")
    httpd.serve_forever()


if __name__ == '__main__':
    run(HTTPServer, RequestHandler, 8080)
