# __________                  __             __     ________             .___ 
# \______   \  ____    ____  |  | __  ____ _/  |_  /  _____/   ____    __| _/ 
#  |       _/ /  _ \ _/ ___\ |  |/ /_/ __ \\   __\/   \  ___  /  _ \  / __ |  
#  |    |   \(  <_> )\  \___ |    < \  ___/ |  |  \    \_\  \(  <_> )/ /_/ |  
#  |____|_  / \____/  \___  >|__|_ \ \___  >|__|   \______  / \____/ \____ |  
#         \/              \/      \/     \/               \/              \/  
#
# IP Analasys Discord Bot by RocketGod
#
# https://github.com/RocketGod-git/ip-hacker

import json
import logging
import discord
import aiohttp
import asyncio
from shodan import Shodan, APIError as ShodanAPIError
import whois
import nmap
from datetime import datetime
import asyncio
from concurrent.futures import ThreadPoolExecutor
import re

executor = ThreadPoolExecutor()

last_analysis_date = datetime.utcfromtimestamp(1695418944).strftime('%Y-%m-%d %H:%M:%S UTC')
whois_date = datetime.utcfromtimestamp(1614909309).strftime('%Y-%m-%d %H:%M:%S UTC')

logging.basicConfig(level=logging.INFO)

def load_config():
    with open('config.json', 'r') as file:
        return json.load(file)

def check_configurations(config):
    if not config:
        return False

    required_keys = ['TOKEN', 'SHODAN_KEY', 'VIRUSTOTAL_API_KEY']
    missing_keys = [key for key in required_keys if key not in config]

    if missing_keys:
        logging.error(f"Missing keys in config.json: {', '.join(missing_keys)}")
        return False

    return True

class AClient(discord.Client):
    def __init__(self, shodan_api_key, virustotal_api_key):
        super().__init__(intents=discord.Intents.default())
        self.shodan_key = shodan_api_key
        self.virustotal_key = virustotal_api_key
        self.tree = discord.app_commands.CommandTree(self)
        self.activity = discord.Activity(type=discord.ActivityType.watching, name="/ip")
        self.discord_message_limit = 2000
        self.rate_limiter = asyncio.Semaphore(5)

    @staticmethod
    async def fetch(session, url):
        async with session.get(url) as response:
            return await response.text()
        
    async def async_nmap_scan(self, nm, ip, ports, arguments):
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(executor, nm.scan, ip, ports, arguments)
        return result

    async def get_virustotal_data(self, ip):
        headers = {'x-apikey': self.virustotal_key}
        API_URL = "https://www.virustotal.com/api/v3/ip_addresses/"
        
        async with aiohttp.ClientSession() as session:
            ip_data = await self.fetch_virustotal_endpoint(session, API_URL + ip, headers)
            last_analysis_results = ip_data.get("data", {}).get("attributes", {}).get("last_analysis_results", {})
            whois_data = await self.fetch_virustotal_endpoint(session, API_URL + ip + "/historical_whois", headers)
            urls_data = await self.fetch_virustotal_endpoint(session, API_URL + ip + "/urls", headers)
            comments_data = await self.fetch_virustotal_endpoint(session, API_URL + ip + "/comments", headers)
            
        processed_data = await self.process_virustotal_data(ip_data, whois_data, urls_data, comments_data, last_analysis_results)
        return processed_data

    async def fetch_virustotal_endpoint(self, session, endpoint, headers):
        async with session.get(endpoint, headers=headers) as response:
            return await response.json()

    async def process_virustotal_data(self, ip_data, whois_data, urls_data, comments_data, last_analysis_results):
        """
        Process and structure data from VirusTotal including IP address details, historical WHOIS, URLs, and comments.
        
        Args:
            ip_data (dict): Data about the IP address.
            whois_data (dict): Historical WHOIS data for the IP address.
            urls_data (dict): URLs associated with the IP address.
            comments_data (dict): Community comments related to the IP address.

        Returns:
            dict: A structured dictionary containing all processed data.
        """
        
        # Process IP data
        ip_info = ip_data.get("data", {}).get("attributes", {})

        # Process WHOIS data
        whois_info = [entry for entry in whois_data.get("data", [])]

        # Process URLs data
        urls_info = [entry for entry in urls_data.get("data", [])]

        # Process comments data
        comments_info = []
        for comment in comments_data.get("data", []):
            comment_attributes = comment.get("attributes", {})
            # Convert the UNIX timestamp to human-readable format
            date = comment_attributes.get("date")
            if date:
                date = datetime.utcfromtimestamp(date).strftime('%Y-%m-%d %H:%M:%S')
            comments_info.append({
                "date": date,
                "html": comment_attributes.get("html"),
                "tags": comment_attributes.get("tags", []),
                "text": comment_attributes.get("text"),
                "votes": comment_attributes.get("votes", {})
            })

        return {
            "ip_info": ip_info,
            "whois_info": whois_info,
            "urls_info": urls_info,
            "comments_info": comments_info,
            "last_analysis_results": last_analysis_results  
        }

    async def send_split_messages(self, interaction, message: str, require_response=True):
        """Sends a message, and if it's too long for Discord, splits it."""
        # Handle empty messages
        if not message.strip():
            logging.warning("Attempted to send an empty message.")
            return

        # Extract the user's query/command from the interaction to prepend it to the first chunk
        query = ""
        for option in interaction.data.get("options", []):
            if option.get("name") == "query":
                query = option.get("value", "")
                break

        prepend_text = ""
        if query:
            prepend_text = f"Query: {query}\n\n"

        lines = message.split("\n")
        chunks = []
        current_chunk = ""

        # First, add the prepend_text (if any) to the initial chunk
        if prepend_text:
            current_chunk += prepend_text

        for line in lines:
            # If the individual line is too long, split it up before chunking
            while len(line) > self.discord_message_limit:
                sub_line = line[:self.discord_message_limit]
                if len(current_chunk) + len(sub_line) + 1 > self.discord_message_limit:
                    chunks.append(current_chunk)
                    current_chunk = ""
                current_chunk += sub_line + "\n"
                line = line[self.discord_message_limit:]

            # If adding the next line to the current chunk would exceed the Discord message limit
            if len(current_chunk) + len(line) + 1 > self.discord_message_limit:
                chunks.append(current_chunk)
                current_chunk = line + "\n"
            else:
                current_chunk += line + "\n"

        if current_chunk:
            chunks.append(current_chunk)

        # Check if there are chunks to send
        if not chunks:
            logging.warning("No chunks generated from the message.")
            return

        # If a response is required and the interaction hasn't been responded to, defer the response
        if require_response and not interaction.response.is_done():
            await interaction.response.defer(ephemeral=False)

        # Edit the deferred response
        try:
            await interaction.followup.send(content=chunks[0], ephemeral=False)
            chunks = chunks[1:]  # Remove the first chunk since we've already sent it
        except Exception as e:
            logging.error(f"Failed to send the first chunk via followup. Error: {e}")

        # Send the rest of the chunks directly to the channel
        for chunk in chunks:
            try:
                await interaction.channel.send(chunk)
            except Exception as e:
                logging.error(f"Failed to send a message chunk to the channel. Error: {e}")

    async def handle_errors(self, interaction, error, error_type="Error", base_url=None, ip=None, headers=None):
        # Acquire the semaphore. If the maximum number is already acquired, this will block until one is free.
        async with self.rate_limiter:
            error_message = f"{error_type}: {error}"
            logging.error(f"Error for user {interaction.user}: {error_message}")
            try:
                if interaction.response.is_done():
                    await interaction.followup.send(error_message)
                else:
                    await interaction.response.send_message(error_message, ephemeral=True)
            except discord.HTTPException as http_err:
                logging.warning(f"HTTP error while responding to {interaction.user}: {http_err}")
                await interaction.followup.send(error_message)
            except Exception as unexpected_err:
                logging.error(f"Unexpected error while responding to {interaction.user}: {unexpected_err}")
                await interaction.followup.send("An unexpected error occurred. Please try again later.")

        async with aiohttp.ClientSession() as session:
            async with session.get(base_url + ip, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    return data
                else:
                    raise Exception(f"VirusTotal API returned a {response.status} status.")

    async def get_geolocation(self, ip):
        url = f"https://ipinfo.io/{ip}/json"
        async with aiohttp.ClientSession() as session:
            response_text = await self.fetch(session, url)
            data = json.loads(response_text)
            return data

    async def get_tor_exit_nodes(self):
        TOR_EXIT_LIST_URL = "https://check.torproject.org/exit-addresses"
        try:
            async with aiohttp.ClientSession() as session:
                response_text = await self.fetch(session, TOR_EXIT_LIST_URL)
                exit_nodes = [line.split(" ")[1] for line in response_text.splitlines() if line.startswith("ExitAddress")]
                return exit_nodes
        except Exception as e:
            print(f"Error fetching Tor exit nodes: {e}")  
            return [] 
        
def run_discord_bot(token, shodan_api_key, virustotal_api_key):
    client = AClient(shodan_api_key, virustotal_api_key)

    @client.event
    async def on_ready():
        await client.tree.sync()
        logging.info(f'{client.user} is done sleeping. Lets go!')
        await client.change_presence(activity=client.activity)

    @client.tree.command(name="ip", description="Retrieve comprehensive information about an IP address.")
    async def ip(interaction: discord.Interaction, ip: str):
        await interaction.response.defer(ephemeral=False)
        status_message = await interaction.followup.send(f'Scanning and analyzing {ip}.\nThis will take a long time. Grab a beer.')
        current_message = f'Scanning and analyzing {ip}.\nThis will take a long time. Grab a beer.' 
        print(f"[INFO] Received IP lookup request for: {ip}")

        config = load_config()
        info = []
        open_ports = []

        info.append('**----------------------------------**')
        info.append(f'**## Report on {ip}**')
        info.append('**----------------------------------**')
            
        # Shodan
        info.append('\n**## Shodan Analysis**')
        try:
            api = Shodan(client.shodan_key)
            results = api.search(ip)  # Using search instead of host

            if results and results.get('matches'):
                shodan_info = [f"Found {results['total']} results for IP {ip} on Shodan.\nHere are 20:"]
                
                # Extracting details for each matching device (limited to top 20 for brevity)
                for match in results['matches'][:20]:  
                    device_info = []

                    device_info.append(f"IP: {match['ip_str']}")
                    if 'os' in match:
                        device_info.append(f"OS: {match['os']}")
                    if 'city' in match and 'country_name' in match:
                        device_info.append(f"Location: {match['city']}, {match['country_name']}")

                    # Services/Banners
                    if 'port' in match:
                        service_info = f"Port: {match['port']}, Service: {match.get('product', 'N/A')}"
                        if 'version' in match:
                            service_info += f", Version: {match['version']}"
                        device_info.append(service_info)

                    shodan_info.append(' | '.join(device_info))

                info.append("\n".join(shodan_info))
                print("[INFO] Completed Shodan search.")
                current_message += '\n- Shodan search completed successfully.'
                await status_message.edit(content=current_message)
            else:
                info.append(f"No results found for IP {ip} on Shodan.")
        except ShodanAPIError:
            info.append("Invalid Shodan API key.")
            print(f"Invalid Shodan API key.")
        except Exception as e:
            info.append(f"Shodan Error: {str(e)}")
            print(f"[ERROR] ...: {e}")
            
            # Tor Exit Node Check
            info.append('\n**## TOR Exit Node Check**')
            try:
                exit_nodes = await client.get_tor_exit_nodes()
                is_tor = ip in exit_nodes
                info.append(f"Tor exit node: {'Yes' if is_tor else 'No'}")
                print("[INFO] TOR check completed.")
                current_message += '\n- TOR check completed.'
                await status_message.edit(content=current_message)

            except Exception as e:
                print(f"Error checking for Tor exit node: {e}") 
                info.append("Error checking for Tor exit node.") 
                print(f"[ERROR] ...: {e}")

            # Whois lookup
            info.append('\n**## Whois Lookup**')
            try:
                whois_data = whois.whois(ip)
                if whois_data:
                    whois_info = ["Whois data for " + ip + ":"]
                    for key, value in whois_data.items():
                        if value and not isinstance(value, (list, dict)):
                            whois_info.append(f"   {key.capitalize()}: {value}")
                        elif isinstance(value, list):
                            # If the value is a list (e.g. multiple name servers), concatenate them
                            whois_info.append(f"   {key.capitalize()}: {', '.join(map(str, value))}")
                    info.extend(whois_info)
                    print("[INFO] WHOIS check completed.")
                    current_message += '\n- WHOIS check completed.\n- :clock1: Scanning lots of ports now...'
                    await status_message.edit(content=current_message)
                else:
                    info.append(f"No Whois data found for {ip}.")
                    print(f"No Whois data found for {ip}.")
            except Exception as e:
                info.append(f"Whois lookup error for {ip}: {e}")
                print(f"[ERROR] ...: {e}")

            # Device and OS Detection (using nmap)
            info.append('\n**## NMAP Data**')
            nm = nmap.PortScanner()

            # List of interesting ports
            interesting_ports = [
                21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389, 8080, 8443, 8888, 
                9100, 9200, 25565, 27015, 86, 888, 10001, 17500, 34567, 5050, 5800, 8090, 554, 
                8554, 37777
            ]

            # Filter out ports that are within the 20-80 range
            filtered_ports = [port for port in interesting_ports if port < 20 or port > 80]

            # Combine the range with the specific ports
            port_string = "20-80," + ",".join(map(str, filtered_ports))

            try:
                # Scanning ports along with aggressive scan for OS, version detection, script scans, and traceroute
                result = await client.async_nmap_scan(nm, ip, port_string, arguments='-A -T4')
                                
                # Ports Information
                open_ports = []
                for proto in nm[ip].all_protocols():
                    lport = nm[ip][proto].keys()
                    open_ports.extend(lport)
                    for port in lport:
                        if 'name' in nm[ip][proto][port]:
                            device = nm[ip][proto][port]['name']
                            info.append(f"Device on port {port}: {device}")

                # OS and Device Information
                if 'osclass' in nm[ip]:
                    os_guess = nm[ip]['osclass']['osfamily']
                    os_gen = nm[ip]['osclass']['osgen'] if 'osgen' in nm[ip]['osclass'] else ''
                    device_type = nm[ip]['osclass']['osclass_type'] if 'osclass_type' in nm[ip]['osclass'] else ''
                    info.append(f"OS guess: {os_guess} {os_gen}")
                    if device_type:
                        info.append('**----------------------------------**')
                        info.append(f"Device type: {device_type}")
                        info.append('**----------------------------------**')
                else:
                    info.append("Failed to determine OS using nmap.")
                    print("[ERROR] Failed to determine OS using nmap.")

                # Traceroute Information
                if 'trace' in nm[ip]:
                    hops = []
                    for hop in nm[ip]['trace']['hops']:
                        hops.append(hop['ipaddr'])
                    info.append('**----------------------------------**')
                    info.append(f"Traceroute: {' -> '.join(hops)}")
                    info.append('**----------------------------------**')

            except Exception as e:
                if "nmap program was not found in path" in str(e):
                    info.append("Error: Nmap is not installed or not found in the system's PATH.")
                    print(f"Error: Nmap is not installed or not found in the system's PATH.")
                else:
                    info.append(f"Error during device and OS detection using nmap: {str(e)}")
                    print(f"[ERROR] ...: {e}")
            
            print("[INFO] NMAP aggressive scan completed.")
            current_message += '\n- NMAP aggressive scan completed.'
            await status_message.edit(content=current_message)

            # Check for common services
            service_links = []

            ports_and_services = {
                20: ("FTP Data Transfer", "ftp"),
                21: ("FTP Control", "ftp"),
                53: ("DNS", "dns"),
                67: ("DHCP Server", "dhcp"),
                68: ("DHCP Client", "dhcp"),
                80: ("HTTP", "http"),
                123: ("NTP", "ntp"),
                389: ("LDAP", "ldap"),
                443: ("HTTPS", "https"),
                636: ("LDAPS", "ldaps"),
                1194: ("OpenVPN", "openvpn"),
                1723: ("PPTP VPN", "pptp"),
                1812: ("RADIUS Authentication", "radius"),
                1813: ("RADIUS Accounting", "radius"),
                1883: ("MQTT (non-SSL)", "mqtt"),
                8883: ("MQTT (SSL)", "mqtts"),
                2049: ("NFS", "nfs"),
                3260: ("iSCSI", "iscsi"),
                3268: ("Microsoft Global Catalog", "gc"),
                5060: ("SIP Non-encrypted", "sip"),
                5061: ("SIP Encrypted (TLS)", "sips"),
                5000: ("UPnP", "upnp"),
                11211: ("Memcached", "memcached"),
                27015: ("Online Gaming (e.g., Valve's Source Engine)", "game"),
                9418: ("Git", "git"),
                10000: ("Webmin", "webmin"),
                # IP Cameras
                554: ("RTSP for IP cameras", "rtsp"),
                8554: ("RTSP alternate", "rtsp"),
                37777: ("Dahua DVR", "dahua"),
                86: ("Wyze Camera", "http"),
                888: ("WebcamXP", "http"),
                8080: ("WebcamXP 5", "http"),
                10001: ("Yawcam", "http"),
                17500: ("Dropcam", "http"),
                34567: ("Hikvision DVR", "hikvision"),
                5050: ("Mobotix IP Camera", "mobotix"),
                5800: ("Vivotek Cameras", "vivotek"),
                8090: ("Apix Cameras", "http"),
                # Printers
                515: ("Line Printer Daemon (LPD)", "lpd"),
                631: ("Internet Printing Protocol (IPP)", "ipp"),
                9100: ("Raw printing (JetDirect, AppSocket, PDL-datastream)", "jetdirect"),
                # Game Servers
                25565: ("Minecraft", "minecraft"),
                27017: ("MongoDB", "mongodb")
            }

            # Generate service links based on detected open ports
            default_label = "Unknown Service"
            default_protocol = "unknown"

            for port, values in ports_and_services.items():
                label = values[0] if len(values) > 0 and values[0] else default_label
                protocol = values[1] if len(values) > 1 and values[1] else default_protocol
                
                # Append the port to the URL if it's not a standard port for the given protocol
                port_str = f":{port}" if (protocol != "http" or port != 80) and (protocol != "https" or port != 443) else ""

                if port in open_ports:
                    service_links.append(f"[{label}]({protocol}://{ip}{port_str})")

            # VirusTotal
            info.append('\n**## VirusTotal Analysis**')
            try:
                processed_data = await client.get_virustotal_data(ip)

                # Extracting IP Info
                ip_info = processed_data.get("ip_info", {})
                if ip_info:
                    info.append("**IP Info:**")
                    for key, value in ip_info.items():
                        if key == "last_analysis_results":
                            continue  
                        if isinstance(value, dict):
                            value = ', '.join(f"{k}: {v}" for k, v in value.items())
                        info.append(f"{key.capitalize()}: {value}")

                # Extracting WHOIS data
                info.append('**----------------------------------**')
                info.append('**Historical WHOIS Data**')
                info.append('**----------------------------------**')
                whois_info = processed_data.get("whois_info", [])
                if whois_info:
                    for entry in whois_info:
                        attributes = entry.get("attributes", {})
                        for key, value in attributes.items():
                            if isinstance(value, dict):  # If the value is another dictionary
                                nested_info = [f"\t{k.capitalize()}: {v}" for k, v in value.items()]
                                info.append(f"{key.capitalize()}:")
                                info.extend(nested_info)
                            else:
                                info.append(f"{key.capitalize()}: {value}")

                # Extracting URLs data
                urls_info = processed_data.get("urls_info", [])
                if urls_info:
                    info.append('**----------------------------------**')
                    info.append("**URLs associated:**")
                    info.append('**----------------------------------**')
                    for entry in urls_info:
                        for key, value in entry.get("attributes", {}).items():
                            info.append(f"{key.capitalize()}: {value}")

                # Extracting Comments data
                comments_info = processed_data.get("comments_info", [])
                if comments_info:
                    info.append('**----------------------------------**')
                    info.append("**Community Comments:**")
                    info.append('**----------------------------------**')
                    for comment in comments_info:
                        for key, value in comment.items():
                            info.append(f"{key.capitalize()}: {value}")

                # Extracting Last Analysis Results 
                last_analysis = processed_data.get("last_analysis_results", {})
                if last_analysis:
                    info.append('**----------------------------------**')
                    info.append("**Last Analysis Results:**")
                    info.append('**----------------------------------**')
                    for engine, details in last_analysis.items():
                        engine_name = details.get('engine_name', 'Unknown Engine')
                        category = details.get('category', 'Unknown Category')
                        result = details.get('result', 'Unknown Result')
                        info.append(f"{engine_name} - Category: {category}, Result: {result}")

                print("[INFO] Virustotal scan completed.")
                current_message += '\n- Virustotal scan completed.'
                await status_message.edit(content=current_message)

            except Exception as e:
                print(f"VirusTotal API Error: {e}")

            # Geolocation
            info.append('\n**## Geolocation**')
            try:
                data = await client.get_geolocation(ip)
                location = f"{data.get('city', 'Unknown')}, {data.get('region', 'Unknown')}, {data.get('country', 'Unknown')}"
                google_maps_link = f"https://www.google.com/maps/search/?api=1&query={data.get('loc', '0,0')}"
                print(data)
                info.append(f"**[View on Google Maps: {location}]({google_maps_link})**")
                print("[INFO] Sent geolocation.")
                current_message += '\n- Geolocation data retrieved.'
                await status_message.edit(content=current_message)                
            except Exception as e:
                info.append(f"Error fetching geolocation data: {e}")
                print(f"[ERROR] Error fetching geolocation data: {e}")

            if service_links:
                info.append("\n**## Possible open services:**")
                for link in service_links:
                    # Extract service name and URL
                    match = re.search(r'\[(.+?)\]\((.+?)\)', link)
                    if match:
                        service_name, service_url = match.groups()
                        info.append(f"- {service_name}: <{service_url}>")
                    else:
                        info.append(f"- {link}")
                print("[INFO] Sent open ports.")
            else:
                info.append('**----------------------------------**')
                info.append("No detected open services.")
                info.append('**----------------------------------**')

            # Create response_message from info
            response_message = "\n".join(info)

            # Suppress URL previews by wrapping URLs with <>
            response_message = re.sub(r'(?<!<)(http[s]?://\S+)(?!\>)', r'<\1>', response_message)

            info.append(f'\n## End of report on {ip}')
            print(f"[INFO] End of report on {ip}")

            await client.send_split_messages(interaction, response_message)
            print("[INFO] Initial Discord response sent.")

        client.run(token)

    if __name__ == "__main__":
        config = load_config()
        if check_configurations(config):
            run_discord_bot(config.get("TOKEN"), config.get("SHODAN_KEY"), config.get("VIRUSTOTAL_API_KEY"))
