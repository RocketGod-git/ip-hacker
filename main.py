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
from concurrent.futures import ThreadPoolExecutor
import re
import time
import traceback
import base64
from io import BytesIO


executor = ThreadPoolExecutor()

last_analysis_date = datetime.utcfromtimestamp(1695418944).strftime('%Y-%m-%d %H:%M:%S UTC')
whois_date = datetime.utcfromtimestamp(1614909309).strftime('%Y-%m-%d %H:%M:%S UTC')

handler = logging.StreamHandler()
handler.addFilter(lambda record: 'Shard ID None has successfully RESUMED session' not in record.getMessage())
logging.basicConfig(handlers=[handler], level=logging.INFO, format='[%(asctime)s] [%(levelname)s] %(name)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

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

def is_valid_ipv4(ip):
    pattern = r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    return re.match(pattern, ip) is not None

def is_valid_ipv6(ip):
    pattern = r'^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}))|:)))(%.+)?\s*$'
    return re.match(pattern, ip) is not None

def validate_ip(ip):
    if is_valid_ipv4(ip) or is_valid_ipv6(ip):
        return True
    else:
        return False

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
        
    # async def async_nmap_scan(self, nm, ip, ports, arguments):
    #     loop = asyncio.get_event_loop()
    #     try:
    #         result = await loop.run_in_executor(executor, nm.scan, ip, ports, arguments)
    #         return result, None  # Return the scan result and no error
    #     except Exception as e:
    #         error_traceback = traceback.format_exc()
    #         logging.error(f"Nmap scanning error for IP {ip} with ports '{ports}' and arguments '{arguments}':\n{error_traceback}")
    #         # Print the full traceback for detailed diagnostics in the terminal
    #         print(f"Traceback error during Nmap scanning for IP {ip} with ports '{ports}' and arguments '{arguments}':\n{error_traceback}")
    #         return None, f"An error occurred during Nmap scanning: {str(e)}"

    async def fetch_shodan_host_info(self, ip):
        SHODAN_API_URL = f"https://api.shodan.io/shodan/host/{ip}"
        params = {'key': self.shodan_key, 'minify': str(False).lower()}
        logging.debug(f"Fetching Shodan host information for IP: {ip}")

        async with aiohttp.ClientSession() as session:
            async with session.get(SHODAN_API_URL, params=params) as response:
                if response.status == 200:
                    logging.debug(f"Successfully fetched host information for IP: {ip}")
                    return await response.json()
                elif response.status == 404:
                    logging.info(f"No data found for IP {ip} on Shodan.")
                    return None
                else:
                    response_text = await response.text()
                    logging.error(f"Shodan API returned a {response.status} status for IP {ip}. Response: {response_text}")
                    return None

    async def request_shodan_scan(self, ip):
        logging.debug(f"Requesting Shodan scan for IP: {ip}")
        async with aiohttp.ClientSession() as session:
            scan_url = f"https://api.shodan.io/shodan/scan?key={self.shodan_key}"
            data = {"ips": ip}
            async with session.post(scan_url, json=data) as response:
                if response.status == 200:
                    logging.debug(f"Shodan scan successfully initiated for IP: {ip}")
                    return await response.json(), False
                elif response.status == 401:
                    logging.error(f"Shodan scan limit reached for IP {ip}. Falling back to fetch_shodan_host_info.")
                    return None, True
                else:
                    response_text = await response.text()
                    logging.error(f"Shodan scan request failed for IP {ip} with status {response.status}. Response: {response_text}")
                    return None, False

    async def check_shodan_scan_status(self, scan_id):
        logging.debug(f"Checking Shodan scan status for scan_id: {scan_id}")
        async with aiohttp.ClientSession() as session:
            status_url = f"https://api.shodan.io/shodan/scan/{scan_id}?key={self.shodan_key}"
            async with session.get(status_url) as response:
                if response.status == 200:
                    logging.debug(f"Successfully fetched Shodan scan status for scan_id: {scan_id}")
                    return await response.json()
                else:
                    logging.error(f"Failed to fetch Shodan scan status for scan_id {scan_id} with status {response.status}")
                    return None


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

#        print("[DEBUG] Sending split messages to Discord...")

        # Edit the deferred response
        try:
#            print(f"[DEBUG] Sending chunk 1/{len(chunks)} to Discord...")
            await interaction.followup.send(content=chunks[0], ephemeral=False)
#            print(f"[DEBUG] Chunk 1/{len(chunks)} sent to Discord.")
            chunks = chunks[1:]  # Remove the first chunk since we've already sent it
        except Exception as e:
            logging.error(f"Failed to send the first chunk via followup. Error: {e}")

        # Send the rest of the chunks directly to the channel
        for i, chunk in enumerate(chunks, start=2):  # Start the index at 2 since we've already sent the first chunk
            try:
#                print(f"[DEBUG] Sending chunk {i}/{len(chunks)+1} to Discord...")
                await interaction.channel.send(chunk)
#                print(f"[DEBUG] Chunk {i}/{len(chunks)+1} sent to Discord.")
            except Exception as e:
                logging.error(f"Failed to send a message chunk to the channel. Error: {e}")

#        print("[DEBUG] Split messages sent to Discord.")


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
            async with session.get(url) as response:
                if response.status == 200:
                    response_text = await response.text()
                    # Check if response_text is not empty
                    if response_text:
                        try:
                            data = json.loads(response_text)
                            return data
                        except json.JSONDecodeError:
                            logging.error(f"Invalid JSON response for IP {ip}: {response_text}")
                            return None  # or a default geolocation data structure
                    else:
                        logging.error(f"Empty response for IP {ip}")
                        return None  # or a default geolocation data structure
                else:
                    logging.error(f"Error fetching geolocation data for IP {ip}: HTTP Status {response.status}")
                    return None  # or a default geolocation data structure

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
        print("[DEBUG] Command tree synced.")

        logging.info(f"Bot {client.user} is ready and running in {len(client.guilds)} servers.")
        for guild in client.guilds:
            # Attempt to fetch the owner as a member of the guild
            try:
                owner = await guild.fetch_member(guild.owner_id)
                owner_name = f"{owner.name}#{owner.discriminator}"
            except Exception as e:
                logging.error(f"Could not fetch owner for guild: {guild.name}, error: {e}")
                owner_name = "Could not fetch owner"
            
            logging.info(f" - {guild.name} (Owner: {owner_name})")

        server_count = len(client.guilds)
        activity_text = f"/ip on {server_count} servers"
        await client.change_presence(activity=discord.Activity(type=discord.ActivityType.watching, name=activity_text))

        logging.info(f'{client.user} is done sleeping. Lets go!')


    @client.tree.command(name="ip", description="Retrieve comprehensive information about an IP address.")
    async def ip(interaction: discord.Interaction, ip: str):
        # Validate the IP address here
        if not validate_ip(ip):
            await interaction.response.send_message("Invalid IP address provided. Please provide a valid IPv4 or IPv6 address.", ephemeral=True)
            return  
        
        await interaction.response.defer(ephemeral=False)
        status_message = await interaction.followup.send(f'Scanning and analyzing {ip}.\n')
        current_message = f'Scanning and analyzing {ip} for {interaction.user.name}.\n' 
        print(f"[INFO] Processing: {ip} for {interaction.user.name} at {interaction.guild}")
        
        shodan_data = None

        config = load_config()
        info = []
        open_ports = []

        def clean_service_banner(banner):
            # Remove HTML tags
            banner_no_html = re.sub(r'<[^>]+>', '', banner)
            # Remove escape sequences and other unwanted patterns
            cleaned_banner = re.sub(r'\s+;|\\n|\\r|\\t', ' ', banner_no_html)
            # Optionally, truncate long strings to keep the output concise
            if len(cleaned_banner) > 100:
                return cleaned_banner[:97] + "..."
            return cleaned_banner


        info.append('**----------------------------------**')
        info.append(f'**## Report on {ip}**')
        info.append('**----------------------------------**')
            
        # Shodan Analysis
#        print("[DEBUG] Starting Shodan analysis...")
        info.append('\n**## Shodan Analysis**')
        try:
            current_message += '\n- Initiating Shodan scan for current open ports.'
            await status_message.edit(content=current_message)

            # Request an on-demand Shodan scan for the IP address
            scan_result = await client.request_shodan_scan(ip)
            if scan_result and 'id' in scan_result:
                scan_id = scan_result['id']
                current_message += f'\n- Shodan scan initiated. Scan ID: {scan_id}. Waiting for scan to complete...'
                await status_message.edit(content=current_message)

                # Poll for Shodan scan completion
                scan_completed = False
                while not scan_completed:
                    scan_status = await client.check_shodan_scan_status(scan_id)
                    if scan_status:
                        if scan_status.get('status') == 'DONE':
                            scan_completed = True
                            current_message += '\n- Shodan scan completed. Fetching updated information...'
                        elif 'error' in scan_status:  # Assuming 'error' key indicates a problem
                            current_message += '\n- Error during Shodan scan. Please check the logs for more details.'
                            logging.error(f"Shodan scan error: {scan_status.get('error')}")
                            break  # Exit the loop on error
                        # Handle other statuses if needed
                    else:
                        current_message += '\n- Failed to fetch Shodan scan status. Retrying...'
                    await status_message.edit(content=current_message)
                    if not scan_completed:
                        await asyncio.sleep(30)  # Use asyncio.sleep() for async code
            else:
                current_message += '\n- Failed to initiate Shodan scan. Probably out of credits.\n- Proceeding with Shodan historical lookup.'
                await status_message.edit(content=current_message)


            # Fetch updated host information from Shodan after the scan
            shodan_data = await client.fetch_shodan_host_info(ip)

            if shodan_data:  
                general_info_exclusions = ['data', 'ports']
                for key, value in shodan_data.items():
                    if key not in general_info_exclusions:
                        if isinstance(value, list):
                            value = ', '.join(map(str, value))
                        info.append(f"**{key.capitalize()}**: {value}")

                # Display detailed service information from 'data' array
                if 'data' in shodan_data and shodan_data['data']:
                    info.append(f"\nFound {len(shodan_data['data'])} services for IP {ip} on Shodan:")
                    
                    for service in shodan_data.get('data', []):
                        cleaned_banner = clean_service_banner(service.get('data', 'No banner information'))
                        service_info = []

                        port = service.get('port', 'N/A')
                        product = service.get('product', 'N/A') or 'N/A'  # Ensures 'N/A' if None
                        version = service.get('version', '') or ''  # Ensures empty string if None
                        service_name = f"{product} {version}".strip()
                        os = service.get('os', 'N/A') or 'N/A'  # Ensures 'N/A' if None
                        location = f"{service.get('location', {}).get('city', 'Unknown city')}, {service.get('location', {}).get('country_name', 'Unknown country')}"
                        ssl_info = service.get('ssl', {}).get('version', 'No SSL') or 'No SSL'  # Ensures 'No SSL' if None

                        # Constructing detailed service information
                        service_info.append(f"Port: {port}")
                        service_info.append(f"Service: {service_name if service_name else 'N/A'}")
                        service_info.append(f"Banner: {cleaned_banner}")
                        if os:
                            service_info.append(f"OS: {os}")
                        if ssl_info != 'No SSL':
                            service_info.append(f"SSL Version: {ssl_info}")
                        service_info.append(f"Location: {location}")

                        # Join service_info list into a single string and add to info
                        info.append('\n'.join(service_info))

                        # Add detailed port information to open_ports for the summary section
                        open_ports.append({
                            "link": f"{ip}:{port}",
                            "summary": f"Service: {service_name if service_name else 'N/A'}, Product: {product}, OS: {os}, SSL: {ssl_info}, Location: {location}"
                        })

            current_message += '\n- Shodan information retrieval completed.'
            await status_message.edit(content=current_message)
#            print("[INFO] Completed Shodan IP data scan.")
#            print("[DEBUG] Shodan Analysis (after completion):")
#            print("[DEBUG] info:", info)

        except Exception as e:
            info.append(f"Error fetching data from Shodan: {e}")
            print(f"[ERROR] Error fetching data from Shodan: {e}")

        # Tor Exit Node Check
#        print("[DEBUG] Starting TOR exit node check...")
        info.append('\n**## TOR Exit Node Check**')
        try:
            exit_nodes = await client.get_tor_exit_nodes()
            is_tor = ip in exit_nodes
            info.append(f"Tor exit node: {'Yes' if is_tor else 'No'}")
#            print("[INFO] TOR check completed.")
            current_message += '\n- TOR check completed.'
            await status_message.edit(content=current_message)
#            print("[DEBUG] TOR exit node check completed.")

        except Exception as e:
            print(f"Error checking for Tor exit node: {e}") 
            info.append("Error checking for Tor exit node.") 
            print(f"[ERROR] ...: {e}")

        # Whois lookup
#        print("[DEBUG] Starting Whois Lookup...")
        info.append('\n**## Whois Lookup**')
        try:
            loop = asyncio.get_event_loop()
            whois_data = await loop.run_in_executor(None, whois.whois, ip)
            if whois_data:
                whois_info = ["Whois data for " + ip + ":"]
                for key, value in whois_data.items():
                    if value and not isinstance(value, (list, dict)):
                        whois_info.append(f"   {key.capitalize()}: {value}")
                    elif isinstance(value, list):
                        # If the value is a list (e.g. multiple name servers), concatenate them
                        whois_info.append(f"   {key.capitalize()}: {', '.join(map(str, value))}")
                info.extend(whois_info)
#                print("[INFO] WHOIS check completed.")
                current_message += '\n- WHOIS check completed.'
                await status_message.edit(content=current_message)

        except Exception as e:
            info.append(f"Whois lookup error for {ip}: {e}")
            print(f"[ERROR] ...: {e}")

        # # High-risk or interesting ports for clickable links or security risks
        # high_risk_ports = '80,443,554,8554'  # Example: HTTP, HTTPS, RTSP for IP cameras

        # # Fetch open ports from Shodan
        # if shodan_data and 'ports' in shodan_data and shodan_data['ports']:
        #     ports_to_scan = ','.join(map(str, shodan_data['ports']))
        # else:
        #     # No Shodan data or no ports in Shodan data, use predefined high-risk ports
        #     ports_to_scan = high_risk_ports
        #     info.append(f"No ports data found for IP {ip} on Shodan.")

        # # Perform the NMAP scan using either Shodan-provided ports or fallback to high-risk ports
        # print("[INFO] NMAP port scan starting. Please wait...")
        # info.append('\n**## NMAP Data**')
        # nm = nmap.PortScanner()
        # try:
        #     service_name = "Unknown Service"
        #     product = "Unknown Product"
        #     os = "Unknown OS"
        #     ssl_info = "No SSL Info"
        #     location = "Unknown Location"
        #     nmap_result, nmap_error = await client.async_nmap_scan(nm, ip, ports_to_scan, arguments='-A -T4')
        #     if nmap_error:
        #         info.append(f"NMAP Data\n\nError during Nmap scanning: {nmap_error}")
        #     else:
        #         if nmap_result is None:
        #             info.append("\n**## NMAP Data**")
        #             info.append("Error during Nmap scanning: Unable to complete the scan. Please check the server logs for details.")
        #         else:
        #             for proto in nm[ip].all_protocols():
        #                 lport = nm[ip][proto].keys()
        #                 for port in lport:
        #                     service_info = nm[ip][proto][port]
        #                     service_desc = f"{service_info.get('name', 'unknown service')} {service_info.get('product', '')} {service_info.get('version', '')} {service_info.get('extrainfo', '')}".strip()
        #                     port_info = f"**Port {port}/tcp** - {service_desc} is **{service_info['state']}**"
        #                     info.append(port_info)
        #                     # Keep track of open ports for the summary
        #                     open_ports.append({
        #                         "link": f"{ip}:{port}",
        #                         "summary": f"Service: {service_name if service_name else 'N/A'}, Product: {product if product and product != 'N/A' else ''}, OS: {os}, SSL: {ssl_info}, Location: {location}"
        #                     })

        # except Exception as e:
        #     info.append(f"Error during Nmap scanning: {str(e)}")

        # print("[INFO] NMAP scan completed.")


        # current_message += '\n- NMAP scan completed.'
        # await status_message.edit(content=current_message)


        # # Check for common services
        # service_links = []

        # ports_and_services = {
        #     20: ("FTP Data Transfer", "ftp"),
        #     21: ("FTP Control", "ftp"),
        #     53: ("DNS", "dns"),
        #     67: ("DHCP Server", "dhcp"),
        #     68: ("DHCP Client", "dhcp"),
        #     80: ("HTTP", "http"),
        #     123: ("NTP", "ntp"),
        #     389: ("LDAP", "ldap"),
        #     443: ("HTTPS", "https"),
        #     636: ("LDAPS", "ldaps"),
        #     1194: ("OpenVPN", "openvpn"),
        #     1723: ("PPTP VPN", "pptp"),
        #     1812: ("RADIUS Authentication", "radius"),
        #     1813: ("RADIUS Accounting", "radius"),
        #     1883: ("MQTT (non-SSL)", "mqtt"),
        #     8883: ("MQTT (SSL)", "mqtts"),
        #     2049: ("NFS", "nfs"),
        #     3260: ("iSCSI", "iscsi"),
        #     3268: ("Microsoft Global Catalog", "gc"),
        #     5060: ("SIP Non-encrypted", "sip"),
        #     5061: ("SIP Encrypted (TLS)", "sips"),
        #     5000: ("UPnP", "upnp"),
        #     11211: ("Memcached", "memcached"),
        #     27015: ("Online Gaming (e.g., Valve's Source Engine)", "game"),
        #     9418: ("Git", "git"),
        #     10000: ("Webmin", "webmin"),
        #     # IP Cameras
        #     554: ("RTSP for IP cameras", "rtsp"),
        #     8554: ("RTSP alternate", "rtsp"),
        #     37777: ("Dahua DVR", "dahua"),
        #     86: ("Wyze Camera", "http"),
        #     888: ("WebcamXP", "http"),
        #     8080: ("WebcamXP 5", "http"),
        #     10001: ("Yawcam", "http"),
        #     17500: ("Dropcam", "http"),
        #     34567: ("Hikvision DVR", "hikvision"),
        #     5050: ("Mobotix IP Camera", "mobotix"),
        #     5800: ("Vivotek Cameras", "vivotek"),
        #     8090: ("Apix Cameras", "http"),
        #     # Printers
        #     515: ("Line Printer Daemon (LPD)", "lpd"),
        #     631: ("Internet Printing Protocol (IPP)", "ipp"),
        #     9100: ("Raw printing (JetDirect, AppSocket, PDL-datastream)", "jetdirect"),
        #     # Game Servers
        #     25565: ("Minecraft", "minecraft"),
        #     27017: ("MongoDB", "mongodb")
        # }

        # # Generate service links based on detected open ports
        # default_label = "Unknown Service"
        # default_protocol = "unknown"

        # for port, values in ports_and_services.items():
        #     label = values[0] if len(values) > 0 and values[0] else default_label
        #     protocol = values[1] if len(values) > 1 and values[1] else default_protocol
            
        #     # Append the port to the URL if it's not a standard port for the given protocol
        #     port_str = f":{port}" if (protocol != "http" or port != 80) and (protocol != "https" or port != 443) else ""

        #     if port in open_ports:
        #         service_links.append(f"[{label}]({protocol}://{ip}{port_str})")

        # VirusTotal
#        print("[DEBUG] Starting VirusTotal Analasis...")
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

#            print("[INFO] Virustotal scan completed.")
            current_message += '\n- Virustotal scan completed.'
#            print (info)
            await status_message.edit(content=current_message)


        except Exception as e:
            print(f"VirusTotal API Error: {e}")


        # Check if any significant data was found across all sources
        if len(info) <= 10:
            final_message = f"No significant data found for IP {ip} across all sources."
#            print("[DEBUG] No significant data found. Sending message...")
            await interaction.followup.send(final_message)
#            print("[DEBUG] Message sent.")
        else:
            # Compile and send the full report
#            print("[DEBUG] Significant data found. Compiling full report...")
            response_message = "\n".join(info)
            response_message = re.sub(r'(?<!<)(http[s]?://\S+)(?!\>)', r'<\1>', response_message)  # Suppress URL previews
            response_message += f'\n## End of report data on {ip} - creating embeds and images if available now...'
 #           print("[DEBUG] Full report compiled. Sending split messages to Discord...")
            await client.send_split_messages(interaction, response_message)
#            print("[DEBUG] Split messages sent to Discord.")

        # Start embeds after report

            # Fetch geolocation data
            geolocation_data = await client.get_geolocation(ip)

            # Geolocation Information Embed
            if geolocation_data:
 #               print("[DEBUG] Creating geolocation embed...")
                geolocation_embed = discord.Embed(title=f"Geolocation for {ip}", color=0x3498db)
                location = f"{geolocation_data.get('city', 'Unknown')}, {geolocation_data.get('region', 'Unknown')}, {geolocation_data.get('country', 'Unknown')}"
                google_maps_link = f"[View on Google Maps](https://www.google.com/maps/search/?api=1&query={geolocation_data.get('loc', '0,0')})"
                geolocation_embed.add_field(name="Location", value=location, inline=False)
                geolocation_embed.add_field(name="Postal Code", value=geolocation_data.get('postal', 'Unknown'), inline=True)
                geolocation_embed.add_field(name="Timezone", value=geolocation_data.get('timezone', 'Unknown'), inline=True)
                geolocation_embed.add_field(name="Google Maps", value=google_maps_link, inline=False)
#                print("[DEBUG] Sending geolocation embed...")
                await interaction.followup.send(embed=geolocation_embed)
#                print("[DEBUG] Geolocation embed sent.")
            else:
#                print("[DEBUG] No geolocation data found.")
                await interaction.followup.send("No geolocation data available for the provided IP address.")
                
        # Possible Open Services Embed
#        print("[DEBUG] Creating open services embed...")
        services_embed = discord.Embed(title="Possible Open Services", color=0x3498db)
        if open_ports:
            for port_info in open_ports:
                link = port_info.get('link', '')
                port = link.split(':')[-1] if ':' in link else 'N/A'
                summary = port_info.get('summary', 'No summary available')
                value_field = f"[{link}](http://{link})\n{summary}"
                services_embed.add_field(name=f"Port {port}", value=value_field, inline=False)
        else:
            services_embed.add_field(name="Status", value="No detected open services.", inline=False)

#        print("[DEBUG] Sending open services embed...")
        await interaction.followup.send(embed=services_embed) 
#        print("[DEBUG] Open services embed sent.")

        # Handle Screenshot Data
        screenshot_data = None             
        if shodan_data:
            for service in shodan_data.get('data', []):
                if 'screenshot' in service and 'data' in service['screenshot']:
                    screenshot_data = service['screenshot']['data']
                    break

        if screenshot_data:
            try:
#                print("[DEBUG] Screenshot data found. Sending screenshot...")
                screenshot_bytes = base64.b64decode(screenshot_data)
                screenshot_file = BytesIO(screenshot_bytes)
                screenshot_file.name = 'screenshot.png'
                await interaction.followup.send("Screenshot found!", file=discord.File(screenshot_file, 'screenshot.png'))
#                print("[DEBUG] Screenshot sent.")
            except Exception as e:
                logging.error(f"Error handling screenshot data: {e}")
#        else:
#            print("[DEBUG] No screenshot data found.")

#        print("[INFO] Discord response sent.")
        await interaction.channel.send(f"## Finished searching {ip} for {interaction.user.name}")

    client.run(token)

if __name__ == "__main__":
    config = load_config()
    if check_configurations(config):
        run_discord_bot(config.get("TOKEN"), config.get("SHODAN_KEY"), config.get("VIRUSTOTAL_API_KEY"))
