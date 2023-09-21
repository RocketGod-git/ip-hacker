import json
import logging
import discord
import os
import asyncio
import requests
import scapy.all as scapy
from shodan import Shodan, APIError as ShodanAPIError

logging.basicConfig(level=logging.INFO)

def load_config():
    try:
        with open('config.json', 'r') as file:
            return json.load(file)
    except Exception as e:
        logging.error(f"Error loading configuration: {e}")
        return None

class aclient(discord.Client):
    def __init__(self) -> None:
        super().__init__(intents=discord.Intents.default())
        self.tree = discord.app_commands.CommandTree(self)
        self.activity = discord.Activity(type=discord.ActivityType.watching, name="IP Analysis")
        self.discord_message_limit = 2000

    async def send_split_messages(self, interaction, message: str, require_response=True):
        if not message.strip():
            logging.warning("Attempted to send an empty message.")
            return

        lines = message.split("\n")
        chunks = []
        current_chunk = ""

        for line in lines:
            if len(current_chunk) + len(line) + 1 > self.discord_message_limit:
                chunks.append(current_chunk)
                current_chunk = line + "\n"
            else:
                current_chunk += line + "\n"

        if not chunks:
            logging.warning("No chunks generated from the message.")
            return

        if require_response and not interaction.response.is_done():
            await interaction.response.defer(ephemeral=False)

        for chunk in chunks:
            try:
                await interaction.followup.send(content=chunk, ephemeral=False)
            except Exception as e:
                logging.error(f"Failed to send a message chunk to the channel. Error: {e}")

    async def handle_errors(self, interaction, error, error_type="Error"):
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

    @discord.app_commands.CommandTree.command(name="ip_info", description="Retrieve comprehensive information about an IP address.")
    async def ip_info(self, interaction: discord.Interaction, ip: str):
        config = load_config()

        info = []

        # [Integrate Scapy, VirusTotal, Shodan, etc. as necessary]
        # For demonstration, let's integrate a simple Shodan lookup and VirusTotal check.

        # Shodan
        try:
            api = Shodan(config["SHODAN_API_KEY"])
            result = api.host(ip)
            info.append(f"Shodan data for {ip}: {result}")
        except ShodanAPIError:
            info.append("Invalid Shodan API key.")
        except Exception as e:
            info.append(f"Shodan Error: {str(e)}")

        # VirusTotal (using a dummy endpoint, you'd replace with an actual endpoint)
        headers = {
            "x-apikey": config["VIRUSTOTAL_API_KEY"]
        }
        response = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers=headers)
        if response.status_code == 403:
            info.append("Invalid VirusTotal API key.")
        elif response.status_code == 200:
            vt_data = response.json()
            # You'd parse the response as needed.
            info.append(f"VirusTotal data for {ip}: {vt_data}")
        else:
            info.append(f"VirusTotal Error: {response.content}")

        # [Add more integrations as needed...]

        await self.send_split_messages(interaction, "\n".join(info))

    async def on_ready(self):
        await self.tree.sync()
        logging.info(f'{self.user} is online.')

def run_discord_bot(token):
    client = aclient()
    client.run(token)

if __name__ == "__main__":
    config = load_config()
    run_discord_bot(config["DISCORD_TOKEN"])
