# discord_bot.py

import discord
import requests

# Define the intents
intents = discord.Intents.default()
intents.message_content = True

# Define the Discord bot client
client = discord.Client(intents=intents)

API_BASE_URL = 'http://localhost:8000'  # Replace with your FastAPI URL

@client.event
async def on_ready():
    print(f'Logged in as {client.user}')

@client.event
async def on_message(message):
    if message.content.startswith("!create_discussion"):
        try:
            # Example command: !create_discussion 1 https://discord.com
            _, scholarship_id, discussion_link = message.content.split(" ", 2)
            scholarship_id = int(scholarship_id)

            # Make a POST request to the FastAPI backend to create the discussion
            response = requests.post(
                f"{API_BASE_URL}/discussions/",
                json={"scholarship_id": scholarship_id, "discussion_link": discussion_link}
            )

            if response.status_code == 200:
                await message.channel.send(f"Discussion created successfully: {discussion_link}")
            else:
                await message.channel.send("Failed to create discussion.")
        except ValueError:
            await message.channel.send("Invalid input. Please use: !create_discussion <scholarship_id> <discussion_link>")
# Run the bot
client.run('')
