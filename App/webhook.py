import asyncio
import discord
from discord import Webhook
import aiohttp

async def anything(url):
    async with aiohttp.ClientSession() as session:
        webhook = Webhook.from_url(url, session=session)
        embed = discord.Embed(title="This is from a weghhhhhhhhhhhhhhbhook!")
        await webhook.send(embed=embed, username="stud", avatar_url="https://i.imgur.com/555.png")
        
if __name__ == "__main__":
    url = "https://discord.com/api/webhooks/1323194304235311145/PcFBFysqtU3ypXS4jgDnTq4EO9Rj6b5Yw62sy0ej9zh5s8VhDv5nkDQzk6etZFL2k_vJ"

    loop = asyncio.new_event_loop()
    loop.run_until_complete(anything(url))
    loop.close()