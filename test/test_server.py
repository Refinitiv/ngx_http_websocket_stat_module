#!/usr/bin/python3

from plumbum import cli
import asyncio
import websockets
from websockets.exceptions import ConnectionClosed

async def hello(websocket, path):
	while(True):
		try:
			name = await websocket.recv()

			greeting = "Hello {}!".format(name)
			await websocket.send(greeting)
		except ConnectionClosed:
			pass

class App(cli.Application):
    port = cli.SwitchAttr(['-p'], int , default = 5000)
    def main(self):
        print("Listening at {}".format(self.port))
        start_server = websockets.serve(hello, '0.0.0.0', self.port)
        asyncio.get_event_loop().run_until_complete(start_server)
        asyncio.get_event_loop().run_forever()

App.run()
        
