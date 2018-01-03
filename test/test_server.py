#!/usr/bin/python

import tornado.ioloop
import tornado.web
import tornado.websocket
import tornado.template

class WSHandler(tornado.websocket.WebSocketHandler):
  def check_origin(self, origin):
    return True
  def open(self):
    print 'connection opened...'
    self.write_message("The server says: 'Hello'. Connection was accepted.")

  def on_message(self, message):
    print (len(message))
    self.write_message("Received {0} bytes".format(len(message)))
    print ('received: {0}'.format(len(message)))

  def on_close(self):
    print 'connection closed...'

application = tornado.web.Application([
  (r'/streaming', WSHandler),
])

if __name__ == "__main__":
  port = 5000
  print("listening on port {0}".format(port))
  application.listen(port)
  tornado.ioloop.IOLoop.instance().start()
