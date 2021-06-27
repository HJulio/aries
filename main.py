import jetforce

from aries import app, settings, init_db


init_db('test.db')

server = jetforce.GeminiServer(app, host='0.0.0.0', hostname='172.28.111.16')
server.run()
