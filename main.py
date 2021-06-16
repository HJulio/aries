import jetforce

from aries import app, init_db, settings

init_db(settings.db)

server = jetforce.GeminiServer(app)
server.run()
