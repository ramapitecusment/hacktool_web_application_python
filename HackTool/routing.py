from channels.auth import AuthMiddlewareStack
from channels.routing import ProtocolTypeRouter, URLRouter
import mac_change.routing
import spoofing.routing
import command_line.routing
import scan.routing
application = ProtocolTypeRouter({
    # (http->django views is added by default)
    'websocket': AuthMiddlewareStack(
        URLRouter(
            mac_change.routing.websocket_urlpatterns +
            spoofing.routing.websocket_urlpatterns +
            command_line.routing.websocket_urlpatterns +
            scan.routing.websocket_urlpatterns
        )
    ),
})


