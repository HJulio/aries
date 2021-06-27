import os
import typing
from datetime import datetime, timedelta
from functools import lru_cache

import jinja2
from jetforce import JetforceApplication, Request, Response, Status
from jetforce.app.base import EnvironDict, RateLimiter, RouteHandler, RoutePattern

from .models import User, Certificate
TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")

template_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(TEMPLATE_DIR),
    undefined=jinja2.StrictUndefined,
    trim_blocks=True,
    lstrip_blocks=True,
)


password_failed_rate_limiter = RateLimiter("10/5m")
new_account_rate_limiter = RateLimiter("2/4h")
message_rate_limiter = RateLimiter("3/h")


@lru_cache(2048)
def load_session(session_id: str) -> dict:
    """
    A poor man's server-side session object.

    Stores session data as a dict in memory that will be wiped on server
    restart. Mutate the dictionary to update the session. This only works
    because the server is running as a single process with shared memory.
    """
    # TODO Redis
    return {}


def render_template(name: str, *args, **kwargs) -> str:
    """
    Render gmi using Jinja2
    """
    return template_env.get_template(name).render(*args, **kwargs)


class AuthenticatedRequest(Request):
    """
    Request class that includes
    """

    user: User
    session: dict
    cert: Certificate

    def __init__(self, environ: EnvironDict, cert: Certificate):
        super().__init__(environ)
        self.cert = cert
        self.user = cert.user
        self.session = load_session(cert.user.user_id)

    def render_template(self, name: str, *args, **kwargs) -> str:
        kwargs["request"] = self
        text = render_template(name, *args, **kwargs)
        return text


class AriesApplication(JetforceApplication):
    def auth_route(self, path: str = ".*") -> typing.Callable[[RouteHandler], RouteHandler]:
        """
        Jetforce route decorator with an added authentication layer.
        """
        route_pattern = RoutePattern(path)

        def wrap(func: RouteHandler) -> RouteHandler:
            authenticated_func = authenticated_route(func)
            app.routes.append((route_pattern, authenticated_func))
            return func

        return wrap


def authenticated_route(func: RouteHandler) -> RouteHandler:
    """
    Wraps a route method to ensure that the request is authenticated.
    """

    def wrapped(request: Request, **kwargs) -> Response:
        if "REMOTE_USER" not in request.environ:
            msg = "Attach your client certificate to continue."
            return Response(Status.CLIENT_CERTIFICATE_REQUIRED, msg)

        if request.environ["TLS_CLIENT_AUTHORISED"]:
            # Old-style verified certificate
            serial_number = request.environ["TLS_CLIENT_SERIAL_NUMBER"]
            fingerprint = f"{serial_number:032X}"  # Convert to hex
        else:
            # New-style self signed certificate
            fingerprint = typing.cast(
                str, request.environ["TLS_CLIENT_HASH_B64"])

        cert = User.login(fingerprint)
        if cert is None:
            body = render_template(
                "register.gmi",
                request=request,
                fingerprint=fingerprint,
                cert=request.environ["client_certificate"],
            )
            return Response(Status.SUCCESS, "text/gemini", body)

        request = AuthenticatedRequest(request.environ, cert)
        response = func(request, **kwargs)
        return response

    return wrapped


app = AriesApplication()


@app.route("")
def index_page(request):
    body = render_template("index.gmi")
    return Response(Status.SUCCESS, "text/gemini", body)


@app.route("/star/(?P<star_id>.*)")
def star_view(request):
    body = render_template("star.gmi", star=star)
    return Response(Status.SUCCESS, "text/gemini", body)


@app.route("/user/(?P<user_id>.*)")
def user_timeline_view(request):
    body = render_template("star.gmi", user=user)
    return Response(Status.SUCCESS, "text/gemini", body)


@app.route("/app/new-user")
def register_new_user_view(request):
    if "REMOTE_USER" not in request.environ:
        msg = "Attach your client certificate to continue."
        return Response(Status.CLIENT_CERTIFICATE_REQUIRED, msg)

    fingerprint = request.environ["TLS_CLIENT_HASH_B64"]
    if Certificate.select().where(Certificate.fingerprint == fingerprint).exists():
        msg = "This certificate has already been linked to an account."
        return Response(Status.CERTIFICATE_NOT_AUTHORISED, msg)

    username = request.query
    if not username:
        msg = "Enter your desired username (US-ASCII characters only)"
        return Response(Status.INPUT, msg)

    if not username.isascii():
        msg = f"The username '{username}' contains invalid characters, try again"
        return Response(Status.INPUT, msg)

    if len(username) > 30:
        msg = f"The username '{username}' is too long, try again"
        return Response(Status.INPUT, msg)

    if User.select().where(User.username == username).exists():
        msg = f"the username '{username}' is already taken, try again"
        return Response(Status.INPUT, msg)

    rate_limit_resp = new_account_rate_limiter.check(request)
    if rate_limit_resp:
        return rate_limit_resp

    cert = request.environ["client_certificate"]

    user = User.create(username=username)
    Certificate.create(
        user=user,
        fingerprint=fingerprint,
        subject=cert.subject.rfc4514_string(),
        not_valid_before_utc=cert.not_valid_before,
        not_valid_after_utc=cert.not_valid_after,
    )

    return Response(Status.REDIRECT_TEMPORARY, "/app")


@app.auth_route("/app")
def app_view(request):
    now = datetime.now()
    body = request.render_template(
        "main_menu.gmi",  now=now
    )
    return Response(Status.SUCCESS, "text/gemini", body)
