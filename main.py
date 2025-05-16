"""
A simple authorization proxy for SLURM Rest API

It checks the incoming token (from Check-in) and maps it to a local user
either directly by using one of the available claims or by using
ALISE (https://github.com/m-team-kit/alise).
"""

import hashlib
from urllib.parse import quote_plus

import httpx
import jwt
from flask import Flask, abort, jsonify, make_response, request
from jwt.exceptions import DecodeError, PyJWTError

app = Flask(__name__)
app.config.from_mapping(
    # OIDC config discovery
    OPENID_CONFIG=(
        "https://aai.egi.eu/auth/realms/" "egi/.well-known/openid-configuration"
    ),
    # User name claim
    USERNAME_CLAIM="sub",
    # Alise endpoint, if all values defined,
    # it will be used for mapping users
    ALISE_URL="https://alise.data.kit.edu/",
    ALISE_API_KEY="",
    ALISE_TARGET="",
)
app.config.from_prefixed_env()

# get the OIDC configration
try:
    r = httpx.get(OPENID_CONFIG)
    config = r.json()
    app.config["JWKS_URI"] = config.get("jwks_uri", "")
    app.config["OIDC_ISSUER"] = config.get("issuer", "")
    app.config["USERINFO_ENDPOINT"] = config.get("userinfo_endpoint", "")
except httpx.RequestError as exc:
    app.logger.info("Unable to get oidc config")
    app.logger.debug(exc)

user_map_function = map_user
# figure out if we use ALISE
if all(app.config.get(v) for v in ["ALISE_URL", "ALISE_API_KEY", "ALISE_TARGET"]):
    user_map_function = map_user_alise


def get_user_info(access_token):
    try:
        r = httpx.get(
            app.config["USERINFO_ENDPOINT"],
            headers={
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/json",
            },
        )
        user = r.json()
    except httpx.RequestError as exc:
        # do not continue
        app.logger.info("Unable to get user info")
        app.logger.debug(exc)
        abort(401)
    return user


def map_user_alise(access_token):
    user = get_user_info(access_token)
    sub = user[app.config["USERNAME_CLAIM"]]

    hash_function = hashlib.sha1()
    hash_function.update(app.config["OIDC_ISSUER"].encode())
    hashed_issuer = hash_function.hexdigest()
    encoded_user = quote_plus(sub)

    url = (
        f"{app.config['ALISE_URL']}/target/{app.config['ALISE_TARGET']}"
        f"/mapping/issuer/{hashed_issuer}/user/{encoded_user}"
    )
    try:
        r = httpx.get(url, params={"apikey": app.config["ALISE_API_KEY"]})
        alise_user = r.json()
        app.logger.debug(alise_user)
    except httpx.RequestError as exc:
        # do not continue
        app.logger.info("Unable to get user mapping")
        app.logger.debug(exc)
        abort(401)
    try:
        return alise_user["internal"]["username"]
    except KeyError:
        abort(401)


def map_user(access_token):
    user = get_user_info(access_token)
    if app.config["USERNAME_CLAIM"] in user:
        return user[app.config["USERNAME_CLAIM"]]
    abort(401)


def validate_access_token(auth_header):
    if not auth_header:
        abort(401)
    split_header = auth_header.split()
    if len(split_header) != 2:
        abort(401)
    if split_header[0].lower() != "bearer":
        abort(401)
    access_token = split_header[1]
    jwks_client = jwt.PyJWKClient(app.config["JWKS_URI"])
    signing_key = jwks_client.get_signing_key_from_jwt(access_token)
    try:
        jwt.decode_complete(
            access_token,
            key=signing_key,
            algorithms=["RS256"],
        )
    except (PyJWTError, DecodeError) as e:
        # do not continue
        app.logger.info("Not a valid token")
        app.logger.debug(e)
        abort(401)
    return access_token


def get_slurm_token(slurm_user):
    app.logger.debug(f"Get token from /auth/slurm for {slurm_user}")
    with open("/auth/slurm") as f:
        return f.read().strip()


@app.route("/authorize")
def authorize():
    app.logger.debug("Authorization attemp")
    auth_header = request.headers.get("Authorization")
    app.logger.debug(f"Obtained headers: {auth_header}")
    access_token = validate_access_token(auth_header)
    app.logger.debug("Access token validated")
    response = make_response()
    slurm_user = map_user(access_token)
    app.logger.debug(f"Mapping user as {slurm_user}")
    response.headers["X-SLURM-USER-NAME"] = slurm_user
    response.headers["X-SLURM-USER-TOKEN"] = get_slurm_token(slurm_user)
    app.logger.debug("Headers: {response.headers}")
    return response
