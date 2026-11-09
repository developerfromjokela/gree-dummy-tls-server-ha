#!/usr/bin/env python3

import asyncio
import base64
import json
import logging
import os
import prometheus_client
import signal
import ssl
import sys
import time
from Crypto.Cipher import AES

logging.basicConfig(
    level=os.environ.get('LOG_LEVEL', 'INFO').upper(),
    format="%(asctime)s.%(msecs)03d %(levelname)-8s %(message)s",
    datefmt='%Y-%m-%d %H:%M:%S',
)

LOGGER = logging.getLogger(__name__)

DEFAULT_KEY = b'a3K8Bx%2r8Y7#xDh'

DEVICES = {}

# Prometheus metrics
GAUGE_OPEN_CONNECTIONS = prometheus_client.Gauge("gree_open_connections", "Current open connections", ["type"])
GAUGE_LAST_HEARTBEAT = prometheus_client.Gauge("gree_last_heartbeat", "Time since the last heartbeat, in seconds", ["mac"])

async def handle_connection(reader, writer):
    is_tls = writer.get_extra_info('cipher') != None
    peername = writer.get_extra_info('peername')
    LOGGER.debug(f"Connected with {peername}, tls={is_tls}")

    gauge_connection = GAUGE_OPEN_CONNECTIONS.labels(type=("tls" if is_tls else "tcp"))
    gauge_connection.inc()

    try:
        keepalive = True

        while keepalive:
            LOGGER.debug("Reading message")
            data = await reader.readline()
            if not data:
                LOGGER.warning("Got no data")
                return

            message = data.decode().strip()
            LOGGER.debug(f"Received: {message}")
            jsn = json.loads(message)

            encrypted = False

            if jsn["t"] == "pack":
                encrypted = True
                if jsn["i"] == 1:
                    cipher = AES.new(DEFAULT_KEY, AES.MODE_ECB)
                else:
                    LOGGER.error("No bind key")
                    keepalive = False
                    return
                decrypted = cipher.decrypt(base64.b64decode(jsn["pack"])).decode()
                decrypted = decrypted.replace(decrypted[decrypted.rindex('}') + 1:], '')
                LOGGER.debug(f"Decrypted: {decrypted}")
                jsn = json.loads(decrypted)

            match jsn["t"]:
                case "dis":
                    external_port = int(os.getenv("LISTEN_PORT_TLS", 1813) if is_tls else os.getenv("LISTEN_PORT_TCP", 5000))
                    ret = {
                        "t": "svr",
                        "ip": os.getenv("EXTERNAL_IP"),
                        "ip2": os.getenv("EXTERNAL_IP"),
                        "Ip3": os.getenv("EXTERNAL_IP"),
                        "host": os.getenv("DOMAIN_NAME"),
                        "udpPort": external_port,
                        "tcpPort": external_port,
                        "protocol": "" if is_tls else "TCP",
                        "datHost": "",
                        "datHostPort": 0,
                    }
                    encrypted = True
                    keepalive = False

                case "devLogin":
                    m = jsn["mac"]
                    sorted_mac = m[8:10] + m[14:16] + m[2:4] + m[10:12] + m[4:6] + m[0:2]
                    ret = {
                        "t": "loginRes",
                        "r": 200,
                        "cid": sorted_mac,
                        "uid": 0
                    }

                case "tm":
                    ret = {
                        "t": "tm",
                        "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                    }

                case "hb":
                    mac = jsn["cid"]
                    if mac not in DEVICES:
                        DEVICES[mac] = {}
                    if "last_heartbeat" not in DEVICES[mac]:
                        GAUGE_LAST_HEARTBEAT.labels(mac=mac).set_function(lambda: time.time() - DEVICES[mac]["last_heartbeat"])
                    DEVICES[mac]["last_heartbeat"] = time.time()

                    ret = {
                        "t": "hbok",
                    }

                case _:
                    LOGGER.warning(f"Unknown request type {jsn['t']}")
                    keepalive = False
                    ret = None

            if ret is not None:
                plain_json = json.dumps(ret, separators=(',', ':'))
                LOGGER.debug(f"Plaintext response: {plain_json}")

                if encrypted and ret["t"] != "pack":
                    cipher = AES.new(DEFAULT_KEY, AES.MODE_ECB)
                    def padded(txt):
                        return txt + (16 - len(txt) % 16) * chr(16 - len(txt) % 16)

                    if jsn["t"] == "dis":
                        tcid = jsn["mac"]
                    else:
                        tcid = ""

                    ret = {
                        "t": "pack",
                        "i": 1,
                        "uid": 0,
                        "cid": "",
                        "tcid": tcid,
                        "pack": base64.b64encode(cipher.encrypt(padded(plain_json).encode())).decode()
                    }

                    encrypted_json = json.dumps(ret, separators=(',', ':'))
                    LOGGER.debug(f"Encrypted response: {encrypted_json}")
                    response_json = encrypted_json
                else:
                    response_json = plain_json

                writer.write((response_json + "\n").encode())
                await writer.drain()
    except Exception:
        LOGGER.exception("Failed to handle connection")
    finally:
        LOGGER.debug(f"Closing connection")
        writer.close()
        await writer.wait_closed()
        gauge_connection.dec()


async def shutdown(servers, prometheus, signal=None):
    if signal:
        LOGGER.info(f"Received exit signal {signal.name}")

    # We need to cancel all tasks when shutting down, otherwise the
    # connections block the server indefinitely.
    all_tasks = asyncio.all_tasks()
    LOGGER.info(f"Cancelling {len(all_tasks) - 1} tasks")
    for task in all_tasks:
        if task != asyncio.current_task():
            task.cancel()

    LOGGER.info(f"Closing {len(servers)} servers")
    for server in servers:
        server.close()
        await server.wait_closed()

    if prometheus is not None:
        LOGGER.info(f"Stopping prometheus")
        prometheus[0].shutdown()
        prometheus[1].join()

    LOGGER.info("Shutdown successful")


def create_ssl_context():
    PATH_CERT = "/keys/selfsigned.crt"
    PATH_PRIVATE_KEY = "/keys/private.key"

    if not os.path.isfile(PATH_CERT) or not os.path.isfile(PATH_PRIVATE_KEY):
        LOGGER.info("Generating self-signed certificate")

        from OpenSSL import crypto

        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, 2048)

        cert = crypto.X509()
        cert.get_subject().C = "XX"
        cert.get_subject().ST = "stateOrProvinceName"
        cert.get_subject().L = "localityName"
        cert.get_subject().O = "organizationName"
        cert.get_subject().OU = "organizationUnitName"
        cert.get_subject().CN = "commonName"
        cert.get_subject().emailAddress = "emailAddress"
        cert.set_serial_number(0)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(k)
        cert.sign(k, 'sha512')

        with open(PATH_CERT, "wt") as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8"))
        with open(PATH_PRIVATE_KEY, "wt") as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k).decode("utf-8"))

    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context.load_cert_chain(certfile=PATH_CERT, keyfile=PATH_PRIVATE_KEY)
    ssl_context.set_ciphers("ALL:@SECLEVEL=0")

    return ssl_context


async def main():
    if os.getenv("DOMAIN_NAME") is None:
        LOGGER.error("DOMAIN_NAME environment variable not set")
        os.sys.exit(1)

    if os.getenv("EXTERNAL_IP") is None:
        LOGGER.error("EXTERNAL_IP environment variable not set")
        os.sys.exit(1)

    server_tls = await asyncio.start_server(
        handle_connection,
        os.getenv("LISTEN_ADDR", "0.0.0.0"),
        int(os.getenv("LISTEN_PORT_TLS", "1813")),
        ssl=create_ssl_context()
    )
    server_tcp = await asyncio.start_server(
        handle_connection,
        os.getenv("LISTEN_ADDR", "0.0.0.0"),
        int(os.getenv("LISTEN_PORT_TCP", "5000"))
    )

    addrs = ", ".join(str(sock.getsockname()) for sock in server_tls.sockets)
    LOGGER.info(f"Listening for tls on {addrs}")
    addrs = ", ".join(str(sock.getsockname()) for sock in server_tcp.sockets)
    LOGGER.info(f"Listening for tcp on {addrs}")

    prometheus_port = os.getenv("LISTEN_PORT_PROMETHEUS")
    if prometheus_port is not None:
        prometheus = prometheus_client.start_http_server(int(os.getenv("LISTEN_PORT_PROMETHEUS", "9090")))
        addrs = prometheus[0].socket.getsockname()
        LOGGER.info(f"Listening for prometheus on {addrs}")
    else:
        prometheus = None

    loop = asyncio.get_running_loop()
    for sig in [signal.SIGINT, signal.SIGTERM]:
        loop.add_signal_handler(sig, lambda: asyncio.create_task(shutdown([server_tcp, server_tls], prometheus, sig)))

    async with server_tls, server_tcp:
        try:
            await asyncio.gather(
                server_tls.serve_forever(),
                server_tcp.serve_forever()
            )
        except asyncio.CancelledError:
            pass


if __name__ == "__main__":
    asyncio.run(main())
