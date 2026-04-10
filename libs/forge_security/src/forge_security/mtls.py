import ssl

def build_client_context(client_cert_pem: bytes, client_key_pem: bytes, ca_pem: bytes) -> ssl.SSLContext:
    import tempfile
    import os
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED

    with tempfile.NamedTemporaryFile(delete=False) as ca_f:
        ca_f.write(ca_pem)
    with tempfile.NamedTemporaryFile(delete=False) as cert_f:
        cert_f.write(client_cert_pem)
    with tempfile.NamedTemporaryFile(delete=False) as key_f:
        key_f.write(client_key_pem)

    ctx.load_verify_locations(cadata=ca_pem.decode('utf-8'))
    ctx.load_cert_chain(certfile=cert_f.name, keyfile=key_f.name)

    os.remove(ca_f.name)
    os.remove(cert_f.name)
    os.remove(key_f.name)
    return ctx

def build_server_context(server_cert_pem: bytes, server_key_pem: bytes, ca_pem: bytes) -> ssl.SSLContext:
    import tempfile
    import os
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.verify_mode = ssl.CERT_REQUIRED

    with tempfile.NamedTemporaryFile(delete=False) as ca_f:
        ca_f.write(ca_pem)
    with tempfile.NamedTemporaryFile(delete=False) as cert_f:
        cert_f.write(server_cert_pem)
    with tempfile.NamedTemporaryFile(delete=False) as key_f:
        key_f.write(server_key_pem)

    ctx.load_verify_locations(cadata=ca_pem.decode('utf-8'))
    ctx.load_cert_chain(certfile=cert_f.name, keyfile=key_f.name)

    os.remove(ca_f.name)
    os.remove(cert_f.name)
    os.remove(key_f.name)
    return ctx
