# coding: utf-8

import getpass
import sys
import argparse
import os.path
import logging

from jinja2 import Environment, FileSystemLoader, select_autoescape

from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.x509.oid import NameOID


logger = logging.getLogger(__name__)

def make_config(preambule, pkcs12_fn, output_dir, tls_auth_key_fn = None):

    env = Environment(loader=FileSystemLoader("templates"),
        autoescape=select_autoescape(),
        trim_blocks = True,
        lstrip_blocks = True)
    template = env.get_template("ovpn")


    password = getpass.getpass("File password: ")
    with open(pkcs12_fn, "rb") as f:
        r = pkcs12.load_key_and_certificates(f.read(), password.encode("utf8"))


    key, cert, ca_chain = r
    
    key_pem = key.private_bytes(encoding=Encoding.PEM, format=PrivateFormat.PKCS8, encryption_algorithm=NoEncryption())
    cert_pem = cert.public_bytes(Encoding.PEM)
    ca_pems = list(map(lambda x: x.public_bytes(Encoding.PEM), ca_chain))

    ca_pems = list(map(lambda x: x.decode("ascii").strip(), ca_pems))
    key_pem, cert_pem = list(map(lambda x: x.decode("ascii").strip(), (key_pem, cert_pem)))

    tls_auth_pem = None
    with open(tls_auth_key_fn, "r") as ta_key:
        tls_auth_pem = ta_key.read().strip()


    cns = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if len(cns) == 0:
        logger.fatal("No common name found. Can't build config file")
        return

    cn = cns[0]
    if len(cns) > 1:
        logger.warning("More than one common name was found: %s. Using the first one", repr(cns))
    
    
    out_fn = "%s.ovpn" % (cn.value,)

    output_fn = os.path.join(output_dir, out_fn)

    if os.path.exists(output_fn):
        logger.fatal("Configuration exists already. Stopping")
        return

    with open(output_fn, "w") as out:
        out.write(preambule)
        out.write(template.render(key_pem=key_pem, ca_pems = ca_pems, cert_pem = cert_pem, tls_auth_pem = tls_auth_pem))


def make_for_profile(profile_name, client_certificate_fn):
    BASE = "_private"
    preambule_fn = os.path.join(BASE, profile_name)
    if not os.path.exists(preambule_fn):
        logger.fatal("No profile %s found", preambule_fn)
        return
        
    tls_auth_key_fn = os.path.join(BASE, "%s_ta.key" % (profile_name,))
    if not os.path.exists(tls_auth_key_fn):
        logger.warning("TLS authentication key won't be used, because it wasn't found under %s", tls_auth_key_fn)
        tls_auth_key_fn = None

    preambule = ""
    with open(preambule_fn, "r") as pf:
        preambule = pf.read()


    make_config(preambule, client_certificate_fn, BASE, tls_auth_key_fn)

if __name__ == "__main__":
    parser = argparse.ArgumentParser("build_config", description="Builds OpenVPN config")
    parser.add_argument("profile")
    parser.add_argument("client_certificate")
    #parser.add_argument("output")
    args = parser.parse_args()

    print (args)
    make_for_profile(args.profile, args.client_certificate)
