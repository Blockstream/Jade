#!/usr/bin/env python

import base64
import json
import click
import functools
import logging
import os
import sys
import time

from jadepy.jade import JadeAPI


def h2b(hexdata):
    if hexdata is None or isinstance(hexdata, (int, bool)):
        return hexdata
    if isinstance(hexdata, list):
        return list(map(h2b, hexdata))
    if isinstance(hexdata, dict):
        return {k: h2b(v) for k, v in hexdata.items()}
    return bytes.fromhex(hexdata)


def b2h_impl(obj, leaf_fn):
    if isinstance(obj, dict):
        return {k: b2h_impl(v, leaf_fn) for k, v in obj.items()}
    if isinstance(obj, list):
        return [b2h_impl(v, leaf_fn) for v in obj]
    if isinstance(obj, tuple):
        return tuple(b2h_impl(v, leaf_fn) for v in obj)
    return leaf_fn(obj)


def b2h(result):
    return b2h_impl(
        result,
        lambda v: bytes(v).hex() if isinstance(v, (bytes, bytearray)) else v
    )


class JadeClient:
    def __init__(self, device='tcp:localhost:30121'):
        self.device = device

    def __enter__(self):
        if self.device == 'libjade':
            self.jade = JadeAPI.create_libjade()
        else:
            self.jade = JadeAPI.create_serial(device=self.device)
        self.jade.connect()
        self.jade.add_entropy(os.urandom(32))
        return self.jade

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.jade.disconnect()


def with_jade_client(f):
    @click.pass_context
    @functools.wraps(f)
    def new_func(ctx, *args, **kwargs):
        device = ctx.obj['DEVICE']
        auth_network = kwargs.get('network') or ctx.obj.get('NETWORK')
        with JadeClient(device=device) as jade:
            if auth_network:
                jade.auth_user(auth_network)
            return f(jade, *args, **kwargs)
    return new_func


# bip32 path - "m/1'/2'/3/4" -> [ 2147483649, 2147483650, 3, 4 ]
class Bip32PathParamType(click.ParamType):
    name = "bip32 path"

    HARDENED_BIT = 0x80000000

    @classmethod
    def to_path_element(cls, s):
        if s[-1] in ["'", "h", "H"]:
            return int(s[:-1]) | cls.HARDENED_BIT
        return int(s)

    def convert(self, value, param, ctx):
        try:
            if value[0] not in ["m", "M"] or value[1] != '/':
                raise ValueError('bad prefix')

            return [self.to_path_element(s) for s in value[2:].split('/')]

        except (ValueError, IndexError):
            self.fail(f"{value!r} is not a valid bip32 path", param, ctx)


@click.group()
@click.option('--verbose', '-v', is_flag=True)
@click.option('--device', default='tcp:localhost:30121', help='Device address to connect to')
@click.pass_context
def cli(ctx, verbose, device):
    ctx.ensure_object(dict)
    ctx.obj['DEVICE'] = device

    if verbose:
        logging.basicConfig(level=logging.INFO)


# DEBUG

@cli.command()
@with_jade_client
def selfcheck(jade):
    response = jade.run_remote_selfcheck()
    click.echo(response)


# INFO

@cli.command()
@with_jade_client
def ping(jade):
    response = jade.ping()
    click.echo(response)


@cli.command()
@with_jade_client
def get_version_info(jade):
    version_info = jade.get_version_info()
    click.echo(version_info)


@cli.command()
@with_jade_client
@click.argument('epoch', type=int, default=int(time.time()))
def set_epoch(jade, epoch):
    response = jade.set_epoch(epoch)
    click.echo(response)


# PINSERVER

@cli.command()
@click.option('--only', type=click.Choice(['certificate', 'details']), required=False)
@with_jade_client
def reset_pinserver(jade, only):
    reset_details = (only != 'certificate')
    reset_certificate = (only != 'details')
    response = jade.reset_pinserver(reset_details, reset_certificate)
    click.echo(response)


@cli.command()
@click.argument('url')
@click.argument('alt_url', required=False)
@click.option('--pubkey', type=click.File('rb'), required=False)
@click.option('--certificate', type=click.File('r'), required=False)
@with_jade_client
def set_pinserver(jade, url, alt_url, pubkey, certificate):
    if pubkey:
        pubkey = pubkey.read()
    if certificate:
        certificate = certificate.read()
    response = jade.set_pinserver(url, alt_url, pubkey, certificate)
    click.echo(response)


# ID

@cli.command()
@click.argument('path', type=Bip32PathParamType())
@click.option('--network', default='testnet')
@with_jade_client
def get_xpub(jade, path, network):
    xpub = jade.get_xpub(network, path)
    click.echo(xpub)


@cli.command()
@click.argument('path', type=Bip32PathParamType())
@click.argument('message')
@click.option('--network')
@with_jade_client
def sign_message(jade, path, message, network):
    b64sig = jade.sign_message(path, message)
    click.echo(b64sig)


# TX / PSBT

@cli.command()
@click.argument('tx')
@click.argument('inputs')
@click.argument('change')
@click.option('--network', default='testnet')
@with_jade_client
def sign_tx(jade, tx, inputs, change, network):
    tx_bytes = bytes.fromhex(tx)
    inputs_obj = h2b(json.loads(inputs))
    change_obj = h2b(json.loads(change))
    result = jade.sign_tx(network, tx_bytes, inputs_obj, change_obj)
    click.echo(json.dumps(b2h(result)))


@cli.command()
@click.argument('psbt')
@click.option('--network', default='testnet')
@with_jade_client
def sign_psbt(jade, psbt, network):
    result = jade.sign_psbt(network, base64.b64decode(psbt))
    click.echo(base64.b64encode(result))


# OTP

@cli.command()
@click.argument('name')
@click.argument('uri')
@click.option('--network', required=False)
@with_jade_client
def register_otp(jade, name, uri, network):
    result = jade.register_otp(name, uri)
    click.echo(result)


@cli.command()
@click.argument('name')
@click.option('--network', required=False)
@with_jade_client
def get_otp_code(jade, name, network):
    result = jade.get_otp_code(name)
    click.echo(result)


# UTILITY/DEBUG

@cli.command()
@click.argument('filename')
@click.option('--check_qr', type=bool, default=False)
@with_jade_client
def capture_image_data(jade, filename, check_qr):
    # NOTE: Requires a DEBUG firmware with CONFIG_RETURN_CAMERA_IMAGES
    # enabled. Used for generating test case .dat image files.
    result = jade.capture_image_data(check_qr)
    with open(filename, 'wb') as f:
        f.write(result)
        click.echo(f'Image data written to {filename}')


if __name__ == "__main__":
    cli()
