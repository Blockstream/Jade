import base64
import click
import functools


from jadepy.jade import JadeAPI


class JadeClient:
    def __init__(self, device='tcp:localhost:30121'):
        self.device = device

    def __enter__(self):
        self.jade = JadeAPI.create_serial(device=self.device)
        self.jade.connect()
        return self.jade

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.jade.disconnect()


def with_jade_client(f):
    @click.pass_context
    @functools.wraps(f)
    def new_func(ctx, *args, **kwargs):
        device = ctx.obj['DEVICE']
        with JadeClient(device=device) as jade:
            return f(jade, *args, **kwargs)
    return new_func


@click.group()
@click.option('--device', default='tcp:localhost:30121', help='Device address to connect to')
@click.pass_context
def cli(ctx, device):
    ctx.ensure_object(dict)
    ctx.obj['DEVICE'] = device


@cli.command()
@with_jade_client
def get_version_info(jade):
    version_info = jade.get_version_info()
    click.echo(version_info)


@cli.command()
@with_jade_client
def ping(jade):
    response = jade.ping()
    click.echo(response)


@cli.command()
@click.argument('psbt')
@click.option('--network', default='testnet')
@with_jade_client
def sign_psbt(jade, psbt, network):
    result = jade.sign_psbt(network, base64.b64decode(psbt))
    click.echo(base64.b64encode(result))


@cli.command()
@click.argument('tx')
@click.option('--network', default='testnet')
@with_jade_client
def sign_tx(jade, tx, network):
    result = jade.sign_tx(network, tx)
    click.echo(base64.b64encode(result))


if __name__ == "__main__":
    cli()
