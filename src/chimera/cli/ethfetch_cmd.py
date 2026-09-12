"""chimera.cli — eth-fetch: read-only EVM JSON-RPC (EtherHiding triage)."""

from __future__ import annotations

import json

import click

from chimera.cli._root import main


@main.command("eth-fetch")
@click.option("--rpc", required=True, help="JSON-RPC endpoint URL.")
@click.option("--allow-network", is_flag=True, default=False,
              help="Required: actually make the live read-only request.")
@click.option("--tx", "tx_hash", default=None,
              help="Fetch this transaction's calldata (get_transaction mode).")
@click.option("--to", default=None, help="Contract address (eth_call mode).")
@click.option("--method", "method_id", default=None, help="4-byte selector, e.g. 0x5684cff5.")
@click.option("--type", "types", multiple=True, help="Param ABI type (repeatable), paired with --arg.")
@click.option("--arg", "args", multiple=True, help="Param value (repeatable), paired with --type.")
@click.option("--block", default="latest", help="Block tag/number (default latest).")
@click.option("--decode", "return_type", default=None, help="ABI type to decode the result as.")
def eth_fetch(rpc, allow_network, tx_hash, to, method_id, types, args, block,
              return_type):
    """Read live on-chain state: an eth_call, or a transaction's calldata.

    The gap `evm_tour` (offline) can't fill — reach the payload an EtherHiding
    dropper hides in a contract. Read-only, and it does nothing over the network
    unless --allow-network is given.

    \b
      chimera eth-fetch --rpc URL --to 0x.. --method 0x5684cff5 \\
          --type string --arg KEY_CHECK_VALUE --decode string --allow-network
      chimera eth-fetch --rpc URL --tx 0xabc... --allow-network
    """
    from chimera.dynamic.eth_rpc import eth_call, get_transaction
    if tx_hash:
        r = get_transaction(rpc, tx_hash, allow_network=allow_network)
    elif to and method_id:
        if len(types) != len(args):
            raise click.UsageError("each --type needs a matching --arg")
        try:
            blk = int(block, 0) if block not in ("latest", "earliest", "pending") else block
        except ValueError:
            blk = block
        r = eth_call(rpc, to, method_id, list(types), list(args), block=blk,
                     return_type=return_type, allow_network=allow_network)
    else:
        raise click.UsageError("give --tx, or --to and --method")
    if not r.get("ok"):
        raise click.ClickException(r.get("error", "request failed"))
    click.echo(json.dumps(r, indent=2))
