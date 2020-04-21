# pylint: disable=unused-argument

import os
import sys
from pathlib import Path

import click

from .. import log
from ..rule import RuleLoader, RuleWorker


@click.option(
    "--rules",
    metavar="<RULES>",
    required=True,
    help="Rules specification containing regex parsing and messaging",
)
@click.option("--output-dir", required=True, help="Where to store results")
@click.option("--debug", is_flag=True)
@click.argument("tarball")
@click.command()
def cli(rules, output_dir, debug, tarball):
    """ Reads a tarball and applies the parser rules
    """
    output_p = Path(output_dir)
    if not output_p.exists():
        os.makedirs(str(output_p), exist_ok=True)

    rule_p = Path(rules)
    if not rule_p.exists():
        log.error(f"Unable to find rules: {rule_p}")
        sys.exit(1)

    tarball_p = Path(tarball)
    if not tarball_p.exists():
        log.error(f"Unable to read: {tarball_p}")
        sys.exit(1)

    worker = RuleWorker(
        rules=RuleLoader(rule_p).parse(), tarball=tarball_p, output=output_p
    )
    worker.extract()
    worker.build_file_list()
    worker.process()
    worker.cleanup()


def start():
    """
    Starts app
    """
    cli()
