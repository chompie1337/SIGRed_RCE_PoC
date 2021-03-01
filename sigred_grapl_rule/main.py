from typing import Any

from grapl_analyzerlib.analyzer import Analyzer, OneOrMany
from grapl_analyzerlib.prelude import Not, AssetQuery, ProcessQuery, ProcessView
from grapl_analyzerlib.execution import ExecutionHit


class CmdChildOfDns(Analyzer):
    def get_queries(self) -> OneOrMany[ProcessQuery]:
        return (
            ProcessQuery()
            .with_process_name(eq='dns.exe')
            .with_children(
                ProcessQuery()
               .with_process_name(eq='cmd.exe')
               .with_process_name(eq='mshta.exe')
               .with_process_name(eq='rundll32.exe')
               .with_process_name(eq='conhost.exe')
               .with_process_name(eq='dnscmd.exe')
               .with_process_name(eq='werfault.exe')
            )
            .with_asset(AssetQuery().with_hostname())
        )
    def on_response(self, response: ProcessView, output: Any):
        hostname = response.get_asset().get_hostname()
        output.send(
            ExecutionHit(
                analyzer_name='CmdChildOfDns',
                node_view=response,
                risk_score=100,
                lenses=[('hostname', hostname)],
            )
        )