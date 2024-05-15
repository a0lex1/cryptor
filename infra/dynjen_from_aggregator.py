from c2.infra.cli_config_aggregator import CLIConfigAggregator
from c2.infra.dyn_jen import DynJen


def dynjen_from_aggregator(agr:CLIConfigAggregator, conf_id:str):
  return DynJen(agr.config(conf_id), agr.get_jen_order(conf_id), agr.get_jen_itergen_class(conf_id),
                  agr.is_reverse_jen(conf_id))

