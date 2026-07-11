from typing import List

from ..threat_intel_providers import VirusTotalProvider, BaseThreatIntelProvider


def get_default_registry() -> List[BaseThreatIntelProvider]:
    """Return the default list of provider instances for the engine.

    Currently only VirusTotalProvider is enabled for this milestone.
    """
    return [VirusTotalProvider()]
