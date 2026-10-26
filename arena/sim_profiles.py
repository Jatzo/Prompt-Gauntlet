"""Simulated-model profiles for mock measurements, each with known answers.

- clean: the detector separates attacks from benign text well, and the strong target obeys a
  visible injection a third of the time, so the baseline-ASR gate passes on rung 0.
- low_asr: the strong target almost never obeys, so the gate must walk to rung 1.
"""

from dataclasses import dataclass

from arena.detector.sim import detector_policy
from arena.simulated import SimulatedBackend
from arena.target.sim import target_policy
from arena.target.world import ATTACKER_ADDRESS


@dataclass(frozen=True)
class SimProfile:
    attack_mean: float
    benign_mean: float
    spread: float
    obey_strong: float
    obey_weak: float
    complete: float


PROFILES = {
    "clean": SimProfile(78.0, 22.0, 12.0, obey_strong=0.35, obey_weak=0.5, complete=0.9),
    "low_asr": SimProfile(78.0, 22.0, 12.0, obey_strong=0.05, obey_weak=0.35, complete=0.9),
}


def simulated_backend(profile: str, seed: int) -> SimulatedBackend:
    chosen = PROFILES[profile]

    def is_attack(text: str) -> bool:
        return ATTACKER_ADDRESS in text

    return SimulatedBackend(
        {
            "detector": detector_policy(
                is_attack, chosen.attack_mean, chosen.benign_mean, chosen.spread
            ),
            "target_strong": target_policy(chosen.obey_strong, chosen.complete, seed),
            "target_weak": target_policy(chosen.obey_weak, chosen.complete, seed),
        },
        seed=seed,
        name=f"simulated-{profile}",
    )
