import logging
import time
import uuid
import numpy as np
from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Optional, Any

from .persona_dna import PersonaGenome
from .idea_engine import GeneratedIdea, IdeaContext, generate_idea

logger = logging.getLogger(__name__)

try:
    from .brain_waves import BrainWave
    from .neuromodulation import NeuromodMethod
except ImportError:
    pass

@dataclass
class SimEvent:
    timestep: int
    event_type: str
    description: str

@dataclass
class PersonaState:
    persona_id: str
    wave_composition: Dict[str, float]
    region_activation: Dict[str, float]
    neurotransmitter_levels: Dict[str, float]
    cognitive_load: float
    stress_level: float
    creativity_level: float
    attention_level: float
    mood_valence: float
    mood_arousal: float
    energy: float
    ideas_buffer: List[str]

@dataclass
class Interaction:
    persona_a_id: str
    persona_b_id: str
    interaction_type: str
    intensity: float

@dataclass
class SimulationState:
    timestep: int
    persona_states: Dict[str, PersonaState]
    interactions: List[Interaction]
    ideas_generated: List[GeneratedIdea]
    events: List[SimEvent]

@dataclass
class SimulationConfig:
    personas: List[PersonaGenome]
    duration_seconds: float
    time_step_ms: float
    task_context: str
    neuromod_protocols: List[str]
    environmental_factors: Dict[str, float]
    seed: int

DATA_FLOW_TIMING = {
    "wave_update_ms": 10,
    "region_activation_ms": 50,
    "neurotransmitter_release_ms": 100,
    "cognitive_state_ms": 500,
    "idea_emergence_ms": 2000
}

def init_persona_state(persona: PersonaGenome) -> PersonaState:
    return PersonaState(
        persona_id=persona.genome_id,
        wave_composition=persona.brain_wave_profile.copy(),
        region_activation=persona.brain_region_weights.copy(),
        neurotransmitter_levels=persona.neurotransmitter_baseline.copy(),
        cognitive_load=0.1,
        stress_level=0.1,
        creativity_level=persona.creativity_index,
        attention_level=1.0,
        mood_valence=0.5,
        mood_arousal=0.5,
        energy=1.0,
        ideas_buffer=[]
    )

def step_simulation(state: SimulationState, config: SimulationConfig) -> SimulationState:
    """Advances the simulation by one timestep."""
    state.timestep += 1
    rng = np.random.RandomState(config.seed + state.timestep)
    
    # 1. Update environments
    for p_id, p_state in state.persona_states.items():
        p_state = apply_environmental_effects(p_state, config.environmental_factors)
        
        # 2. Waves -> Regions -> NTs
        p_state.wave_composition["gamma"] = rng.uniform(0, 1)
        p_state.neurotransmitter_levels["dopamine"] = max(0.0, min(1.0, p_state.neurotransmitter_levels.get("dopamine", 0.5) + rng.normal(0, 0.05)))
        
        # 3. Check for ideas
        genome = next((p for p in config.personas if p.genome_id == p_id), None)
        if genome and rng.rand() < 0.1: # 10% chance per step for demo
            idea = check_idea_emergence(p_state, genome, config.seed + state.timestep)
            if idea:
                state.ideas_generated.append(idea)
                state.events.append(SimEvent(state.timestep, "idea_generated", f"{p_id} generated an idea."))
    
    return state

def run_simulation(config: SimulationConfig) -> Dict[str, Any]:
    """Runs full brain simulation pipeline."""
    logger.info(f"Starting simulation for {len(config.personas)} personas.")
    
    # Init state
    state = SimulationState(
        timestep=0,
        persona_states={p.genome_id: init_persona_state(p) for p in config.personas},
        interactions=[],
        ideas_generated=[],
        events=[]
    )
    
    total_steps = int((config.duration_seconds * 1000) / config.time_step_ms)
    
    for _ in range(total_steps):
        state = step_simulation(state, config)
        
    return generate_simulation_report(state)

def check_idea_emergence(state: PersonaState, persona: PersonaGenome, seed: int) -> Optional[GeneratedIdea]:
    rng = np.random.RandomState(seed)
    if state.creativity_level * state.energy > rng.rand():
        ctx = IdeaContext("general", persona, state.wave_composition, [], [], [], 0.5, "day", "spring")
        return generate_idea(ctx, seed)
    return None

def apply_environmental_effects(state: PersonaState, environment: Dict[str, float]) -> PersonaState:
    noise = environment.get("noise", 0.0)
    state.stress_level = min(1.0, state.stress_level + noise * 0.01)
    state.attention_level = max(0.0, state.attention_level - noise * 0.01)
    return state

def persona_interaction(state_a: PersonaState, state_b: PersonaState, seed: int) -> Tuple[PersonaState, PersonaState, Optional[GeneratedIdea]]:
    state_a.mood_valence += 0.1
    state_b.mood_valence += 0.1
    return state_a, state_b, None

def log_simulation_step(state: SimulationState, log_path: str):
    with open(log_path, "a") as f:
        f.write(f"Step {state.timestep}: {len(state.ideas_generated)} ideas total\n")

def generate_simulation_report(state: SimulationState) -> Dict[str, Any]:
    return {
        "final_timestep": state.timestep,
        "total_ideas": len(state.ideas_generated),
        "total_events": len(state.events),
        "persona_end_states": {k: v.__dict__ for k, v in state.persona_states.items()}
    }

__all__ = [
    "SimulationConfig", "SimulationState", "PersonaState", "Interaction", "SimEvent",
    "run_simulation", "step_simulation", "check_idea_emergence", 
    "apply_environmental_effects", "persona_interaction", "log_simulation_step",
    "generate_simulation_report", "DATA_FLOW_TIMING"
]
