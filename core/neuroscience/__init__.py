"""
Neuroscience Simulation Engine for KFIOSA
=========================================

This package provides a comprehensive, bio-inspired cognitive simulation engine.
It includes:
- Persona DNA: Procedural generation of cognitive traits and personalities based on neurogenetic models.
- Idea Engine: Neuroscience-grounded idea generation influenced by brain state and genome.
- Simulation: Step-by-step simulation of persona cognition, environment interactions, and ideation.

Peer modules (`brain_waves.py`, `brain_map.py`, `neuromodulation.py`) optionally enhance the simulation 
with detailed biological constraints.
"""

from .persona_dna import (
    PersonaGenome, GeneTrait, generate_persona, crossover, mutate,
    batch_generate_population, persona_cognitive_profile
)
from .idea_engine import (
    GeneratedIdea, IdeaContext, generate_idea, batch_generate,
    idea_from_brain_state, cross_pollinate
)
from .simulation import (
    SimulationConfig, SimulationState, PersonaState, run_simulation,
    generate_simulation_report
)

def run_full_pipeline(num_personas: int, duration_sec: float, seed: int):
    """
    Convenience function that ties together the entire neuroscience pipeline:
    1. Generates personas
    2. Configures and runs the simulation
    3. Returns comprehensive results
    """
    import logging
    logger = logging.getLogger(__name__)
    logger.info("Initializing full neuroscience pipeline...")
    
    # 1. Generate diverse personas
    personas = batch_generate_population(n=num_personas, diversity_factor=0.8, seed=seed)
    
    # 2. Set up brain simulation
    config = SimulationConfig(
        personas=personas,
        duration_seconds=duration_sec,
        time_step_ms=100.0,
        task_context="creative_brainstorming",
        neuromod_protocols=["focus_enhancement"],
        environmental_factors={"noise": 0.2, "light": 0.8},
        seed=seed
    )
    
    # 3 & 4 & 5. Run simulation (handles neuromodulation and idea collection internally)
    result = run_simulation(config)
    
    # 6. Evaluate ideas (basic aggregation)
    ideas_generated = result.get("total_ideas", 0)
    logger.info(f"Pipeline complete. Generated {ideas_generated} ideas.")
    
    return result

__all__ = [
    "PersonaGenome", "GeneTrait", "generate_persona", "crossover", "mutate",
    "batch_generate_population", "persona_cognitive_profile",
    "GeneratedIdea", "IdeaContext", "generate_idea", "batch_generate",
    "idea_from_brain_state", "cross_pollinate",
    "SimulationConfig", "SimulationState", "PersonaState", "run_simulation",
    "generate_simulation_report",
    "run_full_pipeline"
]
