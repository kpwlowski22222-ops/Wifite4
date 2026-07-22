#!/usr/bin/env python3
"""
KFIOSA Neuroscience Simulation Module: DNA/RNA Persona Generator
================================================================
Generates unique cognitive personas using a bio-inspired genome model.
Each persona has a cognitive DNA composed of gene loci that interact via
epistasis to produce emergent personality traits, cognitive strengths,
and brain-state profiles.

Deterministic when given a seed; supports mutation, crossover, and aging.
"""

import uuid
import hashlib
import logging
import copy
import math
from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Optional, Any

import numpy as np

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional peer-module imports (fail gracefully for independent testing)
# ---------------------------------------------------------------------------
_HAVE_WAVES = False
_HAVE_MAP = False
try:
    from .brain_waves import BRAIN_WAVE_CATALOG
    _HAVE_WAVES = True
except ImportError:
    pass
try:
    from .brain_map import BRAIN_REGION_CATALOG
    _HAVE_MAP = True
except ImportError:
    pass

# ---------------------------------------------------------------------------
# Constants — procedural name generation syllables
# ---------------------------------------------------------------------------
_PREFIXES = [
    "Aer", "Bal", "Cor", "Dex", "Elo", "Fen", "Gal", "Hel", "Iri", "Jax",
    "Kal", "Lun", "Mir", "Nox", "Ori", "Pax", "Qor", "Rex", "Sol", "Tal",
    "Umi", "Vex", "Wyn", "Xan", "Yel", "Zen", "Ash", "Bre", "Cyr", "Dor",
]
_SUFFIXES = [
    "an", "ia", "us", "el", "is", "on", "ar", "ix", "en", "or",
    "al", "yn", "ex", "os", "um", "ik", "as", "et", "ir", "ok",
    "ith", "ane", "iel", "ous", "een", "ard", "esh", "ova", "ulo", "ent",
]

# ---------------------------------------------------------------------------
# Core data structures
# ---------------------------------------------------------------------------

@dataclass
class GeneTrait:
    """A single gene locus controlling a cognitive/behavioral trait.

    Attributes:
        locus:              Identifier (inspired by real gene names).
        allele_a, allele_b: Two allele values in [0, 1].
        dominance:          Which allele dominates (0 = B dominant, 1 = A).
        expression_modifier: Scales the phenotypic effect.
        epistasis_targets:  Other loci this gene interacts with.
        mutation_rate:      Per-generation mutation probability.
        trait_description:  Human-readable trait controlled.
        trait_category:     Grouping: cognitive, emotional, social, creative,
                            analytical, physical, spiritual.
    """
    locus: str
    allele_a: float
    allele_b: float
    dominance: float
    expression_modifier: float
    epistasis_targets: List[str]
    mutation_rate: float
    trait_description: str = ""
    trait_category: str = "cognitive"


@dataclass
class PersonaGenome:
    """Complete cognitive DNA/RNA of a persona.

    The genome drives brain-wave profile, neurotransmitter baseline, Big Five
    personality, and cognitive indices — all derived deterministically from the
    DNA sequence via ``express_genome()``.
    """
    genome_id: str
    name: str
    dna_sequence: List[GeneTrait]
    # RNA expression — current levels (0-1) that modulate real-time behavior
    rna_expression: Dict[str, float] = field(default_factory=dict)
    # Baseline power for each wave type (keyed by wave name)
    brain_wave_profile: Dict[str, float] = field(default_factory=dict)
    # Relative development of each brain region
    brain_region_weights: Dict[str, float] = field(default_factory=dict)
    # Baseline NT levels
    neurotransmitter_baseline: Dict[str, float] = field(default_factory=dict)
    # Big Five OCEAN scores
    personality_big5: Dict[str, float] = field(default_factory=dict)
    cognitive_strengths: List[str] = field(default_factory=list)
    cognitive_weaknesses: List[str] = field(default_factory=list)
    creativity_index: float = 0.5
    analytical_index: float = 0.5
    emotional_intelligence: float = 0.5
    stress_resilience: float = 0.5
    age_factor: float = 30.0
    learning_rate: float = 0.5
    memory_capacity: float = 7.0       # working-memory slots equiv.
    attention_span_seconds: float = 600.0


# ---------------------------------------------------------------------------
# Gene catalog — 24 loci spanning all trait categories
# ---------------------------------------------------------------------------

GENE_CATALOG: Dict[str, GeneTrait] = {
    # -- Cognitive --
    "DRD4":    GeneTrait("DRD4",    0.5, 0.5, 0.5, 1.0, ["COMT", "DAT1"],  0.015,
                         "Novelty seeking / exploration", "cognitive"),
    "COMT":    GeneTrait("COMT",    0.5, 0.5, 0.5, 1.0, ["DRD4", "BDNF"],  0.010,
                         "Cognitive flexibility vs stability (Val/Met)", "cognitive"),
    "CHRNA4":  GeneTrait("CHRNA4",  0.5, 0.5, 0.5, 1.0, ["CHRNA7"],        0.008,
                         "Sustained attention (nicotinic receptor)", "cognitive"),
    "CHRNA7":  GeneTrait("CHRNA7",  0.5, 0.5, 0.5, 1.0, ["CHRNA4"],        0.008,
                         "Sensory gating / auditory filtering", "cognitive"),
    "KIBRA":   GeneTrait("KIBRA",   0.5, 0.5, 0.5, 1.0, ["BDNF", "APOE"],  0.012,
                         "Episodic memory performance", "cognitive"),
    "APOE":    GeneTrait("APOE",    0.5, 0.5, 0.5, 1.0, ["KIBRA"],         0.005,
                         "Long-term memory / neuroprotection", "cognitive"),
    # -- Emotional --
    "5HTTLPR": GeneTrait("5HTTLPR", 0.5, 0.5, 0.5, 1.0, ["BDNF", "FKBP5"], 0.012,
                         "Emotional regulation (serotonin transporter)", "emotional"),
    "FKBP5":   GeneTrait("FKBP5",  0.5, 0.5, 0.5, 1.0, ["5HTTLPR", "NR3C1"], 0.010,
                         "Stress response / cortisol sensitivity", "emotional"),
    "NR3C1":   GeneTrait("NR3C1",  0.5, 0.5, 0.5, 1.0, ["FKBP5"],         0.010,
                         "Glucocorticoid receptor — HPA axis", "emotional"),
    "MAOA":    GeneTrait("MAOA",   0.5, 0.5, 0.5, 1.0, ["SLC6A4"],         0.010,
                         "Monoamine oxidase — aggression / impulsivity", "emotional"),
    # -- Social --
    "OXTR":    GeneTrait("OXTR",   0.5, 0.5, 0.5, 1.0, ["AVPR1A"],         0.010,
                         "Oxytocin receptor — empathy / bonding", "social"),
    "AVPR1A":  GeneTrait("AVPR1A", 0.5, 0.5, 0.5, 1.0, ["OXTR"],          0.010,
                         "Vasopressin receptor — social behavior", "social"),
    "SLC6A4":  GeneTrait("SLC6A4", 0.5, 0.5, 0.5, 1.0, ["MAOA", "5HTTLPR"], 0.012,
                         "Serotonin transport — mood / sociability", "social"),
    # -- Creative --
    "BDNF":    GeneTrait("BDNF",   0.5, 0.5, 0.5, 1.0, ["5HTTLPR", "COMT"], 0.012,
                         "Brain-derived neurotrophic factor — plasticity", "creative"),
    "TNIK":    GeneTrait("TNIK",   0.5, 0.5, 0.5, 1.0, ["BDNF"],          0.010,
                         "Synaptic plasticity / creative divergence", "creative"),
    "SNAP25":  GeneTrait("SNAP25", 0.5, 0.5, 0.5, 1.0, ["TNIK", "DRD4"],  0.010,
                         "Synaptosomal protein — creative insight", "creative"),
    # -- Analytical --
    "DAT1":    GeneTrait("DAT1",   0.5, 0.5, 0.5, 1.0, ["DRD4", "COMT"],  0.010,
                         "Dopamine transporter — analytical precision", "analytical"),
    "DISC1":   GeneTrait("DISC1",  0.5, 0.5, 0.5, 1.0, ["PDE4B"],         0.008,
                         "Disrupted in schizophrenia — abstract reasoning", "analytical"),
    "PDE4B":   GeneTrait("PDE4B",  0.5, 0.5, 0.5, 1.0, ["DISC1"],         0.008,
                         "Phosphodiesterase — logical processing", "analytical"),
    # -- Physical --
    "CLOCK":   GeneTrait("CLOCK",  0.5, 0.5, 0.5, 1.0, ["PER2"],          0.010,
                         "Circadian rhythm — chronotype (morningness)", "physical"),
    "PER2":    GeneTrait("PER2",   0.5, 0.5, 0.5, 1.0, ["CLOCK"],         0.010,
                         "Period gene — sleep/wake timing", "physical"),
    "CACNA1C": GeneTrait("CACNA1C", 0.5, 0.5, 0.5, 1.0, ["BDNF"],        0.008,
                         "Calcium channel — neural excitability", "physical"),
    # -- Spiritual / Meta-cognitive --
    "VMAT2":   GeneTrait("VMAT2",  0.5, 0.5, 0.5, 1.0, ["5HTTLPR"],       0.008,
                         "Vesicular monoamine transporter — self-transcendence", "spiritual"),
    "HTR2A":   GeneTrait("HTR2A",  0.5, 0.5, 0.5, 1.0, ["5HTTLPR", "VMAT2"], 0.010,
                         "Serotonin 2A receptor — introspection / mystical", "spiritual"),
}

# ---------------------------------------------------------------------------
# Cognitive strength/weakness labels keyed by dominant trait
# ---------------------------------------------------------------------------
_STRENGTH_MAP: Dict[str, List[str]] = {
    "cognitive":   ["Pattern recognition", "Rapid learning", "Working memory", "Abstract reasoning"],
    "emotional":   ["Emotional resilience", "Self-awareness", "Empathic accuracy", "Mood stability"],
    "social":      ["Collaborative leadership", "Persuasion", "Conflict resolution", "Active listening"],
    "creative":    ["Divergent thinking", "Artistic vision", "Lateral association", "Improvisation"],
    "analytical":  ["Logical deduction", "Data synthesis", "Strategic planning", "Precision focus"],
    "physical":    ["Circadian optimization", "Endurance focus", "Motor coordination", "Body awareness"],
    "spiritual":   ["Mindfulness depth", "Intuitive insight", "Flow-state access", "Meta-cognition"],
}
_WEAKNESS_MAP: Dict[str, List[str]] = {
    "cognitive":   ["Information overload", "Analysis paralysis"],
    "emotional":   ["Emotional flooding", "Anxiety sensitivity"],
    "social":      ["Social fatigue", "Over-accommodation"],
    "creative":    ["Distractibility", "Completion difficulty"],
    "analytical":  ["Rigid thinking", "Over-rationalization"],
    "physical":    ["Circadian disruption sensitivity", "Stimulus overload"],
    "spiritual":   ["Detachment tendency", "Reality dissociation"],
}

# Neurotransmitter labels
_NT_NAMES = [
    "dopamine", "serotonin", "GABA", "glutamate", "acetylcholine",
    "norepinephrine", "endorphins", "oxytocin", "melatonin",
    "anandamide", "histamine", "substance_P",
]


# ---------------------------------------------------------------------------
# Procedural name generator
# ---------------------------------------------------------------------------
def _generate_name(rng: np.random.RandomState) -> str:
    """Produce a pronounceable procedural name."""
    prefix = _PREFIXES[rng.randint(0, len(_PREFIXES))]
    suffix = _SUFFIXES[rng.randint(0, len(_SUFFIXES))]
    return f"{prefix}{suffix}"


# ---------------------------------------------------------------------------
# Expression logic — genotype → phenotype
# ---------------------------------------------------------------------------
def _allele_value(g: GeneTrait) -> float:
    """Compute effective allele value considering dominance."""
    return g.allele_a * g.dominance + g.allele_b * (1.0 - g.dominance)


def _apply_epistasis(rna: Dict[str, float], genes: List[GeneTrait]) -> Dict[str, float]:
    """Modify expression levels based on gene-gene interactions."""
    result = dict(rna)
    for g in genes:
        for target_locus in g.epistasis_targets:
            if target_locus in result:
                # Modifier: high expression at one locus slightly shifts its target
                shift = (result[g.locus] - 0.5) * 0.15 * g.expression_modifier
                result[target_locus] = max(0.0, min(1.0, result[target_locus] + shift))
    return result


def express_genome(persona: PersonaGenome) -> PersonaGenome:
    """Recalculate phenotype from genotype (RNA expression → traits).

    This is the core derivation pipeline:
    DNA → RNA expression → epistasis → Big Five → cognitive indices →
    brain-wave profile → NT baseline → strengths/weaknesses.
    """
    p = persona  # alias

    # 1) Raw RNA expression
    rna = {g.locus: _allele_value(g) for g in p.dna_sequence}

    # 2) Epistasis pass (gene-gene interactions)
    rna = _apply_epistasis(rna, p.dna_sequence)
    p.rna_expression = rna

    # 3) Big Five derivation
    p.personality_big5 = {
        "openness": _clamp(
            rna.get("DRD4", 0.5) * 0.35
            + rna.get("BDNF", 0.5) * 0.25
            + rna.get("TNIK", 0.5) * 0.20
            + rna.get("HTR2A", 0.5) * 0.20
        ),
        "conscientiousness": _clamp(
            rna.get("COMT", 0.5) * 0.30
            + rna.get("DAT1", 0.5) * 0.25
            + rna.get("PDE4B", 0.5) * 0.20
            + rna.get("CLOCK", 0.5) * 0.15
            + rna.get("CHRNA4", 0.5) * 0.10
        ),
        "extraversion": _clamp(
            rna.get("OXTR", 0.5) * 0.30
            + rna.get("DRD4", 0.5) * 0.25
            + rna.get("AVPR1A", 0.5) * 0.20
            + rna.get("SNAP25", 0.5) * 0.15
            + rna.get("SLC6A4", 0.5) * 0.10
        ),
        "agreeableness": _clamp(
            rna.get("OXTR", 0.5) * 0.35
            + rna.get("5HTTLPR", 0.5) * 0.25
            + rna.get("AVPR1A", 0.5) * 0.20
            + rna.get("MAOA", 0.5) * 0.10
            + rna.get("VMAT2", 0.5) * 0.10
        ),
        "neuroticism": _clamp(
            (1.0 - rna.get("5HTTLPR", 0.5)) * 0.30
            + rna.get("FKBP5", 0.5) * 0.25
            + (1.0 - rna.get("NR3C1", 0.5)) * 0.20
            + rna.get("CACNA1C", 0.5) * 0.15
            + (1.0 - rna.get("MAOA", 0.5)) * 0.10
        ),
    }
    big5 = p.personality_big5

    # 4) Cognitive indices
    p.creativity_index = _clamp(
        big5["openness"] * 0.40 + rna.get("BDNF", 0.5) * 0.25
        + rna.get("TNIK", 0.5) * 0.20 + rna.get("SNAP25", 0.5) * 0.15
    )
    p.analytical_index = _clamp(
        big5["conscientiousness"] * 0.35 + rna.get("COMT", 0.5) * 0.25
        + rna.get("DAT1", 0.5) * 0.20 + rna.get("DISC1", 0.5) * 0.20
    )
    p.emotional_intelligence = _clamp(
        big5["agreeableness"] * 0.35 + (1 - big5["neuroticism"]) * 0.25
        + rna.get("OXTR", 0.5) * 0.20 + rna.get("5HTTLPR", 0.5) * 0.20
    )
    p.stress_resilience = _clamp(
        (1 - big5["neuroticism"]) * 0.35 + rna.get("NR3C1", 0.5) * 0.25
        + (1 - rna.get("FKBP5", 0.5)) * 0.25 + rna.get("BDNF", 0.5) * 0.15
    )
    p.learning_rate = _clamp(
        rna.get("BDNF", 0.5) * 0.40 + rna.get("KIBRA", 0.5) * 0.30
        + rna.get("CHRNA4", 0.5) * 0.30
    )
    p.memory_capacity = 4.0 + rna.get("KIBRA", 0.5) * 3.0 + rna.get("APOE", 0.5) * 2.0
    p.attention_span_seconds = (
        180.0 + rna.get("CHRNA4", 0.5) * 900.0
        + rna.get("DAT1", 0.5) * 600.0
        + big5["conscientiousness"] * 300.0
    )

    # 5) Brain-wave profile (baseline power per wave, keyed by wave name)
    p.brain_wave_profile = {
        "Infra-low":    _clamp(rna.get("CLOCK", 0.5) * 0.6 + rna.get("PER2", 0.5) * 0.4),
        "Delta":        _clamp(0.3 + rna.get("PER2", 0.5) * 0.4 - big5["neuroticism"] * 0.2),
        "Theta":        _clamp(p.creativity_index * 0.5 + rna.get("HTR2A", 0.5) * 0.3),
        "Alpha":        _clamp(0.4 + (1 - big5["neuroticism"]) * 0.3 + p.stress_resilience * 0.2),
        "Low Beta":     _clamp(big5["conscientiousness"] * 0.5 + rna.get("CHRNA4", 0.5) * 0.3),
        "Beta":         _clamp(p.analytical_index * 0.5 + big5["extraversion"] * 0.2),
        "High Beta":    _clamp(big5["neuroticism"] * 0.4 + rna.get("CACNA1C", 0.5) * 0.3),
        "Gamma":        _clamp(p.creativity_index * 0.3 + rna.get("CHRNA7", 0.5) * 0.3),
        "High Gamma":   _clamp(rna.get("DISC1", 0.5) * 0.4 + rna.get("PDE4B", 0.5) * 0.3),
        "Mu":           _clamp(rna.get("SNAP25", 0.5) * 0.5),
        "Sigma":        _clamp(rna.get("PER2", 0.5) * 0.4 + rna.get("CLOCK", 0.5) * 0.3),
    }

    # 6) Neurotransmitter baseline
    p.neurotransmitter_baseline = {
        "dopamine":       _clamp(rna.get("DRD4", 0.5) * 0.4 + rna.get("DAT1", 0.5) * 0.3 + rna.get("COMT", 0.5) * 0.3),
        "serotonin":      _clamp(rna.get("5HTTLPR", 0.5) * 0.4 + rna.get("SLC6A4", 0.5) * 0.3 + rna.get("HTR2A", 0.5) * 0.3),
        "GABA":           _clamp(rna.get("NR3C1", 0.5) * 0.5 + (1 - big5["neuroticism"]) * 0.3),
        "glutamate":      _clamp(rna.get("CACNA1C", 0.5) * 0.4 + rna.get("DISC1", 0.5) * 0.3),
        "acetylcholine":  _clamp(rna.get("CHRNA4", 0.5) * 0.5 + rna.get("CHRNA7", 0.5) * 0.3),
        "norepinephrine": _clamp(rna.get("MAOA", 0.5) * 0.4 + big5["extraversion"] * 0.3),
        "endorphins":     _clamp(rna.get("BDNF", 0.5) * 0.3 + p.stress_resilience * 0.3),
        "oxytocin":       _clamp(rna.get("OXTR", 0.5) * 0.5 + rna.get("AVPR1A", 0.5) * 0.3),
        "melatonin":      _clamp(rna.get("PER2", 0.5) * 0.4 + rna.get("CLOCK", 0.5) * 0.4),
        "anandamide":     _clamp(rna.get("VMAT2", 0.5) * 0.4 + p.creativity_index * 0.3),
        "histamine":      _clamp(rna.get("CHRNA4", 0.5) * 0.3 + big5["extraversion"] * 0.2),
    }

    # 7) Strengths & weaknesses — pick from top/bottom trait categories
    cat_scores: Dict[str, float] = {}
    for g in p.dna_sequence:
        cat = g.trait_category
        cat_scores[cat] = cat_scores.get(cat, 0.0) + rna.get(g.locus, 0.5)
    # Normalize by gene count per category
    cat_counts: Dict[str, int] = {}
    for g in p.dna_sequence:
        cat_counts[g.trait_category] = cat_counts.get(g.trait_category, 0) + 1
    for cat in cat_scores:
        if cat_counts.get(cat, 1) > 0:
            cat_scores[cat] /= cat_counts[cat]

    sorted_cats = sorted(cat_scores.items(), key=lambda x: x[1], reverse=True)
    p.cognitive_strengths = []
    for cat, score in sorted_cats[:3]:
        if score > 0.45 and cat in _STRENGTH_MAP:
            idx = int(score * 100) % len(_STRENGTH_MAP[cat])
            p.cognitive_strengths.append(_STRENGTH_MAP[cat][idx])

    p.cognitive_weaknesses = []
    for cat, score in sorted_cats[-2:]:
        if score < 0.55 and cat in _WEAKNESS_MAP:
            idx = int(score * 100) % len(_WEAKNESS_MAP[cat])
            p.cognitive_weaknesses.append(_WEAKNESS_MAP[cat][idx])

    # 8) Brain-region weights (if brain_map is available)
    if _HAVE_MAP:
        p.brain_region_weights = {}
        for rid in list(BRAIN_REGION_CATALOG.keys())[:30]:
            region = BRAIN_REGION_CATALOG[rid]
            nt = region.neurotransmitter_primary.lower()
            base = p.neurotransmitter_baseline.get(nt, 0.5)
            p.brain_region_weights[rid] = _clamp(base + (p.learning_rate - 0.5) * 0.2)

    return p


def _clamp(v: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, v))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_persona(seed: int) -> PersonaGenome:
    """Create a unique persona deterministically from a seed.

    Every seed produces a distinct genome with different allele values,
    personality traits, and cognitive profile.
    """
    rng = np.random.RandomState(seed)

    # Generate randomized DNA
    dna: List[GeneTrait] = []
    for locus, template in GENE_CATALOG.items():
        g = GeneTrait(
            locus=template.locus,
            allele_a=float(rng.uniform(0.0, 1.0)),
            allele_b=float(rng.uniform(0.0, 1.0)),
            dominance=float(rng.uniform(0.2, 0.8)),
            expression_modifier=float(rng.uniform(0.7, 1.3)),
            epistasis_targets=list(template.epistasis_targets),
            mutation_rate=template.mutation_rate * float(rng.uniform(0.8, 1.2)),
            trait_description=template.trait_description,
            trait_category=template.trait_category,
        )
        dna.append(g)

    genome_id = str(uuid.UUID(int=int(rng.randint(0, 2**63)) * 2 + int(rng.randint(0, 2**63))))
    name = _generate_name(rng)
    age = float(rng.uniform(18.0, 75.0))

    persona = PersonaGenome(
        genome_id=genome_id,
        name=name,
        dna_sequence=dna,
        age_factor=age,
    )
    persona = express_genome(persona)

    # Apply age-related modifiers
    if age > 30:
        decline_years = age - 30.0
        persona.learning_rate = max(0.1, persona.learning_rate - decline_years * 0.003)
        persona.memory_capacity = max(3.0, persona.memory_capacity - decline_years * 0.02)
    if age > 50:
        # Wisdom boost
        persona.emotional_intelligence = min(1.0, persona.emotional_intelligence + (age - 50) * 0.005)

    logger.debug(f"Generated persona: {name} (seed={seed}, O={persona.personality_big5.get('openness', 0):.2f})")
    return persona


def crossover(parent_a: PersonaGenome, parent_b: PersonaGenome, seed: int) -> PersonaGenome:
    """Genetic crossover — combine DNA from two parent personas.

    Uses single-point crossover with random allele selection from each parent.
    """
    rng = np.random.RandomState(seed)
    child_dna: List[GeneTrait] = []

    for ga, gb in zip(parent_a.dna_sequence, parent_b.dna_sequence):
        child_g = GeneTrait(
            locus=ga.locus,
            allele_a=ga.allele_a if rng.rand() > 0.5 else ga.allele_b,
            allele_b=gb.allele_a if rng.rand() > 0.5 else gb.allele_b,
            dominance=float(rng.uniform(
                min(ga.dominance, gb.dominance),
                max(ga.dominance, gb.dominance)
            )),
            expression_modifier=(ga.expression_modifier + gb.expression_modifier) / 2.0,
            epistasis_targets=list(ga.epistasis_targets),
            mutation_rate=(ga.mutation_rate + gb.mutation_rate) / 2.0,
            trait_description=ga.trait_description,
            trait_category=ga.trait_category,
        )
        child_dna.append(child_g)

    child = PersonaGenome(
        genome_id=str(uuid.UUID(int=int(rng.randint(0, 2**63)) * 2 + int(rng.randint(0, 2**63)))),
        name=_generate_name(rng),
        dna_sequence=child_dna,
        age_factor=float(rng.uniform(18.0, 25.0)),  # children start young
    )
    return express_genome(child)


def mutate(persona: PersonaGenome, mutation_rate: float, seed: int) -> PersonaGenome:
    """Apply random mutations to a persona's genome.

    Each allele has ``mutation_rate × gene.mutation_rate`` chance of shifting.
    """
    rng = np.random.RandomState(seed)
    mutated = copy.deepcopy(persona)

    for g in mutated.dna_sequence:
        effective_rate = mutation_rate * g.mutation_rate * 100  # scale up
        if rng.rand() < effective_rate:
            g.allele_a = _clamp(g.allele_a + float(rng.normal(0, 0.12)))
        if rng.rand() < effective_rate:
            g.allele_b = _clamp(g.allele_b + float(rng.normal(0, 0.12)))
        if rng.rand() < effective_rate * 0.3:
            g.dominance = _clamp(g.dominance + float(rng.normal(0, 0.08)))

    return express_genome(mutated)


def calculate_compatibility(persona_a: PersonaGenome, persona_b: PersonaGenome) -> float:
    """Calculate how well two personas would collaborate (0–1).

    High compatibility = complementary strengths + similar values.
    """
    b5_a = persona_a.personality_big5
    b5_b = persona_b.personality_big5

    # Complementary strengths (one analytical + one creative = synergy)
    comp_creative_analytical = (
        abs(persona_a.creativity_index - persona_b.analytical_index)
        + abs(persona_b.creativity_index - persona_a.analytical_index)
    ) * 0.15

    # Shared openness
    shared_open = min(b5_a.get("openness", 0.5), b5_b.get("openness", 0.5)) * 0.20

    # Low combined neuroticism
    low_neuro = (2.0 - b5_a.get("neuroticism", 0.5) - b5_b.get("neuroticism", 0.5)) * 0.15

    # Similar conscientiousness
    sim_consc = (1.0 - abs(b5_a.get("conscientiousness", 0.5) - b5_b.get("conscientiousness", 0.5))) * 0.15

    # High combined EI
    ei_sum = (persona_a.emotional_intelligence + persona_b.emotional_intelligence) * 0.15

    # Combined agreeableness
    agree = (b5_a.get("agreeableness", 0.5) + b5_b.get("agreeableness", 0.5)) * 0.10

    score = comp_creative_analytical + shared_open + low_neuro + sim_consc + ei_sum + agree
    return _clamp(score)


def age_persona(persona: PersonaGenome, years: float) -> PersonaGenome:
    """Simulate aging effects on a persona's cognition."""
    aged = copy.deepcopy(persona)
    aged.age_factor += years

    # Fluid intelligence decline after 30
    if aged.age_factor > 30:
        excess = aged.age_factor - 30.0
        aged.learning_rate = max(0.1, aged.learning_rate - excess * 0.003)
        aged.memory_capacity = max(3.0, aged.memory_capacity - excess * 0.015)
        aged.attention_span_seconds = max(120, aged.attention_span_seconds - excess * 3)

    # Crystallized intelligence / wisdom gain
    if aged.age_factor > 40:
        wisdom = (aged.age_factor - 40) * 0.004
        aged.emotional_intelligence = min(1.0, aged.emotional_intelligence + wisdom)
        aged.stress_resilience = min(1.0, aged.stress_resilience + wisdom * 0.5)

    return aged


def persona_cognitive_profile(persona: PersonaGenome) -> Dict[str, Any]:
    """Return a comprehensive profile dictionary."""
    return {
        "id": persona.genome_id,
        "name": persona.name,
        "age": persona.age_factor,
        "big5": persona.personality_big5,
        "creativity": persona.creativity_index,
        "analytical": persona.analytical_index,
        "emotional_intelligence": persona.emotional_intelligence,
        "stress_resilience": persona.stress_resilience,
        "learning_rate": persona.learning_rate,
        "memory_capacity": persona.memory_capacity,
        "attention_span_s": persona.attention_span_seconds,
        "strengths": persona.cognitive_strengths,
        "weaknesses": persona.cognitive_weaknesses,
        "dominant_waves": sorted(
            persona.brain_wave_profile.items(), key=lambda x: x[1], reverse=True
        )[:5],
        "dominant_nt": sorted(
            persona.neurotransmitter_baseline.items(), key=lambda x: x[1], reverse=True
        )[:5],
        "gene_count": len(persona.dna_sequence),
    }


def batch_generate_population(
    n: int, diversity_factor: float = 1.0, seed: int = 42
) -> List[PersonaGenome]:
    """Generate a diverse population of N personas.

    ``diversity_factor`` > 1.0 increases genetic spread (wider allele ranges).
    """
    rng = np.random.RandomState(seed)
    population: List[PersonaGenome] = []

    for i in range(n):
        # Each persona gets a well-separated seed
        persona_seed = int(rng.randint(0, 2**31)) + i * 7919  # prime spacing
        p = generate_persona(persona_seed)

        # Apply diversity scaling if requested
        if diversity_factor != 1.0:
            p = mutate(p, mutation_rate=0.3 * diversity_factor, seed=persona_seed + 1)

        population.append(p)

    logger.info(f"Generated population of {n} personas (diversity={diversity_factor:.1f})")
    return population


# ---------------------------------------------------------------------------
# Module exports
# ---------------------------------------------------------------------------
__all__ = [
    "GeneTrait",
    "PersonaGenome",
    "GENE_CATALOG",
    "generate_persona",
    "crossover",
    "mutate",
    "express_genome",
    "calculate_compatibility",
    "age_persona",
    "persona_cognitive_profile",
    "batch_generate_population",
]
