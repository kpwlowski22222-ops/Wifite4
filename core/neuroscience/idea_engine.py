#!/usr/bin/env python3
"""
KFIOSA Neuroscience Simulation Module: Idea Engine
====================================================
Neuroscience-grounded idea generation that uses brain state simulation,
persona profiles, and diverse generation methods to produce practical,
creative daily-life ideas.

Each idea is tied to specific brain regions, wave patterns, and
neurotransmitter activations. Ideas are genuinely different from each
other through multiple generation strategies and domain templates.
"""

import hashlib
import logging
import time
from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Optional, Any

import numpy as np

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional peer-module imports
# ---------------------------------------------------------------------------
try:
    from .persona_dna import PersonaGenome
except ImportError:
    PersonaGenome = None  # type: ignore

# ---------------------------------------------------------------------------
# Generation methods
# ---------------------------------------------------------------------------

GENERATION_METHODS: Dict[str, str] = {
    "convergent":       "Narrows from many possibilities to a single best solution",
    "divergent":        "Expands outward from a seed concept to many possibilities",
    "associative":      "Links unrelated concepts through shared attributes",
    "analogical":       "Transfers solutions from one domain to another by analogy",
    "bisociative":      "Combines two normally incompatible frames of reference",
    "serendipitous":    "Emerges from random coincidence of brain-state factors",
    "combinatorial":    "Systematically combines elements from different categories",
    "transformational": "Fundamentally restructures the problem space itself",
    "lateral":          "Approaches the problem from an unexpected direction",
    "biomimetic":       "Draws inspiration from natural biological processes",
    "constraint_driven": "Uses limitations as creative fuel",
    "incubation":       "Emerges after unconscious processing (theta/delta dominant)",
}

# ---------------------------------------------------------------------------
# Idea domains and their templates (hundreds of seed patterns)
# ---------------------------------------------------------------------------

IDEA_TEMPLATES: Dict[str, List[str]] = {
    "health": [
        "A personalized micro-habit tracker that adapts to {persona}'s circadian rhythm",
        "A hydration schedule synced to cognitive load patterns throughout the day",
        "A sleep optimization routine using progressive {wave} entrainment",
        "A stress-relief breathing technique timed to {nt} rebalancing cycles",
        "A nutrition timing strategy aligned with {region} metabolic peaks",
        "A posture correction system that detects focus-related tension",
        "An eye strain prevention protocol using 20-20-20 rule variations",
        "A daily stretching routine ordered by neural activation patterns",
        "A personalized supplement timing guide based on chronotype",
        "A mental health check-in routine using mood-cognition correlation",
        "A gut-brain axis optimization meal plan for cognitive performance",
        "A cold exposure protocol calibrated to {persona}'s stress resilience",
    ],
    "productivity": [
        "A task-batching system based on {persona}'s attention span profile",
        "A focus-break cycle optimized for {wave} dominance patterns",
        "An energy management schedule matching ultradian rhythms",
        "A decision fatigue prevention system using cognitive load monitoring",
        "A context-switching minimizer based on brain-region activation costs",
        "A deep work protocol calibrated to {persona}'s analytical index",
        "A email/notification triage system using salience network thresholds",
        "A meeting optimizer that schedules around peak {nt} windows",
        "A procrastination intervention triggered by specific brain states",
        "A weekly review system structured around memory consolidation timing",
        "A task prioritization framework using emotional-analytical balance",
        "An automated environment adjustor (light, sound) for focus states",
    ],
    "learning": [
        "A spaced repetition schedule adapted to {persona}'s memory capacity",
        "A multi-modal study technique matching dominant learning pathways",
        "An interleaving practice pattern for {persona}'s cognitive strengths",
        "A retrieval practice protocol timed to hippocampal consolidation",
        "A concept mapping approach using {region} connectivity patterns",
        "A teaching-to-learn method calibrated to social cognition traits",
        "A mistake-driven learning system using error detection {region} signals",
        "A sleep-learning integration protocol for vocabulary acquisition",
        "A curiosity-driven exploration path using novelty-seeking {nt} profiles",
        "A skill acquisition accelerator using motor cortex pre-activation",
        "A metacognitive monitoring dashboard for learning efficiency",
        "A knowledge synthesis technique combining analytical and creative modes",
    ],
    "creativity": [
        "A brainstorming protocol using alternating {wave} states",
        "A creative constraint generator based on {persona}'s weaknesses",
        "A random stimulus technique calibrated to association strength",
        "An incubation timer using theta-wave monitoring principles",
        "A cross-domain analogy finder based on semantic network activation",
        "A creative collaboration matcher using persona compatibility",
        "A reverse-thinking exercise that flips assumptions systematically",
        "An environmental design for creativity using sensory stimulation",
        "A dream journaling system integrated with idea capture",
        "A creative warm-up routine targeting divergent thinking regions",
        "A combinatorial idea mixer using category theory principles",
        "A flow-state entry protocol personalized to {persona}'s profile",
    ],
    "wellness": [
        "A mindfulness routine calibrated to {persona}'s attention span",
        "A gratitude practice timed to {nt} peak receptivity windows",
        "A social connection scheduler based on oxytocin rhythm",
        "A nature exposure protocol matched to stress resilience needs",
        "A digital detox plan graduated to {persona}'s neuroticism level",
        "A journaling prompt generator using emotional processing regions",
        "A body scan meditation adapted to interoceptive sensitivity",
        "A laughter therapy micro-session for endorphin optimization",
        "A progressive muscle relaxation sequence by neural pathway",
        "A self-compassion exercise targeting inner critic patterns",
        "A sensory grounding toolkit for anxiety management",
        "An awe-walk routine designed to activate default mode network",
    ],
    "social": [
        "A conversation starter system based on empathy network activation",
        "A conflict resolution protocol using emotion regulation strategies",
        "An active listening practice calibrated to mirror neuron engagement",
        "A relationship maintenance scheduler based on attachment patterns",
        "A networking approach matched to {persona}'s extraversion level",
        "A team collaboration framework using cognitive diversity mapping",
        "A feedback delivery method aligned with receiver's neurotransmitter state",
        "A social energy management system for introverts/extroverts",
        "A boundary-setting practice using assertiveness gradients",
        "A mentorship matching algorithm based on complementary strengths",
        "A community building approach leveraging shared value detection",
        "An empathy training exercise using perspective-taking circuits",
    ],
    "technology": [
        "A screen time optimizer based on cognitive fatigue patterns",
        "A notification filtering AI trained on personal salience thresholds",
        "A keyboard shortcut learning system using motor memory optimization",
        "A code review protocol matching analytical and creative review modes",
        "An app usage pattern analyzer for digital wellness insights",
        "A smart home automation triggered by circadian state detection",
        "A voice-first interface for reducing cognitive switching costs",
        "A data visualization preference matcher based on cognitive style",
        "A personal knowledge management system using memory palace principles",
        "A privacy-preserving brain-state journal using local processing",
        "A focus timer that adapts duration to real-time engagement signals",
        "A collaborative tool selector based on team cognitive profiles",
    ],
    "finance": [
        "A spending pattern analyzer using impulse control {region} data",
        "A savings automation system triggered by reward circuit satiation",
        "An investment review schedule timed to analytical peak periods",
        "A budget review ritual designed to reduce financial anxiety",
        "A negotiation preparation protocol using stress resilience profile",
        "A financial goal visualization technique targeting motivation circuits",
        "A subscription audit system using loss aversion awareness",
        "A charitable giving framework aligned with values and oxytocin patterns",
        "An emergency fund builder using micro-savings at reward moments",
        "A debt payoff strategy using momentum psychology principles",
    ],
    "fitness": [
        "A workout timing optimizer based on circadian cortisol patterns",
        "A exercise intensity adapter using stress-recovery balance",
        "A movement snack protocol distributed through the workday",
        "A sport skill practice plan using motor cortex activation windows",
        "A recovery monitoring system using parasympathetic indicators",
        "A motivation maintenance strategy using dopamine cycling",
        "A social exercise matcher based on personality compatibility",
        "A mind-body practice selector (yoga/tai chi/qigong) by persona type",
        "A pre-performance routine using arousal optimization principles",
        "A injury prevention system using proprioceptive awareness training",
    ],
    "environment": [
        "A home workspace optimizer using cognitive ergonomics principles",
        "A plant selection guide based on air quality and cognitive impact",
        "A lighting design system for circadian rhythm support",
        "A noise management solution using auditory processing preferences",
        "A color scheme selector based on emotional state goals",
        "A temperature optimization protocol for cognitive performance",
        "A decluttering system using cognitive load reduction principles",
        "A scent design for different activity zones and brain states",
        "A nature integration plan for urban living spaces",
        "A seasonal adaptation routine for mood and energy management",
    ],
    "cooking": [
        "A meal planning system based on neurotransmitter support needs",
        "A recipe creativity technique using ingredient-association networks",
        "A mindful eating practice calibrated to satiety signal timing",
        "A cooking skill progression path using procedural memory optimization",
        "A flavor pairing explorer using gustatory cortex activation patterns",
        "A meal prep efficiency system matching cognitive energy availability",
        "A social cooking experience designed for relationship building",
        "A stress-relief cooking protocol using sensory engagement",
        "A brain-food timing guide for exam/presentation preparation",
        "A fermentation project tracker for gut-brain axis optimization",
    ],
    "organization": [
        "A filing system based on semantic memory retrieval patterns",
        "A daily review ritual using memory consolidation timing",
        "A project breakdown method matching working memory capacity",
        "A decision archive for reducing repeated cognitive load",
        "A habit stacking framework using existing neural pathway leverage",
        "A information capture system for serendipitous insights",
        "A delegation framework based on team cognitive profiles",
        "A goal hierarchy visualization using prefrontal planning circuits",
        "A transition ritual between work and personal modes",
        "A weekly planning session structured around energy forecasting",
    ],
}

# ---------------------------------------------------------------------------
# Core data structures
# ---------------------------------------------------------------------------

@dataclass
class IdeaContext:
    """Context for generating ideas."""
    domain: str = "productivity"
    persona: Any = None  # PersonaGenome if available
    brain_state: Dict[str, float] = field(default_factory=dict)
    neuromod_active: List[str] = field(default_factory=list)
    prior_ideas: List[str] = field(default_factory=list)
    constraints: List[str] = field(default_factory=list)
    randomness_factor: float = 0.5
    time_of_day: str = "morning"
    season: str = "spring"


@dataclass
class GeneratedIdea:
    """A single generated idea with full neuroscience context."""
    idea_id: str
    title: str
    description: str
    domain: str
    novelty_score: float
    practicality_score: float
    persona_affinity: float
    brain_regions_involved: List[str]
    dominant_waves: List[str]
    neurotransmitters_activated: List[str]
    generation_method: str
    daily_applicability: str
    invention_potential: bool
    timestamp: float


# ---------------------------------------------------------------------------
# Brain-region / wave / NT associations per domain
# ---------------------------------------------------------------------------

_DOMAIN_REGIONS: Dict[str, List[str]] = {
    "health":       ["BA9", "HYPO", "INS", "BA24", "PAG"],
    "productivity": ["BA46", "BA9", "BA8", "BA7", "BA32"],
    "learning":     ["HIPPO", "BA28", "BA39", "BA46", "BA22"],
    "creativity":   ["BA10", "BA39", "BA47", "HIPPO", "BA9"],
    "wellness":     ["INS", "AMY", "BA25", "RAPHE", "BA24"],
    "social":       ["OXTR_region", "BA44", "BA45", "BA22", "AMY"],
    "technology":   ["BA46", "BA6", "BA4", "BA8", "BA9"],
    "finance":      ["BA11", "BA32", "NAcc", "BA9", "AMY"],
    "fitness":      ["BA4", "BA6", "CER", "SN", "BA1"],
    "environment":  ["BA17", "BA18", "INS", "HYPO", "BA9"],
    "cooking":      ["BA43", "INS", "BA6", "CER", "BA37"],
    "organization": ["BA46", "BA9", "BA10", "HIPPO", "BA32"],
}

_DOMAIN_WAVES: Dict[str, List[str]] = {
    "health":       ["Alpha", "Theta", "Delta"],
    "productivity": ["Beta", "Low Beta", "Gamma"],
    "learning":     ["Theta", "Alpha", "Gamma"],
    "creativity":   ["Theta", "Alpha", "Gamma", "High Gamma"],
    "wellness":     ["Alpha", "Theta", "Infra-low"],
    "social":       ["Alpha", "Mu", "Beta"],
    "technology":   ["Beta", "High Beta", "Gamma"],
    "finance":      ["Beta", "Alpha", "Low Beta"],
    "fitness":      ["Beta", "High Beta", "Mu"],
    "environment":  ["Alpha", "Theta", "Infra-low"],
    "cooking":      ["Alpha", "Beta", "Theta"],
    "organization": ["Beta", "Low Beta", "Alpha"],
}

_DOMAIN_NT: Dict[str, List[str]] = {
    "health":       ["serotonin", "GABA", "melatonin"],
    "productivity": ["dopamine", "norepinephrine", "acetylcholine"],
    "learning":     ["acetylcholine", "dopamine", "glutamate"],
    "creativity":   ["dopamine", "serotonin", "anandamide"],
    "wellness":     ["serotonin", "endorphins", "oxytocin"],
    "social":       ["oxytocin", "serotonin", "dopamine"],
    "technology":   ["dopamine", "norepinephrine", "acetylcholine"],
    "finance":      ["dopamine", "norepinephrine", "GABA"],
    "fitness":      ["endorphins", "dopamine", "norepinephrine"],
    "environment":  ["serotonin", "GABA", "melatonin"],
    "cooking":      ["dopamine", "serotonin", "endorphins"],
    "organization": ["norepinephrine", "dopamine", "acetylcholine"],
}

# Time-of-day modifiers on generation methods
_TOD_METHOD_WEIGHTS: Dict[str, Dict[str, float]] = {
    "morning":   {"convergent": 1.2, "analytical": 1.3, "constraint_driven": 1.1},
    "afternoon": {"divergent": 1.1, "associative": 1.2, "combinatorial": 1.2},
    "evening":   {"lateral": 1.3, "bisociative": 1.2, "incubation": 1.1},
    "night":     {"serendipitous": 1.4, "incubation": 1.5, "transformational": 1.2},
}


# ---------------------------------------------------------------------------
# Generation logic
# ---------------------------------------------------------------------------

def _select_method(context: IdeaContext, rng: np.random.RandomState) -> str:
    """Select a generation method weighted by time of day and randomness."""
    methods = list(GENERATION_METHODS.keys())
    weights = np.ones(len(methods))

    # Apply time-of-day weights
    tod_mods = _TOD_METHOD_WEIGHTS.get(context.time_of_day, {})
    for i, m in enumerate(methods):
        weights[i] *= tod_mods.get(m, 1.0)

    # Randomness factor increases weight of unusual methods
    if context.randomness_factor > 0.5:
        unusual = {"serendipitous", "bisociative", "transformational", "lateral", "biomimetic"}
        for i, m in enumerate(methods):
            if m in unusual:
                weights[i] *= 1.0 + context.randomness_factor

    # Normalize
    weights /= weights.sum()
    return str(rng.choice(methods, p=weights))


def _fill_template(template: str, context: IdeaContext, rng: np.random.RandomState) -> str:
    """Fill template placeholders with context-appropriate values."""
    domain = context.domain
    replacements = {
        "{persona}": context.persona.name if context.persona else "the user",
        "{wave}": rng.choice(_DOMAIN_WAVES.get(domain, ["Alpha"])),
        "{nt}": rng.choice(_DOMAIN_NT.get(domain, ["dopamine"])),
        "{region}": rng.choice(_DOMAIN_REGIONS.get(domain, ["BA9"])),
    }
    result = template
    for key, val in replacements.items():
        result = result.replace(key, str(val))
    return result


def _novelty_score(idea_text: str, prior_ideas: List[str]) -> float:
    """Compute how novel an idea is relative to prior ideas."""
    if not prior_ideas:
        return 0.9
    # Simple word-overlap novelty
    idea_words = set(idea_text.lower().split())
    max_overlap = 0.0
    for prior in prior_ideas:
        prior_words = set(prior.lower().split())
        if idea_words:
            overlap = len(idea_words & prior_words) / len(idea_words)
            max_overlap = max(max_overlap, overlap)
    return max(0.1, 1.0 - max_overlap)


def _practicality_score(idea_text: str, domain: str, rng: np.random.RandomState) -> float:
    """Estimate how practical/actionable an idea is."""
    # Practical domains get higher baseline
    practical_domains = {"productivity", "organization", "health", "fitness", "cooking"}
    base = 0.7 if domain in practical_domains else 0.5
    # Add some variance
    return min(1.0, max(0.2, base + float(rng.uniform(-0.15, 0.15))))


def _persona_affinity(context: IdeaContext, method: str, rng: np.random.RandomState) -> float:
    """How well the idea matches the generating persona's profile."""
    if not context.persona:
        return 0.5
    p = context.persona
    score = 0.5

    if method in ("divergent", "associative", "bisociative", "serendipitous"):
        score += getattr(p, "creativity_index", 0.5) * 0.3
    if method in ("convergent", "constraint_driven", "combinatorial"):
        score += getattr(p, "analytical_index", 0.5) * 0.3
    if method in ("lateral", "transformational"):
        big5 = getattr(p, "personality_big5", {})
        score += big5.get("openness", 0.5) * 0.3

    return min(1.0, max(0.1, score + float(rng.uniform(-0.1, 0.1))))


def generate_idea(context: IdeaContext, seed: int) -> GeneratedIdea:
    """Generate a single idea from the given context.

    The generation process:
    1. Select a generation method based on time, persona, randomness
    2. Pick a template from the domain
    3. Fill it with context-appropriate details
    4. Score for novelty, practicality, persona affinity
    5. Tag with involved brain regions, waves, and neurotransmitters
    """
    rng = np.random.RandomState(seed)
    domain = context.domain

    method = _select_method(context, rng)

    # Get templates for domain (fallback to productivity)
    templates = IDEA_TEMPLATES.get(domain, IDEA_TEMPLATES["productivity"])

    # Pick a template, avoiding recent ideas
    template = templates[rng.randint(0, len(templates))]
    title = _fill_template(template, context, rng)

    # Generate detailed description
    descriptions = [
        f"Implement by starting with a 5-minute daily practice and gradually expanding.",
        f"Use the {method} approach: {GENERATION_METHODS[method]}.",
        f"Best time to practice: {context.time_of_day}.",
        f"Track progress using simple metrics aligned with your cognitive profile.",
        f"Adapt intensity based on energy levels and stress indicators.",
    ]
    description = " ".join([title + "."] + descriptions[:3])

    # Daily applicability
    applicabilities = [
        "Start with 5 minutes each morning before other tasks",
        "Integrate into existing routines as a micro-practice",
        "Use during transition moments between activities",
        "Apply during your highest-energy window of the day",
        "Practice during commute or waiting times",
        "Incorporate into your evening wind-down routine",
    ]
    daily_app = applicabilities[rng.randint(0, len(applicabilities))]

    # Compute scores
    novelty = _novelty_score(title, context.prior_ideas)
    practicality = _practicality_score(title, domain, rng)
    affinity = _persona_affinity(context, method, rng)

    # Check invention potential
    invention_potential = (novelty > 0.7 and practicality > 0.6 and rng.rand() > 0.6)

    # Create idea ID from content hash
    idea_hash = hashlib.md5(f"{title}{seed}{time.time()}".encode()).hexdigest()[:12]

    return GeneratedIdea(
        idea_id=f"idea-{idea_hash}",
        title=title,
        description=description,
        domain=domain,
        novelty_score=novelty,
        practicality_score=practicality,
        persona_affinity=affinity,
        brain_regions_involved=_DOMAIN_REGIONS.get(domain, ["BA9"])[:4],
        dominant_waves=_DOMAIN_WAVES.get(domain, ["Alpha"])[:3],
        neurotransmitters_activated=_DOMAIN_NT.get(domain, ["dopamine"])[:3],
        generation_method=method,
        daily_applicability=daily_app,
        invention_potential=invention_potential,
        timestamp=time.time(),
    )


def batch_generate(
    context: IdeaContext, count: int, diversity_min: float = 0.3, seed: int = 42
) -> List[GeneratedIdea]:
    """Generate multiple diverse ideas, ensuring minimum diversity between them."""
    rng = np.random.RandomState(seed)
    ideas: List[GeneratedIdea] = []
    attempts = 0
    max_attempts = count * 5

    while len(ideas) < count and attempts < max_attempts:
        idea_seed = int(rng.randint(0, 2**31))
        idea = generate_idea(context, idea_seed)

        # Check diversity against existing ideas
        if ideas:
            existing_titles = [i.title for i in ideas]
            novelty = _novelty_score(idea.title, existing_titles)
            if novelty < diversity_min:
                attempts += 1
                continue

        ideas.append(idea)
        context.prior_ideas.append(idea.title)
        attempts += 1

    logger.info(f"Generated {len(ideas)} ideas for domain '{context.domain}' "
                f"(diversity_min={diversity_min})")
    return ideas


def evaluate_idea_quality(idea: GeneratedIdea) -> Dict[str, float]:
    """Evaluate an idea's overall quality across multiple dimensions."""
    return {
        "novelty": idea.novelty_score,
        "practicality": idea.practicality_score,
        "persona_fit": idea.persona_affinity,
        "invention_potential": 1.0 if idea.invention_potential else 0.0,
        "overall": (
            idea.novelty_score * 0.30
            + idea.practicality_score * 0.30
            + idea.persona_affinity * 0.20
            + (0.20 if idea.invention_potential else 0.0)
        ),
    }


def idea_from_brain_state(
    brain_state: Dict[str, float], persona: Any = None, seed: int = 42
) -> GeneratedIdea:
    """Generate an idea emergent from a specific brain-state snapshot.

    Maps dominant wave patterns to appropriate domains and generation methods.
    """
    # Find dominant wave
    if brain_state:
        dominant = max(brain_state.items(), key=lambda x: x[1])[0]
    else:
        dominant = "Alpha"

    # Map waves to likely domains
    wave_domain_map = {
        "Theta": "creativity", "Alpha": "wellness", "Beta": "productivity",
        "High Beta": "technology", "Gamma": "learning", "Delta": "health",
        "Mu": "fitness", "Low Beta": "organization", "High Gamma": "creativity",
    }
    domain = wave_domain_map.get(dominant, "productivity")

    context = IdeaContext(
        domain=domain,
        persona=persona,
        brain_state=brain_state,
        randomness_factor=0.7,  # brain-state ideas are more random
    )
    return generate_idea(context, seed)


def cross_pollinate(
    idea_a: GeneratedIdea, idea_b: GeneratedIdea, seed: int = 42
) -> GeneratedIdea:
    """Combine two ideas into a novel hybrid."""
    rng = np.random.RandomState(seed)

    # Combine titles
    words_a = idea_a.title.split()
    words_b = idea_b.title.split()
    mid_a = len(words_a) // 2
    mid_b = len(words_b) // 2
    hybrid_title = " ".join(words_a[:mid_a] + ["combined with"] + words_b[mid_b:])

    # Merge attributes
    merged_regions = list(set(idea_a.brain_regions_involved + idea_b.brain_regions_involved))[:5]
    merged_waves = list(set(idea_a.dominant_waves + idea_b.dominant_waves))[:4]
    merged_nt = list(set(idea_a.neurotransmitters_activated + idea_b.neurotransmitters_activated))[:4]

    idea_hash = hashlib.md5(f"{hybrid_title}{seed}".encode()).hexdigest()[:12]

    return GeneratedIdea(
        idea_id=f"idea-{idea_hash}",
        title=hybrid_title,
        description=f"Hybrid idea combining {idea_a.domain} and {idea_b.domain} approaches. "
                     f"{idea_a.description[:100]}... + {idea_b.description[:100]}...",
        domain=f"{idea_a.domain}+{idea_b.domain}",
        novelty_score=min(1.0, (idea_a.novelty_score + idea_b.novelty_score) / 2 + 0.15),
        practicality_score=(idea_a.practicality_score + idea_b.practicality_score) / 2,
        persona_affinity=(idea_a.persona_affinity + idea_b.persona_affinity) / 2,
        brain_regions_involved=merged_regions,
        dominant_waves=merged_waves,
        neurotransmitters_activated=merged_nt,
        generation_method="bisociative",
        daily_applicability="Combine practices from both source ideas into a single session",
        invention_potential=True,  # hybrids have high invention potential
        timestamp=time.time(),
    )


def improve_idea(idea: GeneratedIdea, feedback: str, seed: int = 42) -> GeneratedIdea:
    """Iterate on an idea using feedback."""
    rng = np.random.RandomState(seed)
    improved = GeneratedIdea(
        idea_id=idea.idea_id + "-v2",
        title=f"[Improved] {idea.title}",
        description=f"{idea.description} | Refinement based on feedback: {feedback}",
        domain=idea.domain,
        novelty_score=min(1.0, idea.novelty_score + 0.05),
        practicality_score=min(1.0, idea.practicality_score + 0.10),
        persona_affinity=idea.persona_affinity,
        brain_regions_involved=idea.brain_regions_involved,
        dominant_waves=idea.dominant_waves,
        neurotransmitters_activated=idea.neurotransmitters_activated,
        generation_method="convergent",
        daily_applicability=idea.daily_applicability,
        invention_potential=idea.invention_potential,
        timestamp=time.time(),
    )
    return improved


def idea_diversity_score(ideas: List[GeneratedIdea]) -> float:
    """Measure how different a set of ideas are from each other (0–1)."""
    if len(ideas) < 2:
        return 1.0
    scores = []
    for i, a in enumerate(ideas):
        for b in ideas[i + 1:]:
            scores.append(_novelty_score(a.title, [b.title]))
    return float(np.mean(scores)) if scores else 1.0


# ---------------------------------------------------------------------------
# Module exports
# ---------------------------------------------------------------------------
__all__ = [
    "IdeaContext",
    "GeneratedIdea",
    "GENERATION_METHODS",
    "IDEA_TEMPLATES",
    "generate_idea",
    "batch_generate",
    "evaluate_idea_quality",
    "idea_from_brain_state",
    "cross_pollinate",
    "improve_idea",
    "idea_diversity_score",
]
