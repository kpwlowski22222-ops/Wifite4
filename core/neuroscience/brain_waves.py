"""
Neuroscience Simulation Module: Brain Waves
Part of the KFIOSA neuroscience engine.

This module provides definitions, simulations, and transition models for various types
of neural oscillations (brain waves), ranging from infra-low cortical potentials to
exotic lambda and epsilon waves. It handles signal generation, cross-frequency coupling,
entrainment compatibility, and Markov-based transition probabilities between cognitive states.

All functions are pure or explicitly parameterized with a seed for deterministic behavior,
allowing reliable simulation replay.

References:
- Buzsáki, G. (2006). Rhythms of the Brain.
- Nunez, P. L., & Srinivasan, R. (2006). Electric Fields of the Brain.
"""

import math
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Optional, Any
import numpy as np

__all__ = [
    "BrainWave",
    "BRAIN_WAVE_CATALOG",
    "generate_wave_state",
    "cross_frequency_coupling",
    "dominant_wave_for_state",
    "entrainment_compatibility",
    "wave_transition_probability",
    "WAVE_TRANSITION_MATRIX",
    "sample_wave_composition"
]

# -----------------------------------------------------------------------------
# Module Setup and Logging
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
if not logger.handlers:
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)
    logger.addHandler(ch)


# -----------------------------------------------------------------------------
# Core Data Structures
# -----------------------------------------------------------------------------

@dataclass(frozen=True)
class BrainWave:
    """
    Represents a specific category of neural oscillation.
    
    Attributes:
        name: Common name of the wave (e.g., 'Alpha', 'Theta').
        category: Broad classification (e.g., 'Standard', 'Specialized', 'Transient').
        freq_min: Minimum frequency in Hz.
        freq_max: Maximum frequency in Hz.
        amplitude_range: Typical amplitude range in microvolts (µV) as a tuple (min, max).
        region_affinity: List of brain regions where this wave is most prominent.
        cognitive_states: Mental or physiological states associated with this wave.
        neurotransmitter_associations: Neurotransmitters highly correlated with this wave.
        cross_coupling_partners: Other waves this commonly modulates or is modulated by.
        description: Detailed scientific description of the wave's function.
    """
    name: str
    category: str
    freq_min: float
    freq_max: float
    amplitude_range: Tuple[float, float]
    region_affinity: List[str]
    cognitive_states: List[str]
    neurotransmitter_associations: List[str]
    cross_coupling_partners: List[str]
    description: str


# -----------------------------------------------------------------------------
# Brain Wave Catalog
# -----------------------------------------------------------------------------

_catalog = [
    BrainWave(
        name="Infra-low",
        category="Standard",
        freq_min=0.01,
        freq_max=0.5,
        amplitude_range=(50.0, 200.0),
        region_affinity=["Global Cortex", "Brainstem"],
        cognitive_states=["Autonomic Regulation", "Basic Cortical Rhythms"],
        neurotransmitter_associations=["Melatonin", "Serotonin"],
        cross_coupling_partners=["Delta", "Theta"],
        description="Slow Cortical Potentials (SCP). These underlie basic cortical rhythms, integrating large neural networks and resetting membrane potentials."
    ),
    BrainWave(
        name="Delta",
        category="Standard",
        freq_min=0.5,
        freq_max=4.0,
        amplitude_range=(20.0, 200.0),
        region_affinity=["Frontal Lobe", "Thalamus", "Cortex"],
        cognitive_states=["Deep Dreamless Sleep", "Healing", "Regeneration", "Unconscious Mind"],
        neurotransmitter_associations=["GABA", "Melatonin", "Endorphins"],
        cross_coupling_partners=["Alpha", "High Gamma"],
        description="High-amplitude, slow waves characterizing deep sleep (NREM stage 3). Crucial for physical healing and immune system restoration."
    ),
    BrainWave(
        name="Theta",
        category="Standard",
        freq_min=4.0,
        freq_max=8.0,
        amplitude_range=(10.0, 50.0),
        region_affinity=["Hippocampus", "Prefrontal Cortex"],
        cognitive_states=["Deep Relaxation", "Meditation", "Creativity", "Memory Consolidation", "REM Sleep"],
        neurotransmitter_associations=["Acetylcholine", "Serotonin"],
        cross_coupling_partners=["Gamma", "Beta"],
        description="Associated with subconscious states, memory consolidation, and REM sleep. Crucial for associative learning."
    ),
    BrainWave(
        name="Alpha",
        category="Standard",
        freq_min=8.0,
        freq_max=12.0,
        amplitude_range=(20.0, 60.0),
        region_affinity=["Occipital Lobe", "Parietal Lobe", "Thalamus"],
        cognitive_states=["Relaxed Alertness", "Calm Focus", "Flow State", "Visualization"],
        neurotransmitter_associations=["Serotonin", "GABA", "Acetylcholine"],
        cross_coupling_partners=["Beta", "Theta", "Delta"],
        description="The resting state of the brain. Predominant when eyes are closed. Bridges the conscious and subconscious."
    ),
    BrainWave(
        name="Low Beta",
        category="Standard",
        freq_min=12.0,
        freq_max=15.0,
        amplitude_range=(10.0, 20.0),
        region_affinity=["Sensorimotor Cortex"],
        cognitive_states=["Relaxed Focus", "Body Awareness", "Motor Planning"],
        neurotransmitter_associations=["Dopamine", "GABA"],
        cross_coupling_partners=["Mu", "Gamma"],
        description="Also known as Sensorimotor Rhythm (SMR) when in the motor cortex. Represents a state of physical stillness paired with cognitive presence."
    ),
    BrainWave(
        name="Beta",
        category="Standard",
        freq_min=15.0,
        freq_max=20.0,
        amplitude_range=(5.0, 20.0),
        region_affinity=["Frontal Lobe", "Parietal Lobe"],
        cognitive_states=["Active Thinking", "Concentration", "Alertness", "Analytical Thought"],
        neurotransmitter_associations=["Dopamine", "Norepinephrine", "Glutamate"],
        cross_coupling_partners=["Alpha", "Theta"],
        description="Dominates during normal waking states of consciousness when attention is directed towards cognitive tasks and the outside world."
    ),
    BrainWave(
        name="High Beta",
        category="Standard",
        freq_min=20.0,
        freq_max=30.0,
        amplitude_range=(2.0, 15.0),
        region_affinity=["Frontal Lobe", "Temporal Lobe"],
        cognitive_states=["Intense Focus", "Anxiety", "Hyperalertness", "Complex Thought", "Stress"],
        neurotransmitter_associations=["Norepinephrine", "Cortisol", "Glutamate"],
        cross_coupling_partners=["Gamma", "Alpha"],
        description="Associated with high-level processing, but also stress, agitation, and anxiety when excessively sustained."
    ),
    BrainWave(
        name="Gamma",
        category="Standard",
        freq_min=30.0,
        freq_max=44.0,
        amplitude_range=(1.0, 10.0),
        region_affinity=["Global Cortex", "Hippocampus", "Thalamus"],
        cognitive_states=["Higher Cognitive Processing", "Perception", "Consciousness Binding", "Insight"],
        neurotransmitter_associations=["Acetylcholine", "Glutamate", "GABA"],
        cross_coupling_partners=["Theta", "Alpha"],
        description="Involved in cognitive processing, information synthesis, and the 'binding problem' of consciousness. Peaks during insight (aha moments)."
    ),
    BrainWave(
        name="High Gamma",
        category="Standard",
        freq_min=44.0,
        freq_max=100.0,
        amplitude_range=(0.5, 5.0),
        region_affinity=["Somatosensory Cortex", "Prefrontal Cortex"],
        cognitive_states=["Memory Recall", "Sensory Processing", "Peak Performance", "Lucid Dreaming"],
        neurotransmitter_associations=["Glutamate", "Dopamine"],
        cross_coupling_partners=["Theta", "Delta"],
        description="Fast network oscillations critical for precise timing in sensory processing and memory encoding. Often coupled with Theta phases."
    ),
    BrainWave(
        name="Hyper-Gamma",
        category="Standard",
        freq_min=100.0,
        freq_max=200.0,
        amplitude_range=(0.1, 2.0),
        region_affinity=["Global Cortex"],
        cognitive_states=["Advanced Consciousness", "Transcendence", "Deep Mystical States"],
        neurotransmitter_associations=["Endorphins", "DMT (Endogenous)", "Oxytocin"],
        cross_coupling_partners=["Epsilon", "Lambda"],
        description="Extremely high-frequency oscillations linked to advanced meditative states and transcendent subjective experiences."
    ),
    BrainWave(
        name="Lambda",
        category="Standard",
        freq_min=200.0,
        freq_max=300.0,
        amplitude_range=(0.1, 1.0),
        region_affinity=["Right Hemisphere", "Prefrontal Cortex"],
        cognitive_states=["Exotic Consciousness States", "Spiritual Experiences", "Profound Integration"],
        neurotransmitter_associations=["Serotonin", "Endogenous Psychedelics"],
        cross_coupling_partners=["Epsilon"],
        description="Rarest and fastest identified wave, hypothesized to ride on extremely slow Epsilon waves. Linked to wholeness and spiritual awakening."
    ),
    BrainWave(
        name="Epsilon",
        category="Standard",
        freq_min=0.01,
        freq_max=0.5,
        amplitude_range=(20.0, 100.0),
        region_affinity=["Thalamus", "Hypothalamus", "Brainstem"],
        cognitive_states=["Suspended Animation", "Profound Stillness", "Carrier Wave State"],
        neurotransmitter_associations=["GABA", "Melatonin", "Endorphins"],
        cross_coupling_partners=["Lambda", "Hyper-Gamma"],
        description="Extremely slow rhythm distinct from SCP, acting as a carrier wave for high-frequency bursts (Lambda, Hyper-Gamma) during profound meditation."
    ),
    BrainWave(
        name="Mu",
        category="Specialized",
        freq_min=8.0,
        freq_max=13.0,
        amplitude_range=(10.0, 50.0),
        region_affinity=["Motor Cortex", "Somatosensory Cortex"],
        cognitive_states=["Motor Planning", "Mirror Neuron Activity", "Empathy", "Action Observation"],
        neurotransmitter_associations=["Dopamine", "Acetylcholine", "Oxytocin"],
        cross_coupling_partners=["Beta", "Gamma"],
        description="Attenuated with voluntary movement. Linked to mirror neurons, facilitating observational learning and empathy."
    ),
    BrainWave(
        name="Kappa",
        category="Specialized",
        freq_min=8.0,
        freq_max=12.0,
        amplitude_range=(5.0, 20.0),
        region_affinity=["Temporal Lobe"],
        cognitive_states=["Thinking", "Cognitive Processing", "Mental Arithmetic"],
        neurotransmitter_associations=["Acetylcholine", "Dopamine"],
        cross_coupling_partners=["Alpha"],
        description="An alpha-like rhythm occurring during mental effort, particularly arithmetic or problem-solving, prominent over the temporal lobes."
    ),
    BrainWave(
        name="Sigma",
        category="Specialized",
        freq_min=12.0,
        freq_max=14.0,
        amplitude_range=(10.0, 40.0),
        region_affinity=["Thalamus", "Cortex"],
        cognitive_states=["Memory Consolidation during Sleep", "Sleep Spindles", "Sensory Gating"],
        neurotransmitter_associations=["GABA", "Glutamate"],
        cross_coupling_partners=["Cortical Slow Oscillation", "Hippocampal SWR"],
        description="Also known as sleep spindles. Bursts of oscillatory activity during NREM stage 2 sleep, gating sensory input to protect sleep."
    ),
    BrainWave(
        name="K-Complex",
        category="Transient",
        freq_min=0.5,
        freq_max=2.0,
        amplitude_range=(100.0, 300.0),
        region_affinity=["Frontal Cortex"],
        cognitive_states=["Sleep Stage Marker", "Response to External Stimuli in Sleep"],
        neurotransmitter_associations=["GABA"],
        cross_coupling_partners=["Sigma"],
        description="Large, single, sharp negative high-voltage peak followed by a slower positive complex. Supresses cortical arousal to maintain sleep."
    ),
    BrainWave(
        name="PGO Waves",
        category="Transient",
        freq_min=4.0,
        freq_max=8.0, # Characteristic frequency of bursts
        amplitude_range=(20.0, 80.0),
        region_affinity=["Pons", "LGN", "Occipital Lobe"],
        cognitive_states=["Dream Generation", "REM Sleep Transition", "Visual Hallucination"],
        neurotransmitter_associations=["Acetylcholine", "Serotonin (suppressed)"],
        cross_coupling_partners=["Theta"],
        description="Pontine-Geniculate-Occipital waves. Phasic field potentials signaling the onset of REM sleep and closely tied to dreaming."
    ),
    BrainWave(
        name="Hippocampal SWR",
        category="Transient",
        freq_min=150.0,
        freq_max=250.0,
        amplitude_range=(20.0, 100.0),
        region_affinity=["Hippocampus (CA1)"],
        cognitive_states=["Memory Replay", "Consolidation", "Spatial Learning"],
        neurotransmitter_associations=["Glutamate", "GABA"],
        cross_coupling_partners=["Cortical Slow Oscillation", "Sigma"],
        description="Sharp-Wave Ripples. Extremely fast, short-lived oscillations transferring memories from hippocampus to neocortex during rest or sleep."
    ),
    BrainWave(
        name="Hippocampal Theta",
        category="Specialized",
        freq_min=4.0,
        freq_max=8.0,
        amplitude_range=(20.0, 80.0),
        region_affinity=["Hippocampus"],
        cognitive_states=["Spatial Navigation", "Memory Encoding", "Active Locomotion"],
        neurotransmitter_associations=["Acetylcholine", "Glutamate"],
        cross_coupling_partners=["Gamma", "Hippocampal SWR"],
        description="Highly regular oscillation in the hippocampus during active exploration and REM sleep, phase-locking single neuron firing."
    ),
    BrainWave(
        name="Cortical Slow Oscillation",
        category="Standard",
        freq_min=0.5,
        freq_max=1.0,
        amplitude_range=(50.0, 150.0),
        region_affinity=["Neocortex"],
        cognitive_states=["Sleep", "Memory Transfer (Cortex-Hippocampus)", "Up/Down States"],
        neurotransmitter_associations=["GABA", "Glutamate", "Neuromodulators (low)"],
        cross_coupling_partners=["Sigma", "Hippocampal SWR"],
        description="~0.75 Hz rhythm coordinating widespread cortical UP (active) and DOWN (silent) states during slow-wave sleep."
    ),
    BrainWave(
        name="PDR",
        category="Specialized",
        freq_min=8.0,
        freq_max=13.0,
        amplitude_range=(20.0, 70.0),
        region_affinity=["Occipital Lobe", "Parietal Lobe"],
        cognitive_states=["Eye-Closed Resting State", "Visual System Idling"],
        neurotransmitter_associations=["GABA", "Serotonin"],
        cross_coupling_partners=["Beta"],
        description="Posterior Dominant Rhythm. The classic 'Alpha' rhythm seen in clinical EEGs over the back of the head when eyes are closed."
    )
]

BRAIN_WAVE_CATALOG: Dict[str, BrainWave] = { wave.name: wave for wave in _catalog }

# -----------------------------------------------------------------------------
# Signal Generation Capabilities (Deterministic & Pure)
# -----------------------------------------------------------------------------

def _generate_pink_noise(num_samples: int, np_random: np.random.Generator) -> np.ndarray:
    """
    Generates 1/f pink noise common in biological systems.
    Pure function relying on passed generator.
    """
    # Create white noise
    white = np_random.standard_normal(num_samples)
    
    # FFT to frequency domain
    X = np.fft.rfft(white)
    
    # Create 1/f amplitude multiplier
    frequencies = np.fft.rfftfreq(num_samples)
    frequencies[0] = 1.0  # Avoid divide by zero
    multiplier = 1.0 / np.sqrt(frequencies)
    
    # Apply and inverse FFT
    X = X * multiplier
    pink = np.fft.irfft(X, n=num_samples)
    
    # Normalize to standard deviation of 1
    if np.std(pink) > 0:
        pink = pink / np.std(pink)
        
    return pink

def _generate_k_complex(num_samples: int, sample_rate: float, np_random: np.random.Generator) -> np.ndarray:
    """Generates a transient K-Complex wave shape."""
    t = np.linspace(0, num_samples / sample_rate, num_samples)
    signal = np.zeros_like(t)
    
    # K-Complex is roughly a sharp negative peak followed by a slower positive wave lasting ~1-2 seconds
    event_start = num_samples // 4
    duration_sec = 1.5
    duration_samples = int(duration_sec * sample_rate)
    
    if event_start + duration_samples < num_samples:
        t_event = np.linspace(0, duration_sec, duration_samples)
        # Biphasic waveform model
        wave = -150.0 * np.exp(-15 * (t_event - 0.2)**2) + 80.0 * np.exp(-3 * (t_event - 0.6)**2)
        signal[event_start:event_start + duration_samples] = wave
        
    return signal

def generate_wave_state(wave_names: List[str], duration_ms: float, sample_rate: int, seed: int) -> np.ndarray:
    """
    Generates a realistic composite EEG signal based on a mixture of specified brain waves.
    
    Args:
        wave_names: List of wave names from the BRAIN_WAVE_CATALOG to composite.
        duration_ms: Duration of the signal in milliseconds.
        sample_rate: Sampling frequency in Hz (e.g., 256, 512, 1024).
        seed: Random seed for reproducible generation.
        
    Returns:
        A 1D numpy array containing the simulated voltage timeseries.
    """
    if sample_rate <= 0:
        raise ValueError("Sample rate must be positive.")
    if duration_ms <= 0:
        raise ValueError("Duration must be positive.")
        
    rng = np.random.default_rng(seed)
    num_samples = int((duration_ms / 1000.0) * sample_rate)
    t = np.linspace(0, duration_ms / 1000.0, num_samples, endpoint=False)
    
    # Base baseline drift (infra-slow pink noise)
    composite_signal = _generate_pink_noise(num_samples, rng) * 10.0 
    
    for w_name in wave_names:
        if w_name not in BRAIN_WAVE_CATALOG:
            logger.warning(f"Wave '{w_name}' not found in catalog. Skipping.")
            continue
            
        wave = BRAIN_WAVE_CATALOG[w_name]
        
        # Special transient cases
        if wave.name == "K-Complex":
            composite_signal += _generate_k_complex(num_samples, sample_rate, rng)
            continue
            
        if wave.name in ["Hippocampal SWR", "PGO Waves", "Sigma"]:
            # Phasic bursts
            burst_freq = rng.uniform(wave.freq_min, wave.freq_max)
            amplitude = rng.uniform(wave.amplitude_range[0], wave.amplitude_range[1])
            
            # Envelope to create bursts
            envelope_freq = rng.uniform(0.1, 1.0) # Burst rate
            envelope = (np.sin(2 * np.pi * envelope_freq * t) > 0.8).astype(float)
            
            # Smoothing the envelope
            window_len = max(3, int(sample_rate * 0.05))
            window = np.hanning(window_len)
            smoothed_env = np.convolve(envelope, window, mode='same') / np.sum(window)
            
            phase = rng.uniform(0, 2*np.pi)
            component = amplitude * np.sin(2 * np.pi * burst_freq * t + phase) * smoothed_env
            composite_signal += component
            continue
            
        # Standard continuous oscillatory components
        # We simulate a narrow-band process rather than a pure sine
        center_freq = (wave.freq_min + wave.freq_max) / 2.0
        bandwidth = (wave.freq_max - wave.freq_min) / 2.0
        
        # Instantenous frequency with brownian noise walk
        freq_noise = np.cumsum(rng.standard_normal(num_samples))
        # Normalize to [-1, 1]
        if np.max(np.abs(freq_noise)) > 0:
            freq_noise = freq_noise / np.max(np.abs(freq_noise))
            
        inst_freq = center_freq + (bandwidth * freq_noise)
        
        # Integrate frequency to get phase
        phase = 2 * np.pi * np.cumsum(inst_freq) / sample_rate
        initial_phase = rng.uniform(0, 2*np.pi)
        
        amplitude = rng.uniform(wave.amplitude_range[0], wave.amplitude_range[1])
        
        # Add amplitude modulation (1/f noise for natural look)
        amp_mod = _generate_pink_noise(num_samples, rng)
        # Scale to [0.5, 1.5] roughly
        amp_mod = 1.0 + (amp_mod * 0.2)
        amp_mod = np.clip(amp_mod, 0.1, 2.0)
        
        component = amplitude * np.sin(phase + initial_phase) * amp_mod
        composite_signal += component
        
    return composite_signal

# -----------------------------------------------------------------------------
# Interactions and State Modeling
# -----------------------------------------------------------------------------

def cross_frequency_coupling(slow_wave: str, fast_wave: str, modulation_index: float) -> float:
    """
    Computes a synthetic coupling strength metric between a slow phase and fast amplitude.
    Phase-Amplitude Coupling (PAC) is a key mechanism for brain state integration.
    
    Args:
        slow_wave: Name of the modulating slower frequency wave (e.g., 'Theta').
        fast_wave: Name of the modulated faster frequency wave (e.g., 'Gamma').
        modulation_index: Raw modulation strength observed [0.0, 1.0].
        
    Returns:
        Coupling strength float, normalized based on known physiological partnerships.
    """
    if slow_wave not in BRAIN_WAVE_CATALOG or fast_wave not in BRAIN_WAVE_CATALOG:
        return 0.0
        
    sw = BRAIN_WAVE_CATALOG[slow_wave]
    fw = BRAIN_WAVE_CATALOG[fast_wave]
    
    # Must actually be slower
    if sw.freq_max >= fw.freq_min:
        logger.debug(f"Invalid PAC pairing: {slow_wave} is not slower than {fast_wave}.")
        return 0.0
        
    # Check physiological plausibility
    plausible_coupling = 0.1
    if fast_wave in sw.cross_coupling_partners or slow_wave in fw.cross_coupling_partners:
        plausible_coupling = 1.0
        
    # Example physiological rule: optimal phase-amplitude coupling often occurs 
    # when the fast frequency is >5x the slow frequency.
    ratio = fw.freq_min / max(sw.freq_max, 0.01)
    ratio_multiplier = min(1.0, ratio / 5.0) 
    
    strength = modulation_index * plausible_coupling * ratio_multiplier
    return max(0.0, min(strength, 1.0))


def entrainment_compatibility(wave_a: str, wave_b: str) -> float:
    """
    Calculates how readily two wave frequencies can synchronize (entrain).
    Based on harmonic resonance theory. Harmonic integer ratios (e.g., 2:1, 3:1) 
    entrain easily.
    
    Returns:
        Float score [0.0, 1.0] indicating compatibility.
    """
    if wave_a not in BRAIN_WAVE_CATALOG or wave_b not in BRAIN_WAVE_CATALOG:
        return 0.0
        
    a = BRAIN_WAVE_CATALOG[wave_a]
    b = BRAIN_WAVE_CATALOG[wave_b]
    
    a_mid = (a.freq_min + a.freq_max) / 2.0
    b_mid = (b.freq_min + b.freq_max) / 2.0
    
    if a_mid == 0 or b_mid == 0:
        return 0.0
        
    high, low = max(a_mid, b_mid), min(a_mid, b_mid)
    
    # Exact match is perfect compatibility
    if math.isclose(high, low, rel_tol=0.1):
        return 1.0
        
    ratio = high / low
    closest_integer = round(ratio)
    
    # Deviation from a perfect integer harmonic
    deviation = abs(ratio - closest_integer)
    
    # Score decays exponentially with deviation from harmonic
    score = math.exp(-10.0 * deviation)
    
    # Higher order harmonics entrain less strongly
    score *= (1.0 / closest_integer)
    
    return max(0.0, min(score, 1.0))


def dominant_wave_for_state(cognitive_state: str) -> List[BrainWave]:
    """
    Retrieves the brain waves most strongly associated with a given cognitive or physiological state.
    
    Args:
        cognitive_state: String describing the state (e.g., "Deep Dreamless Sleep", "Flow State").
        
    Returns:
        List of BrainWave objects that prominently feature this state.
    """
    state_lower = cognitive_state.lower().strip()
    matches = []
    
    for wave in BRAIN_WAVE_CATALOG.values():
        wave_states = [s.lower() for s in wave.cognitive_states]
        # Partial substring match (e.g., "sleep" matches "rem sleep")
        if any(state_lower in s for s in wave_states):
            matches.append(wave)
            
    # Sort by how specific the match is (fewer general states -> higher specificity)
    matches.sort(key=lambda w: len(w.cognitive_states))
    return matches


# -----------------------------------------------------------------------------
# Markov Transition Matrix Models
# -----------------------------------------------------------------------------

# This matrix represents the baseline transition probabilities between major states.
# In a real brain, transitions are state-dependent, but this serves as a 1st-order Markov chain.
# Unlisted transitions default to 0.001 (rare jump).
_WAVE_TRANSITION_MATRIX_RAW = {
    "Delta": {"Delta": 0.8, "Cortical Slow Oscillation": 0.1, "Theta": 0.08, "Infra-low": 0.02},
    "Cortical Slow Oscillation": {"Cortical Slow Oscillation": 0.6, "Delta": 0.3, "Sigma": 0.05, "Hippocampal SWR": 0.05},
    "Theta": {"Theta": 0.6, "Delta": 0.1, "Alpha": 0.15, "Hippocampal Theta": 0.1, "PGO Waves": 0.05},
    "Alpha": {"Alpha": 0.5, "Theta": 0.2, "PDR": 0.1, "Low Beta": 0.1, "Beta": 0.1},
    "Low Beta": {"Low Beta": 0.5, "Alpha": 0.2, "Beta": 0.2, "Mu": 0.1},
    "Beta": {"Beta": 0.6, "Low Beta": 0.15, "High Beta": 0.15, "Gamma": 0.1},
    "High Beta": {"High Beta": 0.5, "Beta": 0.3, "Gamma": 0.15, "Kappa": 0.05},
    "Gamma": {"Gamma": 0.6, "Beta": 0.2, "High Gamma": 0.15, "Theta": 0.05}, # Gamma often rides Theta
    "High Gamma": {"High Gamma": 0.4, "Gamma": 0.4, "Hyper-Gamma": 0.1, "Theta": 0.1},
    "Hyper-Gamma": {"Hyper-Gamma": 0.3, "High Gamma": 0.4, "Lambda": 0.2, "Epsilon": 0.1},
    "Lambda": {"Lambda": 0.2, "Hyper-Gamma": 0.3, "Epsilon": 0.5}, # Lambda rides Epsilon
    "Epsilon": {"Epsilon": 0.7, "Lambda": 0.1, "Infra-low": 0.2},
    "Mu": {"Mu": 0.6, "Low Beta": 0.2, "Alpha": 0.2},
    "Sigma": {"Sigma": 0.3, "Cortical Slow Oscillation": 0.4, "K-Complex": 0.3},
    "K-Complex": {"Delta": 0.5, "Cortical Slow Oscillation": 0.4, "Sigma": 0.1} # Transients die out quickly
}

# Normalize to ensure rows sum to 1.0, construct strict matrix
WAVE_TRANSITION_MATRIX: Dict[str, Dict[str, float]] = {}

def _initialize_transition_matrix():
    all_names = list(BRAIN_WAVE_CATALOG.keys())
    for source in all_names:
        WAVE_TRANSITION_MATRIX[source] = {}
        row_sum = 0.0
        
        for target in all_names:
            val = _WAVE_TRANSITION_MATRIX_RAW.get(source, {}).get(target, 0.005) # Default baseline
            if source == target and val == 0.005: 
                val = 0.5 # Default self-transition preference
            WAVE_TRANSITION_MATRIX[source][target] = val
            row_sum += val
            
        # Normalize
        for target in all_names:
            WAVE_TRANSITION_MATRIX[source][target] /= row_sum

_initialize_transition_matrix()

def wave_transition_probability(current_wave: str, target_wave: str) -> float:
    """
    Returns the Markov transition probability from current_wave to target_wave.
    
    Args:
        current_wave: Starting wave state.
        target_wave: Target wave state.
        
    Returns:
        Probability float [0.0, 1.0]. Returns 0.0 if waves are unrecognized.
    """
    if current_wave not in WAVE_TRANSITION_MATRIX:
        return 0.0
    return WAVE_TRANSITION_MATRIX[current_wave].get(target_wave, 0.0)


def sample_wave_composition(activity_type: str, seed: int) -> Dict[str, float]:
    """
    Generates a power spectrum composition (mixing weights) of brain waves suitable 
    for a given macro-level human activity.
    
    Args:
        activity_type: High-level activity (e.g., "creative_problem_solving", "deep_sleep").
        seed: Random seed for deterministic variation around standard baselines.
        
    Returns:
        Dictionary mapping wave names to relative power weights (summing to 1.0).
    """
    rng = np.random.default_rng(seed)
    
    # Baselines for activity types
    activity_profiles = {
        "deep_sleep": {"Delta": 0.70, "Cortical Slow Oscillation": 0.20, "Infra-low": 0.05, "Sigma": 0.05},
        "rem_sleep": {"Theta": 0.50, "PGO Waves": 0.20, "Hippocampal Theta": 0.20, "Gamma": 0.10},
        "meditation": {"Alpha": 0.40, "Theta": 0.30, "Gamma": 0.10, "Epsilon": 0.10, "Hyper-Gamma": 0.10},
        "focused_work": {"Beta": 0.40, "Low Beta": 0.30, "Gamma": 0.20, "Kappa": 0.10},
        "creative_problem_solving": {"Alpha": 0.30, "Theta": 0.30, "Gamma": 0.30, "Beta": 0.10},
        "exercise": {"High Beta": 0.30, "Beta": 0.30, "Mu": 0.20, "Gamma": 0.20}, # Mu desynchronization implies active motor
        "social_interaction": {"Beta": 0.30, "Alpha": 0.20, "Mu": 0.30, "Gamma": 0.20}, # Empathy/Mu rhythm active
        "resting": {"Alpha": 0.50, "PDR": 0.20, "Low Beta": 0.15, "Theta": 0.15},
        "learning": {"Gamma": 0.40, "Theta": 0.30, "Hippocampal Theta": 0.20, "Beta": 0.10} # Theta-Gamma coupling crucial for learning
    }
    
    base_profile = activity_profiles.get(activity_type.lower().strip())
    
    if not base_profile:
        logger.warning(f"Unknown activity type '{activity_type}', defaulting to 'resting'.")
        base_profile = activity_profiles["resting"]
        
    # Apply variance based on seed
    composition = {}
    total = 0.0
    
    for wave, base_weight in base_profile.items():
        # ±20% variation
        noise = rng.uniform(-0.2, 0.2)
        adjusted_weight = max(0.01, base_weight * (1.0 + noise))
        composition[wave] = adjusted_weight
        total += adjusted_weight
        
    # Normalize to 1.0
    return {wave: weight / total for wave, weight in composition.items()}
