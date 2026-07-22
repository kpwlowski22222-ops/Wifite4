from dataclasses import dataclass, field
from typing import Dict, List, Optional
import math

@dataclass
class BrainRegion:
    id: str
    name: str
    lobe: str
    hemisphere: str
    function_list: List[str]
    neurotransmitter_primary: str
    connected_regions: Dict[str, float]
    wave_affinity: List[str]
    blood_flow_baseline: float
    metabolic_rate: float
    brodmann_area: Optional[int] = None

@dataclass
class NeuralNetwork:
    name: str
    regions: List[str]
    function: str
    connectivity_strength: float

BRAIN_REGIONS: Dict[str, BrainRegion] = {}
NEURAL_NETWORKS: Dict[str, NeuralNetwork] = {}

def _add_region(r: BrainRegion):
    BRAIN_REGIONS[r.id] = r

def _add_network(n: NeuralNetwork):
    NEURAL_NETWORKS[n.name] = n

# --- BRODMANN AREAS ---
_add_region(BrainRegion("BA1", "Primary Somatosensory Cortex", "Parietal", "Both", ["Somatosensation"], "Glutamate", {}, ["Alpha"], 50.0, 1.2, 1))
_add_region(BrainRegion("BA2", "Primary Somatosensory Cortex", "Parietal", "Both", ["Somatosensation"], "Glutamate", {}, ["Alpha"], 50.0, 1.2, 2))
_add_region(BrainRegion("BA3", "Primary Somatosensory Cortex", "Parietal", "Both", ["Somatosensation"], "Glutamate", {}, ["Alpha"], 50.0, 1.2, 3))
_add_region(BrainRegion("BA4", "Primary Motor Cortex", "Frontal", "Both", ["Voluntary Movement"], "Glutamate", {"BA6": 0.8}, ["Beta", "Mu"], 55.0, 1.3, 4))
_add_region(BrainRegion("BA5", "Somatosensory Association Cortex", "Parietal", "Both", ["Stereognosis", "Spatial memory"], "Glutamate", {"BA7": 0.7}, ["Alpha", "Beta"], 48.0, 1.1, 5))
_add_region(BrainRegion("BA6", "Premotor Cortex", "Frontal", "Both", ["Motor planning", "Sensory guidance of movement"], "Glutamate", {"BA4": 0.9, "BA8": 0.6}, ["Beta"], 52.0, 1.2, 6))
_add_region(BrainRegion("BA7", "Somatosensory Association Cortex", "Parietal", "Both", ["Visuomotor coordination"], "Glutamate", {"BA5": 0.7}, ["Alpha", "Theta"], 49.0, 1.1, 7))
_add_region(BrainRegion("BA8", "Frontal Eye Fields", "Frontal", "Both", ["Saccadic eye movements"], "Glutamate", {"BA6": 0.6}, ["Beta"], 50.0, 1.2, 8))
_add_region(BrainRegion("BA9", "Dorsolateral Prefrontal Cortex", "Frontal", "Both", ["Working memory", "Executive function"], "Dopamine", {"BA46": 0.8, "BA10": 0.7}, ["Gamma"], 60.0, 1.5, 9))
_add_region(BrainRegion("BA10", "Anterior Prefrontal Cortex", "Frontal", "Both", ["Strategic processes", "Memory retrieval"], "Dopamine", {"BA9": 0.7}, ["Gamma", "Theta"], 58.0, 1.4, 10))
_add_region(BrainRegion("BA11", "Orbitofrontal Cortex", "Frontal", "Both", ["Decision making", "Reward processing"], "Dopamine", {"Amygdala": 0.8}, ["Theta", "Delta"], 55.0, 1.3, 11))
_add_region(BrainRegion("BA12", "Orbitofrontal Cortex", "Frontal", "Both", ["Reward processing"], "Dopamine", {}, ["Theta"], 54.0, 1.3, 12))
_add_region(BrainRegion("BA13", "Insular Cortex", "Insula", "Both", ["Interoception", "Emotion"], "Serotonin", {"Amygdala": 0.7}, ["Theta"], 56.0, 1.4, 13))
_add_region(BrainRegion("BA14", "Insular Cortex", "Insula", "Both", ["Visceral processing"], "Serotonin", {}, ["Theta"], 56.0, 1.4, 14))
_add_region(BrainRegion("BA15", "Anterior Temporal Lobe", "Temporal", "Both", ["Auditory processing"], "Glutamate", {}, ["Alpha"], 50.0, 1.2, 15))
_add_region(BrainRegion("BA16", "Insular Cortex", "Insula", "Both", ["Pain processing", "Emotion"], "Serotonin", {}, ["Theta"], 56.0, 1.4, 16))
_add_region(BrainRegion("BA17", "Primary Visual Cortex", "Occipital", "Both", ["Visual processing"], "Glutamate", {"BA18": 0.9}, ["Gamma"], 65.0, 1.6, 17))
_add_region(BrainRegion("BA18", "Secondary Visual Cortex", "Occipital", "Both", ["Visual association"], "Glutamate", {"BA17": 0.9, "BA19": 0.8}, ["Gamma"], 62.0, 1.5, 18))
_add_region(BrainRegion("BA19", "Associative Visual Cortex", "Occipital", "Both", ["Visual processing", "Feature extraction"], "Glutamate", {"BA18": 0.8}, ["Gamma"], 60.0, 1.4, 19))
_add_region(BrainRegion("BA20", "Inferior Temporal Gyrus", "Temporal", "Both", ["Visual object recognition"], "Glutamate", {}, ["Alpha", "Beta"], 55.0, 1.3, 20))
_add_region(BrainRegion("BA21", "Middle Temporal Gyrus", "Temporal", "Both", ["Semantic memory processing"], "Glutamate", {}, ["Alpha"], 54.0, 1.3, 21))
_add_region(BrainRegion("BA22", "Superior Temporal Gyrus (Wernicke's)", "Temporal", "Left", ["Language comprehension"], "Glutamate", {"BA44": 0.8, "BA45": 0.8}, ["Beta", "Gamma"], 58.0, 1.4, 22))
_add_region(BrainRegion("BA23", "Ventral Posterior Cingulate", "Limbic", "Both", ["Memory", "Emotion"], "Glutamate", {"BA24": 0.6}, ["Theta"], 56.0, 1.3, 23))
_add_region(BrainRegion("BA24", "Ventral Anterior Cingulate", "Limbic", "Both", ["Emotion regulation"], "Serotonin", {"Amygdala": 0.7, "BA23": 0.6}, ["Theta"], 57.0, 1.4, 24))
_add_region(BrainRegion("BA25", "Subgenual Area", "Limbic", "Both", ["Mood regulation", "Depression link"], "Serotonin", {"Amygdala": 0.8, "Hypothalamus": 0.7}, ["Theta", "Delta"], 60.0, 1.5, 25))
_add_region(BrainRegion("BA26", "Ectosplenial Area", "Limbic", "Both", ["Autobiographical memory"], "Glutamate", {}, ["Theta"], 50.0, 1.2, 26))
_add_region(BrainRegion("BA27", "Piriform Cortex", "Limbic", "Both", ["Olfaction"], "Glutamate", {}, ["Theta"], 48.0, 1.1, 27))
_add_region(BrainRegion("BA28", "Ventral Entorhinal Cortex", "Limbic", "Both", ["Memory", "Navigation"], "Acetylcholine", {"Hippocampus": 0.9}, ["Theta", "Gamma"], 55.0, 1.3, 28))
_add_region(BrainRegion("BA29", "Retrosplenial Cingulate Cortex", "Limbic", "Both", ["Episodic memory", "Spatial navigation"], "Glutamate", {"Hippocampus": 0.8}, ["Theta"], 54.0, 1.3, 29))
_add_region(BrainRegion("BA30", "Subicular Cortex", "Limbic", "Both", ["Memory retrieval"], "Glutamate", {}, ["Theta"], 53.0, 1.3, 30))
_add_region(BrainRegion("BA31", "Dorsal Posterior Cingulate", "Limbic", "Both", ["Visuospatial processing"], "Glutamate", {}, ["Theta", "Alpha"], 54.0, 1.3, 31))
_add_region(BrainRegion("BA32", "Dorsal Anterior Cingulate", "Limbic", "Both", ["Cognitive control", "Error detection"], "Dopamine", {"BA24": 0.8}, ["Theta", "Beta"], 58.0, 1.4, 32))
_add_region(BrainRegion("BA33", "Anterior Cingulate", "Limbic", "Both", ["Emotion", "Pain"], "Serotonin", {}, ["Theta"], 55.0, 1.3, 33))
_add_region(BrainRegion("BA34", "Dorsal Entorhinal Cortex", "Limbic", "Both", ["Memory", "Navigation"], "Acetylcholine", {"Hippocampus": 0.9}, ["Theta", "Gamma"], 55.0, 1.3, 34))
_add_region(BrainRegion("BA35", "Perirhinal Cortex", "Limbic", "Both", ["Familiarity", "Object memory"], "Acetylcholine", {"Hippocampus": 0.8}, ["Theta"], 54.0, 1.3, 35))
_add_region(BrainRegion("BA36", "Parahippocampal Cortex", "Limbic", "Both", ["Scene recognition", "Spatial memory"], "Glutamate", {"Hippocampus": 0.8}, ["Theta"], 54.0, 1.3, 36))
_add_region(BrainRegion("BA37", "Fusiform Gyrus", "Temporal", "Both", ["Face recognition", "Word form recognition"], "Glutamate", {}, ["Alpha", "Beta"], 56.0, 1.4, 37))
_add_region(BrainRegion("BA38", "Temporopolar Area", "Temporal", "Both", ["Semantic memory", "Emotion"], "Glutamate", {"Amygdala": 0.7}, ["Theta", "Alpha"], 55.0, 1.3, 38))
_add_region(BrainRegion("BA39", "Angular Gyrus", "Parietal", "Left", ["Language", "Number processing", "Spatial cognition", "Memory retrieval"], "Glutamate", {"BA40": 0.7, "BA22": 0.6}, ["Alpha", "Beta"], 57.0, 1.4, 39))
_add_region(BrainRegion("BA40", "Supramarginal Gyrus", "Parietal", "Left", ["Phonological processing", "Language"], "Glutamate", {"BA39": 0.7}, ["Alpha", "Beta"], 56.0, 1.4, 40))
_add_region(BrainRegion("BA41", "Primary Auditory Cortex", "Temporal", "Both", ["Auditory processing"], "Glutamate", {"BA42": 0.9}, ["Gamma", "Beta"], 60.0, 1.5, 41))
_add_region(BrainRegion("BA42", "Secondary Auditory Cortex", "Temporal", "Both", ["Auditory processing"], "Glutamate", {"BA41": 0.9, "BA22": 0.8}, ["Gamma", "Beta"], 58.0, 1.4, 42))
_add_region(BrainRegion("BA43", "Primary Gustatory Cortex", "Parietal", "Both", ["Taste processing"], "Glutamate", {"Insula": 0.7}, ["Alpha", "Theta"], 52.0, 1.2, 43))
_add_region(BrainRegion("BA44", "Broca's Area (Pars Opercularis)", "Frontal", "Left", ["Speech production", "Syntactic processing"], "Glutamate", {"BA45": 0.9, "BA22": 0.8}, ["Beta", "Gamma"], 59.0, 1.4, 44))
_add_region(BrainRegion("BA45", "Broca's Area (Pars Triangularis)", "Frontal", "Left", ["Semantic processing", "Speech production"], "Glutamate", {"BA44": 0.9}, ["Beta", "Gamma"], 58.0, 1.4, 45))
_add_region(BrainRegion("BA46", "Dorsolateral Prefrontal Cortex", "Frontal", "Both", ["Working memory", "Executive function"], "Dopamine", {"BA9": 0.8}, ["Gamma"], 60.0, 1.5, 46))
_add_region(BrainRegion("BA47", "Inferior Prefrontal Gyrus", "Frontal", "Both", ["Language syntax", "Semantics"], "Glutamate", {"BA45": 0.7}, ["Beta"], 55.0, 1.3, 47))
_add_region(BrainRegion("BA48", "Retrosubicular Area", "Limbic", "Both", ["Memory integration"], "Glutamate", {}, ["Theta"], 50.0, 1.2, 48))
_add_region(BrainRegion("BA49", "Parasubiculum", "Limbic", "Both", ["Spatial navigation"], "Glutamate", {}, ["Theta"], 50.0, 1.2, 49))
_add_region(BrainRegion("BA52", "Parainsular Area", "Temporal", "Both", ["Auditory processing", "Vestibular function"], "Glutamate", {}, ["Alpha"], 50.0, 1.2, 52))
# Note: BA50 and BA51 are generally not well-defined or used in modern cytoarchitectonics, but we'll include placeholders to reach 52.
_add_region(BrainRegion("BA50", "BA50 Placeholder", "Unknown", "Both", ["Unknown"], "Unknown", {}, ["Unknown"], 45.0, 1.0, 50))
_add_region(BrainRegion("BA51", "BA51 Placeholder", "Unknown", "Both", ["Unknown"], "Unknown", {}, ["Unknown"], 45.0, 1.0, 51))

# --- SUBCORTICAL STRUCTURES ---
_add_region(BrainRegion("Hippocampus", "Hippocampus", "Limbic", "Both", ["Episodic memory", "Spatial navigation", "Learning"], "Glutamate", {"Amygdala": 0.7, "BA28": 0.9, "BA34": 0.9}, ["Theta", "Gamma"], 65.0, 1.6))
_add_region(BrainRegion("Amygdala", "Amygdala", "Limbic", "Both", ["Fear processing", "Emotion regulation", "Reward"], "Glutamate", {"Hippocampus": 0.7, "BA11": 0.8, "BA25": 0.8}, ["Theta", "Gamma"], 68.0, 1.7))
_add_region(BrainRegion("Thalamus", "Thalamus", "Subcortical", "Both", ["Sensory relay", "Motor relay", "Consciousness"], "Glutamate", {"BA1": 0.6, "BA4": 0.6, "BA17": 0.6}, ["Alpha", "Beta"], 70.0, 1.8))
_add_region(BrainRegion("Hypothalamus", "Hypothalamus", "Subcortical", "Both", ["Homeostasis", "Endocrine regulation", "Autonomic control"], "Various", {"Pituitary": 0.9, "Amygdala": 0.6}, ["Delta", "Theta"], 60.0, 1.5))
_add_region(BrainRegion("Caudate", "Caudate Nucleus", "Basal Ganglia", "Both", ["Motor control", "Learning", "Reward"], "Dopamine", {"Putamen": 0.8, "Thalamus": 0.6}, ["Beta"], 62.0, 1.5))
_add_region(BrainRegion("Putamen", "Putamen", "Basal Ganglia", "Both", ["Motor control", "Motor learning"], "Dopamine", {"Caudate": 0.8, "Globus_Pallidus": 0.8}, ["Beta", "Gamma"], 62.0, 1.5))
_add_region(BrainRegion("Globus_Pallidus", "Globus Pallidus", "Basal Ganglia", "Both", ["Voluntary movement regulation"], "GABA", {"Thalamus": 0.7, "Subthalamic_Nucleus": 0.8}, ["Beta"], 60.0, 1.4))
_add_region(BrainRegion("Nucleus_Accumbens", "Nucleus Accumbens", "Basal Ganglia", "Both", ["Reward", "Pleasure", "Addiction", "Motivation"], "Dopamine", {"VTA": 0.9, "Prefrontal_Cortex": 0.8}, ["Gamma", "Theta"], 65.0, 1.6))
_add_region(BrainRegion("VTA", "Ventral Tegmental Area", "Midbrain", "Both", ["Reward", "Motivation", "Cognition"], "Dopamine", {"Nucleus_Accumbens": 0.9, "Prefrontal_Cortex": 0.7}, ["Theta", "Gamma"], 58.0, 1.4))
_add_region(BrainRegion("Substantia_Nigra", "Substantia Nigra", "Midbrain", "Both", ["Motor control", "Reward", "Addiction"], "Dopamine", {"Putamen": 0.9, "Caudate": 0.8}, ["Beta", "Gamma"], 60.0, 1.5))
_add_region(BrainRegion("Cerebellum", "Cerebellum", "Hindbrain", "Both", ["Motor coordination", "Balance", "Cognitive functions"], "Glutamate", {"Thalamus": 0.7, "Pons": 0.8}, ["Gamma"], 75.0, 1.9))
_add_region(BrainRegion("Medulla", "Medulla Oblongata", "Brainstem", "Both", ["Autonomic functions", "Breathing", "Heart rate"], "Various", {"Pons": 0.9}, ["Delta"], 80.0, 2.0))
_add_region(BrainRegion("Pons", "Pons", "Brainstem", "Both", ["Sleep", "Respiration", "Swallowing", "Bladder control"], "Various", {"Medulla": 0.9, "Midbrain": 0.9, "Cerebellum": 0.8}, ["Delta", "Theta"], 75.0, 1.9))
_add_region(BrainRegion("Midbrain", "Midbrain", "Brainstem", "Both", ["Vision", "Hearing", "Motor control", "Sleep/wake", "Arousal"], "Dopamine", {"Pons": 0.9, "Thalamus": 0.8}, ["Alpha", "Beta"], 70.0, 1.8))
_add_region(BrainRegion("Pineal_Gland", "Pineal Gland", "Subcortical", "Both", ["Melatonin secretion", "Circadian rhythms"], "Melatonin", {"Hypothalamus": 0.7}, ["Delta"], 50.0, 1.2))
_add_region(BrainRegion("Locus_Coeruleus", "Locus Coeruleus", "Brainstem", "Both", ["Arousal", "Attention", "Stress response"], "Norepinephrine", {"Cortex": 0.8, "Amygdala": 0.8}, ["Beta", "Gamma"], 60.0, 1.5))
_add_region(BrainRegion("Raphe_Nuclei", "Raphe Nuclei", "Brainstem", "Both", ["Mood", "Sleep", "Pain"], "Serotonin", {"Cortex": 0.7, "Limbic_System": 0.8}, ["Alpha", "Theta"], 58.0, 1.4))
_add_region(BrainRegion("PAG", "Periaqueductal Gray", "Midbrain", "Both", ["Pain modulation", "Defensive behavior"], "Endorphins", {"Amygdala": 0.7, "Hypothalamus": 0.6}, ["Theta"], 62.0, 1.5))
_add_region(BrainRegion("Insula", "Insula", "Insular", "Both", ["Consciousness", "Emotion", "Homeostasis", "Empathy"], "Various", {"BA13": 0.9, "Amygdala": 0.7}, ["Theta", "Gamma"], 65.0, 1.6))
_add_region(BrainRegion("Claustrum", "Claustrum", "Subcortical", "Both", ["Consciousness integration", "Multisensory integration"], "Glutamate", {"Cortex": 0.9}, ["Gamma"], 60.0, 1.5))


# --- NEURAL NETWORKS ---
_add_network(NeuralNetwork("DMN", ["BA9", "BA10", "BA23", "BA24", "BA29", "BA30", "BA31", "BA39", "Hippocampus"], "Default Mode Network: active during rest and mind-wandering.", 0.85))
_add_network(NeuralNetwork("CEN", ["BA9", "BA46", "BA39", "BA40"], "Central Executive Network: active during demanding cognitive tasks.", 0.88))
_add_network(NeuralNetwork("Salience", ["BA32", "Insula", "Amygdala", "Thalamus"], "Salience Network: detecting and filtering salient stimuli.", 0.82))
_add_network(NeuralNetwork("DAN", ["BA8", "BA6", "BA7", "BA39"], "Dorsal Attention Network: top-down, voluntary allocation of attention.", 0.78))
_add_network(NeuralNetwork("VAN", ["BA40", "BA47", "BA22", "Insula"], "Ventral Attention Network: bottom-up, stimulus-driven attention.", 0.75))
_add_network(NeuralNetwork("Frontoparietal", ["BA9", "BA46", "BA7", "BA39", "BA40"], "Frontoparietal Network: cognitive control and working memory.", 0.86))
_add_network(NeuralNetwork("Limbic", ["Hippocampus", "Amygdala", "Hypothalamus", "BA24", "BA38", "BA28", "BA34", "BA35", "BA36"], "Limbic Network: emotion, memory, and arousal.", 0.90))
_add_network(NeuralNetwork("Visual", ["BA17", "BA18", "BA19"], "Visual Network: processing of visual information.", 0.92))
_add_network(NeuralNetwork("Auditory", ["BA41", "BA42", "BA22"], "Auditory Network: processing of auditory information.", 0.91))
_add_network(NeuralNetwork("Sensorimotor", ["BA1", "BA2", "BA3", "BA4", "BA6"], "Sensorimotor Network: sensory processing and motor control.", 0.89))
_add_network(NeuralNetwork("Language", ["BA44", "BA45", "BA22", "BA39", "BA40", "BA47"], "Language Network: comprehension and production of language.", 0.87))
_add_network(NeuralNetwork("Mirror_Neuron", ["BA44", "BA40", "BA6"], "Mirror Neuron Network: action observation and imitation.", 0.80))

# --- CONNECTIVITY MATRIX ---
CONNECTIVITY_MATRIX: Dict[str, Dict[str, float]] = {
    # Generate some realistic weights based on connected_regions and network overlaps
}
# Precompute connectivity from defined connected_regions
for r1_id, r1 in BRAIN_REGIONS.items():
    if r1_id not in CONNECTIVITY_MATRIX:
        CONNECTIVITY_MATRIX[r1_id] = {}
    for r2_id, weight in r1.connected_regions.items():
        CONNECTIVITY_MATRIX[r1_id][r2_id] = weight
        if r2_id in BRAIN_REGIONS:
            if r2_id not in CONNECTIVITY_MATRIX:
                CONNECTIVITY_MATRIX[r2_id] = {}
            if r1_id not in CONNECTIVITY_MATRIX[r2_id]:
                CONNECTIVITY_MATRIX[r2_id][r1_id] = weight * 0.9 # Slightly asymmetric

# Add intrinsic network connectivity
for net in NEURAL_NETWORKS.values():
    for i, r1 in enumerate(net.regions):
        for j, r2 in enumerate(net.regions):
            if i != j:
                if r1 in BRAIN_REGIONS and r2 in BRAIN_REGIONS:
                    if r1 not in CONNECTIVITY_MATRIX: CONNECTIVITY_MATRIX[r1] = {}
                    if r2 not in CONNECTIVITY_MATRIX: CONNECTIVITY_MATRIX[r2] = {}
                    
                    # Network connectivity overrides if stronger
                    current = CONNECTIVITY_MATRIX[r1].get(r2, 0.0)
                    if net.connectivity_strength > current:
                        CONNECTIVITY_MATRIX[r1][r2] = net.connectivity_strength
                        CONNECTIVITY_MATRIX[r2][r1] = net.connectivity_strength


# --- FUNCTIONS ---
def get_regions_for_function(func: str) -> List[BrainRegion]:
    """Return all brain regions associated with a specific function."""
    func_lower = func.lower()
    return [
        region for region in BRAIN_REGIONS.values()
        if any(func_lower in f.lower() for f in region.function_list)
    ]

def get_connected_regions(region_id: str, threshold: float = 0.5) -> Dict[str, float]:
    """Get connected regions above a given threshold."""
    if region_id not in CONNECTIVITY_MATRIX:
        return {}
    return {
        r_id: weight
        for r_id, weight in CONNECTIVITY_MATRIX[region_id].items()
        if weight >= threshold
    }

def simulate_activation_spread(start_region_id: str, initial_activation: float = 1.0, steps: int = 3) -> Dict[str, float]:
    """Simulate spread of neural activation from a source region."""
    if start_region_id not in BRAIN_REGIONS:
        raise ValueError(f"Unknown region: {start_region_id}")

    activations = {start_region_id: initial_activation}
    
    for _ in range(steps):
        new_activations = activations.copy()
        for active_region, level in activations.items():
            if active_region in CONNECTIVITY_MATRIX:
                for target, weight in CONNECTIVITY_MATRIX[active_region].items():
                    # Spread activation attenuated by weight and distance factor
                    spread_amount = level * weight * 0.5
                    new_activations[target] = min(1.0, new_activations.get(target, 0.0) + spread_amount)
        activations = new_activations
        
    return activations

def get_network_for_task(task_type: str) -> Optional[NeuralNetwork]:
    """Retrieve the primary neural network associated with a task type."""
    task_type = task_type.lower()
    for net in NEURAL_NETWORKS.values():
        if task_type in net.name.lower() or task_type in net.function.lower():
            return net
    # Some basic heuristics
    if "memory" in task_type or "emotion" in task_type:
        return NEURAL_NETWORKS["Limbic"]
    if "attention" in task_type:
        return NEURAL_NETWORKS["DAN"]
    if "rest" in task_type or "default" in task_type:
        return NEURAL_NETWORKS["DMN"]
    if "motor" in task_type or "movement" in task_type:
        return NEURAL_NETWORKS["Sensorimotor"]
    if "visual" in task_type:
        return NEURAL_NETWORKS["Visual"]
    if "audio" in task_type or "hear" in task_type:
        return NEURAL_NETWORKS["Auditory"]
    if "language" in task_type or "speech" in task_type:
        return NEURAL_NETWORKS["Language"]
    
    return None

def compute_regional_activity(region_id: str, inputs: Dict[str, float]) -> float:
    """
    Compute activity for a given region based on inputs from other regions.
    inputs is a dict of {source_region_id: activation_level}
    """
    if region_id not in BRAIN_REGIONS:
        return 0.0
        
    region = BRAIN_REGIONS[region_id]
    total_input = 0.0
    
    # Intrinsic baseline activity
    activity = region.blood_flow_baseline / 100.0 
    
    for src_id, act_level in inputs.items():
        if src_id in CONNECTIVITY_MATRIX and region_id in CONNECTIVITY_MATRIX[src_id]:
            weight = CONNECTIVITY_MATRIX[src_id][region_id]
            total_input += act_level * weight
            
    # Sigmoid activation function
    activity += 1.0 / (1.0 + math.exp(-(total_input - 1.0)))
    return min(1.0, max(0.0, activity))

# EOF