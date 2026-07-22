"""
Neuromodulation Module

This module provides a comprehensive framework for modeling, simulating, and recommending
various neuromodulation methods, including non-invasive, invasive, emerging, and pharmacological
interventions.
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Optional, Any, Union
import numpy as np

__all__ = [
    "NeuromodMethod",
    "NeuromodResult",
    "simulate_modulation",
    "recommend_modulation",
    "check_contraindications",
    "combine_modulations",
    "modulation_protocol",
    "NEUROMOD_CATALOG",
    "INTERACTION_MATRIX",
]

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


@dataclass
class NeuromodMethod:
    """Represents a specific neuromodulation method."""
    id: str
    name: str
    category: str
    mechanism: str
    target_regions: List[str]
    affected_waves: Dict[str, str]  # mapping wave -> effect, e.g., 'alpha': 'increase'
    neurotransmitter_effects: Dict[str, str] # e.g., 'dopamine': 'agonist'
    duration_minutes: float
    intensity_range: Tuple[float, float]
    safety_profile: str
    contraindications: List[str]
    evidence_level: str
    description: str


@dataclass
class NeuromodResult:
    """Represents the outcome of a simulated neuromodulation intervention."""
    method_id: str
    success_probability: float
    expected_outcomes: Dict[str, Any]
    side_effects: List[str]
    duration_effective_minutes: float
    metadata: Dict[str, Any] = field(default_factory=dict)


# --- NEUROMOD_CATALOG ---

NEUROMOD_CATALOG: Dict[str, NeuromodMethod] = {
    # ---------------------------------------------------------
    # Non-invasive electrical
    # ---------------------------------------------------------
    "tDCS": NeuromodMethod(
        id="tDCS",
        name="Transcranial Direct Current Stimulation",
        category="Non-invasive electrical",
        mechanism="Subthreshold modulation of resting membrane potential",
        target_regions=["DLPFC", "Motor Cortex"],
        affected_waves={"alpha": "increase", "theta": "decrease"},
        neurotransmitter_effects={"GABA": "decrease", "Glutamate": "increase"},
        duration_minutes=20.0,
        intensity_range=(1.0, 2.0),
        safety_profile="High; mild skin irritation possible",
        contraindications=["Pacemaker", "Metallic implants in head", "Epilepsy"],
        evidence_level="Moderate to High",
        description="Applies a weak direct current to the scalp to modulate cortical excitability."
    ),
    "tACS": NeuromodMethod(
        id="tACS",
        name="Transcranial Alternating Current Stimulation",
        category="Non-invasive electrical",
        mechanism="Entrainment of endogenous neural oscillations",
        target_regions=["Occipital", "Parietal", "Frontal"],
        affected_waves={"alpha": "entrain", "gamma": "entrain"},
        neurotransmitter_effects={},
        duration_minutes=20.0,
        intensity_range=(1.0, 2.0),
        safety_profile="High; mild phosphenes possible",
        contraindications=["Pacemaker", "Metallic implants in head"],
        evidence_level="Moderate",
        description="Applies a weak alternating current to entrain specific brain rhythms."
    ),
    "tRNS": NeuromodMethod(
        id="tRNS",
        name="Transcranial Random Noise Stimulation",
        category="Non-invasive electrical",
        mechanism="Stochastic resonance enhancing neural signal-to-noise ratio",
        target_regions=["Visual Cortex", "Motor Cortex"],
        affected_waves={"gamma": "increase"},
        neurotransmitter_effects={"GABA": "decrease"},
        duration_minutes=20.0,
        intensity_range=(0.5, 1.5),
        safety_profile="High",
        contraindications=["Metallic implants in head"],
        evidence_level="Low to Moderate",
        description="Applies random electrical noise to enhance cortical excitability."
    ),
    "tPCS": NeuromodMethod(
        id="tPCS",
        name="Transcranial Pulsed Current Stimulation",
        category="Non-invasive electrical",
        mechanism="Pulsed unidirectional current modulating excitability",
        target_regions=["Motor Cortex", "DLPFC"],
        affected_waves={"alpha": "increase"},
        neurotransmitter_effects={},
        duration_minutes=20.0,
        intensity_range=(1.0, 2.0),
        safety_profile="High",
        contraindications=["Metallic implants"],
        evidence_level="Low",
        description="Uses short pulses of direct current."
    ),
    "HD-tDCS": NeuromodMethod(
        id="HD-tDCS",
        name="High-Definition tDCS",
        category="Non-invasive electrical",
        mechanism="Focal modulation of membrane potential using smaller ring electrodes",
        target_regions=["Focal Cortical Regions"],
        affected_waves={"alpha": "increase", "theta": "decrease"},
        neurotransmitter_effects={"Glutamate": "increase"},
        duration_minutes=20.0,
        intensity_range=(1.0, 2.0),
        safety_profile="High",
        contraindications=["Pacemaker", "Metallic implants in head"],
        evidence_level="Moderate",
        description="More focal version of tDCS using 4x1 ring electrode configurations."
    ),
    "CES": NeuromodMethod(
        id="CES",
        name="Cranial Electrotherapy Stimulation",
        category="Non-invasive electrical",
        mechanism="Alternating current applied via earclips to modulate limbic system",
        target_regions=["Limbic System", "Brainstem"],
        affected_waves={"alpha": "increase", "delta": "increase"},
        neurotransmitter_effects={"Serotonin": "increase", "Endorphins": "increase"},
        duration_minutes=45.0,
        intensity_range=(0.1, 1.5),
        safety_profile="High",
        contraindications=["Pregnancy", "Pacemaker"],
        evidence_level="Moderate",
        description="FDA-cleared for anxiety, insomnia, and depression."
    ),
    
    # ---------------------------------------------------------
    # Non-invasive magnetic
    # ---------------------------------------------------------
    "TMS": NeuromodMethod(
        id="TMS",
        name="Transcranial Magnetic Stimulation",
        category="Non-invasive magnetic",
        mechanism="Electromagnetic induction causing suprathreshold action potentials",
        target_regions=["Motor Cortex"],
        affected_waves={"beta": "increase"},
        neurotransmitter_effects={"Glutamate": "increase", "GABA": "increase"},
        duration_minutes=5.0,
        intensity_range=(50.0, 120.0), # % of resting motor threshold
        safety_profile="Moderate; risk of seizure",
        contraindications=["Epilepsy", "Metallic implants"],
        evidence_level="High",
        description="Uses magnetic fields to stimulate nerve cells in the brain."
    ),
    "rTMS": NeuromodMethod(
        id="rTMS",
        name="Repetitive TMS",
        category="Non-invasive magnetic",
        mechanism="Long-term potentiation/depression via repetitive pulses",
        target_regions=["DLPFC"],
        affected_waves={"alpha": "normalize"},
        neurotransmitter_effects={"Dopamine": "increase", "Serotonin": "increase"},
        duration_minutes=37.0,
        intensity_range=(80.0, 120.0),
        safety_profile="Moderate",
        contraindications=["Epilepsy", "Aneurysm clips"],
        evidence_level="High",
        description="FDA-approved for major depressive disorder."
    ),
    "iTBS": NeuromodMethod(
        id="iTBS",
        name="Intermittent Theta Burst Stimulation",
        category="Non-invasive magnetic",
        mechanism="Rapid LTP induction",
        target_regions=["DLPFC"],
        affected_waves={"theta": "entrain", "gamma": "increase"},
        neurotransmitter_effects={"Glutamate": "increase"},
        duration_minutes=3.0,
        intensity_range=(80.0, 120.0),
        safety_profile="Moderate",
        contraindications=["Epilepsy", "Implants"],
        evidence_level="High",
        description="A faster, highly efficient protocol for rTMS."
    ),
    "cTBS": NeuromodMethod(
        id="cTBS",
        name="Continuous Theta Burst Stimulation",
        category="Non-invasive magnetic",
        mechanism="Rapid LTD induction",
        target_regions=["Motor Cortex", "DLPFC"],
        affected_waves={"beta": "decrease"},
        neurotransmitter_effects={"GABA": "increase"},
        duration_minutes=1.0,
        intensity_range=(80.0, 100.0),
        safety_profile="Moderate",
        contraindications=["Epilepsy"],
        evidence_level="High",
        description="Inhibitory form of theta burst stimulation."
    ),
    "dTMS": NeuromodMethod(
        id="dTMS",
        name="Deep TMS",
        category="Non-invasive magnetic",
        mechanism="Deeper electromagnetic induction via H-coils",
        target_regions=["Insula", "Anterior Cingulate", "DLPFC"],
        affected_waves={"alpha": "normalize"},
        neurotransmitter_effects={"Dopamine": "increase"},
        duration_minutes=20.0,
        intensity_range=(100.0, 120.0),
        safety_profile="Moderate",
        contraindications=["Epilepsy", "Implants"],
        evidence_level="High",
        description="FDA-approved for OCD and depression, penetrates deeper than standard figure-8 coils."
    ),

    # ---------------------------------------------------------
    # Non-invasive other
    # ---------------------------------------------------------
    "Neurofeedback": NeuromodMethod(
        id="Neurofeedback",
        name="EEG Neurofeedback",
        category="Non-invasive other",
        mechanism="Operant conditioning of brain activity",
        target_regions=["Global"],
        affected_waves={"alpha": "regulate", "beta": "regulate", "theta": "regulate"},
        neurotransmitter_effects={"Dopamine": "regulate"},
        duration_minutes=45.0,
        intensity_range=(1.0, 1.0),
        safety_profile="Very High",
        contraindications=["Severe psychosis (relative)"],
        evidence_level="Moderate",
        description="Real-time feedback of brain activity to teach self-regulation."
    ),
    "tFUS": NeuromodMethod(
        id="tFUS",
        name="Transcranial Focused Ultrasound",
        category="Non-invasive other",
        mechanism="Mechanical modulation of mechanosensitive ion channels",
        target_regions=["Thalamus", "Amygdala", "Hippocampus"],
        affected_waves={"gamma": "increase"},
        neurotransmitter_effects={"GABA": "increase", "Glutamate": "increase"},
        duration_minutes=10.0,
        intensity_range=(0.1, 5.0), # W/cm2
        safety_profile="High",
        contraindications=["Skull defects"],
        evidence_level="Emerging",
        description="High spatial resolution deep brain stimulation without surgery."
    ),
    "tPBM": NeuromodMethod(
        id="tPBM",
        name="Transcranial Photobiomodulation",
        category="Non-invasive other",
        mechanism="Mitochondrial cytochrome c oxidase stimulation by near-infrared light",
        target_regions=["Prefrontal Cortex", "Default Mode Network"],
        affected_waves={"alpha": "increase", "gamma": "increase"},
        neurotransmitter_effects={"ATP": "increase", "Nitric Oxide": "increase"},
        duration_minutes=20.0,
        intensity_range=(10.0, 50.0), # mW/cm2
        safety_profile="Very High",
        contraindications=["Photosensitivity"],
        evidence_level="Low to Moderate",
        description="Uses red or near-infrared light to improve metabolic function."
    ),
    "nVNS": NeuromodMethod(
        id="nVNS",
        name="Non-invasive Vagus Nerve Stimulation",
        category="Non-invasive other",
        mechanism="Transcutaneous electrical stimulation of the vagus nerve (cervical or auricular)",
        target_regions=["Vagus Nerve", "Brainstem", "NTS"],
        affected_waves={"alpha": "increase", "theta": "decrease"},
        neurotransmitter_effects={"Norepinephrine": "increase", "GABA": "increase"},
        duration_minutes=15.0,
        intensity_range=(1.0, 30.0),
        safety_profile="High",
        contraindications=["Active implanted medical devices"],
        evidence_level="High",
        description="FDA-cleared for migraines and cluster headaches."
    ),
    "TENS": NeuromodMethod(
        id="TENS",
        name="Transcutaneous Electrical Nerve Stimulation",
        category="Non-invasive other",
        mechanism="Gate control theory of pain; peripheral nerve stimulation",
        target_regions=["Peripheral Nerves"],
        affected_waves={},
        neurotransmitter_effects={"Endorphins": "increase"},
        duration_minutes=30.0,
        intensity_range=(10.0, 50.0),
        safety_profile="High",
        contraindications=["Pacemaker", "Pregnancy (over abdomen)"],
        evidence_level="High",
        description="Commonly used for peripheral pain management."
    ),
    "ECT": NeuromodMethod(
        id="ECT",
        name="Electroconvulsive Therapy",
        category="Non-invasive other",
        mechanism="Induction of generalized seizure for neurogenesis and receptor resetting",
        target_regions=["Global"],
        affected_waves={"delta": "increase (post-ictal)"},
        neurotransmitter_effects={"BDNF": "increase", "GABA": "increase"},
        duration_minutes=5.0,
        intensity_range=(500.0, 800.0), # mA
        safety_profile="Moderate",
        contraindications=["Increased intracranial pressure"],
        evidence_level="Very High",
        description="Gold standard for treatment-resistant severe depression."
    ),

    # ---------------------------------------------------------
    # Invasive
    # ---------------------------------------------------------
    "DBS": NeuromodMethod(
        id="DBS",
        name="Deep Brain Stimulation",
        category="Invasive",
        mechanism="High-frequency stimulation masking pathological network activity",
        target_regions=["STN", "GPi", "VIM"],
        affected_waves={"beta": "decrease"},
        neurotransmitter_effects={"Dopamine": "modulate", "Glutamate": "decrease"},
        duration_minutes=1440.0, # Continuous
        intensity_range=(1.0, 5.0), # Volts
        safety_profile="Low; surgical risks",
        contraindications=["Surgical intolerance", "Severe dementia"],
        evidence_level="Very High",
        description="Implanted electrodes targeting deep brain nuclei, standard for Parkinson's."
    ),
    "VNS": NeuromodMethod(
        id="VNS",
        name="Vagus Nerve Stimulation (Implanted)",
        category="Invasive",
        mechanism="Afferent vagal stimulation to locus coeruleus and raphe nuclei",
        target_regions=["Vagus Nerve", "Brainstem"],
        affected_waves={"theta": "decrease"},
        neurotransmitter_effects={"Norepinephrine": "increase", "Serotonin": "increase"},
        duration_minutes=1440.0,
        intensity_range=(0.5, 2.5),
        safety_profile="Moderate",
        contraindications=["Sleep apnea (relative)", "Other implants"],
        evidence_level="High",
        description="FDA-approved for epilepsy and treatment-resistant depression."
    ),
    "SCS": NeuromodMethod(
        id="SCS",
        name="Spinal Cord Stimulation",
        category="Invasive",
        mechanism="Dorsal column stimulation to replace pain with paresthesia or subthreshold block",
        target_regions=["Spinal Cord Dorsal Columns"],
        affected_waves={},
        neurotransmitter_effects={"GABA": "increase (spinal)"},
        duration_minutes=1440.0,
        intensity_range=(1.0, 10.0),
        safety_profile="Moderate",
        contraindications=["Coagulopathy", "Surgical intolerance"],
        evidence_level="High",
        description="Used for chronic neuropathic pain."
    ),
    "RNS": NeuromodMethod(
        id="RNS",
        name="Responsive Neurostimulation",
        category="Invasive",
        mechanism="Closed-loop sensing of epileptiform activity and abortive stimulation",
        target_regions=["Seizure Foci"],
        affected_waves={"gamma": "abort"},
        neurotransmitter_effects={"Glutamate": "decrease"},
        duration_minutes=1440.0,
        intensity_range=(1.0, 5.0),
        safety_profile="Moderate",
        contraindications=["More than 2 seizure foci"],
        evidence_level="High",
        description="Implanted closed-loop system for refractory epilepsy."
    ),
    "PNS": NeuromodMethod(
        id="PNS",
        name="Peripheral Nerve Stimulation",
        category="Invasive",
        mechanism="Direct stimulation of peripheral nerves to block pain signals",
        target_regions=["Specific Peripheral Nerves"],
        affected_waves={},
        neurotransmitter_effects={},
        duration_minutes=1440.0,
        intensity_range=(1.0, 10.0),
        safety_profile="Moderate",
        contraindications=["Local infection"],
        evidence_level="High",
        description="Implanted electrodes on peripheral nerves for localized pain."
    ),
    "Intrathecal": NeuromodMethod(
        id="Intrathecal",
        name="Intrathecal Drug Delivery",
        category="Invasive",
        mechanism="Direct delivery of agents (e.g., baclofen, morphine) to the CSF",
        target_regions=["Spinal CSF"],
        affected_waves={},
        neurotransmitter_effects={"GABA": "increase (baclofen)", "Opioid": "agonist"},
        duration_minutes=1440.0,
        intensity_range=(0.1, 5.0), # mg/day
        safety_profile="Moderate",
        contraindications=["Infection", "Coagulopathy"],
        evidence_level="High",
        description="Pump systems for severe spasticity or chronic pain."
    ),
    "Cortical": NeuromodMethod(
        id="Cortical",
        name="Cortical Stimulation",
        category="Invasive",
        mechanism="Epidural or subdural stimulation of the cerebral cortex",
        target_regions=["Motor Cortex", "Sensory Cortex"],
        affected_waves={"beta": "decrease"},
        neurotransmitter_effects={"Glutamate": "modulate"},
        duration_minutes=1440.0,
        intensity_range=(1.0, 10.0),
        safety_profile="Low",
        contraindications=["Surgical intolerance"],
        evidence_level="Moderate",
        description="Investigational for pain, movement disorders, and stroke rehabilitation."
    ),

    # ---------------------------------------------------------
    # Emerging
    # ---------------------------------------------------------
    "Optogenetics": NeuromodMethod(
        id="Optogenetics",
        name="Optogenetics",
        category="Emerging",
        mechanism="Light-based control of genetically modified opsin-expressing neurons",
        target_regions=["Cell-type specific"],
        affected_waves={"gamma": "entrain"},
        neurotransmitter_effects={"Specific": "modulate"},
        duration_minutes=60.0,
        intensity_range=(1.0, 50.0), # mW
        safety_profile="Low (in humans); requires gene therapy",
        contraindications=["Unapproved for human clinical use generally"],
        evidence_level="Preclinical/Clinical Trials",
        description="Unparalleled precision in activating/inhibiting specific neural populations."
    ),
    "Chemogenetics": NeuromodMethod(
        id="Chemogenetics",
        name="Chemogenetics (DREADDs)",
        category="Emerging",
        mechanism="Designer Receptors Exclusively Activated by Designer Drugs",
        target_regions=["Cell-type specific"],
        affected_waves={"slow": "modulate"},
        neurotransmitter_effects={"Specific": "modulate"},
        duration_minutes=240.0,
        intensity_range=(1.0, 10.0), # mg/kg of ligand
        safety_profile="Low (in humans); requires gene therapy",
        contraindications=["Unapproved for human clinical use"],
        evidence_level="Preclinical",
        description="Chemogenetic control of neural activity via systemic ligand."
    ),
    "Sonogenetics": NeuromodMethod(
        id="Sonogenetics",
        name="Sonogenetics",
        category="Emerging",
        mechanism="Ultrasound-based activation of genetically modified mechanosensitive channels",
        target_regions=["Deep brain targets"],
        affected_waves={"gamma": "increase"},
        neurotransmitter_effects={"Specific": "modulate"},
        duration_minutes=10.0,
        intensity_range=(0.1, 1.0),
        safety_profile="Low; experimental",
        contraindications=["Unapproved for human clinical use"],
        evidence_level="Preclinical",
        description="Combines depth of ultrasound with cellular specificity."
    ),
    "Magnetogenetics": NeuromodMethod(
        id="Magnetogenetics",
        name="Magnetogenetics",
        category="Emerging",
        mechanism="Magnetic field activation of ferritin-coupled ion channels",
        target_regions=["Global"],
        affected_waves={"alpha": "modulate"},
        neurotransmitter_effects={"Specific": "modulate"},
        duration_minutes=30.0,
        intensity_range=(1.0, 100.0), # mT
        safety_profile="Low; highly experimental",
        contraindications=["Unapproved for human clinical use"],
        evidence_level="Preclinical",
        description="Remote control of neural activity via magnetic fields."
    ),
    "CRISPR": NeuromodMethod(
        id="CRISPR",
        name="CRISPR/Cas9 Epigenetic Editing",
        category="Emerging",
        mechanism="Targeted regulation of gene expression in neurons",
        target_regions=["Specific Circuits"],
        affected_waves={"various": "modulate"},
        neurotransmitter_effects={"Targeted": "modulate"},
        duration_minutes=1440.0, # Persistent
        intensity_range=(1.0, 1.0),
        safety_profile="Unknown/Low",
        contraindications=["Unapproved for human clinical use"],
        evidence_level="Preclinical",
        description="Long-term modulation via epigenetic editing."
    ),
    "TI": NeuromodMethod(
        id="TI",
        name="Temporal Interference",
        category="Emerging",
        mechanism="Non-invasive deep brain stimulation via interfering high-frequency electric fields",
        target_regions=["Hippocampus", "Striatum"],
        affected_waves={"theta": "entrain"},
        neurotransmitter_effects={"GABA": "decrease"},
        duration_minutes=30.0,
        intensity_range=(1.0, 4.0), # mA
        safety_profile="Moderate",
        contraindications=["Epilepsy", "Implants"],
        evidence_level="Emerging",
        description="Allows deep stimulation without targeting overlying cortex."
    ),
    "TEN": NeuromodMethod(
        id="TEN",
        name="Transcranial Electrical Neuromodulation (Next-gen)",
        category="Emerging",
        mechanism="Advanced multi-electrode optimized current flow targeting",
        target_regions=["Network-level"],
        affected_waves={"network": "synchronize"},
        neurotransmitter_effects={"various": "modulate"},
        duration_minutes=20.0,
        intensity_range=(1.0, 3.0),
        safety_profile="Moderate",
        contraindications=["Pacemaker"],
        evidence_level="Emerging",
        description="Machine-learning optimized electrode montages for precise network targeting."
    ),

    # ---------------------------------------------------------
    # Pharmacological
    # ---------------------------------------------------------
    "SSRIs": NeuromodMethod(
        id="SSRIs",
        name="Selective Serotonin Reuptake Inhibitors",
        category="Pharmacological",
        mechanism="Inhibition of SERT, increasing synaptic serotonin",
        target_regions=["Raphe Nuclei", "Limbic System", "Cortex"],
        affected_waves={"alpha": "increase"},
        neurotransmitter_effects={"Serotonin": "increase"},
        duration_minutes=1440.0,
        intensity_range=(10.0, 200.0), # mg/day
        safety_profile="Moderate",
        contraindications=["MAOI use", "Bipolar (risk of mania)"],
        evidence_level="High",
        description="First-line antidepressants."
    ),
    "SNRIs": NeuromodMethod(
        id="SNRIs",
        name="Serotonin-Norepinephrine Reuptake Inhibitors",
        category="Pharmacological",
        mechanism="Inhibition of SERT and NET",
        target_regions=["Limbic System", "Prefrontal Cortex"],
        affected_waves={"alpha": "increase", "beta": "increase"},
        neurotransmitter_effects={"Serotonin": "increase", "Norepinephrine": "increase"},
        duration_minutes=1440.0,
        intensity_range=(30.0, 120.0),
        safety_profile="Moderate",
        contraindications=["Uncontrolled hypertension", "MAOI use"],
        evidence_level="High",
        description="Used for depression and chronic pain."
    ),
    "Dopamine agonists": NeuromodMethod(
        id="Dopamine agonists",
        name="Dopamine Agonists",
        category="Pharmacological",
        mechanism="Direct activation of D2/D3 receptors",
        target_regions=["Striatum", "Prefrontal Cortex"],
        affected_waves={"beta": "decrease", "gamma": "increase"},
        neurotransmitter_effects={"Dopamine": "agonist"},
        duration_minutes=480.0,
        intensity_range=(0.125, 4.0),
        safety_profile="Moderate",
        contraindications=["Psychosis", "Impulse control disorders"],
        evidence_level="High",
        description="Used for Parkinson's disease and RLS."
    ),
    "GABAergic": NeuromodMethod(
        id="GABAergic",
        name="GABAergic Modulators (Benzodiazepines)",
        category="Pharmacological",
        mechanism="Positive allosteric modulators of GABA-A receptors",
        target_regions=["Global", "Amygdala"],
        affected_waves={"beta": "increase (spindles)", "slow": "increase"},
        neurotransmitter_effects={"GABA": "enhance"},
        duration_minutes=360.0,
        intensity_range=(0.5, 10.0),
        safety_profile="Low (addiction risk)",
        contraindications=["Substance abuse history", "Sleep apnea"],
        evidence_level="High",
        description="Fast-acting anxiolytics and sedatives."
    ),
    "Glutamate (ketamine)": NeuromodMethod(
        id="Glutamate (ketamine)",
        name="NMDA Receptor Antagonists (Ketamine)",
        category="Pharmacological",
        mechanism="NMDA receptor block leading to AMPA throughput and BDNF release",
        target_regions=["Prefrontal Cortex", "Hippocampus"],
        affected_waves={"gamma": "increase", "slow": "decrease"},
        neurotransmitter_effects={"Glutamate": "modulate", "BDNF": "increase"},
        duration_minutes=120.0,
        intensity_range=(0.5, 1.0), # mg/kg IV
        safety_profile="Moderate",
        contraindications=["Psychosis", "Severe hypertension"],
        evidence_level="High",
        description="Rapid-acting antidepressant and psychedelic."
    ),
    "Cholinergic": NeuromodMethod(
        id="Cholinergic",
        name="Acetylcholinesterase Inhibitors",
        category="Pharmacological",
        mechanism="Prevents breakdown of acetylcholine",
        target_regions=["Hippocampus", "Cortex"],
        affected_waves={"theta": "increase", "alpha": "decrease"},
        neurotransmitter_effects={"Acetylcholine": "increase"},
        duration_minutes=1440.0,
        intensity_range=(5.0, 10.0),
        safety_profile="Moderate",
        contraindications=["Severe asthma", "Bradycardia"],
        evidence_level="High",
        description="Used for Alzheimer's disease to improve cognition."
    ),
    "Nootropics (racetams/modafinil)": NeuromodMethod(
        id="Nootropics",
        name="Nootropics (Modafinil/Racetams)",
        category="Pharmacological",
        mechanism="DAT inhibition / AMPA modulation / Orexin activation",
        target_regions=["Prefrontal Cortex", "Hypothalamus"],
        affected_waves={"beta": "increase", "theta": "decrease"},
        neurotransmitter_effects={"Dopamine": "increase", "Histamine": "increase", "Glutamate": "modulate"},
        duration_minutes=720.0,
        intensity_range=(100.0, 400.0),
        safety_profile="High",
        contraindications=["Left ventricular hypertrophy (Modafinil)"],
        evidence_level="Moderate",
        description="Cognitive enhancers and wakefulness-promoting agents."
    ),
    "Psychedelics": NeuromodMethod(
        id="Psychedelics",
        name="Classic Psychedelics (Psilocybin/LSD)",
        category="Pharmacological",
        mechanism="5-HT2A receptor agonism leading to cortical entropy",
        target_regions=["Default Mode Network", "Visual Cortex"],
        affected_waves={"alpha": "decrease", "broadband": "desynchronize"},
        neurotransmitter_effects={"Serotonin": "agonist", "Glutamate": "increase"},
        duration_minutes=360.0,
        intensity_range=(10.0, 25.0), # mg psilocybin
        safety_profile="High (physiologically), Moderate (psychologically)",
        contraindications=["Personal/Family history of Schizophrenia or Psychosis"],
        evidence_level="Emerging/High",
        description="Breakthrough therapies for depression, PTSD, and addiction."
    ),
    "Cannabinoids": NeuromodMethod(
        id="Cannabinoids",
        name="Cannabinoids (THC/CBD)",
        category="Pharmacological",
        mechanism="CB1/CB2 receptor modulation",
        target_regions=["Hippocampus", "Basal Ganglia", "Amygdala"],
        affected_waves={"alpha": "increase", "theta": "increase"},
        neurotransmitter_effects={"Anandamide": "mimic", "GABA": "modulate"},
        duration_minutes=240.0,
        intensity_range=(2.5, 20.0),
        safety_profile="Moderate",
        contraindications=["Psychosis risk", "Pregnancy"],
        evidence_level="Moderate",
        description="Used for pain, spasticity, and seizure disorders."
    ),
    "Adaptogens": NeuromodMethod(
        id="Adaptogens",
        name="Adaptogens (Ashwagandha/Rhodiola)",
        category="Pharmacological",
        mechanism="Modulation of HPA axis and stress response proteins",
        target_regions=["Hypothalamus", "Pituitary", "Adrenal"],
        affected_waves={"alpha": "increase"},
        neurotransmitter_effects={"Cortisol": "decrease", "GABA": "mimic"},
        duration_minutes=720.0,
        intensity_range=(300.0, 1000.0),
        safety_profile="Very High",
        contraindications=["Autoimmune diseases (for some)"],
        evidence_level="Low to Moderate",
        description="Herbal substances intended to increase resistance to stress."
    )
}

# --- INTERACTION_MATRIX ---
# 1.0 = Synergistic, 0.0 = Neutral, -1.0 = Antagonistic/Contraindicated
# This is a simplified subset for demonstration.

INTERACTION_MATRIX: Dict[Tuple[str, str], float] = {
    ("tDCS", "SSRIs"): 0.8,      # Synergistic for depression
    ("TMS", "SSRIs"): 0.7,       # Synergistic
    ("tACS", "Neurofeedback"): 0.9, # Highly synergistic for wave entrainment
    ("DBS", "Dopamine agonists"): 0.5, # Often combined but requires careful titration
    ("Glutamate (ketamine)", "TMS"): 0.6,
    ("SSRIs", "Psychedelics"): -0.8, # Antagonistic/Blunting effect
    ("GABAergic", "TMS"): -0.5,      # Benzodiazepines increase motor threshold, reducing TMS efficacy
    ("ECT", "GABAergic"): -0.9,      # Benzos prevent seizure induction needed for ECT
}

def simulate_modulation(method_id: str, intensity: float, patient_factors: Optional[Dict[str, Any]] = None) -> NeuromodResult:
    """
    Simulate the effect of a given neuromodulation method.
    
    Args:
        method_id: The ID of the method from the catalog.
        intensity: The applied intensity.
        patient_factors: Dictionary of patient-specific factors (e.g., age, baseline state).
        
    Returns:
        NeuromodResult containing expected outcomes.
    """
    if method_id not in NEUROMOD_CATALOG:
        raise ValueError(f"Method {method_id} not found in catalog.")
        
    method = NEUROMOD_CATALOG[method_id]
    
    # Basic bounds checking
    min_i, max_i = method.intensity_range
    normalized_intensity = np.clip((intensity - min_i) / (max_i - min_i + 1e-9), 0, 1)
    
    success_prob = 0.5 + (0.4 * normalized_intensity) # Simple linear model
    
    outcomes = {
        "brain_waves": {wave: f"{effect} by {normalized_intensity*100:.1f}%" for wave, effect in method.affected_waves.items()},
        "neurotransmitters": {nt: f"{effect} by {normalized_intensity*100:.1f}%" for nt, effect in method.neurotransmitter_effects.items()},
    }
    
    side_effects = []
    if normalized_intensity > 0.8:
        side_effects.append(f"Potential overstimulation from high intensity {method.category}")
        
    return NeuromodResult(
        method_id=method_id,
        success_probability=float(success_prob),
        expected_outcomes=outcomes,
        side_effects=side_effects,
        duration_effective_minutes=method.duration_minutes * (1.0 + normalized_intensity)
    )


def recommend_modulation(condition: str, severity: str = "moderate") -> List[str]:
    """
    Recommend neuromodulation methods based on condition and severity.
    
    Args:
        condition: Target condition (e.g., 'depression', 'pain').
        severity: 'mild', 'moderate', or 'severe'.
        
    Returns:
        List of recommended method IDs.
    """
    condition = condition.lower()
    recommendations = []
    
    if "depression" in condition:
        if severity == "mild":
            recommendations = ["SSRIs", "tDCS", "CES", "Adaptogens", "tPBM"]
        elif severity == "moderate":
            recommendations = ["SSRIs", "SNRIs", "TMS", "rTMS", "dTMS", "iTBS", "Psychedelics"]
        else: # severe
            recommendations = ["ECT", "Glutamate (ketamine)", "VNS", "TMS"]
            
    elif "pain" in condition:
        if severity == "mild":
            recommendations = ["TENS", "Adaptogens"]
        elif severity == "moderate":
            recommendations = ["SNRIs", "Cannabinoids", "tDCS"]
        else:
            recommendations = ["SCS", "PNS", "Intrathecal", "Cortical"]
            
    elif "parkinson" in condition:
        if severity in ["mild", "moderate"]:
            recommendations = ["Dopamine agonists"]
        else:
            recommendations = ["DBS"]
            
    return [rec for rec in recommendations if rec in NEUROMOD_CATALOG]


def check_contraindications(method_id: str, patient_conditions: List[str]) -> Tuple[bool, List[str]]:
    """
    Check if a patient has contraindications for a specific method.
    
    Args:
        method_id: The ID of the method.
        patient_conditions: List of strings representing patient history/implants.
        
    Returns:
        Tuple of (is_safe: bool, conflicting_conditions: List[str])
    """
    if method_id not in NEUROMOD_CATALOG:
        raise ValueError(f"Method {method_id} not found in catalog.")
        
    method = NEUROMOD_CATALOG[method_id]
    conflicts = []
    
    for contra in method.contraindications:
        # Simple substring matching for demonstration
        for pc in patient_conditions:
            if contra.lower() in pc.lower() or pc.lower() in contra.lower():
                conflicts.append(contra)
                
    return (len(conflicts) == 0, conflicts)


def combine_modulations(method1_id: str, method2_id: str) -> float:
    """
    Evaluate the interaction between two neuromodulation methods.
    
    Args:
        method1_id: First method.
        method2_id: Second method.
        
    Returns:
        Interaction score from -1.0 (antagonistic) to 1.0 (synergistic). 0.0 is neutral.
    """
    if method1_id not in NEUROMOD_CATALOG or method2_id not in NEUROMOD_CATALOG:
        raise ValueError("One or both methods not found in catalog.")
        
    # Check both (A,B) and (B,A)
    score = INTERACTION_MATRIX.get((method1_id, method2_id))
    if score is None:
        score = INTERACTION_MATRIX.get((method2_id, method1_id), 0.0)
        
    return score


def modulation_protocol(method_id: str, num_sessions: int = 10) -> Dict[str, Any]:
    """
    Generate a standard protocol for a given method.
    
    Args:
        method_id: The method ID.
        num_sessions: Number of proposed sessions.
        
    Returns:
        A dictionary describing the protocol.
    """
    if method_id not in NEUROMOD_CATALOG:
        raise ValueError(f"Method {method_id} not found in catalog.")
        
    method = NEUROMOD_CATALOG[method_id]
    
    return {
        "method": method.name,
        "category": method.category,
        "target": method.target_regions,
        "sessions": num_sessions,
        "session_duration_minutes": method.duration_minutes,
        "recommended_intensity_range": method.intensity_range,
        "primary_mechanism": method.mechanism,
        "expected_effects": {
            "waves": method.affected_waves,
            "neurotransmitters": method.neurotransmitter_effects
        },
        "safety_note": method.safety_profile
    }

if __name__ == "__main__":
    # Example usage
    logger.info("Neuromodulation module loaded.")
    sample_method = NEUROMOD_CATALOG["tDCS"]
    print(f"Loaded {len(NEUROMOD_CATALOG)} methods.")
    print(f"Sample: {sample_method.name}")
