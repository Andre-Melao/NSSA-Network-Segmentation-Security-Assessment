"""Shared data models and boundary contracts.

Contains only pure data models (frozen dataclasses), the SPM parser, and the
APU/OAE boundary contracts.

Import rules: apu/ and oae/ may import from shared/; apu/ and oae/ must never
import from each other; shared/ must never import from apu/ or oae/.
"""
