---
title: About
---

# About Deapplefy

Deapplefy is an automated documentation generator for Apple's private frameworks.

## How it works

1. **Discovery**: Scans `/System/Library/PrivateFrameworks` for framework binaries
2. **Decompilation**: Uses radare2 to extract symbols and pseudo-code
3. **Documentation**: Leverages AI to generate human-readable documentation
4. **Publishing**: Automatically generates this static site using Hugo

## Technology Stack

- **Hugo**: Static site generator
- **Hextra**: Documentation theme
- **radare2**: Reverse engineering framework
- **Python**: Automation scripts
- **AI**: Documentation generation
