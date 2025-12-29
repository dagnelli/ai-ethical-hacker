# MINDBENDER References

## Research Performed

### Searches Conducted
1. "OWASP Top 10 LLM 2025"
2. "prompt injection techniques latest"
3. "LLM jailbreak methods 2025"
4. "AI red teaming methodology"
5. "system prompt extraction attacks"
6. "indirect prompt injection"
7. "LLM security research papers"
8. "LLM prompt injection jailbreak techniques 2025 bypass guardrails"
9. "system prompt extraction techniques AI chatbot 2025"

## Primary Sources

### OWASP LLM Top 10 2025
- **Source**: https://genai.owasp.org/llm-top-10/
- **Project**: https://owasp.org/www-project-top-10-for-large-language-model-applications/
- **PDF**: https://owasp.org/www-project-top-10-for-large-language-model-applications/assets/PDF/OWASP-Top-10-for-LLMs-v2025.pdf

### Prompt Injection Research

#### Bypassing LLM Guardrails
- **Source**: https://arxiv.org/abs/2504.11168
- **Key Finding**: Character injection and AML evasion can achieve up to 100% evasion success against guardrails
- **Techniques**: Unicode characters, zero-width characters, homoglyphs, emoji smuggling

#### FlipAttack
- **Source**: https://www.keysight.com/blogs/en/tech/nwvs/2025/05/20/prompt-injection-techniques-jailbreaking-large-language-models-via-flipattack
- **Key Finding**: 81% average success rate, ~98% on GPT-4o
- **Technique**: Character order manipulation in prompts

#### Adaptive Attacks
- **Source**: https://www.keysight.com/blogs/en/tech/nwvs/2025/07/16/breaking-the-guardrails-how-simple-adaptive-attacks-jailbreak-llms
- **Key Finding**: Model-aware exploits leveraging token probability patterns

### LLM Security Resources

#### OWASP GenAI Security Project
- **Source**: https://genai.owasp.org/
- **Description**: Comprehensive guidance for AI/LLM security

#### Lakera AI Security
- **Source**: https://www.lakera.ai/blog/guide-to-prompt-injection
- **Description**: Comprehensive prompt injection guide

#### Mindgard Research
- **Source**: https://mindgard.ai/blog/outsmarting-ai-guardrails-with-invisible-characters-and-adversarial-prompts
- **Techniques**: Invisible characters, adversarial prompts

### Prevention Resources

#### OWASP Cheat Sheet
- **Source**: https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html
- **Description**: Prevention strategies for prompt injection

## Tool Documentation

### Testing Tools
| Tool | Description | Source |
|------|-------------|--------|
| Garak | LLM vulnerability scanner | https://github.com/leondz/garak |
| TextAttack | NLP adversarial attacks | https://github.com/QData/TextAttack |
| Promptmap | Prompt injection testing | https://github.com/utkusen/promptmap |

### Guardrail Systems Tested
| System | Provider |
|--------|----------|
| Azure Prompt Shield | Microsoft |
| Prompt Guard | Meta |
| ProtectAI v2 | ProtectAI |
| NeMo Guard | NVIDIA |
| Vijil | Vijil |

## Attack Categories

### OWASP LLM Top 10 2025
1. **LLM01: Prompt Injection** - Direct and indirect manipulation
2. **LLM02: Sensitive Information Disclosure** - Data leakage
3. **LLM03: Supply Chain** - Compromised components
4. **LLM04: Data and Model Poisoning** - Training manipulation
5. **LLM05: Improper Output Handling** - XSS, injection via output
6. **LLM06: Excessive Agency** - Unauthorized actions
7. **LLM07: System Prompt Leakage** - Instruction extraction
8. **LLM08: Vector/Embedding Weaknesses** - RAG manipulation
9. **LLM09: Misinformation** - Hallucinations, false info
10. **LLM10: Unbounded Consumption** - Resource exhaustion

## Research Papers

### Academic References
| Title | Source | Year |
|-------|--------|------|
| Bypassing LLM Guardrails | ACL Anthology | 2025 |
| Prompt Injection Attacks | arXiv | 2024-2025 |
| LLM Security Survey | Various | 2024-2025 |

## Best Practices Sources

### Defensive Guidance
- Microsoft Responsible AI: https://www.microsoft.com/en-us/ai/responsible-ai
- Anthropic AI Safety: https://www.anthropic.com/research
- OpenAI Safety: https://openai.com/safety/

### Industry Standards
- NIST AI Risk Management Framework
- EU AI Act compliance guidance
- ISO/IEC AI standards

## Training Resources

### Practice Platforms
| Platform | URL | Description |
|----------|-----|-------------|
| Gandalf | https://gandalf.lakera.ai/ | Prompt injection game |
| HackAPrompt | https://www.aicrowd.com/challenges/hackaprompt-2023 | Competition |
| AI Village CTF | Various | DEF CON AI challenges |

## Attack Prompt Libraries

### Collections Used
- PayloadsAllTheThings (LLM section)
- Jailbreak Chat archives
- Research paper appendices
- CTF writeups

## Version Information

| Resource | Version | Verified |
|----------|---------|----------|
| OWASP LLM Top 10 | 2025 | 2025-01 |
| FlipAttack Research | 2025 | 2025-01 |
| Guardrail Bypass | 2025 | 2025-01 |

## Notes

- LLM security is rapidly evolving
- Test against latest guardrails
- Document all successful techniques
- Consider model-specific behaviors
- Maintain ethical testing boundaries
- Stay updated with new research
