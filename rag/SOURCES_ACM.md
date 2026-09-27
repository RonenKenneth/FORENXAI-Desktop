# RAG sources: ACM references

The 22 documents in `rag/_sources/` that the retrieval stage uses, in the ACM
Reference Format (alphabetical by first author, numbered). "Used by" says how
each one reaches a recommendation, measured by calling `retrieve()` for all
16 classes after the index rebuild of 26 Sep 2026.

| Used by | Meaning |
|---|---|
| passages | Numbered sections are in the search pool and are quoted in recommendations |
| controls | NIST SP 800-53 controls, read from the CPRT catalogue by control ID |
| profile | Cited by the attack profiles and playbooks in `rag/knowledge/` and returned with them |
| caveats | Cited in `interpretability/caveats.md`, which every recommendation loads |

## References

[1] Daniel Arp, Erwin Quiring, Feargus Pendlebury, Alexander Warnecke, Fabio Pierazzi, Christian Wressnegger, Lorenzo Cavallaro, and Konrad Rieck. 2024. Pitfalls in Machine Learning for Computer Security. *Communications of the ACM* 67, 11 (Nov. 2024), 104–112. https://doi.org/10.1145/3643456 — *passages*

[2] Recep Arslan, Turgut Ozseven, Metin Mutlu Aydin, and Yasin Celik. 2026. Cybersecurity in Intelligent Transportation Systems: A Comparative Study on AI-Based Anomaly Detection and Threat Analysis. *Mechatronics and Intelligent Transportation Systems* 5, 1 (2026), 11–30. https://doi.org/10.56578/mits050102 — *passages*

[3] M. A. Bilal, I. Ul Islam, S. Idrees, M. Qasim, M. J. Khan, and J. Khan. 2026. Dataset-Centric Evaluation of Federated Intrusion Detection Models in IoT Networks. *Scientific Reports* (2026). https://doi.org/10.1038/s41598-025-32567-w — *profile*

[4] Marta Catillo, Andrea Del Vecchio, Antonio Pecchia, and Umberto Villano. 2022. Transferability of Machine Learning Models Learned from Public Intrusion Detection Datasets: The CICIDS2017 Case Study. *Software Quality Journal* (2022). https://doi.org/10.1007/s11219-022-09587-0 — *profile*

[5] Tianqi Chen and Carlos Guestrin. 2016. XGBoost: A Scalable Tree Boosting System. In *Proceedings of the 22nd ACM SIGKDD International Conference on Knowledge Discovery and Data Mining (KDD '16)*. ACM, San Francisco, CA, USA, 785–794. https://doi.org/10.1145/2939672.2939785 — *passages*

[6] H. I. Cosar, C. Arisoy, and H. Ulutas. 2024. Intrusion Detection on CSE-CIC-IDS2018 Dataset Using Machine Learning Methods. *Artificial Intelligence Theory and Applications* 4, 2 (2024), 143–154. — *profile*

[7] Cybersecurity and Infrastructure Security Agency. 2024. *Federal Government Cybersecurity Incident and Vulnerability Response Playbooks*. CISA, Washington, DC. — *passages*

[8] M. Gombar. 2026. From Detection to Triage: Explainable Suspicious Flow Prioritization for Multiclass Intrusion Detection Using CSE-CIC-IDS2018. *Electronics* 15, 12 (2026), 2739. https://doi.org/10.3390/electronics15122739 — *profile*

[9] S. S. Iyengar, Seyedsina Nabavirazavi, Yashas Hariprasad, Prasad HB, and C. Krishna Mohan. 2025. *Artificial Intelligence in Practice: Theory and Application for Cyber Security and Forensics*. Springer Nature, Cham, Switzerland. https://doi.org/10.1007/978-3-031-89327-8 — *passages*

[10] Joint Task Force. 2025. *Security and Privacy Controls for Information Systems and Organizations*. NIST Special Publication 800-53, Revision 5.2.0. National Institute of Standards and Technology, Gaithersburg, MD. https://doi.org/10.6028/NIST.SP.800-53r5 — *controls*

[11] Karen Kent, Suzanne Chevalier, Tim Grance, and Hung Dang. 2006. *Guide to Integrating Forensic Techniques into Incident Response*. NIST Special Publication 800-86. National Institute of Standards and Technology, Gaithersburg, MD. https://doi.org/10.6028/NIST.SP.800-86 — *passages, baseline*

[12] Jeremy Licata, Rebecca McWhite, Laura Calloway, Dylan Gilbert, Meghan Anderson, Julie Snyder, and Jeremy Miller. 2026. *Developing Security, Privacy, and Cybersecurity Supply Chain Risk Management Plans for Systems*. NIST Special Publication 800-18r2. National Institute of Standards and Technology, Gaithersburg, MD. https://doi.org/10.6028/NIST.SP.800-18r2 — *passages*

[13] Scott M. Lundberg, Gabriel Erion, Hugh Chen, Alex DeGrave, Jordan M. Prutkin, Bala Nair, Ronit Katz, Jonathan Himmelfarb, Nisha Bansal, and Su-In Lee. 2020. From Local Explanations to Global Understanding with Explainable AI for Trees. *Nature Machine Intelligence* 2, 1 (2020), 56–67. https://doi.org/10.1038/s42256-019-0138-9 — *caveats*

[14] Kerry McKay and David Cooper. 2019. *Guidelines for the Selection, Configuration, and Use of Transport Layer Security (TLS) Implementations*. NIST Special Publication 800-52r2. National Institute of Standards and Technology, Gaithersburg, MD. https://doi.org/10.6028/NIST.SP.800-52r2 — *passages*

[15] Ian Miller. 2001. *Protection Against a Variant of the Tiny Fragment Attack*. RFC 3128. Internet Engineering Task Force. https://doi.org/10.17487/RFC3128 — *passages*

[16] National Institute of Standards and Technology. 2023. *Artificial Intelligence Risk Management Framework (AI RMF 1.0)*. NIST AI 100-1. National Institute of Standards and Technology, Gaithersburg, MD. https://doi.org/10.6028/NIST.AI.100-1 — *passages*

[17] Alex Nelson, Sanjay Rekhi, Murugiah Souppaya, and Karen Scarfone. 2025. *Incident Response Recommendations and Considerations for Cybersecurity Risk Management*. NIST Special Publication 800-61r3. National Institute of Standards and Technology, Gaithersburg, MD. https://doi.org/10.6028/NIST.SP.800-61r3 — *passages, baseline*

[18] Open Worldwide Application Security Project. 2025. *OWASP Top 10:2025 – Web Application Security Risks*. OWASP Foundation. — *passages*

[19] Kirsty Paine, Ollie Whitehouse, James Sellwood, and Andrew Shaw. 2023. *Indicators of Compromise (IoCs) and Their Role in Attack Defence*. RFC 9424. Internet Engineering Task Force. https://doi.org/10.17487/RFC9424 — *passages*

[20] Iman Sharafaldin, Arash Habibi Lashkari, and Ali A. Ghorbani. 2018. Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization. In *Proceedings of the 4th International Conference on Information Systems Security and Privacy (ICISSP 2018)*. SciTePress, 108–116. https://doi.org/10.5220/0006639801080116 — *profile*

[21] Alejandro Villafranca, Ivan Tasic, and Maria-Dolores Cano. 2026. TRUSTLab Dataset: A Real-World CICFlowMeter Dataset for IoT/Edge Intrusion Detection. *Frontiers in Computer Science* 8 (2026), 1803271. https://doi.org/10.3389/fcomp.2026.1803271 — *profile*

[22] G. Paul Ziemba, Darren Reed, and Paul Traina. 1995. *Security Considerations for IP Fragment Filtering*. RFC 1858. Internet Engineering Task Force. https://doi.org/10.17487/RFC1858 — *passages*

Check before submitting: full given names are from memory where the source manifest gives initials only (Arp, Catillo, Chen, Lundberg, McKay, Miller, Paine, Sharafaldin, Villafranca, Ziemba); the volume and issue numbers of Catillo et al. [4] and Bilal et al. [3]; and a URL for the CISA playbooks [7].

## Removed on 26 Sep 2026 (never used by retrieval)

Moved to `Thesis/removed_rag_sources/`, not deleted. None had a passage in the search pool that retrieval returned for any class, and none is cited by the knowledge files:

- NIST RMF step FAQs (Prepare, Categorize, Select, Implement, Assess, Authorize, Monitor)
- NIST Privacy Framework 1.0, NIST FIPS 200, NIST IR 8312, NIST CSWP 29
- NIST SP 800-53 Rev. 5.2.0 change summary (the controls come from the CPRT catalogue)
- OWASP A01, A05 and A07:2025 single-risk pages (duplicates of sections of the full OWASP Top 10:2025, which stays)
- Sommer and Paxson (2010), "Outside the closed world"
- Lundberg and Lee (2017), "A unified approach to interpreting model predictions"
- Herzalla et al. (2023), TII-SSRC-23; Mchina et al. (2026); Badiger et al. (2025)
- `knowledge/FORENXAI_TechStack.pdf`

Removing them from the retrieval corpus does not stop you citing them in the thesis itself (for example TII-SSRC-23 and the 2017 SHAP paper).
