# RAG sources: APA 7th edition references

The 22 documents in `rag/_sources/` that the retrieval stage uses. "Used by"
says how each one reaches a recommendation, measured by calling
`retrieve()` for all 16 classes after the index rebuild of 26 Sep 2026.

| Used by | Meaning |
|---|---|
| passages | Numbered sections are in the search pool and are quoted in recommendations |
| controls | NIST SP 800-53 controls, read from the CPRT catalogue by control ID |
| profile | Cited by the attack profiles and playbooks in `rag/knowledge/` and returned with them |

## Incident-response guidance and standards

1. Nelson, A., Rekhi, S., Souppaya, M., & Scarfone, K. (2025). *Incident response recommendations and considerations for cybersecurity risk management* (NIST Special Publication 800-61r3). National Institute of Standards and Technology. https://doi.org/10.6028/NIST.SP.800-61r3 (passages, baseline)
2. Kent, K., Chevalier, S., Grance, T., & Dang, H. (2006). *Guide to integrating forensic techniques into incident response* (NIST Special Publication 800-86). National Institute of Standards and Technology. https://doi.org/10.6028/NIST.SP.800-86 (passages, baseline)
3. Joint Task Force. (2025). *Security and privacy controls for information systems and organizations* (NIST Special Publication 800-53, Rev. 5.2.0). National Institute of Standards and Technology. https://doi.org/10.6028/NIST.SP.800-53r5 (controls)
4. McKay, K., & Cooper, D. (2019). *Guidelines for the selection, configuration, and use of Transport Layer Security (TLS) implementations* (NIST Special Publication 800-52r2). National Institute of Standards and Technology. https://doi.org/10.6028/NIST.SP.800-52r2 (passages)
5. Licata, J., McWhite, R., Calloway, L., Gilbert, D., Anderson, M., Snyder, J., & Miller, J. (2026). *Developing security, privacy, and cybersecurity supply chain risk management plans for systems* (NIST Special Publication 800-18r2). National Institute of Standards and Technology. https://doi.org/10.6028/NIST.SP.800-18r2 (passages)
6. National Institute of Standards and Technology. (2023). *Artificial intelligence risk management framework (AI RMF 1.0)* (NIST AI 100-1). https://doi.org/10.6028/NIST.AI.100-1 (passages)
7. Cybersecurity and Infrastructure Security Agency. (2024). *Federal government cybersecurity incident and vulnerability response playbooks*. CISA. (passages)
8. Paine, K., Whitehouse, O., Sellwood, J., & Shaw, A. (2023). *Indicators of compromise (IoCs) and their role in attack defence* (RFC 9424). Internet Engineering Task Force. https://doi.org/10.17487/RFC9424 (passages)
9. Ziemba, G., Reed, D., & Traina, P. (1995). *Security considerations for IP fragment filtering* (RFC 1858). Internet Engineering Task Force. https://doi.org/10.17487/RFC1858 (passages)
10. Miller, I. (2001). *Protection against a variant of the tiny fragment attack* (RFC 3128). Internet Engineering Task Force. https://doi.org/10.17487/RFC3128 (passages)
11. Open Worldwide Application Security Project. (2025). *OWASP Top 10:2025: Web application security risks*. OWASP Foundation. (passages)

## Machine learning, explainability and methodology

12. Chen, T., & Guestrin, C. (2016). XGBoost: A scalable tree boosting system. In *Proceedings of the 22nd ACM SIGKDD International Conference on Knowledge Discovery and Data Mining* (pp. 785–794). ACM. https://doi.org/10.1145/2939672.2939785 (passages)
13. Lundberg, S. M., Erion, G., Chen, H., DeGrave, A., Prutkin, J. M., Nair, B., Katz, R., Himmelfarb, J., Bansal, N., & Lee, S.-I. (2020). From local explanations to global understanding with explainable AI for trees. *Nature Machine Intelligence, 2*(1), 56–67. https://doi.org/10.1038/s42256-019-0138-9 (cited in `interpretability/caveats.md`, which every recommendation loads)
14. Arp, D., Quiring, E., Pendlebury, F., Warnecke, A., Pierazzi, F., Wressnegger, C., Cavallaro, L., & Rieck, K. (2024). Pitfalls in machine learning for computer security. *Communications of the ACM, 67*(11), 104–112. https://doi.org/10.1145/3643456 (passages)
15. Iyengar, S. S., Nabavirazavi, S., Hariprasad, Y., HB, P., & Mohan, C. K. (2025). *Artificial intelligence in practice: Theory and application for cyber security and forensics*. Springer Nature. https://doi.org/10.1007/978-3-031-89327-8 (passages)
16. Arslan, R., Ozseven, T., Aydin, M. M., & Celik, Y. (2026). Cybersecurity in intelligent transportation systems: A comparative study on AI-based anomaly detection and threat analysis. *Mechatronics and Intelligent Transportation Systems, 5*(1), 11–30. https://doi.org/10.56578/mits050102 (passages)

## Datasets and comparable studies

17. Villafranca, A., Tasic, I., & Cano, M.-D. (2026). TRUSTLab dataset: A real-world CICFlowMeter dataset for IoT/edge intrusion detection. *Frontiers in Computer Science, 8*, Article 1803271. https://doi.org/10.3389/fcomp.2026.1803271 (profile)
18. Sharafaldin, I., Lashkari, A. H., & Ghorbani, A. A. (2018). Toward generating a new intrusion detection dataset and intrusion traffic characterization. In *Proceedings of the 4th International Conference on Information Systems Security and Privacy (ICISSP 2018)* (pp. 108–116). SciTePress. https://doi.org/10.5220/0006639801080116 (profile)
19. Catillo, M., Del Vecchio, A., Pecchia, A., & Villano, U. (2022). Transferability of machine learning models learned from public intrusion detection datasets: The CICIDS2017 case study. *Software Quality Journal*. https://doi.org/10.1007/s11219-022-09587-0 (profile)
20. Cosar, H. I., Arisoy, C., & Ulutas, H. (2024). Intrusion detection on CSE-CIC-IDS2018 dataset using machine learning methods. *Artificial Intelligence Theory and Applications, 4*(2), 143–154. (profile)
21. Gombar, M. (2026). From detection to triage: Explainable suspicious flow prioritization for multiclass intrusion detection using CSE-CIC-IDS2018. *Electronics, 15*(12), Article 2739. https://doi.org/10.3390/electronics15122739 (profile)
22. Bilal, M. A., Ul Islam, I., Idrees, S., Qasim, M., Khan, M. J., & Khan, J. (2026). Dataset-centric evaluation of federated intrusion detection models in IoT networks. *Scientific Reports*. https://doi.org/10.1038/s41598-025-32567-w (profile)

Check before submitting: the Lundberg et al. (2020) author list (the manifest records "et al." only), the Catillo et al. (2022) and Bilal et al. (2026) volume and issue numbers, and the CISA playbooks URL.

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

Removing them from the RAG corpus does not stop you citing them in the thesis itself (for example TII-SSRC-23 and the 2017 SHAP paper).
