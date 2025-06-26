## PCI DSS v4.0.1 Requirements (Detailed)

### Requirement 1: Install and Maintain Network Security Controls

* **1.1 Processes and mechanisms for installing and maintaining network security controls are defined and understood.**
    * 1.1.1 All security policies and operational procedures that are identified in Requirement 1 are:
        * Documented.
        * Kept up to date.
        * In use.
        * Known to all affected parties. [cite: 468]
    * 1.1.2 Roles and responsibilities for performing activities in Requirement 1 are documented, assigned, and understood. [cite: 472]
* **1.2 Network security controls (NSCs) are configured and maintained.**
    * 1.2.1 Configuration standards for NSC rulesets are:
        * Defined.
        * Implemented.
        * Maintained. [cite: 476]
    * 1.2.2 All changes to network connections and to configurations of NSCs are approved and managed in accordance with the change control process defined at Requirement 6.5.1. [cite: 480]
    * 1.2.3 An accurate network diagram(s) is maintained that shows all connections between the CDE and other networks, including any wireless networks. [cite: 484]
    * 1.2.4 An accurate data-flow diagram(s) is maintained that meets the following:
        * Shows all account data flows across systems and networks.
        * Updated as needed upon changes to the environment. [cite: 488]
    * 1.2.5 All services, protocols, and ports allowed are identified, approved, and have a defined business need. [cite: 502]
    * 1.2.6 Security features are defined and implemented for all services, protocols, and ports that are in use and considered to be insecure, such that the risk is mitigated. [cite: 510]
    * 1.2.7 Configurations of NSCs are reviewed at least once every six months to confirm they are relevant and effective. [cite: 521]
    * 1.2.8 Configuration files for NSCs are:
        * Secured from unauthorized access.
        * Kept consistent with active network configurations. [cite: 530]
* **1.3 Network access to and from the cardholder data environment is restricted.**
    * 1.3.1 Inbound traffic to the CDE is restricted as follows:
        * To only traffic that is necessary.
        * All other traffic is specifically denied. [cite: 541]
    * 1.3.2 Outbound traffic from the CDE is restricted as follows:
        * To only traffic that is necessary.
        * All other traffic is specifically denied. [cite: 550]
    * 1.3.3 NSCs are installed between all wireless networks and the CDE, regardless of whether the wireless network is a CDE, such that:
        * All wireless traffic from wireless networks into the CDE is denied by default.
        * Only wireless traffic with an authorized business purpose is allowed into the CDE. [cite: 558]
* **1.4 Network connections between trusted and untrusted networks are controlled.**
    * 1.4.1 NSCs are implemented between trusted and untrusted networks. [cite: 567]
    * 1.4.2 Inbound traffic from untrusted networks to trusted networks is restricted to:
        * Communications with system components that are authorized to provide publicly accessible services, protocols, and ports.
        * Stateful responses to communications initiated by system components in a trusted network.
        * All other traffic is denied. [cite: 577]
    * 1.4.3 Anti-spoofing measures are implemented to detect and block forged source IP addresses from entering the trusted network. [cite: 589]
    * 1.4.4 System components that store cardholder data are not directly accessible from untrusted networks. [cite: 595]
    * 1.4.5 The disclosure of internal IP addresses and routing information is limited to only authorized parties. [cite: 608]
* **1.5 Risks to the CDE from computing devices that are able to connect to both untrusted networks and the CDE are mitigated.**
    * 1.5.1 Security controls are implemented on any computing devices, including company- and employee-owned devices, that connect to both untrusted networks (including the Internet) and the CDE as follows:
        * Specific configuration settings are defined to prevent threats being introduced into the entity’s network.
        * Security controls are actively running.
        * Security controls are not alterable by users of the computing devices unless specifically documented and authorized by management on a case-by-case basis for a limited period. [cite: 616]

### Requirement 2: Apply Secure Configurations to All System Components

* **2.1 Processes and mechanisms for applying secure configurations to all system components are defined and understood.**
    * 2.1.1 All security policies and operational procedures that are identified in Requirement 2 are:
        * Documented.
        * Kept up to date.
        * In use.
        * Known to all affected parties. [cite: 645]
    * 2.1.2 Roles and responsibilities for performing activities in Requirement 2 are documented, assigned, and understood. [cite: 655]
* **2.2 System components are configured and managed securely.**
    * 2.2.1 Configuration standards are developed, implemented, and maintained to:
        * Cover all system components.
        * Address all known security vulnerabilities.
        * Be consistent with industry-accepted system hardening standards or vendor hardening recommendations.
        * Be updated as new vulnerability issues are identified, as defined in Requirement 6.3.1.
        * Be applied when new systems are configured and verified as in place before or immediately after a system component is connected to a production environment. [cite: 670, 671, 672, 673]
    * 2.2.2 Vendor default accounts are managed as follows:
        * If the vendor default account(s) will be used, the default password is changed per Requirement 8.3.6.
        * If the vendor default account(s) will not be used, the account is removed or disabled. [cite: 686, 687]
    * 2.2.3 Primary functions requiring different security levels are managed as follows:
        * Only one primary function exists on a system component, OR
        * Primary functions with differing security levels that exist on the same system component are isolated from each other, OR
        * Primary functions with differing security levels on the same system component are all secured to the level required by the function with the highest security need. [cite: 701]
    * 2.2.4 Only necessary services, protocols, daemons, and functions are enabled, and all unnecessary functionality is removed or disabled. [cite: 723]
    * 2.2.5 If any insecure services, protocols, or daemons are present:
        * Business justification is documented.
        * Additional security features are documented and implemented that reduce the risk of using insecure services, protocols, or daemons. [cite: 733, 734]
    * 2.2.6 System security parameters are configured to prevent misuse. [cite: 744]
    * 2.2.7 All non-console administrative access is encrypted using strong cryptography. [cite: 756]
* **2.3 Wireless environments are configured and managed securely.**
    * 2.3.1 For wireless environments connected to the CDE or transmitting account data, all wireless vendor defaults are changed at installation or are confirmed to be secure, including but not limited to:
        * Default wireless encryption keys.
        * Passwords on wireless access points.
        * SNMP defaults.
        * Any other security-related wireless vendor defaults. [cite: 767, 768]
    * 2.3.2 For wireless environments connected to the CDE or transmitting account data, wireless encryption keys are changed as follows:
        * Whenever personnel with knowledge of the key leave the company or the role for which the knowledge was necessary.
        * Whenever a key is suspected of or known to be compromised. [cite: 780, 781]

### Requirement 3: Protect Stored Account Data

* **3.1 Processes and mechanisms for protecting stored account data are defined and understood.**
    * 3.1.1 All security policies and operational procedures that are identified in Requirement 3 are:
        * Documented.
        * Kept up to date.
        * In use.
        * Known to all affected parties. [cite: 807, 808]
    * 3.1.2 Roles and responsibilities for performing activities in Requirement 3 are documented, assigned, and understood. [cite: 817]
* **3.2 Storage of account data is kept to a minimum.**
    * 3.2.1 Account data storage is kept to a minimum through implementation of data retention and disposal policies, procedures, and processes that include at least the following:
        * Coverage for all locations of stored account data. [cite: 831]
        * Coverage for any sensitive authentication data (SAD) stored prior to completion of authorization. [cite: 832, 833] [This bullet is a best practice until its effective date; refer to Applicability Notes below for details.]
        * Limiting data storage amount and retention time to that which is required for legal or regulatory, and/or business requirements. [cite: 834]
        * Specific retention requirements for stored account data that defines length of retention period and includes a documented business justification. [cite: 835]
        * Processes for secure deletion or rendering account data unrecoverable when no longer needed per the retention policy. [cite: 836]
        * A process for verifying, at least once every three months, that stored account data exceeding the defined retention period has been securely deleted or rendered unrecoverable. [cite: 837]
* **3.3 Sensitive authentication data (SAD) is not stored after authorization.**
    * 3.3.1 SAD is not stored after authorization, even if encrypted. All sensitive authentication data received is rendered unrecoverable upon completion of the authorization process. [cite: 864, 865]
        * 3.3.1.1 The full contents of any track are not stored upon completion of the authorization process. [cite: 880]
        * 3.3.1.2 The card verification code is not stored upon completion of the authorization process. [cite: 894]
        * 3.3.1.3 The personal identification number (PIN) and the PIN block are not stored upon completion of the authorization process. [cite: 905]
    * 3.3.2 SAD that is stored electronically prior to completion of authorization is encrypted using strong cryptography. [cite: 913]
    * 3.3.3 Additional requirement for issuers and companies that support issuing services and store sensitive authentication data: Any storage of sensitive authentication data is:
        * Limited to that which is needed for a legitimate issuing business need and is secured. [cite: 930]
        * Encrypted using strong cryptography. [cite: 931] [This bullet is a best practice until its effective date; refer to Applicability Notes below for details.]
* **3.4 Access to displays of full PAN and ability to copy PAN are restricted.**
    * 3.4.1 PAN is masked when displayed (the BIN and last four digits are the maximum number of digits to be displayed), such that only personnel with a legitimate business need can see more than the BIN and last four digits of the PAN. [cite: 950, 951]
    * 3.4.2 When using remote-access technologies, technical controls prevent copy and/or relocation of PAN for all personnel, except for those with documented, explicit authorization and a legitimate, defined business need. [cite: 974]
* **3.5 Primary account number (PAN) is secured wherever it is stored.**
    * 3.5.1 PAN is rendered unreadable anywhere it is stored by using any of the following approaches:
        * One-way hashes based on strong cryptography of the entire PAN. [cite: 899]
        * Truncation (hashing cannot be used to replace the truncated segment of PAN). [cite: 990]
            * If hashed and truncated versions of the same PAN, or different truncation formats of the same PAN, are present in an environment, additional controls are in place such that the different versions cannot be correlated to reconstruct the original PAN. [cite: 991]
        * Index tokens. [cite: 992]
        * Strong cryptography with associated key-management processes and procedures. [cite: 992]
        * 3.5.1.1 Hashes used to render PAN unreadable (per the first bullet of Requirement 3.5.1) are keyed cryptographic hashes of the entire PAN, with associated key-management processes and procedures in accordance with Requirements 3.6 and 3.7. [cite: 1006]
        * 3.5.1.2 If disk-level or partition-level encryption (rather than file-, column-, or field-level database encryption) is used to render PAN unreadable, it is implemented only as follows:
            * On removable electronic media OR
            * If used for non-removable electronic media, PAN is also rendered unreadable via another mechanism that meets Requirement 3.5.1. [cite: 1021]
        * 3.5.1.3 If disk-level or partition-level encryption is used (rather than file-, column-, or field-level database encryption) to render PAN unreadable, it is managed as follows:
            * Logical access is managed separately and independently of native operating system authentication and access control mechanisms. [cite: 1041]
            * Decryption keys are not associated with user accounts. [cite: 1042]
            * Authentication factors (passwords, passphrases, or cryptographic keys) that allow access to unencrypted data are stored securely. [cite: 1042]
* **3.6 Cryptographic keys used to protect stored account data are secured.**
    * 3.6.1 Procedures are defined and implemented to protect cryptographic keys used to protect stored account data against disclosure and misuse that include:
        * Access to keys is restricted to the fewest number of custodians necessary. [cite: 1052]
        * Key-encrypting keys are at least as strong as the data-encrypting keys they protect. [cite: 1053]
        * Key-encrypting keys are stored separately from data-encrypting keys. [cite: 1054]
        * Keys are stored securely in the fewest possible locations and forms. [cite: 1054]
        * 3.6.1.1 Additional requirement for service providers only: A documented description of the cryptographic architecture is maintained that includes:
            * Details of all algorithms, protocols, and keys used for the protection of stored account data, including key strength and expiry date. [cite: 1066]
            * Preventing the use of the same cryptographic keys in production and test environments. [cite: 1067, 1068] [This bullet is a best practice until its effective date; refer to Applicability Notes below for details.]
            * Description of the key usage for each key. [cite: 1069]
            * Inventory of any hardware security modules (HSMs), key management systems (KMS), and other secure cryptographic devices (SCDs) used for key management, including type and location of devices, to support meeting Requirement 12.3.4. [cite: 1069]
        * 3.6.1.2 Secret and private keys used to protect stored account data are stored in one (or more) of the following forms at all times:
            * Encrypted with a key-encrypting key that is at least as strong as the data-encrypting key, and that is stored separately from the data-encrypting key. [cite: 1080]
            * Within a secure cryptographic device (SCD), such as a hardware security module (HSM) or PTS-approved point-of-interaction device. [cite: 1081]
            * As at least two full-length key components or key shares, in accordance with an industry-accepted method. [cite: 1082]
        * 3.6.1.3 Access to cleartext cryptographic key components is restricted to the fewest number of custodians necessary. [cite: 1096]
        * 3.6.1.4 Cryptographic keys are stored in the fewest possible locations. [cite: 1101]
* **3.7 Where cryptography is used to protect stored account data, key management processes and procedures covering all aspects of the key lifecycle are defined and implemented.**
    * 3.7.1 Key-management policies and procedures are implemented to include generation of strong cryptographic keys used to protect stored account data. [cite: 1107]
    * 3.7.2 Key-management policies and procedures are implemented to include secure distribution of cryptographic keys used to protect stored account data. [cite: 1111]
    * 3.7.3 Key-management policies and procedures are implemented to include secure storage of cryptographic keys used to protect stored account data. [cite: 1120]
    * 3.7.4 Key management policies and procedures are implemented for cryptographic key changes for keys that have reached the end of their cryptoperiod, as defined by the associated application vendor or key owner, and based on industry best practices and guidelines, including the following:
        * A defined cryptoperiod for each key type in use. [cite: 1131]
        * A process for key changes at the end of the defined cryptoperiod. [cite: 1132]
    * 3.7.5 Key management policies procedures are implemented to include the retirement, replacement, or destruction of keys used to protect stored account data, as deemed necessary when:
        * The key has reached the end of its defined cryptoperiod. [cite: 1143]
        * The integrity of the key has been weakened, including when personnel with knowledge of a cleartext key component leaves the company, or the role for which the key component was known. [cite: 1144]
        * The key is suspected of or known to be compromised. [cite: 1145]
        * Retired or replaced keys are not used for encryption operations. [cite: 1146]
    * 3.7.6 Where manual cleartext cryptographic key-management operations are performed by personnel, key-management policies and procedures are implemented, including managing these operations using split knowledge and dual control. [cite: 1159]
    * 3.7.7 Key management policies and procedures are implemented to include the prevention of unauthorized substitution of cryptographic keys. [cite: 1172]
    * 3.7.8 Key management policies and procedures are implemented to include that cryptographic key custodians formally acknowledge (in writing or electronically) that they understand and accept their key-custodian responsibilities. [cite: 1180]
    * 3.7.9 Additional requirement for service providers only: Where a service provider shares cryptographic keys with its customers for transmission or storage of account data, guidance on secure transmission, storage and updating of such keys is documented and distributed to the service provider’s customers. [cite: 1187]

### Requirement 4: Protect Cardholder Data with Strong Cryptography During Transmission Over Open, Public Networks

* **4.1 Processes and mechanisms for protecting cardholder data with strong cryptography during transmission over open, public networks are defined and understood.**
    * 4.1.1 All security policies and operational procedures that are identified in Requirement 4 are:
        * Documented.
        * Kept up to date.
        * In use.
        * Known to all affected parties. [cite: 1209, 1210]
    * 4.1.2 Roles and responsibilities for performing activities in Requirement 4 are documented, assigned, and understood. [cite: 1218]
* **4.2 PAN is protected with strong cryptography during transmission.**
    * 4.2.1 Strong cryptography and security protocols are implemented as follows to safeguard PAN during transmission over open, public networks:
        * Only trusted keys and certificates are accepted. [cite: 1232]
        * Certificates used to safeguard PAN during transmission over open, public networks are confirmed as valid and are not expired or revoked. [cite: 1233, 1234] [This bullet is a best practice until its effective date; refer to applicability notes below for details.]
        * The protocol in use supports only secure versions or configurations and does not support fallback to, or use of insecure versions, algorithms, key sizes, or implementations. [cite: 1235]
        * The encryption strength is appropriate for the encryption methodology in use. [cite: 1236]
        * 4.2.1.1 An inventory of the entity’s trusted keys and certificates used to protect PAN during transmission is maintained. [cite: 1262]
        * 4.2.1.2 Wireless networks transmitting PAN or connected to the CDE use industry best practices to implement strong cryptography for authentication and transmission. [cite: 1275]
    * 4.2.2 PAN is secured with strong cryptography whenever it is sent via end-user messaging technologies. [cite: 1282]

### Requirement 5: Protect All Systems and Networks from Malicious Software

* **5.1 Processes and mechanisms for protecting all systems and networks from malicious software are defined and understood.**
    * 5.1.1 All security policies and operational procedures that are identified in Requirement 5 are:
        * Documented.
        * Kept up to date.
        * In use.
        * Known to all affected parties. [cite: 1303, 1304]
    * 5.1.2 Roles and responsibilities for performing activities in Requirement 5 are documented, assigned, and understood. [cite: 1312]
* **5.2 Malicious software (malware) is prevented, or detected and addressed.**
    * 5.2.1 An anti-malware solution(s) is deployed on all system components, except for those system components identified in periodic evaluations per Requirement 5.2.3 that concludes the system components are not at risk from malware. [cite: 1323]
    * 5.2.2 The deployed anti-malware solution(s):
        * Detects all known types of malware. [cite: 1333]
        * Removes, blocks, or contains all known types of malware. [cite: 1334]
    * 5.2.3 Any system components that are not at risk for malware are evaluated periodically to include the following:
        * A documented list of all system components not at risk for malware. [cite: 1346]
        * Identification and evaluation of evolving malware threats for those system components. [cite: 1347]
        * Confirmation whether such system components continue to not require anti-malware protection. [cite: 1348]
        * 5.2.3.1 The frequency of periodic evaluations of system components identified as not at risk for malware is defined in the entity’s targeted risk analysis, which is performed according to all elements specified in Requirement 12.3.1. [cite: 1356]
* **5.3 Anti-malware mechanisms and processes are active, maintained, and monitored.**
    * 5.3.1 The anti-malware solution(s) is kept current via automatic updates. [cite: 1368]
    * 5.3.2 The anti-malware solution(s):
        * Performs periodic scans and active or real-time scans. [cite: 1380] OR
        * Performs continuous behavioral analysis of systems or processes. [cite: 1381]
        * 5.3.2.1 If periodic malware scans are performed to meet Requirement 5.3.2, the frequency of scans is defined in the entity’s targeted risk analysis, which is performed according to all elements specified in Requirement 12.3.1. [cite: 1387]
    * 5.3.3 For removable electronic media, the anti-malware solution(s):
        * Performs automatic scans of when the media is inserted, connected, or logically mounted, OR
        * Performs continuous behavioral analysis of systems or processes when the media is inserted, connected, or logically mounted. [cite: 1397]
    * 5.3.4 Audit logs for the anti-malware solution(s) are enabled and retained in accordance with Requirement 10.5.1. [cite: 1406]
    * 5.3.5 Anti-malware mechanisms cannot be disabled or altered by users, unless specifically documented, and authorized by management on a case-by-case basis for a limited time period. [cite: 1416]
* **5.4 Anti-phishing mechanisms protect users against phishing attacks.**
    * 5.4.1 Processes and automated mechanisms are in place to detect and protect personnel against phishing attacks. [cite: 1430]

### Requirement 6: Develop and Maintain Secure Systems and Software

* **6.1 Processes and mechanisms for developing and maintaining secure systems and software are defined and understood.**
    * 6.1.1 All security policies and operational procedures that are identified in Requirement 6 are:
        * Documented.
        * Kept up to date.
        * In use.
        * Known to all affected parties. [cite: 1461, 1462]
    * 6.1.2 Roles and responsibilities for performing activities in Requirement 6 are documented, assigned, and understood. [cite: 1470]
* **6.2 Bespoke and custom software are developed securely.**
    * 6.2.1 Bespoke and custom software are developed securely, as follows:
        * Based on industry standards and/or best practices for secure development. [cite: 1481]
        * In accordance with PCI DSS (for example, secure authentication and logging). [cite: 1482]
        * Incorporating consideration of information security issues during each stage of the software development lifecycle. [cite: 1483]
    * 6.2.2 Software development personnel working on bespoke and custom software are trained at least once every 12 months as follows:
        * On software security relevant to their job function and development languages. [cite: 1493]
        * Including secure software design and secure coding techniques. [cite: 1494]
        * Including, if security testing tools are used, how to use the tools for detecting vulnerabilities in software. [cite: 1494]
    * 6.2.3 Bespoke and custom software is reviewed prior to being released into production or to customers, to identify and correct potential coding vulnerabilities, as follows:
        * Code reviews ensure code is developed according to secure coding guidelines. [cite: 1508]
        * Code reviews look for both existing and emerging software vulnerabilities. [cite: 1509]
        * Appropriate corrections are implemented prior to release. [cite: 1509]
        * 6.2.3.1 If manual code reviews are performed for bespoke and custom software prior to release to production, code changes are:
            * Reviewed by individuals other than the originating code author, and who are knowledgeable about code-review techniques and secure coding practices. [cite: 1524]
            * Reviewed and approved by management prior to release. [cite: 1525]
    * 6.2.4 Software engineering techniques or other methods are defined and in use by software development personnel to prevent or mitigate common software attacks and related vulnerabilities in bespoke and custom software, including but not limited to the following:
        * Injection attacks, including SQL, LDAP, XPath, or other command, parameter, object, fault, or injection-type flaws. [cite: 1537]
        * Attacks on data and data structures, including attempts to manipulate buffers, pointers, input data, or shared data. [cite: 1538]
        * Attacks on cryptography usage, including attempts to exploit weak, insecure, or inappropriate cryptographic implementations, algorithms, cipher suites, or modes of operation. [cite: 1539]
        * Attacks on business logic, including attempts to abuse or bypass application features and functionalities through the manipulation of APIs, communication protocols and channels, client-side functionality, or other system/application functions and resources. This includes cross-site scripting (XSS) and cross-site request forgery (CSRF). [cite: 1540, 1541]
        * Attacks on access control mechanisms, including attempts to bypass or abuse identification, authentication, or authorization mechanisms, or attempts to exploit weaknesses in the implementation of such mechanisms. [cite: 1542]
        * Attacks via any “high-risk” vulnerabilities identified in the vulnerability identification process, as defined in Requirement 6.3.1. [cite: 1543]
* **6.3 Security vulnerabilities are identified and addressed.**
    * 6.3.1 Security vulnerabilities are identified and managed as follows:
        * New security vulnerabilities are identified using industry-recognized sources for security vulnerability information, including alerts from international and national computer emergency response teams (CERTs). [cite: 1560]
        * Vulnerabilities are assigned a risk ranking based on industry best practices and consideration of potential impact. [cite: 1561]
        * Risk rankings identify, at a minimum, all vulnerabilities considered to be a high-risk or critical to the environment. [cite: 1562]
        * Vulnerabilities for bespoke and custom, and third-party software (for example operating systems and databases) are covered. [cite: 1563]
    * 6.3.2 An inventory of bespoke and custom software, and third-party software components incorporated into bespoke and custom software is maintained to facilitate vulnerability and patch management. [cite: 1593]
    * 6.3.3 All system components are protected from known vulnerabilities by installing applicable security patches/updates as follows:
        * Patches/updates for critical vulnerabilities (identified according to the risk ranking process at Requirement 6.3.1) are installed within one month of release. [cite: 1605]
        * All other applicable security patches/updates are installed within an appropriate time frame as determined by the entity’s assessment of the criticality of the risk to the environment as identified according to the risk ranking process at Requirement 6.3.1. [cite: 1606]
* **6.4 Public-facing web applications are protected against attacks.**
    * 6.4.1 For public-facing web applications, new threats and vulnerabilities are addressed on an ongoing basis and these applications are protected against known attacks as follows:
        * Reviewing public-facing web applications via manual or automated application vulnerability security assessment tools or methods as follows:
            * At least once every 12 months and after significant changes. [cite: 1624]
            * By an entity that specializes in application security. [cite: 1625]
            * Including, at a minimum, all common software attacks in Requirement 6.2.4. [cite: 1625]
            * All vulnerabilities are ranked in accordance with requirement 6.3.1. [cite: 1626]
            * All vulnerabilities are corrected. [cite: 1626]
            * The application is re-evaluated after the corrections. [cite: 1627] OR
        * Installing an automated technical solution(s) that continually detects and prevents web-based attacks as follows:
            * Installed in front of public-facing web applications to detect and prevent web-based attacks. [cite: 1627]
            * Actively running and up to date as applicable. [cite: 1628]
            * Generating audit logs. [cite: 1628]
            * Configured to either block web-based attacks or generate an alert that is immediately investigated. [cite: 1629]
    * 6.4.2 For public-facing web applications, an automated technical solution is deployed that continually detects and prevents web-based attacks, with at least the following:
        * Is installed in front of public-facing web applications and is configured to detect and prevent web-based attacks. [cite: 1645]
        * Actively running and up to date as applicable. [cite: 1646]
        * Generating audit logs. [cite: 1646]
        * Configured to either block web-based attacks or generate an alert that is immediately investigated. [cite: 1647]
    * 6.4.3 All payment page scripts that are loaded and executed in the consumer’s browser are managed as follows:
        * A method is implemented to confirm that each script is authorized. [cite: 1659]
        * A method is implemented to assure the integrity of each script. [cite: 1660]
        * An inventory of all scripts is maintained with written business or technical justification as to why each is necessary. [cite: 1661]
* **6.5 Changes to all system components are managed securely.**
    * 6.5.1 Changes to all system components in the production environment are made according to established procedures that include:
        * Reason for, and description of, the change. [cite: 1688]
        * Documentation of security impact. [cite: 1689]
        * Documented change approval by authorized parties. [cite: 1689]
        * Testing to verify that the change does not adversely impact system security. [cite: 1690]
        * For bespoke and custom software changes, all updates are tested for compliance with Requirement 6.2.4 before being deployed into production. [cite: 1691]
        * Procedures to address failures and return to a secure state. [cite: 1692]
    * 6.5.2 Upon completion of a significant change, all applicable PCI DSS requirements are confirmed to be in place on all new or changed systems and networks, and documentation is updated as applicable. [cite: 1706]
    * 6.5.3 Pre-production environments are separated from production environments and the separation is enforced with access controls. [cite: 1714]
    * 6.5.4 Roles and functions are separated between production and pre-production environments to provide accountability such that only reviewed and approved changes are deployed. [cite: 1723]
    * 6.5.5 Live PANs are not used in pre-production environments, except where those environments are included in the CDE and protected in accordance with all applicable PCI DSS requirements. [cite: 1735]
    * 6.5.6 Test data and test accounts are removed from system components before the system goes into production. [cite: 1743]

### Requirement 7: Restrict Access to System Components and Cardholder Data by Business Need to Know

* **7.1 Processes and mechanisms for restricting access to system components and cardholder data by business need to know are defined and understood.**
    * 7.1.1 All security policies and operational procedures that are identified in Requirement 7 are:
        * Documented.
        * Kept up to date.
        * In use.
        * Known to all affected parties. [cite: 1767, 1768]
    * 7.1.2 Roles and responsibilities for performing activities in Requirement 7 are documented, assigned, and understood. [cite: 1776]
* **7.2 Access to system components and data is appropriately defined and assigned.**
    * 7.2.1 An access control model is defined and includes granting access as follows:
        * Appropriate access depending on the entity’s business and access needs. [cite: 1789]
        * Access to system components and data resources that is based on users’ job classification and functions. [cite: 1790]
        * The least privileges required (for example, user, administrator) to perform a job function. [cite: 1791]
    * 7.2.2 Access is assigned to users, including privileged users, based on:
        * Job classification and function. [cite: 1809]
        * Least privileges necessary to perform job responsibilities. [cite: 1810]
    * 7.2.3 Required privileges are approved by authorized personnel. [cite: 1816]
    * 7.2.4 All user accounts and related access privileges, including third-party/vendor accounts, are reviewed as follows:
        * At least once every six months. [cite: 1830]
        * To ensure user accounts and access remain appropriate based on job function. [cite: 1831]
        * Any inappropriate access is addressed. [cite: 1831]
        * Management acknowledges that access remains appropriate. [cite: 1832]
    * 7.2.5 All application and system accounts and related access privileges are assigned and managed as follows:
        * Based on the least privileges necessary for the operability of the system or application. [cite: 1845]
        * Access is limited to the systems, applications, or processes that specifically require their use. [cite: 1846]
        * 7.2.5.1 All access by application and system accounts and related access privileges are reviewed as follows:
            * Periodically (at the frequency defined in the entity’s targeted risk analysis, which is performed according to all elements specified in Requirement 12.3.1). [cite: 1854]
            * The application/system access remains appropriate for the function being performed. [cite: 1855]
            * Any inappropriate access is addressed. [cite: 1855]
            * Management acknowledges that access remains appropriate. [cite: 1856]
    * 7.2.6 All user access to query repositories of stored cardholder data is restricted as follows:
        * Via applications or other programmatic methods, with access and allowed actions based on user roles and least privileges. [cite: 1868]
        * Only the responsible administrator(s) can directly access or query repositories of stored CHD. [cite: 1869]
* **7.3 Access to system components and data is managed via an access control system(s).**
    * 7.3.1 An access control system(s) is in place that restricts access based on a user’s need to know and covers all system components. [cite: 1879]
    * 7.3.2 The access control system(s) is configured to enforce permissions assigned to individuals, applications, and systems based on job classification and function. [cite: 1883]
    * 7.3.3 The access control system(s) is set to “deny all” by default. [cite: 1889]

### Requirement 8: Identify Users and Authenticate Access to System Components

* **8.1 Processes and mechanisms for identifying users and authenticating access to system components are defined and understood.**
    * 8.1.1 All security policies and operational procedures that are identified in Requirement 8 are:
        * Documented.
        * Kept up to date.
        * In use.
        * Known to all affected parties. [cite: 1924, 1925]
    * 8.1.2 Roles and responsibilities for performing activities in Requirement 8 are documented, assigned, and understood. [cite: 1933]
* **8.2 User identification and related accounts for users and administrators are strictly managed throughout an account’s lifecycle.**
    * 8.2.1 All users are assigned a unique ID before access to system components or cardholder data is allowed. [cite: 1943]
    * 8.2.2 Group, shared, or generic IDs, or other shared authentication credentials are only used when necessary on an exception basis, and are managed as follows:
        * ID use is prevented unless needed for an exceptional circumstance. [cite: 1954]
        * Use is limited to the time needed for the exceptional circumstance. [cite: 1955]
        * Business justification for use is documented. [cite: 1955]
        * Use is explicitly approved by management. [cite: 1956]
        * Individual user identity is confirmed before access to an account is granted. [cite: 1956]
        * Every action taken is attributable to an individual user. [cite: 1957]
    * 8.2.3 Additional requirement for service providers only: Service providers with remote access to customer premises use unique authentication factors for each customer premises. [cite: 1970]
    * 8.2.4 Addition, deletion, and modification of user IDs, authentication factors, and other identifier objects are managed as follows:
        * Authorized with the appropriate approval. [cite: 1982]
        * Implemented with only the privileges specified on the documented approval. [cite: 1983]
    * 8.2.5 Access for terminated users is immediately revoked. [cite: 1988]
    * 8.2.6 Inactive user accounts are removed or disabled within 90 days of inactivity. [cite: 1995]
    * 8.2.7 Accounts used by third parties to access, support, or maintain system components via remote access are managed as follows:
        * Enabled only during the time period needed and disabled when not in use. [cite: 2000]
        * Use is monitored for unexpected activity. [cite: 2001]
    * 8.2.8 If a user session has been idle for more than 15 minutes, the user is required to re-authenticate to re-activate the terminal or session. [cite: 2016]
* **8.3 Strong authentication for users and administrators is established and managed.**
    * 8.3.1 All user access to system components for users and administrators is authenticated via at least one of the following authentication factors:
        * Something you know, such as a password or passphrase. [cite: 2026]
        * Something you have, such as a token device or smart card. [cite: 2027]
        * Something you are, such as a biometric element. [cite: 2028]
    * 8.3.2 Strong cryptography is used to render all authentication factors unreadable during transmission and storage on all system components. [cite: 2037]
    * 8.3.3 User identity is verified before modifying any authentication factor. [cite: 2047]
    * 8.3.4 Invalid authentication attempts are limited by:
        * Locking out the user ID after not more than 10 attempts. [cite: 2055]
        * Setting the lockout duration to a minimum of 30 minutes or until the user’s identity is confirmed. [cite: 2056]
    * 8.3.5 If passwords/passphrases are used as authentication factors to meet Requirement 8.3.1, they are set and reset for each user as follows:
        * Set to a unique value for first-time use and upon reset. [cite: 2062]
        * Forced to be changed immediately after the first use. [cite: 2063]
    * 8.3.6 If passwords/passphrases are used as authentication factors to meet Requirement 8.3.1, they meet the following minimum level of complexity:
        * A minimum length of 12 characters (or IF the system does not support 12 characters, a minimum length of eight characters). [cite: 2074]
        * Contain both numeric and alphabetic characters. [cite: 2075]
    * 8.3.7 Individuals are not allowed to submit a new password/passphrase that is the same as any of the last four passwords/passphrases used. [cite: 2085]
    * 8.3.8 Authentication policies and procedures are documented and communicated to all users including:
        * Guidance on selecting strong authentication factors. [cite: 2094]
        * Guidance for how users should protect their authentication factors. [cite: 2095]
        * Instructions not to reuse previously used passwords/passphrases. [cite: 2095]
        * Instructions to change passwords/passphrases if there is any suspicion or knowledge that the password/passphrases have been compromised and how to report the incident. [cite: 2096]
    * 8.3.9 If passwords/passphrases are used as the only authentication factor for user access (i.e., in any single-factor authentication implementation) then either:
        * Passwords/passphrases are changed at least once every 90 days, OR
        * The security posture of accounts is dynamically analyzed, and real-time access to resources is automatically determined accordingly. [cite: 2108]
    * 8.3.10 Additional requirement for service providers only: If passwords/passphrases are used as the only authentication factor for customer user access to cardholder data (i.e., in any single-factor authentication implementation), then guidance is provided to customer users including:
        * Guidance for customers to change their user passwords/passphrases periodically. [cite: 2124]
        * Guidance as to when, and under what circumstances, passwords/passphrases are to be changed. [cite: 2125]
    * 8.3.10.1 Additional requirement for service providers only: If passwords/passphrases are used as the only authentication factor for customer user access (i.e., in any single-factor authentication implementation) then either:
        * Passwords/passphrases are changed at least once every 90 days, OR
        * The security posture of accounts is dynamically analyzed, and real-time access to resources is automatically determined accordingly. [cite: 2140]
    * 8.3.11 Where authentication factors such as physical or logical security tokens, smart cards, or certificates are used:
        * Factors are assigned to an individual user and not shared among multiple users. [cite: 2150]
        * Physical and/or logical controls ensure only the intended user can use that factor to gain access. [cite: 2151]
* **8.4 Multi-factor authentication (MFA) is implemented to secure access into the CDE.**
    * 8.4.1 MFA is implemented for all non-console access into the CDE for personnel with administrative access. [cite: 2162]
    * 8.4.2 MFA is implemented for all non-console access into the CDE. [cite: 2170]
    * 8.4.3 MFA is implemented for all remote access originating from outside the entity’s network that could access or impact the CDE. [cite: 2195]
* **8.5 Multi-factor authentication (MFA) systems are configured to prevent misuse.**
    * 8.5.1 MFA systems are implemented as follows:
        * The MFA system is not susceptible to replay attacks. [cite: 2213]
        * MFA systems cannot be bypassed by any users, including administrative users unless specifically documented, and authorized by management on an exception basis, for a limited time period. [cite: 2214]
        * At least two different types of authentication factors are used. [cite: 2215]
        * Success of all authentication factors is required before access is granted. [cite: 2216]
* **8.6 Use of application and system accounts and associated authentication factors is strictly managed.**
    * 8.6.1 If accounts used by systems or applications can be used for interactive login, they are managed as follows:
        * Interactive use is prevented unless needed for an exceptional circumstance. [cite: 2234]
        * Interactive use is limited to the time needed for the exceptional circumstance. [cite: 2235]
        * Business justification for interactive use is documented. [cite: 2236]
        * Interactive use is explicitly approved by management. [cite: 2236]
        * Individual user identity is confirmed before access to account is granted. [cite: 2237]
        * Every action taken is attributable to an individual user. [cite: 2238]
    * 8.6.2 Passwords/passphrases for any application and system accounts that can be used for interactive login are not hard coded in scripts, configuration/property files, or bespoke and custom source code. [cite: 2246]
    * 8.6.3 Passwords/passphrases for any application and system accounts are protected against misuse as follows:
        * Passwords/passphrases are changed periodically (at the frequency defined in the entity’s targeted risk analysis, which is performed according to all elements specified in Requirement 12.3.1) and upon suspicion or confirmation of compromise. [cite: 2259]
        * Passwords/passphrases are constructed with sufficient complexity appropriate for how frequently the entity changes the passwords/passphrases. [cite: 2260]

### Requirement 9: Restrict Physical Access to Cardholder Data

* **9.1 Processes and mechanisms for restricting physical access to cardholder data are defined and understood.**
    * 9.1.1 All security policies and operational procedures that are identified in Requirement 9 are:
        * Documented.
        * Kept up to date.
        * In use.
        * Known to all affected parties. [cite: 2293, 2294]
    * 9.1.2 Roles and responsibilities for performing activities in Requirement 9 are documented, assigned, and understood. [cite: 2302]
* **9.2 Physical access controls manage entry into facilities and systems containing cardholder data.**
    * 9.2.1 Appropriate facility entry controls are in place to restrict physical access to systems in the CDE. [cite: 2314]
        * 9.2.1.1 Individual physical access to sensitive areas within the CDE is monitored with either video cameras or physical access control mechanisms (or both) as follows:
            * Entry and exit points to/from sensitive areas within the CDE are monitored. [cite: 2324]
            * Monitoring devices or mechanisms are protected from tampering or disabling. [cite: 2325]
            * Collected data is reviewed and correlated with other entries. [cite: 2326]
            * Collected data is stored for at least three months, unless otherwise restricted by law. [cite: 2327]
    * 9.2.2 Physical and/or logical controls are implemented to restrict use of publicly accessible network jacks within the facility. [cite: 2338]
    * 9.2.3 Physical access to wireless access points, gateways, networking/communications hardware, and telecommunication lines within the facility is restricted. [cite: 2344]
    * 9.2.4 Access to consoles in sensitive areas is restricted via locking when not in use. [cite: 2349]
* **9.3 Physical access for personnel and visitors is authorized and managed.**
    * 9.3.1 Procedures are implemented for authorizing and managing physical access of personnel to the CDE, including:
        * Identifying personnel. [cite: 2358]
        * Managing changes to an individual’s physical access requirements. [cite: 2359]
        * Revoking or terminating personnel identification. [cite: 2359]
        * Limiting access to the identification process or system to authorized personnel. [cite: 2360]
        * 9.3.1.1 Physical access to sensitive areas within the CDE for personnel is controlled as follows:
            * Access is authorized and based on individual job function. [cite: 2369]
            * Access is revoked immediately upon termination. [cite: 2370]
            * All physical access mechanisms, such as keys, access cards, etc., are returned or disabled upon termination. [cite: 2370]
    * 9.3.2 Procedures are implemented for authorizing and managing visitor access to the CDE, including:
        * Visitors are authorized before entering. [cite: 2378]
        * Visitors are escorted at all times. [cite: 2379]
        * Visitors are clearly identified and given a badge or other identification that expires. [cite: 2379]
        * Visitor badges or other identification visibly distinguishes visitors from personnel. [cite: 2380]
    * 9.3.3 Visitor badges or identification are surrendered or deactivated before visitors leave the facility or at the date of expiration. [cite: 2391]
    * 9.3.4 Visitor logs are used to maintain a physical record of visitor activity both within the facility and within sensitive areas, including:
        * The visitor’s name and the organization represented. [cite: 2398]
        * The date and time of the visit. [cite: 2399]
        * The name of the personnel authorizing physical access. [cite: 2399]
        * Retaining the log for at least three months, unless otherwise restricted by law. [cite: 2400]
* **9.4 Media with cardholder data is securely stored, accessed, distributed, and destroyed.**
    * 9.4.1 All media with cardholder data is physically secured. [cite: 2410]
        * 9.4.1.1 Offline media backups with cardholder data are stored in a secure location. [cite: 2415]
        * 9.4.1.2 The security of the offline media backup location(s) with cardholder data is reviewed at least once every 12 months. [cite: 2422]
    * 9.4.2 All media with cardholder data is classified in accordance with the sensitivity of the data. [cite: 2429]
    * 9.4.3 Media with cardholder data sent outside the facility is secured as follows:
        * Media sent outside the facility is logged. [cite: 2436]
        * Media is sent by secured courier or other delivery method that can be accurately tracked. [cite: 2437]
        * Offsite tracking logs include details about media location. [cite: 2438]
    * 9.4.4 Management approves all media with cardholder data that is moved outside the facility (including when media is distributed to individuals). [cite: 2444]
    * 9.4.5 Inventory logs of all electronic media with cardholder data are maintained. [cite: 2451]
        * 9.4.5.1 Inventories of electronic media with cardholder data are conducted at least once every 12 months. [cite: 2457]
    * 9.4.6 Hard-copy materials with cardholder data are destroyed when no longer needed for business or legal reasons, as follows:
        * Materials are cross-cut shredded, incinerated, or pulped so that cardholder data cannot be reconstructed. [cite: 2467]
        * Materials are stored in secure storage containers prior to destruction. [cite: 2468]
    * 9.4.7 Electronic media with cardholder data is destroyed when no longer needed for business or legal reasons via one of the following:
        * The electronic media is destroyed. OR
        * The cardholder data is rendered unrecoverable so that it cannot be reconstructed. [cite: 2479, 2480]
* **9.5 Point of interaction (POI) devices are protected from tampering and unauthorized substitution.**
    * 9.5.1 POI devices that capture payment card data via direct physical interaction with the payment card form factor are protected from tampering and unauthorized substitution, including the following:
        * Maintaining a list of POI devices. [cite: 2491]
        * Periodically inspecting POI devices to look for tampering or unauthorized substitution. [cite: 2492]
        * Training personnel to be aware of suspicious behavior and to report tampering or unauthorized substitution of devices. [cite: 2493]
        * 9.5.1.1 An up-to-date list of POI devices is maintained, including:
            * Make and model of the device. [cite: 2505]
            * Location of device. [cite: 2506]
            * Device serial number or other methods of unique identification. [cite: 2506]
        * 9.5.1.2 POI device surfaces are periodically inspected to detect tampering and unauthorized substitution. [cite: 2517]
            * 9.5.1.2.1 The frequency of periodic POI device inspections and the type of inspections performed is defined in the entity’s targeted risk analysis, which is performed according to all elements specified in Requirement 12.3.1. [cite: 2536]
        * 9.5.1.3 Training is provided for personnel in POI environments to be aware of attempted tampering or replacement of POI devices, and includes:
            * Verifying the identity of any third-party persons claiming to be repair or maintenance personnel, before granting them access to modify or troubleshoot devices. [cite: 2549]
            * Procedures to ensure devices are not installed, replaced, or returned without verification. [cite: 2550]
            * Being aware of suspicious behavior around devices. [cite: 2551]
            * Reporting suspicious behavior and indications of device tampering or substitution to appropriate personnel. [cite: 2551]

### Requirement 10: Log and Monitor All Access to System Components and Cardholder Data

* **10.1 Processes and mechanisms for logging and monitoring all access to system components and cardholder data are defined and understood.**
    * 10.1.1 All security policies and operational procedures that are identified in Requirement 10 are:
        * Documented. [cite: 2577]
        * Kept up to date. [cite: 2578]
        * In use. [cite: 2578]
        * Known to all affected parties. [cite: 2578]
    * 10.1.2 Roles and responsibilities for performing activities in Requirement 10 are documented, assigned, and understood. [cite: 2587]
* **10.2 Audit logs are implemented to support the detection of anomalies and suspicious activity, and the forensic analysis of events.**
    * 10.2.1 Audit logs are enabled and active for all system components and cardholder data. [cite: 2599]
        * 10.2.1.1 Audit logs capture all individual user access to cardholder data. [cite: 2605]
        * 10.2.1.2 Audit logs capture all actions taken by any individual with administrative access, including any interactive use of application or system accounts. [cite: 2613]
        * 10.2.1.3 Audit logs capture all access to audit logs. [cite: 2619]
        * 10.2.1.4 Audit logs capture all invalid logical access attempts. [cite: 2622]
        * 10.2.1.5 Audit logs capture all changes to identification and authentication credentials including, but not limited to:
            * Creation of new accounts. [cite: 2630]
            * Elevation of privileges. [cite: 2631]
            * All changes, additions, or deletions to accounts with administrative access. [cite: 2631]
        * 10.2.1.6 Audit logs capture the following:
            * All initialization of new audit logs, and
            * All starting, stopping, or pausing of the existing audit logs. [cite: 2636]
        * 10.2.1.7 Audit logs capture all creation and deletion of system-level objects. [cite: 2642]
    * 10.2.2 Audit logs record the following details for each auditable event:
        * User identification. [cite: 2646]
        * Type of event. [cite: 2646]
        * Date and time. [cite: 2647]
        * Success and failure indication. [cite: 2647]
        * Origination of event. [cite: 2647]
        * Identity or name of affected data, system component, resource, or service (for example, name and protocol). [cite: 2648]
* **10.3 Audit logs are protected from destruction and unauthorized modifications.**
    * 10.3.1 Read access to audit logs files is limited to those with a job-related need. [cite: 2656]
    * 10.3.2 Audit log files are protected to prevent modifications by individuals. [cite: 2664]
    * 10.3.3 Audit log files, including those for external-facing technologies, are promptly backed up to a secure, central, internal log server(s) or other media that is difficult to modify. [cite: 2671]
    * 10.3.4 File integrity monitoring or change-detection mechanisms is used on audit logs to ensure that existing log data cannot be changed without generating alerts. [cite: 2679]
* **10.4 Audit logs are reviewed to identify anomalies or suspicious activity.**
    * 10.4.1 The following audit logs are reviewed at least once daily:
        * All security events. [cite: 2692]
        * Logs of all system components that store, process, or transmit CHD and/or SAD. [cite: 2693]
        * Logs of all critical system components. [cite: 2694]
        * Logs of all servers and system components that perform security functions (for example, network security controls, intrusion-detection systems/intrusion-prevention systems (IDS/IPS), authentication servers). [cite: 2694]
        * 10.4.1.1 Automated mechanisms are used to perform audit log reviews. [cite: 2704]
    * 10.4.2 Logs of all other system components (those not specified in Requirement 10.4.1) are reviewed periodically. [cite: 2710]
        * 10.4.2.1 The frequency of periodic log reviews for all other system components (not defined in Requirement 10.4.1) is defined in the entity’s targeted risk analysis, which is performed according to all elements specified in Requirement 12.3.1 [cite: 2717]
    * 10.4.3 Exceptions and anomalies identified during the review process are addressed. [cite: 2724]
* **10.5 Audit log history is retained and available for analysis.**
    * 10.5.1 Retain audit log history for at least 12 months, with at least the most recent three months immediately available for analysis. [cite: 2734]
* **10.6 Time-synchronization mechanisms support consistent time settings across all systems.**
    * 10.6.1 System clocks and time are synchronized using time-synchronization technology. [cite: 2745]
    * 10.6.2 Systems are configured to the correct and consistent time as follows:
        * One or more designated time servers are in use. [cite: 2752]
        * Only the designated central time server(s) receives time from external sources. [cite: 2753]
        * Time received from external sources is based on International Atomic Time or Coordinated Universal Time (UTC). [cite: 2754]
        * The designated time server(s) accept time updates only from specific industry-accepted external sources. [cite: 2755]
        * Where there is more than one designated time server, the time servers peer with one another to keep accurate time. [cite: 2756]
        * Internal systems receive time information only from designated central time server(s). [cite: 2757]
    * 10.6.3 Time synchronization settings and data are protected as follows:
        * Access to time data is restricted to only personnel with a business need. [cite: 2763]
        * Any changes to time settings on critical systems are logged, monitored, and reviewed. [cite: 2764]
* **10.7 Failures of critical security control systems are detected, reported, and responded to promptly.**
    * 10.7.1 Additional requirement for service providers only: Failures of critical security control systems are detected, alerted, and addressed promptly, including but not limited to failure of the following critical security control systems:
        * Network security controls. [cite: 2773]
        * IDS/IPS. [cite: 2774]
        * FIM. [cite: 2774]
        * Anti-malware solutions. [cite: 2774]
        * Physical access controls. [cite: 2774]
        * Logical access controls. [cite: 2774]
        * Audit logging mechanisms. [cite: 2774]
        * Segmentation controls (if used). [cite: 2775]
    * 10.7.2 Failures of critical security control systems are detected, alerted, and addressed promptly, including but not limited to failure of the following critical security control systems:
        * Network security controls. [cite: 2784]
        * IDS/IPS. [cite: 2785]
        * Change-detection mechanisms. [cite: 2785]
        * Anti-malware solutions. [cite: 2785]
        * Physical access controls. [cite: 2785]
        * Logical access controls. [cite: 2785]
        * Audit logging mechanisms. [cite: 2785]
        * Segmentation controls (if used). [cite: 2786]
        * Audit log review mechanisms. [cite: 2786]
        * Automated security testing tools (if used). [cite: 2786]
    * 10.7.3 Failures of any critical security control systems are responded to promptly, including but not limited to:
        * Restoring security functions. [cite: 2797]
        * Identifying and documenting the duration (date and time from start to end) of the security failure. [cite: 2798]
        * Identifying and documenting the cause(s) of failure and documenting required remediation. [cite: 2799]
        * Identifying and addressing any security issues that arose during the failure. [cite: 2800]
        * Determining whether further actions are required as a result of the security failure. [cite: 2801]
        * Implementing controls to prevent the cause of failure from reoccurring. [cite: 2802]
        * Resuming monitoring of security controls. [cite: 2802]

### Requirement 11: Test Security of Systems and Networks Regularly

* **11.1 Processes and mechanisms for regularly testing security of systems and networks are defined and understood.**
    * 11.1.1 All security policies and operational procedures that are identified in Requirement 11 are:
        * Documented. [cite: 2829]
        * Kept up to date. [cite: 2830]
        * In use. [cite: 2830]
        * Known to all affected parties. [cite: 2830]
    * 11.1.2 Roles and responsibilities for performing activities in Requirement 11 are documented, assigned, and understood. [cite: 2839]
* **11.2 Wireless access points are identified and monitored, and unauthorized wireless access points are addressed.**
    * 11.2.1 Authorized and unauthorized wireless access points are managed as follows:
        * The presence of wireless (Wi-Fi) access points is tested for, [cite: 2851]
        * All authorized and unauthorized wireless access points are detected and identified, [cite: 2851]
        * Testing, detection, and identification occurs at least once every three months. [cite: 2851]
        * If automated monitoring is used, personnel are notified via generated alerts. [cite: 2852]
    * 11.2.2 An inventory of authorized wireless access points is maintained, including a documented business justification. [cite: 2876]
* **11.3 External and internal vulnerabilities are regularly identified, prioritized, and addressed.**
    * 11.3.1 Internal vulnerability scans are performed as follows:
        * At least once every three months. [cite: 2888]
        * Vulnerabilities that are either high-risk or critical (according to the entity’s vulnerability risk rankings defined at Requirement 6.3.1) are resolved. [cite: 2889]
        * Rescans are performed that confirm all high-risk and all critical vulnerabilities (as noted above) have been resolved. [cite: 2890]
        * Scan tool is kept up to date with latest vulnerability information. [cite: 2891]
        * Scans are performed by qualified personnel and organizational independence of the tester exists. [cite: 2892]
        * 11.3.1.1 All other applicable vulnerabilities (those not ranked as high-risk vulnerabilities or critical vulnerabilities according to the entity’s vulnerability risk rankings defined at Requirement 6.3.1) are managed as follows:
            * Addressed based on the risk defined in the entity’s targeted risk analysis, which is performed according to all elements specified in Requirement 12.3.1. [cite: 2905]
            * Rescans are conducted as needed. [cite: 2906]
        * 11.3.1.2 Internal vulnerability scans are performed via authenticated scanning as follows:
            * Systems that are unable to accept credentials for authenticated scanning are documented. [cite: 2917]
            * Sufficient privileges are used for those systems that accept credentials for scanning. [cite: 2918]
            * If accounts used for authenticated scanning can be used for interactive login, they are managed in accordance with Requirement 8.2.2. [cite: 2919]
        * 11.3.1.3 Internal vulnerability scans are performed after any significant change as follows:
            * Vulnerabilities that are either high-risk or critical (according to the entity’s vulnerability risk rankings defined at Requirement 6.3.1) are resolved. [cite: 2934]
            * Rescans are conducted as needed. [cite: 2935]
            * Scans are performed by qualified personnel and organizational independence of the tester exists (not required to be a QSA or ASV). [cite: 2935]
    * 11.3.2 External vulnerability scans are performed as follows:
        * At least once every three months. [cite: 2951]
        * By a PCI SSC Approved Scanning Vendor (ASV). [cite: 2952]
        * Vulnerabilities are resolved and ASV Program Guide requirements for a passing scan are met. [cite: 2952]
        * Rescans are performed as needed to confirm that vulnerabilities are resolved per the ASV Program Guide requirements for a passing scan. [cite: 2953]
        * 11.3.2.1 External vulnerability scans are performed after any significant change as follows:
            * Vulnerabilities that are scored 4.0 or higher by the CVSS are resolved. [cite: 2968]
            * Rescans are conducted as needed. [cite: 2969]
            * Scans are performed by qualified personnel and organizational independence of the tester exists (not required to be a QSA or ASV). [cite: 2969]
* **11.4 External and internal penetration testing is regularly performed, and exploitable vulnerabilities and security weaknesses are corrected.**
    * 11.4.1 A penetration testing methodology is defined, documented, and implemented by the entity, and includes:
        * Industry-accepted penetration testing approaches. [cite: 2985]
        * Coverage for the entire CDE perimeter and critical systems. [cite: 2986]
        * Testing from both inside and outside the network. [cite: 2986]
        * Testing to validate any segmentation and scope-reduction controls. [cite: 2987]
        * Application-layer penetration testing to identify, at a minimum, the vulnerabilities listed in Requirement 6.2.4. [cite: 2987]
        * Network-layer penetration tests that encompass all components that support network functions as well as operating systems. [cite: 2988]
        * Review and consideration of threats and vulnerabilities experienced in the last 12 months. [cite: 2989]
        * Documented approach to assessing and addressing the risk posed by exploitable vulnerabilities and security weaknesses found during penetration testing. [cite: 2990]
        * Retention of penetration testing results and remediation activities results for at least 12 months. [cite: 2991]
    * 11.4.2 Internal penetration testing is performed:
        * Per the entity’s defined methodology,
        * At least once every 12 months
        * After any significant infrastructure or application upgrade or change
        * By a qualified internal resource or qualified external third-party
        * Organizational independence of the tester exists (not required to be a QSA or ASV). [cite: 3013]
    * 11.4.3 External penetration testing is performed:
        * Per the entity’s defined methodology
        * At least once every 12 months
        * After any significant infrastructure or application upgrade or change
        * By a qualified internal resource or qualified external third party
        * Organizational independence of the tester exists (not required to be a QSA or ASV) [cite: 3023]
    * 11.4.4 Exploitable vulnerabilities and security weaknesses found during penetration testing are corrected as follows:
        * In accordance with the entity’s assessment of the risk posed by the security issue as defined in Requirement 6.3.1. [cite: 3033]
        * Penetration testing is repeated to verify the corrections. [cite: 3034]
    * 11.4.5 If segmentation is used to isolate the CDE from other networks, penetration tests are performed on segmentation controls as follows:
        * At least once every 12 months and after any changes to segmentation controls/methods [cite: 3041]
        * Covering all segmentation controls/methods in use. [cite: 3041]
        * According to the entity’s defined penetration testing methodology. [cite: 3042]
        * Confirming that the segmentation controls/methods are operational and effective, and isolate the CDE from all out-of-scope systems. [cite: 3042]
        * Confirming effectiveness of any use of isolation to separate systems with differing security levels (see Requirement 2.2.3). [cite: 3043]
        * Performed by a qualified internal resource or qualified external third party. [cite: 3044]
        * Organizational independence of the tester exists (not required to be a QSA or ASV). [cite: 3045]
    * 11.4.6 Additional requirement for service providers only: If segmentation is used to isolate the CDE from other networks, penetration tests are performed on segmentation controls as follows:
        * At least once every six months and after any changes to segmentation controls/methods. [cite: 3056]
        * Covering all segmentation controls/methods in use. [cite: 3057]
        * According to the entity’s defined penetration testing methodology. [cite: 3057]
        * Confirming that the segmentation controls/methods are operational and effective, and isolate the CDE from all out-of-scope systems. [cite: 3058]
        * Confirming effectiveness of any use of isolation to separate systems with differing security levels (see Requirement 2.2.3). [cite: 3059]
        * Performed by a qualified internal resource or qualified external third party. [cite: 3060]
        * Organizational independence of the tester exists (not required to be a QSA or ASV). [cite: 3061]
    * 11.4.7 Additional requirement for multi-tenant service providers only: Multi-tenant service providers support their customers for external penetration testing per Requirement 11.4.3 and 11.4.4. [cite: 3071]
* **11.5 Network intrusions and unexpected file changes are detected and responded to.**
    * 11.5.1 Intrusion-detection and/or intrusion-prevention techniques are used to detect and/or prevent intrusions into the network as follows:
        * All traffic is monitored at the perimeter of the CDE. [cite: 3088]
        * All traffic is monitored at critical points in the CDE. [cite: 3089]
        * Personnel are alerted to suspected compromises. [cite: 3089]
        * All intrusion-detection and prevention engines, baselines, and signatures are kept up to date. [cite: 3090]
        * 11.5.1.1 Additional requirement for service providers only: Intrusion-detection and/or intrusion-prevention techniques detect, alert on/prevent, and address covert malware communication channels. [cite: 3102]
    * 11.5.2 A change-detection mechanism (for example, file integrity monitoring tools) is deployed as follows:
        * To alert personnel to unauthorized modification (including changes, additions, and deletions) of critical files. [cite: 3120]
        * To perform critical file comparisons at least once weekly. [cite: 3121]
* **11.6 Unauthorized changes on payment pages are detected and responded to.**
    * 11.6.1 A change- and tamper-detection mechanism is deployed as follows:
        * To alert personnel to unauthorized modification (including indicators of compromise, changes, additions, and deletions) to the security-impacting HTTP headers and the script contents of payment pages as received by the consumer browser. [cite: 3142]
        * The mechanism is configured to evaluate the received HTTP headers and payment pages. [cite: 3143]
        * The mechanism functions are performed as follows:
            * At least weekly OR
            * Periodically (at the frequency defined in the entity’s targeted risk analysis, which is performed according to all elements specified in Requirement 12.3.1). [cite: 3144]

### Requirement 12: Support Information Security with Organizational Policies and Programs

* **12.1 A comprehensive information security policy that governs and provides direction for protection of the entity’s information assets is known and current.**
    * 12.1.1 An overall information security policy is:
        * Established. [cite: 3182]
        * Published. [cite: 3182]
        * Maintained. [cite: 3182]
        * Disseminated to all relevant personnel, as well as to relevant vendors and business partners. [cite: 3183]
    * 12.1.2 The information security policy is:
        * Reviewed at least once every 12 months. [cite: 3195]
        * Updated as needed to reflect changes to business objectives or risks to the environment. [cite: 3196]
    * 12.1.3 The security policy clearly defines information security roles and responsibilities for all personnel, and all personnel are aware of and acknowledge their information security responsibilities. [cite: 3200]
    * 12.1.4 Responsibility for information security is formally assigned to a Chief Information Security Officer or other information security knowledgeable member of executive management. [cite: 3211]
* **12.2 Acceptable use policies for end-user technologies are defined and implemented.**
    * 12.2.1 Acceptable use policies for end-user technologies are documented and implemented, including:
        * Explicit approval by authorized parties. [cite: 3221]
        * Acceptable uses of the technology. [cite: 3222]
        * List of products approved by the company for employee use, including hardware and software. [cite: 3222]
* **12.3 Risks to the cardholder data environment are formally identified, evaluated, and managed.**
    * 12.3.1 For each PCI DSS requirement that specifies completion of a targeted risk analysis, the analysis is documented and includes:
        * Identification of the assets being protected. [cite: 3234]
        * Identification of the threat(s) that the requirement is protecting against. [cite: 3235]
        * Identification of factors that contribute to the likelihood and/or impact of a threat being realized. [cite: 3236]
        * Resulting analysis that determines, and includes justification for, how the frequency or processes defined by the entity to meet the requirement minimize the likelihood and/or impact of the threat being realized. [cite: 3237]
        * Review of each targeted risk analysis at least once every 12 months to determine whether the results are still valid or if an updated risk analysis is needed. [cite: 3238]
        * Performance of updated risk analyses when needed, as determined by the annual review. [cite: 3239]
    * 12.3.2 A targeted risk analysis is performed for each PCI DSS requirement that the entity meets with the customized approach, to include:
        * Documented evidence detailing each element specified in Appendix D: Customized Approach (including, at a minimum, a controls matrix and risk analysis). [cite: 3256]
        * Approval of documented evidence by senior management. [cite: 3257]
        * Performance of the targeted analysis of risk at least once every 12 months. [cite: 3257]
    * 12.3.3 Cryptographic cipher suites and protocols in use are documented and reviewed at least once every 12 months, including at least the following:
        * An up-to-date inventory of all cryptographic cipher suites and protocols in use, including purpose and where used. [cite: 3268]
        * Active monitoring of industry trends regarding continued viability of all cryptographic cipher suites and protocols in use. [cite: 3269]
        * Documentation of a plan, to respond to anticipated changes in cryptographic vulnerabilities. [cite: 3270]
    * 12.3.4 Hardware and software technologies in use are reviewed at least once every 12 months, including at least the following:
        * Analysis that the technologies continue to receive security fixes from vendors promptly. [cite: 3281]
        * Analysis that the technologies continue to support (and do not preclude) the entity’s PCI DSS compliance. [cite: 3282]
        * Documentation of any industry announcements or trends related to a technology, such as when a vendor has announced “end of life” plans for a technology. [cite: 3283]
        * Documentation of a plan, approved by senior management, to remediate outdated technologies, including those for which vendors have announced “end of life” plans. [cite: 3284]
* **12.4 PCI DSS compliance is managed.**
    * 12.4.1 Additional requirement for service providers only: Responsibility is established by executive management for the protection of cardholder data and a PCI DSS compliance program to include:
        * Overall accountability for maintaining PCI DSS compliance. [cite: 3292]
        * Defining a charter for a PCI DSS compliance program and communication to executive management. [cite: 3293]
    * 12.4.2 Additional requirement for service providers only: Reviews are performed at least once every three months to confirm that personnel are performing their tasks in accordance with all security policies and operational procedures. Reviews are performed by personnel other than those responsible for performing the given task and include, but are not limited to, the following tasks:
        * Daily log reviews. [cite: 3308]
        * Configuration reviews for network security controls. [cite: 3309]
        * Applying configuration standards to new systems. [cite: 3309]
        * Responding to security alerts. [cite: 3309]
        * Change-management processes. [cite: 3310]
        * 12.4.2.1 Additional requirement for service providers only: Reviews conducted in accordance with Requirement 12.4.2 are documented to include:
            * Results of the reviews. [cite: 3318]
            * Documented remediation actions taken for any tasks that were found to not be performed at Requirement 12.4.2. [cite: 3319]
            * Review and sign-off of results by personnel assigned responsibility for the PCI DSS compliance program. [cite: 3320]
* **12.5 PCI DSS scope is documented and validated.**
    * 12.5.1 An inventory of system components that are in scope for PCI DSS, including a description of function/use, is maintained and kept current. [cite: 3332]
    * 12.5.2 PCI DSS scope is documented and confirmed by the entity at least once every 12 months and upon significant change to the in-scope environment. At a minimum, the scoping validation includes: [cite: 3341]
        * Identifying all data flows for the various payment stages (for example, authorization, capture settlement, chargebacks, and refunds) and acceptance channels (for example, card-present, card-not-present, and e-commerce). [cite: 3342]
        * Updating all data-flow diagrams per Requirement 1.2.4. [cite: 3343]
        * Identifying all locations where account data is stored, processed, and transmitted, including but not limited to: 1) any locations outside of the currently defined CDE, 2) applications that process CHD, 3) transmissions between systems and networks, and 4) file backups. [cite: 3343]
        * Identifying all system components in the CDE, connected to the CDE, or that could impact security of the CDE. [cite: 3344]
        * Identifying all segmentation controls in use and the environment(s) from which the CDE is segmented, including justification for environments being out of scope. [cite: 3345]
        * Identifying all connections from third-party entities with access to the CDE. [cite: 3346]
        * Confirming that all identified data flows, account data, system components, segmentation controls, and connections from third parties with access to the CDE are included in scope. [cite: 3347]
        * 12.5.2.1 Additional requirement for service providers only: PCI DSS scope is documented and confirmed by the entity at least once every six months and upon significant change to the in-scope environment. At a minimum, the scoping validation includes all the elements specified in Requirement 12.5.2. [cite: 3363, 3364]
    * 12.5.3 Additional requirement for service providers only: Significant changes to organizational structure result in a documented (internal) review of the impact to PCI DSS scope and applicability of controls, with results communicated to executive management. [cite: 3374]
* **12.6 Security awareness education is an ongoing activity.**
    * 12.6.1 A formal security awareness program is implemented to make all personnel aware of the entity’s information security policy and procedures, and their role in protecting the cardholder data. [cite: 3383]
    * 12.6.2 The security awareness program is:
        * Reviewed at least once every 12 months, and
        * Updated as needed to address any new threats and vulnerabilities that may impact the security of the entity’s cardholder data and/or sensitive authentication data, or the information provided to personnel about their role in protecting cardholder data. [cite: 3389]
    * 12.6.3 Personnel receive security awareness training as follows:
        * Upon hire and at least once every 12 months. [cite: 3401]
        * Multiple methods of communication are used. [cite: 3402]
        * Personnel acknowledge at least once every 12 months that they have read and understood the information security policy and procedures. [cite: 3402]
        * 12.6.3.1 Security awareness training includes awareness of threats and vulnerabilities that could impact the security of cardholder data and/or sensitive authentication data, including but not limited to:
            * Phishing and related attacks. [cite: 3415]
            * Social engineering. [cite: 3416]
        * 12.6.3.2 Security awareness training includes awareness about the acceptable use of end-user technologies in accordance with Requirement 12.2.1. [cite: 3424]
* **12.7 Personnel are screened to reduce risks from insider threats.**
    * 12.7.1 Potential personnel who will have access to the CDE are screened, within the constraints of local laws, prior to hire to minimize the risk of attacks from internal sources. [cite: 3436]
* **12.8 Risk to information assets associated with third-party service provider (TPSP) relationships is managed.**
    * 12.8.1 A list of all third-party service providers (TPSPs) with which account data is shared or that could affect the security of account data is maintained, including a description for each of the services provided. [cite: 3446]
    * 12.8.2 Written agreements with TPSPs are maintained as follows:
        * Written agreements are maintained with all TPSPs with which account data is shared or that could affect the security of the CDE. [cite: 3455]
        * Written agreements include acknowledgments from TPSPs that TPSPs are responsible for the security of account data the TPSPs possess or otherwise store, process, or transmit on behalf of the entity, or to the extent that the TPSP could impact the security of the entity’s cardholder data and/or sensitive authentication data. [cite: 3456]
    * 12.8.3 An established process is implemented for engaging TPSPs, including proper due diligence prior to engagement. [cite: 3474]
    * 12.8.4 A program is implemented to monitor TPSPs’ PCI DSS compliance status at least once every 12 months. [cite: 3481]
    * 12.8.5 Information is maintained about which PCI DSS requirements are managed by each TPSP, which are managed by the entity, and any that are shared between the TPSP and the entity. [cite: 3500]
* **12.9 Third-party service providers (TPSPs) support their customers’ PCI DSS compliance.**
    * 12.9.1 Additional requirement for service providers only: TPSPs provide written agreements to customers that include acknowledgments that TPSPs are responsible for the security of account data the TPSP possesses or otherwise stores, processes, or transmits on behalf of the customer, or to the extent that the TPSP could impact the security of the customer’s cardholder data and/or sensitive authentication data. [cite: 3515]
    * 12.9.2 Additional requirement for service providers only: TPSPs support their customers’ requests for information to meet Requirements 12.8.4 and 12.8.5 by providing the following upon customer request:
        * PCI DSS compliance status information (Requirement 12.8.4). [cite: 3532]
        * Information about which PCI DSS requirements are the responsibility of the TPSP and which are the responsibility of the customer, including any shared responsibilities (Requirement 12.8.5), for any service the TPSP provides that meets a PCI DSS requirement(s) on behalf of customers or that can impact security of customers’ cardholder data or sensitive authentication data. [cite: 3533]
* **12.10 Suspected and confirmed security incidents that could impact the CDE are responded to immediately.**
    * 12.10.1 An incident response plan exists and is ready to be activated in the event of a suspected or confirmed security incident. The plan includes, but is not limited to: [cite: 3550]
        * Roles, responsibilities, and communication and contact strategies in the event of a suspected or confirmed security incident, including notification of payment brands and acquirers, at a minimum. [cite: 3551]
        * Incident response procedures with specific containment and mitigation activities for different types of incidents. [cite: 3552]
        * Business recovery and continuity procedures. [cite: 3553]
        * Data backup processes. [cite: 3553]
        * Analysis of legal requirements for reporting compromises. [cite: 3553]
        * Coverage and responses of all critical system components. [cite: 3554]
        * Reference or inclusion of incident response procedures from the payment brands. [cite: 3554]
    * 12.10.2 At least once every 12 months, the security incident response plan is:
        * Reviewed and the content is updated as needed. [cite: 3565]
        * Tested, including all elements listed in Requirement 12.10.1. [cite: 3566]
    * 12.10.3 Specific personnel are designated to be available on a 24/7 basis to respond to suspected or confirmed security incidents. [cite: 3574]
    * 12.10.4 Personnel responsible for responding to suspected and confirmed security incidents are appropriately and periodically trained on their incident response responsibilities. [cite: 3580]
        * 12.10.4.1 The frequency of periodic training for incident response personnel is defined in the entity’s targeted risk analysis, which is performed according to all elements specified in Requirement 12.3.1. [cite: 3585]
    * 12.10.5 The security incident response plan includes monitoring and responding to alerts from security monitoring systems, including but not limited to:
        * Intrusion-detection and intrusion-prevention systems. [cite: 3592]
        * Network security controls. [cite: 3593]
        * Change-detection mechanisms for critical files. [cite: 3593]
        * The change-and tamper-detection mechanism for payment pages. [cite: 3593, 3594] [This bullet is a best practice until its effective date; refer to Applicability Notes below for details.]
        * Detection of unauthorized wireless access points. [cite: 3595]
    * 12.10.6 The security incident response plan is modified and evolved according to lessons learned and to incorporate industry developments. [cite: 3604]
    * 12.10.7 Incident response procedures are in place, to be initiated upon the detection of stored PAN anywhere it is not expected, and include:
        * Determining what to do if PAN is discovered outside the CDE, including its retrieval, secure deletion, and/or migration into the currently defined CDE, as applicable. [cite: 3613]
        * Identifying whether sensitive authentication data is stored with PAN. [cite: 3614]
        * Determining where the account data came from and how it ended up where it was not expected. [cite: 3615]
        * Remediating data leaks or process gaps that resulted in the account data being where it was not expected. [cite: 3616]