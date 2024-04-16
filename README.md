# 5G_ciphered_NAS_decipher_tool
 ## A python tool to decipher/decrypt 5G ciphered NAS payload and export plain 5G NAS payload back into wireshark pcap file
 
  During my work in 5G testing and troubleshooting, I have been seeing many cases that 5G NAS message captured in wireshark are ciphered by AES,snow3G, or ZUC, and the SUCI in registration request could also be ciphered by profileA/profileB defined in 3GPP 33.501.
So I come up with this idea to write a python program to decipher the 5G NAS payload retrieved from pcap file, then write the plain NAS payload back into the pcap file. By that, we can browse and check the deciphered NAS details by wireshark very easily.
### warning: This is tool is not in well maintenance, it may not work with new wireshark due to json output format change.
# Python dependencies of this tool:
  pyshark: https://github.com/KimiNewt/pyshark/ Python wrapper for tshark, allowing python packet parsing using wireshark dissectors
  
  pycryptodome: https://github.com/Legrandin/pycryptodome a self-contained Python package of low-level cryptographic primitives
  
  cryptography: https://github.com/pyca/cryptography a package which provides cryptographic recipes and primitives to Python developers
  
  CryptoMobile: https://github.com/mitshell/CryptoMobile python wrappers around 3G and LTE encryption and integrity protection   algorithms 


# Supported ciphering algorithm:
  a.	SUCI encryption based on profile A(curve 22519)  or profile B( EC secp256r1)
  
  b.	NAS ciphering with EEA1(snow3G)/EEA2(AES)/EEA3(ZUC)
# Current limitation:
  Support 5G AKA authentication only, no EAP-AKA’ support.
# Environment/Versions
  wireshark 3.0+ on windows 7/10.
# The basic idea of how to decipher the 5G NAS message:
  3GPP TS 33.501 Annex C defines Elliptic Curve Integrated Encryption Scheme (ECIES) to conceal the Subscription Permanent Identifier(SUPI) in registration request. The encrption of ECIES profileA or profileB is based on below diagram, so if we have the private key of home network, and retreive the Eph. public key of UE in regisration request message from pcap file,then we can compute the Eph. shared key based on the private key of home network and Eph. public key of UE. With the Eph. shared key computed, we can derive Eph. decription key to decrypt the SUCI and get the plain text based SUPI.
  
  Below is the diaram of encryption of SUPI based on ECIES:
  ![Encryption based on ECIES at UE](/images/ECIES.png)
  
  Further more, after getting SUPI,if we have the secret key of UE and OP(or OPc) of network,we can retrieve the RAND/MAC/RES value from authentication request in pcap file, then compute the CK/IK based on Milenage algorithm(3GPP 35.205/35.206) on our own. With the CK/IK and below key derivation scheme defined in 3GPP 33.501, we can eventually derive the KAMF and the subsquent KNASenc key to decipher the NAS payload.
  
  Below is the Key derivation scheme defined by 33.501, based on which we could compute the Eph. shared key and encryption key for SUCI decryption.
  
  ![Key derivation scheme defined by 33.501](/images/key-derivation.png)
  5G AKA authentication procedure defined by 33.501, from which we could retrieve the RAND value and compute CK/IK and eventually get the encryption key of NAS to decrypt NAS payload.
  
  ![5G AKA authentication procedure defined by 33.501](/images/AKA.png)
  
  An alternative way to derive KAMF and KNASenc key is to capture the message between AUSF and SEAF, then derive the Kseaf from message, by that, we can eventually derive the KAMF & KNASenc without having to get the secret key and OP value,as usually secret key and OP are quite confidential and won't be exposed to outside user. This tool currently support deriving the encryption key based on secret key and OP only, as it's supposed to be used for internal testing so it's shouldn't be a problem to get secret key and OP, it may support later the derivation of encription key based on Kseaf captured between AUSF and SEAF(AMF).
  
  With the encryption key derived, we can decrypt the NAS payload based on below scheme of ciphering-data defined in 33.401 Annex B.
   ![ciphering-data](/images/ciphering-data.png)
  
# Prerequisite needed to make this tool work:
  1.	Your pcap need to contain the registration request or identity response message from UEs so that the tool could retrieve the SUPI from that, the pcap need to contain authentication request message as well so that the tool could retrieve the CK/IK based on the rand value during authentication procedure.
  
  2.	Running on windows 7/10 only.
  
  3.	Wireshark 3.0 or above installed on the computer on which this tool is running, as tshark of wireshark is needed to read the pcap file. Old wireshark(lower than 3.0) may not decode new 5G nas message well.
  
 # how to use this tool:
  1. In your wireshak,make sure you have the option “edit->preference->try to detect and decode EEA0 ciphered messages” enabled in     wireshark, so that it would decode  and display the “null encrypted message” generated by this tool. 
  ![wireshark-setting](/images/tool-usage-1.png)
  2. Run the python code on your windows PC.
  
  3. Input the secret key and op in GUI, to decrypt ciphered NAS. If your SUPI is encrypted, you need to input private key to allow the tool decrypt SUCI and retrieve the SUPI for NAS encryption key computation.
  ![tool-setup](/images/tool-usage-2.png)
  4. Select the .pcap file, then click “decrypt”, the tool will filter it by ngap protocol first, then generate a new pcap file with decrypted message content inside, the encrypted nas message inside pcap would be replace by new plain message.
  5. After that, open the new .pcap file by wireshark, you’ll see the plain 5G nas message inside. Also, the SUCI in the first registration message would be decrypted and replaced by a plain SUPI string with the “null scheme” format in spec and BCD based encoding , padded by all ‘ff’ to keep the original length of the message unchanged, otherwise, it may cause checksum error in other layer. 
  6. message before de-ciphering in wireshark:
  ![tool-setup](/images/tool-usage-3.png)
  7. plain NAS payload after de-ciphering in wireshark:
  ![tool-setup](/images/tool-usage-4.png)
  8. deciphered SUPI in wireshark:
  ![tool-setup](/images/tool-usage-5.png)
# some other reference from 3GPP spec 33.501 used for NAS decryption.
## 1. 33.501 Annex A, KDF defintion and key derivation details:
  A.1	KDF interface and input parameter construction
  A.1.1	General
  All key derivations (including input parameter encoding) for 5GC shall be performed using the key derivation function (KDF) specified in Annex B.2.0 of TS 33.220 [28]. 
  This clause specifies how to construct the input string, S, and the input key, KEY, for each distinct use of the KDF. Note that "KEY" is denoted "Key" in TS 33.220 [28].
    A.2	KAUSF derivation function
  This clause applies to 5G AKA only. 
  When deriving a KAUSF from CK, IK and the serving network name when producing authentication vectors, and when the UE computes KAUSF during 5G AKA, the following parameters shall be used to form the input S to the  KDF:
  -	FC =  0x6A;
  -	P0 = serving network  name;
  -	L0 = length of the serving network name (variable length as specified in 24.501  [35]);
  -	P1 = SQN   AK,
  -	L1 = length of SQN  AK (i.e. 0x00 0x06).
  The XOR of the Sequence Number (SQN) and the Anonymity Key (AK) is sent to the UE as a part of the Authentication Token (AUTN), see TS 33.102. If AK is not used, AK shall be treated in accordance with TS 33.102, i.e. as 000…0.
  The serving network name shall be constructed as specified in clause 6.1.1.4.

  The input key KEY shall be equal to the concatenation CK || IK of CK and IK.
  
  A.3	CK' and IK' derivation function
When deriving CK' and IK' then the KDF of TS 33.402 [11] clause A.2 shall be used with the following exception: the serving network name (specified in clause 6.1.1.4) shall be used as the value of access network identity (P0).

A.4	RES* and XRES* derivation function 
  When deriving RES* from RES, RAND, and serving network name in the UE and when deriving XRES* from XRES, RAND, and the serving network name in the ARPF, the following parameters shall be used to form the input S to the KDF. 
  -	FC = 0x6B,
  -	P0 = serving network name,
  -	L0 = length of the serving network name (variable length as specified in 24.501 [35]),
  -	P1 = RAND,
  -	L1 = length of RAND (i.e. 0x00  0x10),
  -	P2 = RES or XRES,
  -	L2 = length RES or XRES (i.e. variable length between 0x00 0x04 and 0x00  0x10).
  The input key KEY shall be equal to the concatenation CK || IK of CK and IK.
  The serving network name shall be constructed as specified in clause 6.1.1.4.

  The (X)RES* is identified with the 128 least significant bits of the output of the KDF.

A.6	KSEAF derivation function
  When deriving a KSEAF from KAUSF, the following parameters shall be used to form the input S to the  KDF:
  -	FC = 0x6C,
  -	P0 = <serving network name>,
  -	L0 = length of <serving network  name>.
  The input key KEY shall be KAUSF. 
  The serving network name shall be constructed as specified in clause 6.1.1.4.
  A.7	KAMF derivation function
    A.7.0	Parameters for the input S to the KDF
      When deriving a KAMF from KSEAF the following parameters shall be used to form the input S to the KDF. 
      -	FC = 0x6D
      -	P0 = SUPI 
      -	L0 = P0 length - number of octets in P0
      -	P1 = ABBA parameter 
      -	L1 = P1 length - number of octets in P1 
      The input key KEY shall be the 256-bit KSEAF.
      For P0, when the SUPI type is IMSI, SUPI shall be set to IMSI as defined in clause 2.2 of TS 23.003 [19]. For P0, when the SUPI type is network specific identifier, the SUPI shall be set to Network Access Identifier (NAI) as defined in clause 28.7.2 of TS 23.003 [19]. SUPI shall be represented as a character string as specified in B.2.1.2 of TS 33.220 [28], for both IMSI based SUPI as well as in NAI based SUPI.
      For ABBA parameter values please refer to clause A.7.1.
  
  A.8	Algorithm key derivation functions
  
    When deriving keys for NAS integrity and NAS encryption algorithms from KAMF in the AMF and UE or ciphering and integrity keys from KgNB/ KSN in the gNB and UE, the following parameters shall be used to form the string S.
    -	FC = 0x69
    -	P0 = algorithm type distinguisher
    -	L0 = length of algorithm type distinguisher (i.e. 0x00 0x01)
    -	P1 = algorithm identity
    -	L1 = length of algorithm identity (i.e. 0x00 0x01)
    The algorithm type distinguisher shall be N-NAS-enc-alg for NAS encryption algorithms and N-NAS-int-alg for NAS integrity protection algorithms. The algorithm type distinguisher shall be N-RRC-enc-alg for RRC encryption algorithms, N-RRC-int-alg for RRC integrity protection algorithms, N-UP-enc-alg for UP encryption algorithms and N-UP-int-alg for UP integrity protection algorithms (see table A.8-1). The values 0x00 and 0x07 to 0xf0 are reserved for future use, and the values 0xf1 to 0xff are reserved for private use.
    Table A.8-1: Algorithm type distinguishers
    Algorithm distinguisher	Value
    N-NAS-enc-alg	0x01
    N-NAS-int-alg	0x02
    N-RRC-enc-alg	0x03
    N-RRC-int-alg	0x04
    N-UP-enc-alg	0x05
    N-UP-int-alg	0x06

    The algorithm identity (as specified in clause 5) shall be put in the four least significant bits of the octet. The two least significant bits of the four most significant bits are reserved for future use, and the two most significant bits of the most significant nibble are reserved for private use. The entire four most significant bits shall be set to all zeros. 
    For the derivation of integrity and ciphering keys used between the UE and gNB, the input key shall be the 256-bit KgNB// KSN. For the derivation of integrity and ciphering keys used between the UE and AMF, the input key shall be the 256-bit KAMF.
    For an algorithm key of length n bits, where n is less or equal to 256, the n least significant bits of the 256 bits of the KDF output shall be used as the algorithm key.


C.3.4	ECIES profiles

  C.3.4.0	General
  
  Unless otherwise stated, the ECIES profiles follow the terminology and processing specified in SECG version 2 [29] and [30]. The profiles shall use "named curves" over prime fields.
  For generating successive counter blocks from the initial counter block (ICB) in CTR mode, the profiles shall use the standard incrementing function in section B.1 of NIST Special Publication 800-38A [16] with m = 32 bits. The ICB corresponds to T1 in section 6.5 of [16].
  The value of the MAC tag in ECIES, shall be the L most significant octects of the output generated by the HMAC function, where L equals to the maclen.
  Profile A shall use its own standardized processing for key generation (section 6 of RFC 7748 [46]) and shared secret calculation (section 5 of RFC 7748 [46]). The Diffie-Hellman primitive X25519 (section 5 of RFC 7748 [46]) takes two random octet strings as input, decodes them as scalar and coordinate, performs multiplication, and encodes the result as an octet string. The shared secret output octet string from X25519 shall be used as the input Z in the ECIES KDF (section 3.6.1 of [29]).
  Profile B shall use point compression to save overhead and shall use the Elliptic Curve Cofactor Diffie-Hellman Primitive (section 3.3.2 of [29]) to enable future addition of profiles with cofactor h ≠ 1. For curves with cofactor h = 1 the two primitives (section 3.3.1 and 3.3.2 of [29]) are equal.
  The profiles shall not use backwards compatibility mode (therefore are not compatible with version 1 of SECG).
  
  C.3.4.1	Profile A
  
  The ME and SIDF shall implement this profile. The ECIES parameters for this profile shall be the following:
  -	EC domain parameters							: Curve25519 [46]
  -	EC Diffie-Hellman primitive					: X25519 [46]
  -	point compression								: N/A
  -	KDF												: ANSI-X9.63-KDF [29]
  -	Hash												: SHA-256
  -	SharedInfo1										:   (the ephemeral public key octet string – see [29] section 5.1.3)
  -	MAC												: HMAC–SHA-256
  -	mackeylen										: 32 octets (256 bits)
  -	maclen											: 8 octets (64 bits)
  -	SharedInfo2										: the empty string
  -	ENC												: AES–128 in CTR mode
  -	enckeylen											: 16 octets (128 bits)
  -	icblen												: 16 octets (128 bits)
  -	backwards compatibility mode					: false
  
  C.3.4.2	Profile B
  
  The ME and SIDF shall implement this profile. The ECIES parameters for this profile shall be the following:
  -	EC domain parameters							: secp256r1 [30]
  -	EC Diffie-Hellman primitive					: Elliptic Curve Cofactor Diffie-Hellman Primitive [29]
  -	point compression								: true
  -	KDF												: ANSI-X9.63-KDF [29]
  -	Hash												: SHA-256
  -	SharedInfo1										:   (the ephemeral public key octet string – see [29] section 5.1.3)
  -	MAC												: HMAC–SHA-256
  -	mackeylen										: 32 octets (256 bits)
  -	maclen											: 8 octets (64 bits)
  -	SharedInfo2										: the empty string
  -	ENC												: AES–128 in CTR mode
  -	enckeylen											: 16 octets (128 bits)
  -	icblen												: 16 octets (128 bits)
  -	backwards compatibility mode					: false


