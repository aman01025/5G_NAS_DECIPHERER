from contextlib import nullcontext
from pickle import LIST
from sre_constants import ANY
import tkinter
from tkinter.filedialog import askopenfilename
import threading
import queue
from Crypto.Hash import HMAC, SHA256
from Crypto.Cipher import AES
import pyshark
import sys
# import binascii
# import string
import os.path
import subprocess
from datetime import datetime
from time import sleep as module_time_sleep
import logging
import logging.handlers
from CryptoMobile.Milenage import Milenage
# import traceback
import pysnow
import pyzuc
#from scapy.all import *
from logging.handlers import QueueHandler
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.x963kdf import X963KDF
from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
import glob
import os

#logging.basicConfig()
logging.basicConfig(filename='snowpher.log', filemode='w', format='%(name)s - %(levelname)s - %(message)s', level=logging.DEBUG)
#logger = logging.getLogger(name="decipher")     # get logger instance .
logger = logging.getLogger()
logger.info("\n\n\n*********************** SNOWPHER.EXE LOG File Begins ***********************\n\n\n")

class TSharkNotFoundException(Exception):
    pass


class Decryption:
    #def __init__(self,secret_key,op, opc, file_location, _queue,tshark_path,new_bearer_id):
    def __init__(self, file_location, _queue,tshark_path,new_bearer_id):
        """
                self.ue_dict contains all data for each UE like ngap_id,rand,encryption key,RES,use SUPI as index.
                It's a three dimensionals dictionary and key in first level is ran-UE-ngap-ID, key in second
                level dict is GNB-IP,third level dictionary contains a single UE's all kinds of data.
                self.ue_dict structure: {"ran-UE-ngap-ID":{"GNB-IP":{AMF-UE-ngap-ID":"xxxx",encrytion key:"xxxx",
                rand:"xxxx",res:"xxxx",mac:"xxxx",.....}}}
                self.ue_dict:
                mcc:string of 3 digits base 10
                mnc:string of 3 digits base 10,padded by 0 in the front if it's 2 digits.
                supi:string of 15 digits base 10, need to convert to ascii before usage.
                ran-UE-ngap-id: string of hex digits.
                rand,res,ck,ik: bytes string.
                snn: string of network name.
                kausf/kseaf/kamf/cipher_key: bytes string.
                algorithm_id_4g: string of 1 digit based 10.
                local_downlink_nas_count: integer
                local_uplink_nas_count: integer
            """
        logger.debug("\n\nInside Decryption::__init__ function\n")

        self.secret_key:bytes = bytes.fromhex('54484953204953204120534543524554')           # bytes string.
        logger.info("Secret key used: {}".format(self.secret_key))
        #self.use_op = use_op
        self.OP: bytes = bytes.fromhex('')
        self.OPC: bytes = bytes.fromhex('576FE92DC7B03D69F47801E3B02ED0D7')         # bytes string.
        logger.info("OPc value: {}".format(self.OPC))
        self.ck = None
        self.ik = None
        self.file_location = file_location
        logger.info("File location searching: {}".format(file_location))
        self.file_name = None
        self.queue = _queue
        self.TIME_OUT_FILTER_PCAP= 300
        self.ue_dict = {}
        self.amf_ip_list = []
        self.amf_ip = None
        self.gnb_ip = None
        self.buffer = None
        self.supi = None
        self.snn = None
        self.cipher_key = None
        self.cipher_key_4g = None
        self.packet_number = 0
        self.nas_pdu = None
        self.capture = None #the capture object genereated by pyshark.Capture
        self.filtered_file_name =None
        self.tshark_path = tshark_path
        logger.info("tshark path: {}".format(tshark_path))
        self.new_bearer_id= new_bearer_id
        logger.info("new_bearer_id: {}".format(new_bearer_id))


    def call_milenage(self,sk, op:bytes, opc:bytes,rand, autn, sqn_xor_ak, amf, retrieved_mac):
        # need enhancement here to handle OPc.
        logger.info("\n\nInside Decrytion::call_milenage\n")
        logger.info("Received Parameters:\nsk: {}\nop: {}\nopc: {}\nrand: {}\nautn: {}\nsqn_xor_ak: {}\namf: {}retrieved_mac: {}".format(sk,op,opc,rand,autn,sqn_xor_ak,amf,retrieved_mac))
        if opc:
            mil = Milenage(b'00')
            mil.set_opc(opc)
        elif op:
            mil = Milenage(op)
        else:
            return None,None,None


        res, ck, ik, ak = mil.f2345(sk, rand)
        logger.info("res: {}\nck: {}\nik: {}\nak: {}".format(res,ck,ik,ak))
        # get sqn by ak xor sqn_xor_ak
        sqn = (int.from_bytes(ak, byteorder='big') ^
               int.from_bytes(sqn_xor_ak, byteorder="big")).to_bytes(6, byteorder='big')
        computed_mac = mil.f1(sk, rand, sqn, amf)
        logger.info("Computed MAC: {}".format(computed_mac))
        if computed_mac == retrieved_mac:
            return res, ck, ik
        else:
            logger.warning("warning: mac failure! one authentication request message skipped!\n")
            return None, None, None

    def get_tshark_path(self,tshark_path=None):
        """
            Finds the path of the tshark executable. If the user has provided a path
            it will be used. Otherwise default locations will be searched.

            :param tshark_path: Path of the tshark binary
            :raises TSharkNotFoundException in case TShark is not found in any location.
        """
        logger.info("\n\nInside Decrytion::get_tshark_path\n")
        possible_paths = [r'python3 /home/amantya/local/lib/python3.8/site-packages/pyshark/tshark/tshark.py']
        if self.tshark_path:
            #possible_paths.insert(0, self.tshark_path)
            possible_paths.insert(0, possible_paths)
        if sys.platform.startswith('win'):
            for env in ('ProgramFiles(x86)', 'ProgramFiles'):
                program_files = os.getenv(env)
                if program_files is not None:
                    possible_paths.append(
                        os.path.join(program_files, 'Wireshark', 'tshark.exe')
                    )
        for path in possible_paths:
            if os.path.exists(path):
                logger.info("TSHARK Path: {}".format(path))
                return path
        return None

    def process_reg_request(self,packet,gnb_ip,amf_ip):
        # add a new entry and use ran_ue_ngap_id as key in dictionary.
        logger.info("\nInside Decrytion::process_reg_request")
        logger.info("Start processing registration request")
     #   ran_ue_ngap_id=packet.ngap.ran_ue_ngap_id.raw_value
      #  if not (ran_ue_ngap_id in self.ue_dict):
       #     self.ue_dict[ran_ue_ngap_id] = {}
        logger.info("\n\nInside Decrytion::process_reg_request\n")
        # add source_ip as key in second level dictionary.
        if not (gnb_ip in self.ue_dict):
            self.ue_dict[gnb_ip] = {}
            logger.debug(packet[5].dedicatednas_message.raw_value)
            logger.debug('process_reg_request 1')

        self.ue_dict[gnb_ip]['amf_ip'] = amf_ip
        logger.debug('process_reg_request 1-2')
        if not hasattr(packet['nas-5gs'], 'nas_5gs_mm_type_id'):
            logger.debug('process_reg_request 2')
            logger.warning(
                f'error: mandatory IE type of ID missing in registrationReuqest or identity response.'
                f'pac   ket: IP identification: {packet.ip.id.raw_value},'
                f'src IP:{packet.ip.src} skip this packet!\n')
            return False
        # if ID type is SUCI:
        logger.debug(packet['nas-5gs'].nas_5gs_mm_type_id)
        if packet['nas-5gs'].nas_5gs_mm_type_id == '1' or packet['nas-5gs'].nas_5gs_mm_type_id == '2':
            logger.debug('process_reg_request 3')
          
            if 0 != len(packet[5].dedicatednas_message.raw_value) : #hasattr(packet['nr-rrc'], ''):
                logger.debug('process_reg_request 4')
              
                # need further coding here, to check whether SUCI or SUPI.
                try:
                   
                    nas_pdu = packet[5].dedicatednas_message.raw_value #packet['nas-5gs'].nas_pdu.raw_value
                    logger.debug(nas_pdu)
                    self.nas_pdu = nas_pdu
                   
                    # if it's plain registration request message.
                    if nas_pdu.startswith('7e0041'):
                        logger.debug('process_reg_request 5')
                        id_length = int(nas_pdu[8:12],16)
                        suci:str = nas_pdu[12:12+id_length*2]
                        logger.info(f'SUCI obtained: {suci}')
                    # elif it's identity response during GUTI attach.
                    elif nas_pdu.startswith('7e01') and ((nas_pdu[14:20] == '7e005c') or (nas_pdu[14:20] == '7e0041')):
                        logger.debug('process_reg_request 6')
                      
                        id_length = int(nas_pdu[20:24], 16)
                        logger.debug(f'ID Len: {id_length}')
                        suci: str = nas_pdu[24:24 + id_length * 2]
                        logger.info(f'SUCI obtained: {suci}')
                 
                    bcd_supi:str = ''   # BCD string of plain SUPI
                 
                except Exception as e:
                    logger.error("failed to get SUCI content, operation aborted.\n")
                    logger.error(f"the error info is : {str(e)}\n")
                    return False

                # if SUPI is IMSI format:
                if suci[0] =='0':
                    # if suci is not encrypted:
                    if suci[13] == '0':
                        bcd_supi = suci[2:8] + suci[16:]  # BCD string of SUPI, for example:'13001341000021f0'

                    # if suci is encrypted by profile A
                    elif suci[13] == '1':
                        try:
                            if not self.private_key:
                                logger.debug('process_reg_request 7.0')
                                raise Exception('no private_key found for SUCI deciphering, please input it before deciphering.')
                            logger.debug('process_reg_request 7.1')
                            imsi_prefix:str = suci[2:8]     #BCD string
                            routing_indicator = suci[8:12]
                            home_network_key_id = suci[14:16]
                            scheme_output = suci[16:106]
                            public_key_ue_bytes = bytes.fromhex(suci[16:80])
                            encrypted_msin:bytes = bytes.fromhex(suci[80:90])
                            mac_tag_from_message = suci[90:]
                            backend = default_backend()
                            # new output would be '01'+imsi_prefix+routing_indicator+'00'+home_network_key_id
                            # +decrypted_msin+padding ff
                            private_key_amf = x25519.X25519PrivateKey.from_private_bytes(self.private_key)  # private_key class
                            public_key_ue = x25519.X25519PublicKey.from_public_bytes(public_key_ue_bytes)  # public_key class
                            shared_secret_key = private_key_amf.exchange(public_key_ue)  # raw binary string.
                            xkdf = X963KDF(
                                algorithm=hashes.SHA256(),
                                length=64,
                                sharedinfo=public_key_ue_bytes,
                                backend=backend
                            )
                            xkdf_output: bytes = xkdf.derive(shared_secret_key)
                            suci_enc_key: bytes = xkdf_output[0:16]
                            suci_icb: bytes = xkdf_output[16:32]
                            suci_mac_key: bytes = xkdf_output[32:]
                            self.ue_dict[gnb_ip]['suci_enc_key'] = suci_enc_key
                            self.ue_dict[gnb_ip]['suci_icb'] = suci_icb
                            self.ue_dict[gnb_ip]['suci_mac_key'] = suci_mac_key
                            # get mac tag from first 8 bytes of the HMAC output.
                            computed_mac_tag:str = HMAC.new(suci_mac_key, encrypted_msin, SHA256).hexdigest()[0:16]
                            if computed_mac_tag == mac_tag_from_message:
                                #first 8 bytes of ICB will be nonce input of AES, and last 8 bytes of ICB will be Initial_value input.
                                crypto = AES.new(suci_enc_key, mode=AES.MODE_CTR, nonce=suci_icb[0:8],initial_value=suci_icb[8:16])
                                plain_msin:bytes = crypto.decrypt(encrypted_msin)
                                # BCD string of SUPI, for example:'13001341000021f0'
                                bcd_supi = imsi_prefix + plain_msin.hex()
                                decrypted_suci:str = suci[0:2]+imsi_prefix+routing_indicator+'00'+\
                                                 home_network_key_id+plain_msin.hex()
                                # to maintain the same lenght as old message, the new SUCI
                                # would be padded by 'ff' until original length is met
                                decrypted_suci =decrypted_suci + (106-len(decrypted_suci))*'f'
                                decrypted_suci_bytes = bytes.fromhex(decrypted_suci)
                                self.buffer = self.buffer.replace(bytes.fromhex(suci), decrypted_suci_bytes)
                            else:
                                raise Exception('found mac tag mismatched.')
                        except Exception as e:
                            logger.error("failed to decrypt SUCI based on profileA, operation aborted.\n")
                            logger.error(f"the error info is : {str(e)}\n")
                            # traceback.print_exc(file=sys.stdout)
                            # traceback.print_stack(file=sys.stdout)
                            # return False
                    # if suci is encrypted by profile B
                    elif suci[13] == '2':
                        try:
                            if not self.private_key:
                                raise Exception('no private_key found for SUCI deciphering, please input it before deciphering.')
                            imsi_prefix: str = suci[2:8]  # BCD string
                            routing_indicator = suci[8:12]
                            home_network_key_id = suci[14:16]
                            scheme_output = suci[16:108]
                            public_key_ue_bytes = bytes.fromhex(suci[16:82])
                            encrypted_msin: bytes = bytes.fromhex(suci[82:92])
                            mac_tag_from_message = suci[92:]
                            # new output would be '01'+imsi_prefix+routing_indicator+'00'+home_network_key_id
                            # +decrypted_msin+padding ff
                            backend = default_backend()
                            private_key_amf_int = int(self.private_key.hex(),base=16)
                            private_key_amf = ec.derive_private_key(
                                private_key_amf_int, ec.SECP256R1(), backend)
                            public_key_amf = private_key_amf.public_key()
                            public_key_ue = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(
                                ),public_key_ue_bytes)  # public_key class
                            shared_key = private_key_amf.exchange(
                                ec.ECDH(), public_key_ue)  # raw binary string.
                            xkdf = X963KDF(
                                algorithm=hashes.SHA256(),
                                length=64,
                                sharedinfo=public_key_ue_bytes,
                                backend=backend
                            )
                            xkdf_output: bytes = xkdf.derive(shared_key)
                            suci_enc_key: bytes = xkdf_output[0:16]
                            suci_icb: bytes = xkdf_output[16:32]
                            suci_mac_key: bytes = xkdf_output[32:]
                            # self.ue_dict[ran_ue_ngap_id][gnb_ip]['suci_enc_key'] = suci_enc_key
                            # self.ue_dict[ran_ue_ngap_id][gnb_ip]['suci_icb'] = suci_icb
                            # self.ue_dict[ran_ue_ngap_id][gnb_ip]['suci_mac_key'] = suci_mac_key
                            computed_mac_tag: str = HMAC.new(suci_mac_key, encrypted_msin, SHA256).hexdigest()[0:16]
                            if computed_mac_tag == mac_tag_from_message:
                                self.ue_dict[gnb_ip]['suci_enc_key'] = suci_enc_key
                                self.ue_dict[gnb_ip]['suci_icb'] = suci_icb
                                self.ue_dict[gnb_ip]['suci_mac_key'] = suci_mac_key
                                crypto = AES.new(suci_enc_key, mode=AES.MODE_CTR, nonce=suci_icb[0:8],initial_value=suci_icb[8:16])
                                plain_msin: bytes = crypto.decrypt(encrypted_msin)
                                # BCD string of SUPI, for example:'13001341000021f0'
                                bcd_supi = imsi_prefix + plain_msin.hex()
                                decrypted_suci: str = suci[0:2] + imsi_prefix + routing_indicator + '00' + \
                                                      home_network_key_id + plain_msin.hex()
                                # to maintain the same lenght as old message, the new SUCI
                                # would be padded by 'ff' until original length is met
                                decrypted_suci = decrypted_suci + (108 - len(decrypted_suci)) * 'f'
                                decrypted_suci_bytes = bytes.fromhex(decrypted_suci)
                                self.buffer = self.buffer.replace(bytes.fromhex(suci), decrypted_suci_bytes)
                            else:
                                raise Exception('found mac tag mismatched.')
                        except Exception as e:
                            logger.error("failed to decrypt SUCI, operation aborted.\n")
                            logger.error(f"the error info is :{str(e)}\n")
                            traceback.print_exc(file=sys.stdout)
                            traceback.print_stack(file=sys.stdout)
                            return False
                # if SUPI is NAI format:
                elif suci[0] =='1':
                   
                    pass

                if bcd_supi:
                  
                    supi = bcd_supi[1] + bcd_supi[0] + bcd_supi[3] + bcd_supi[5] + bcd_supi[4] + \
                           bcd_supi[2] + bcd_supi[7] + bcd_supi[6] + bcd_supi[9] + bcd_supi[8] + \
                           bcd_supi[11] + bcd_supi[10] + bcd_supi[13] + bcd_supi[12] + \
                           bcd_supi[15] + bcd_supi[14]
                    supi = supi.replace('f', '')
                    logger.info(f'SUPI is drived successfully. SUPI: {supi}')
                    self.ue_dict[gnb_ip]['supi'] = supi
                    self.supi = supi
                #else:
                    logger.info(f'bcd_supi is NULL')

            if hasattr(packet['nas-5gs'], 'e212_guami_mcc') and hasattr(packet['nas-5gs'], 'e212_guami_mnc'):
                try:
                    logger.debug("In try of MCC/MNC")
                    #logger.info(f"MCC: {packet['nas-5gs'].e212_guami_mcc.get_default_value()} and MNC: {packet['nas-5gs'].e212_guami_mnc.get_default_value()}")
                    mcc = '0' * (3 - len(packet['nas-5gs'].e212_guami_mcc.get_default_value())) + \
                                                    packet['nas-5gs'].e212_guami_mcc.get_default_value()
                    mnc = '0' * (3 - len(packet['nas-5gs'].e212_guami_mnc.get_default_value())) + \
                                                    packet['nas-5gs'].e212_guami_mnc.get_default_value()
                    logger.info(f'MCC: {mcc}   MNC: {mnc}')
                    self.ue_dict[gnb_ip]['mcc'] = mcc
                    self.ue_dict[gnb_ip]['mnc'] = mnc
                    self.ue_dict[gnb_ip]['snn'] = '5G:mnc' + mnc + '.mcc' + mcc + '.3gppnetwork.org'
                    # self.ue_dict[gnb_ip]['snn'] = '5G:' + '130184'
                    self.snn = self.ue_dict[gnb_ip]['snn']
                    logger.info(f'SNN: {self.snn}')

                except Exception as e:
                    logger.warning(f'error: encountered error with mcc/mnc of '
                                   f'packet: IP identification: {packet.ip.id.raw_value},'
                                   f'src IP:{packet.ip.src} skip handling mcc/mnc! for {e}\n')
                    return False


            elif hasattr(packet['nas-5gs'], 'e212_mcc') and hasattr(packet['nas-5gs'], 'e212_mnc'):
                try:
                    logger.debug("In try of MCC/MNC")
                    #logger.info(f"MCC: {packet['nas-5gs'].e212_mcc.get_default_value()} and MNC: {packet['nas-5gs'].e212_mnc.get_default_value()}")
                    mcc = '0' * (3 - len(packet['nas-5gs'].e212_mcc.get_default_value())) + \
                                                    packet['nas-5gs'].e212_mcc.get_default_value()
                    mnc = '0' * (3 - len(packet['nas-5gs'].e212_mnc.get_default_value())) + \
                                                    packet['nas-5gs'].e212_mnc.get_default_value()
                    logger.info(f'MCC: {mcc}   MNC: {mnc}')
                    self.ue_dict[gnb_ip]['mcc'] = mcc
                    self.ue_dict[gnb_ip]['mnc'] = mnc
                    self.ue_dict[gnb_ip]['snn'] = '5G:mnc' + mnc + '.mcc' + mcc + '.3gppnetwork.org'
                    self.snn = self.ue_dict[gnb_ip]['snn']
                    logger.info(f'SNN: {self.snn}')
                except Exception as e:
                    logger.warning(f'error: encountered error with mcc/mnc of '
                                   f'packet: IP identification: {packet.ip.id.raw_value},'
                                   f'src IP:{packet.ip.src} skip handling mcc/mnc! for {e}\n')
                    return False
        # else if id type is GUTI:
        elif packet['nas-5gs'].nas_5gs_mm_type_id == '2':
            pass
        # else if ID type is IMEI:
        elif packet['nas-5gs'].nas_5gs_mm_type_id == '3':
            pass
        # else if ID type is 5G-S-TMSI:
        elif packet['nas-5gs'].nas_5gs_mm_type_id == '4':
            pass
        # else if ID type is IMEISV:
        elif packet['nas-5gs'].nas_5gs_mm_type_id == '5':
            pass
        # no identity
        else:
            return False
        return True

    def process_auth_request_for_5gs(self,packet,gnb_ip):
        # future question: how to tell whether it's AKA or EAP-AKA' challenge?
        #ran_ue_ngap_id = packet.ngap.ran_ue_ngap_id.raw_value
        logger.debug('\nIn Process Auth Request for 5gs')
        logger.debug('Process Auth Request')
        try:
            # below rand/autn/mac/amf/sqn are all binary strings.
            #abba = bytes.fromhex(packet.ngap.nas_5gs_mm_abba_contents.raw_value)
            rand = bytes.fromhex(packet['nas-5gs'].gsm_a_dtap_rand.raw_value)
            autn = bytes.fromhex(packet['nas-5gs'].gsm_a_dtap_autn.raw_value)
            sqn_xor_ak = bytes.fromhex(packet['nas-5gs'].gsm_a_dtap_autn_sqn_xor_ak.raw_value)
            amf = bytes.fromhex(packet['nas-5gs'].gsm_a_dtap_autn_amf.raw_value)
            mac = bytes.fromhex(packet['nas-5gs'].gsm_a_dtap_autn_mac.raw_value)
            logger.debug('In Process Auth Request for 5gs 2')
            #self.ue_dict[ran_ue_ngap_id][gnb_ip]['abba'] = abba
            self.ue_dict[gnb_ip]['rand'] = rand
            self.ue_dict[gnb_ip]['autn'] = autn
            self.ue_dict[gnb_ip]['sqn_xor_ak'] = sqn_xor_ak
            self.ue_dict[gnb_ip]['amf'] = amf
            self.ue_dict[gnb_ip]['mac'] = mac

            res, ck, ik = self.call_milenage(self.secret_key, self.OP, self.OPC,rand, autn, sqn_xor_ak, amf, mac)
            if res is None:
                logger.warning(f'error generating res/ck/ik, skip packet : IP identification: {packet.ip.id.raw_value},'
                                   f'src IP:{packet.ip.src} \n')
                return False
            logger.info('Computed CK/IK from auth_request message successfully!\n')
            logger.info(f'CK: {ck.hex()}')
            logger.info(f'IK: {ik.hex()}')
            logger.info(f'RES: {res.hex()}')

            self.ck = ck
            self.ik = ik
            # get SNN from dict as bytes string.
            logger.debug('SNN is before converting bytes')
            logger.debug(f'self.snn: {self.snn}')
            logger.debug(f'self.supi: {self.supi}')
            self.supi = '311480000004600'
            number_of_cli = len(sys.argv)  # Reading number of command line arguments
            if number_of_cli < 3:
                logger.error('No IMSI received from the TM')
            else:
                self.supi = sys.argv[2]
            logger.info(f'SUPI: {self.supi}')
            self.ue_dict[gnb_ip]['snn'] = self.snn
            self.ue_dict[gnb_ip]['supi'] = self.supi
            snn:bytes = self.ue_dict[gnb_ip]['snn'].encode('ascii')
            logger.debug(f'SNN is {snn}')
            supi:bytes = self.ue_dict[gnb_ip]['supi'].encode('ascii')
            if not snn or not supi:
                logger.warning(f'error getting SNN or SUPI for this UE, skip packet : IP identification: {packet.ip.id.raw_value},'
                                   f'src IP:{packet.ip.src}\n ')
                return False

            input_key = ck + ik
            # computing kausf
           
            input_string = b'\x6a' + snn + len(snn).to_bytes(2, byteorder='big') \
                           + sqn_xor_ak + len(sqn_xor_ak).to_bytes(2, byteorder='big')
            input_key = ck + ik
            
            logger.info(f'input_key: {input_key.hex()}\n')
            logger.info(f'input_string: {input_string.hex()}\n')
  


            kausf = bytes.fromhex(HMAC.new(input_key, input_string, SHA256).hexdigest())
            self.ue_dict[gnb_ip]['kausf'] = kausf
            logger.info(f'Kausf: {kausf.hex()}\n')
            # computing kseaf
            input_string = b'\x6c' + snn + len(snn).to_bytes(2, byteorder='big')
            input_key = kausf

            logger.info(f'input_key: {input_key.hex()}\n')
            logger.info(f'input_string: {input_string}\n')
            kseaf = bytes.fromhex(HMAC.new(input_key, input_string, SHA256).hexdigest())
            self.ue_dict[gnb_ip]['kseaf'] = kseaf
            logger.info(f'Kseaf: {kseaf.hex()}\n')
            # computing kamf

            abba = b'\x00\x00'
            supi = '333131343830303030303034363030'       # This is the hex value of 311480000004600
            # supi = '333131323730313233343536373839'       # This is the hex value of 311270123456789
            # supi = '333131323830313233343536373839'       # This is the hex value of 311280123456789
            number_of_cli = len(sys.argv)  # Reading number of command line arguments
            if number_of_cli < 3:
                logger.error('No IMSI received from the TM')
            else:
                supi = (sys.argv[2]).encode('utf-8')
                supi = supi.hex()
            logger.info(f'SUPI: {supi}')
            supi = bytes.fromhex(supi)
            input_string = b'\x6d' + supi + len(supi).to_bytes(2, byteorder='big') + abba + b'\x00\x02'
            input_key = kseaf
            logger.info(f'input_key: {input_key.hex()}\n')
            logger.info(f'input_string: {input_string}\n')
            kamf = bytes.fromhex(HMAC.new(input_key, input_string, SHA256).hexdigest())
            self.ue_dict[gnb_ip]['kamf'] = kamf
            logger.info('compute Kamf based on supi and CK/IK successfully!\n')
            logger.info(f'Kamf: {kamf.hex()}\n')

            '''
            #computing Kasme
            input_string_hex = '10' + '130184' + '0003'+'9a963379eb98'+'0006'
            input_string = bytes.fromhex(input_string_hex)
            kasme = bytes.fromhex(HMAC.new(input_key, input_string, SHA256).hexdigest())


            #computing Knasenc
            input_string_hex = '15'+'01'+'0001'+'01'+'0001'
            input_string = bytes.fromhex(input_string_hex)
            kasme = bytes.fromhex(HMAC.new(input_key, input_string, SHA256).hexdigest())
            '''
            # computing Kasme
            input_string_kasme = '10' + '130184' + '0003' + '9a963379eb98' + '0006'
            input_string_kasme = bytes.fromhex(input_string_kasme)
            kasme = bytes.fromhex(HMAC.new((self.ck + self.ik), input_string_kasme, SHA256).hexdigest())

            # computing Knasenc
            input_string_knasenc = '15' + '01' + '0001' + '01' + '0001'
            input_string_knasenc = bytes.fromhex(input_string_knasenc)
            # knasenc = bytes.fromhex(HMAC.new(kasme, input_string, SHA256).hexdigest())
            knasenc = (HMAC.new(kasme, input_string_knasenc, SHA256).hexdigest())[32:]

            logger.info(f"KASME: {kasme.hex()}\n")
            logger.info(f'KNASENC: {knasenc}\n')

            cipher_key_4g = bytes.fromhex(knasenc)
            self.cipher_key_4g = cipher_key_4g
            return True

        except Exception as e:
            logger.warning(f'error: error handling authentication vector '
                           f'from packet : IP identification: {packet.ip.id.raw_value},'
                            f'src IP:{packet.ip.src} \n')
            logger.warning(f'the error info is : {str(e)}\n')
            return False

    def process_auth_request(self,packet,gnb_ip):
        # future question: how to tell whether it's AKA or EAP-AKA' challenge?
        #ran_ue_ngap_id = packet.ngap.ran_ue_ngap_id.raw_value
        logger.debug('\nIn Process Auth Request for eps')
        logger.debug('Process Auth Request')
        try:
            # below rand/autn/mac/amf/sqn are all binary strings.
            #abba = bytes.fromhex(packet.ngap.nas_5gs_mm_abba_contents.raw_value)
            rand = bytes.fromhex(packet['nas-eps'].gsm_a_dtap_rand.raw_value)
            autn = bytes.fromhex(packet['nas-eps'].gsm_a_dtap_autn.raw_value)
            sqn_xor_ak = bytes.fromhex(packet['nas-eps'].gsm_a_dtap_autn_sqn_xor_ak.raw_value)
            amf = bytes.fromhex(packet['nas-eps'].gsm_a_dtap_autn_amf.raw_value)
            mac = bytes.fromhex(packet['nas-eps'].gsm_a_dtap_autn_mac.raw_value)
            #self.ue_dict[ran_ue_ngap_id][gnb_ip]['abba'] = abba
            if not (gnb_ip in self.ue_dict):
                self.ue_dict[gnb_ip] = {}
            self.ue_dict[gnb_ip]['rand'] = rand
            self.ue_dict[gnb_ip]['autn'] = autn
            self.ue_dict[gnb_ip]['sqn_xor_ak'] = sqn_xor_ak
            self.ue_dict[gnb_ip]['amf'] = amf
            self.ue_dict[gnb_ip]['mac'] = mac

            res, ck, ik = self.call_milenage(self.secret_key, self.OP, self.OPC,rand, autn, sqn_xor_ak, amf, mac)
            if res is None:
                logger.warning(f'error generating res/ck/ik, skip packet : IP identification: {packet.ip.id.raw_value},'
                                   f'src IP:{packet.ip.src} \n')
                return False
            logger.info('compute CK/IK from auth_request message successfully!\n')
            logger.info(f'CK: {ck.hex()}\n')
            logger.info(f'IK: {ik.hex()}\n')
            logger.info(f'RES: {res.hex()}\n')

            self.ck = ck
            self.ik = ik
            # get SNN from dict as bytes string.
            '''
            snn:bytes = self.ue_dict[gnb_ip]['snn'].encode('ascii')
            supi:bytes = self.ue_dict[gnb_ip]['supi'].encode('ascii')
            if not snn or not supi:
                logger.warning(f'error getting SNN or SUPI for this UE, skip packet : IP identification: {packet.ip.id.raw_value},'
                                   f'src IP:{packet.ip.src}\n ')
                return False
            '''
            input_key = ck + ik
            # computing kausf
            '''
            input_string = b'\x6a' + snn + len(snn).to_bytes(2, byteorder='big') \
                           + sqn_xor_ak + len(sqn_xor_ak).to_bytes(2, byteorder='big')
            input_key = ck + ik
            
            logger.info(f'input_key: {input_key.hex()}\n')
            logger.info(f'input_string: {input_string.hex()}\n')
  


            kausf = bytes.fromhex(HMAC.new(input_key, input_string, SHA256).hexdigest())
            self.ue_dict[gnb_ip]['kausf'] = kausf
            logger.info(f'Kausf: {kausf.hex()}\n')
            # computing kseaf
            input_string = b'\x6c' + snn + len(snn).to_bytes(2, byteorder='big')
            input_key = kausf

            logger.info(f'input_key: {input_key.hex()}\n')
            logger.info(f'input_string: {input_string}\n')
            kseaf = bytes.fromhex(HMAC.new(input_key, input_string, SHA256).hexdigest())
            self.ue_dict[gnb_ip]['kseaf'] = kseaf
            logger.info(f'Kseaf: {kseaf.hex()}\n')
            # computing kamf
            abba = b'\x00\x00'
            input_string = b'\x6d' + supi + len(supi).to_bytes(2, byteorder='big') + abba + b'\x00\x02'
            input_key = kseaf
            logger.info(f'input_key: {input_key.hex()}\n')
            logger.info(f'input_string: {input_string}\n')
            kamf = bytes.fromhex(HMAC.new(input_key, input_string, SHA256).hexdigest())
            self.ue_dict[gnb_ip]['kamf'] = kamf
            logger.info('compute Kamf based on supi and CK/IK successfully!\n')
            logger.info(f'Kausf: {kamf.hex()}\n')
            '''

            #computing Kasme
            input_string_hex = '10' + '130184' + '0003'+'9a963379eb98'+'0006'
            input_string = bytes.fromhex(input_string_hex)
            kasme = bytes.fromhex(HMAC.new(input_key, input_string, SHA256).hexdigest())


            #computing Knasenc
            input_string_hex = '15'+'01'+'0001'+'01'+'0001'
            input_string = bytes.fromhex(input_string_hex)
            kasme = bytes.fromhex(HMAC.new(input_key, input_string, SHA256).hexdigest())


            return True

        except Exception as e:
            logger.warning(f'error: error handling authentication vector '
                          f'from packet : IP identification: {packet.ip.id.raw_value},'
                           f'src IP:{packet.ip.src} \n')
            logger.warning(f'the error info is : {str(e)}\n')
            return False

    def process_securitymode_command_5gs(self,packet,gnb_ip,amf_ip):
        try:
            logger.info('Inside process_securitymode_command_5gs')
            # ran_ue_ngap_id = packet['nas-5gs'].ran_ue_ngap_id.raw_value
            # get encryption algorithm from security mode command message.
            # algorithm_id_5g ='0' for null encryption, '1' for snow3G, '2' for 'AES', '3' for ZUC
            if hasattr(packet['nas-5gs'],'nas_5gs_mm_nas_sec_algo_enc'):
                algorithm_id_5g = packet['nas-5gs'].nas_5gs_mm_nas_sec_algo_enc.raw_value
                logger.info(f'5G NAS encryption Algorithm id found: {algorithm_id_5g}')
            else:
                logger.info('5G NAS encryption algorithm ID not found')
                return False
            self.ue_dict[gnb_ip]['algorithm_id_5g'] = algorithm_id_5g
            self.ue_dict[amf_ip]['algorithm_id_5g'] = algorithm_id_5g
            #Now checking for Selected EPS NAS security algorithms for Handover scenarios
            if hasattr(packet['nas-5gs'],'nas_eps_emm_toc'):
                algorithm_id_4g = packet['nas-5gs'].nas_eps_emm_toc.raw_value
                logger.info(f'SELECTED EPS NAS security Algorithm id found: {algorithm_id_4g}')
                self.ue_dict[amf_ip]['algorithm_id_4g'] = algorithm_id_4g
            else:
                logger.info('Selected EPS NAS security algorithm id not found')
            if algorithm_id_5g == '0':                      # if null encryption , exit and do nothing.
                logger.info('Alogrithm ID is 0, i.e. NULL Ciphered.')
                return False
            if (gnb_ip not in self.ue_dict) or ('kamf' not in self.ue_dict[gnb_ip]):
                return False
            algorithm_type_dist = b'\x01'   # type_id for nas_encryption_key
            input_string = b'\x69' + algorithm_type_dist + b'\x00\x01' + \
                           bytes.fromhex('0'+algorithm_id_5g) + b'\x00\x01'
            logger.info('Input string generated')
            input_key = self.ue_dict[gnb_ip]['kamf']
            # cipher_key uses only last 128 bytes of HMAC output, the bytes string would be 32 bytes long
            # so get the last 16 bytes of bytes string only for cipher_key.
            # should add more logic here, add cipher_key only if auth is successful.
            cipher_key = bytes.fromhex(HMAC.new(input_key, input_string, SHA256).hexdigest())[16:]
            logger.debug(f'cipher_key: {cipher_key}')
            self.ue_dict[gnb_ip]['cipher_key'] = cipher_key
            logger.debug(f'process security mode comm: {self.ue_dict}')
            self.cipher_key = cipher_key
            logger.info("compute alg_enc for 5G key successfully!\n")
            return True
        except Exception as e:
            logger.warning(f'error: error handling security_mode_command message,'
                          f'skip packet : IP identification: {packet.ip.id.raw_value},'
                          f'src IP:{packet.ip.src} \n')
            logger.warning(f'the error info is : {str(e)}\n')
            return False

    def process_securitymode_command(self,packet,gnb_ip):
        try:
            logger.debug('In Process Security Mode\n')
            #logger.info(f'nas_pdu: {self.nas_pdu}')
            #ran_ue_ngap_id = packet.ngap.ran_ue_ngap_id.raw_value
            # get encryption algorithm from security mode command message.
            #algorithm_id_4g = '1' #self.nas_pdu[20]
            if hasattr(packet['nas-eps'],'nas_eps_emm_toc'):
                algorithm_id_4g = packet['nas-eps'].nas_eps_emm_toc.raw_value
                logger.info(f'Algorithm found: {algorithm_id_4g}')
            else:
                logger.info('Algorithm ID not found')
                return False
            logger.info(f"Algorithm ID is : {algorithm_id_4g}\n")
            # if null encryption , exit and do nothing.
            self.ue_dict[gnb_ip]['algorithm_id_4g'] = algorithm_id_4g
            # self.ue_dict[self.amf_ip]['algorithm_id_4g'] = algorithm_id_4g
            # algorithm_id_4g ='0' for null encryption, '1' for snow3G, '2' for 'AES', '3' for ZUC
            if algorithm_id_4g == '0':
                return False
            #input_key = self.ue_dict[gnb_ip]['kamf']
            # cipher_key uses only last 128 bytes of HMAC output, the bytes string would be 32 bytes long
            # so get the last 16 bytes of bytes string only for cipher_key.
            # should add more logic here, add cipher_key only if auth is successful.

            input_key = self.ck + self.ik

                
            logger.debug('Process security mode 1')
            #computing Kasme
            input_string_hex = '10' + '130184' + '0003'+'9a963379eb98'+'0006'
            logger.debug('Process security mode 2')
            input_string = bytes.fromhex(input_string_hex)
            logger.debug('Process security mode 3')
            kasme = bytes.fromhex(HMAC.new(input_key, input_string, SHA256).hexdigest())
            logger.debug('Process security mode 4')


            #computing Knasenc
            if(algorithm_id_4g == '1'):
                input_string_hex = '15'+'01'+'0001'+'01'+'0001'
            elif(algorithm_id_4g == '2'):
                input_string_hex = '15' + '01' + '0001' + '02' + '0001'
            logger.debug('Process security mode 5')
            input_string = bytes.fromhex(input_string_hex)
            logger.debug('Process security mode 6')
            #knasenc = bytes.fromhex(HMAC.new(kasme, input_string, SHA256).hexdigest())
            knasenc = (HMAC.new(kasme, input_string, SHA256).hexdigest())[32:]
            logger.debug('Process security mode 7')

            logger.info(f"KASME: {kasme.hex()}\n")
            logger.info(f'KNASENC: {knasenc}\n')

            cipher_key = bytes.fromhex(knasenc)
            #cipher_key = bytes.fromhex(HMAC.new(input_key, input_string, SHA256).hexdigest())[16:]
            self.ue_dict[gnb_ip]['cipher_key'] = cipher_key
            self.cipher_key_4g = cipher_key
            logger.debug(f'process security mode comm 4g: {self.ue_dict}')
            logger.info("compute alg_enc for 4G key successfully!\n")
            return True
        except Exception as e:
            logger.warning(f'error: error handling security_mode_command message,'
                           f'skip packet : IP identification: {packet.ip.id.raw_value},'
                           f'src IP:{packet.ip.src} \n')
            logger.warning(f'the error info is : {e}\n')
            return False

    def hex_to_bin(self,hexstring):
        retval = bin(int(hexstring, 16))[2:].zfill(8)
        while len(retval) % 4 != 0:
            retval = '0' + retval
        for n in hexstring:
            if n != '0':
                break
            else:
                retval = '0000' + retval
        return retval

    def bin_to_hex(self,binstring):
        retVal = '%0*X' % ((len(binstring) + 3) // 4, int(binstring, 2))
        return retVal

    def decipher_nas(self,packet,gnb_ip,direction):
        #ran_ue_ngap_id= packet.ngap.ran_ue_ngap_id.raw_value
        #if (gnb_ip not in self.ue_dict): #or (cipher_key not in self.ue_dict[gnb_ip]):
        #if 1 == 0:
        #    logger.warning(f'error: no cipher key available for this UE found,'
        #                   f'skip packet : IP identification: {packet.ip.id.raw_value},'
        #                   f'src IP:{packet.ip.src} \n')
        #    return False
        try:
            # get seq in message by converting string of hex value into integer.
            msg_nas_count = int(packet['nas-eps'].nas_eps_seq_no.raw_value,base=16)        # msg_nas_count is integer.

            logger.info(f'Direction: {direction}\n')

            # if it's downlink tansport packet.
            if direction == 1:
                if 'local_downlink_nas_count' in self.ue_dict[gnb_ip]:
                    # local nas count in dict is stored as an integer.
                    local_nas_count = self.ue_dict[gnb_ip]['local_downlink_nas_count']
                else:
                    local_nas_count = 0
            # elif it's uplink transport packet.
            else:
                if 'local_uplink_nas_count' in self.ue_dict[gnb_ip]:
                    local_nas_count = self.ue_dict[gnb_ip]['local_uplink_nas_count']
                else:
                    local_nas_count = 0
            # end if
            count_for_ciphering = None
            
            # if incoming packet's seq is higher than or same as previous one.
            if msg_nas_count % 256 >= local_nas_count % 256 :
                 count_for_ciphering = local_nas_count = (local_nas_count//256)*256 + msg_nas_count % 256
            # elif incoming packet's seq is smaller than previous one.
            elif msg_nas_count % 256 < local_nas_count % 256 :
                # assume wrap around of seq happens with no more than 10 packets lost.
                if local_nas_count % 256 > 250 and msg_nas_count % 256 < 5:
                    count_for_ciphering = local_nas_count = (local_nas_count//256+1) * 256 + msg_nas_count % 256
                else:
                    count_for_ciphering = local_nas_count // 256 + msg_nas_count % 256
            # end if
            logger.info(f'NAS Count Value: {local_nas_count}')
            # save local_nas_count back to dict.
            if direction == 1:
                self.ue_dict[gnb_ip]['local_downlink_nas_count'] = local_nas_count
            elif direction == 0:
                self.ue_dict[gnb_ip]['local_uplink_nas_count'] = local_nas_count
            # end if

            # #######deciphering with seq number count_for_ciphering#######
            logger.debug('decipher_nas_1 4G')
            logger.debug(self.ue_dict)
            # cipher_key = self.ue_dict[gnb_ip]['cipher_key']
            cipher_key = self.cipher_key_4g
            logger.debug(f'Cipher Key: {cipher_key.hex()}')
            logger.debug('decipher_nas_2')
            nas_pdu_hex = None
            nas_pdu = None
            ciphered_payload = None
            nas_pdu_hex = packet['nas-eps'].nas_eps_security_header_type.raw_value + \
               packet['nas-eps'].gsm_a_l3_protocol_discriminator.raw_value + \
               packet['nas-eps'].nas_eps_msg_auth_code.raw_value + \
               packet['nas-eps'].nas_eps_seq_no.raw_value + \
               packet['nas-eps'].nas_eps_ciphered_msg.raw_value
            nas_pdu = bytes.fromhex(nas_pdu_hex)


            # whole nas pdu including the outer security header and mac
            '''if hasattr(packet.ngap,'nas_pdu'):
                nas_pdu = bytes.fromhex(packet.ngap.nas_pdu.raw_value)
            elif hasattr(packet.ngap,'pdusessionnas_pdu'):
                nas_pdu = bytes.fromhex(packet.ngap.pdusessionnas_pdu.raw_value)
            else:
                raise Exception('no nas_pdu found!') '''
            # get outer security header and mac+seq.
            outer_header = nas_pdu[0:6]

            # get ciphered payload only.
            ciphered_payload = nas_pdu[6:]
  
            # initial counter block for AES input  should be :
            # COUNT[0] .. COUNT[31] │ BEARER[0] .. BEARER[4] │ DIRECTION │ 0^26 (i.e. 26 zero bits)
            bearer = self.new_bearer_id  # bearer would be 0 in old spec 33.501 and 1 in new spec.
            logger.debug(f'Bearer: {bearer}')
            first_byte_of_bearer_and_direction = (bearer<<3)|(direction<<2)
            plain_payload = None
            logger.info(gnb_ip)
            # if AES ciphering:
            # algorithm_id_4g = self.ue_dict[ran_ue_ngap_id][gnb_ip]['algorithm_id_4g']
            if self.ue_dict[gnb_ip]['algorithm_id_4g'] == '2' and count_for_ciphering is not None:
                logger.info('Algorithm ID found to be 2')
                logger.info(
                    f'Ciphered Key: {cipher_key.hex()} \n count_for_ciphering : {count_for_ciphering} \n ciphered_payload : {ciphered_payload.hex()}\n')

                logger.info('AES called for nas-eps packet')
                # counter_block for AES should be 16 bytes long binary string.
                counter_block = count_for_ciphering.to_bytes(4,byteorder='big') + \
                                first_byte_of_bearer_and_direction.to_bytes(1,byteorder='big') + \
                                b'\x00\x00\x00' + b'\x00'*8
                crypto = AES.new(cipher_key, mode=AES.MODE_CTR, nonce=counter_block[0:8],initial_value=counter_block[8:16])
                plain_payload = crypto.decrypt(ciphered_payload)
                logger.info(f'Plain Payload in Hex : {plain_payload.hex()}')
            # elif snow3G algorithm:
            elif self.ue_dict[gnb_ip]['algorithm_id_4g'] == '1' and count_for_ciphering is not None:
                logger.info('Algorithm ID found to be 1')
                logger.info(f'Ciphered Key: {cipher_key.hex()} \n count_for_ciphering : {count_for_ciphering} \n ciphered_payload : {ciphered_payload.hex()}\n' )

                logger.info('snow_f8 called for nas-eps packet')
                plain_payload = pysnow.snow_f8(cipher_key, count_for_ciphering, bearer,
                                               direction, ciphered_payload, len(ciphered_payload)*8)
                logger.info(f'Plain Payload in Hex : {plain_payload.hex()}')
            # elif ZUC algorithm:
            elif self.ue_dict[gnb_ip]['algorithm_id_4g'] == '3' and count_for_ciphering is not None:
                logger.info('Algorithm ID found to be 3')
                plain_payload = pyzuc.zuc_eea3(cipher_key, count_for_ciphering, bearer,
                                               direction, len(ciphered_payload) * 8, ciphered_payload)
            # end if
           
            logger.info(f'NAS PDU OLD: {nas_pdu.hex()}\n\n')
            replaced_nas = None
      

            packet['nas-eps'].nas_eps_ciphered_msg.raw_value = plain_payload.hex()

            logger.debug(packet['nas-eps'].nas_eps_ciphered_msg.raw_value)

            replaced_nas = outer_header+plain_payload
            logger.info(f'NAS PDU NEW: {replaced_nas.hex()}\n\n')
            udp_payload = packet.udp.payload.raw_value
            logger.debug(udp_payload)
            logger.debug(len(udp_payload))

            udp_payload_in_bits = self.hex_to_bin(udp_payload)
            nas_pdu_old_in_bit = self.hex_to_bin(nas_pdu.hex())
            nas_pdu_new_in_bit = self.hex_to_bin(replaced_nas.hex())
            logger.debug('Going to compare ciphered NAS message in ciphered UDP payload\n')
            if nas_pdu_old_in_bit in udp_payload_in_bits:
                logger.debug('Ciphered NAS message bits are present in ciphered UDP payload bits\n')
                logger.debug(len(udp_payload_in_bits))
                new_udp_payload_in_bits = udp_payload_in_bits.replace(nas_pdu_old_in_bit, nas_pdu_new_in_bit)
                logger.debug(len(udp_payload_in_bits))
                old_udp_bytes = bytes.fromhex(udp_payload)
                logger.debug(old_udp_bytes.hex())
                new_udp_bytes = bytes.fromhex(self.bin_to_hex(new_udp_payload_in_bits))
                logger.debug(new_udp_bytes.hex())
            else:
                logger.debug('Ciphered NAS message bits are NOT present in ciphered UDP payload bits\n')
                extra_bits_udp_payload = udp_payload[0:4]
                udp_payload = udp_payload[4:]

                logger.debug(f'udp_payload:\n{udp_payload}')

                udp_bit_string = self.hex_to_bin(udp_payload)


                if (direction == 0):
                    ul_dcch_bits = udp_bit_string[0:19]
                    udp_bit_string = udp_bit_string[19:]
                    bit_len = len(udp_bit_string)

                    if((bit_len%8) != 0):
                        udp_bit_string = udp_bit_string[0:(bit_len-(bit_len%8))]
                    else:
                        udp_bit_string = udp_bit_string[0:(bit_len-4)]

                    logger.debug(udp_bit_string)

                    hex_udp = self.bin_to_hex(udp_bit_string)
                elif (direction == 1):
                    ul_dcch_bits = udp_bit_string[0:21]
                    udp_bit_string = udp_bit_string[21:]
                    bit_len = len(udp_bit_string)

                    if((bit_len%8) != 0):
                        udp_bit_string = udp_bit_string[0:(bit_len-(bit_len%8))]
                    else:
                        udp_bit_string = udp_bit_string[0:(bit_len-4)]

                    logger.debug(udp_bit_string)

                    hex_udp = self.bin_to_hex(udp_bit_string)


                logger.debug('\n\n\n')
                logger.debug('---------------------')
                logger.debug(hex_udp)
                logger.debug('---------------------')
                logger.debug('\n\n\n')


                old_udp_bytes = bytes.fromhex(packet.udp.payload.raw_value)

                logger.debug(self.hex_to_bin(extra_bits_udp_payload))

                if((bit_len%8) != 0):
                    new_udp_payload = self.hex_to_bin(extra_bits_udp_payload) + ul_dcch_bits + self.hex_to_bin(outer_header.hex())+self.hex_to_bin(plain_payload.hex()) + ('0')*(bit_len%8)
                else:
                    new_udp_payload = self.hex_to_bin(extra_bits_udp_payload) + ul_dcch_bits + self.hex_to_bin(outer_header.hex())+self.hex_to_bin(plain_payload.hex()) + '0000'

                hex_new_udp_payload = self.bin_to_hex(new_udp_payload)

                logger.debug(hex_new_udp_payload)

                new_udp_bytes = bytes.fromhex(hex_new_udp_payload)




               # hex_udp = "{0:0>4X}".format(int(udp_bit_string, 2))






                #packetHexRaw = packet['eth'].dst.raw_value + packet['eth'].src.raw_value + packet['eth'].type.raw_value \
                #      + packet['ip'].version.raw_value + packet['ip'].hdr_len.raw_value + packet['ip'].dsfield.raw_value \
                #      + packet['ip'].len.raw_value + packet['ip'].id.raw_value + packet['ip'].flags.raw_value + packet['ip'].frag_offset.raw_value \
                #      + packet['ip'].ttl.raw_value + packet['ip'].proto.raw_value + packet['ip'].checksum.raw_value  \
                #      + packet['ip'].src.raw_value + packet['ip'].dst.raw_value + packet['udp'].srcport.raw_value + packet['udp'].dstport.raw_value \
                #      + packet['udp'].length.raw_value + packet['udp'].checksum.raw_value + packet['udp'].payload.raw_value
                #

                #packetHexRaw = 'd43d7e1be7a60050c2bd268308004500002e0000400040110cd80101010102020202d4e0270f001a5a2c01024801a4f8dc95a5404adf56b51bd81800'
                #packetBytes = bytes.fromhex(packetHexRaw)
                logger.debug(packet)


                #with open('test.pcap', "wb") as file:
                 #   file.write(packetBytes)

                #if old_udp_bytes in self.buffer:
                #    print('\nYES, NAS PDU IS PRESENT\n')
                #else:
                #    print('\nNA, NAS PDU NOT PRESENT\n')

                if direction == 0:
                    file_header_values = ['\n', str(self.packet_number), 'UL',  packet.ip.src, packet.ip.dst, plain_payload.hex(), '\n']
                elif direction == 1:
                    file_header_values = ['\n', str(self.packet_number), 'DL',  packet.ip.src, packet.ip.dst, plain_payload.hex(), '\n']


                join_str = '            '

                join_str = join_str.join(file_header_values)


                #with open('deciphered_nas.txt', 'a') as file:
                #        file.write(join_str)
                #        file.close()

            logger.debug(f'Debug Old UDP:\n{old_udp_bytes.hex()}')
            logger.debug(f'Debug New UDP:\n{new_udp_bytes.hex()}')
            if len(old_udp_bytes.hex()) != len(new_udp_bytes.hex()):
                logger.warning('Old and New UDP Payload length mismatced')
                return True

            if plain_payload: # and plain_payload.startswith(b'\x7e'):
                self.buffer = self.buffer.replace(old_udp_bytes, new_udp_bytes)
                return True

        except Exception as e:
            logger.warning(f'error: error deciphering '
                       f' packet : IP identification: {packet.ip.id.raw_value},'
                       f'src IP:{packet.ip.src} \n')
            logger.warning(f'the error info is : {str(e)}\n')
            #traceback.print_exc(file=sys.stdout)
            #traceback.print_stack(file=sys.stdout)

            return False

    def decipher_nas_5gs(self,packet,gnb_ip,direction):
        #ran_ue_ngap_id= packet.ngap.ran_ue_ngap_id.raw_value
        #if (gnb_ip not in self.ue_dict): #or (cipher_key not in self.ue_dict[gnb_ip]):
        #if 1 == 0:
        #    logger.warning(f'error: no cipher key available for this UE found,'
        #                   f'skip packet : IP identification: {packet.ip.id.raw_value},'
        #                   f'src IP:{packet.ip.src} \n')
        #    return False
        try:
            # get seq in message by converting string of hex value into integer.
            msg_nas_count = int(packet['nas-5gs'].nas_5gs_seq_no.raw_value,base=16)        # msg_nas_count is integer.

            logger.info(f'Direction: {direction}\n')

            # if it's downlink tansport packet.
            if direction == 1:
                if 'local_downlink_nas_count' in self.ue_dict[gnb_ip]:
                    # local nas count in dict is stored as an integer.
                    local_nas_count = self.ue_dict[gnb_ip]['local_downlink_nas_count']
                else:
                    local_nas_count = 0
            # elif it's uplink transport packet.
            else:
                if 'local_uplink_nas_count' in self.ue_dict[gnb_ip]:
                    local_nas_count = self.ue_dict[gnb_ip]['local_uplink_nas_count']
                else:
                    local_nas_count = 0
            # end if
            count_for_ciphering = None
            
            # if incoming packet's seq is higher than or same as previous one.
            if msg_nas_count % 256 >= local_nas_count % 256 :
                 count_for_ciphering = local_nas_count = (local_nas_count//256)*256 + msg_nas_count % 256
            # elif incoming packet's seq is smaller than previous one.
            elif msg_nas_count % 256 < local_nas_count % 256 :
                # assume wrap around of seq happens with no more than 10 packets lost.
                if local_nas_count % 256 > 250 and msg_nas_count % 256 < 5:
                    count_for_ciphering = local_nas_count = (local_nas_count//256+1) * 256 + msg_nas_count % 256
                else:
                    count_for_ciphering = local_nas_count // 256 + msg_nas_count % 256
            # end if

            # save local_nas_count back to dict.
            if direction == 1:
                self.ue_dict[gnb_ip]['local_downlink_nas_count'] = local_nas_count
            elif direction == 0:
                self.ue_dict[gnb_ip]['local_uplink_nas_count'] = local_nas_count
            # end if

            # #######deciphering with seq number count_for_ciphering#######
            #cipher_key = self.ue_dict[gnb_ip]['cipher_key']
            cipher_key = self.cipher_key
  
            nas_pdu_hex = None
            nas_pdu = None
            ciphered_payload = None
            nas_pdu_hex = packet[5].dedicatednas_message.raw_value
            nas_pdu = bytes.fromhex(nas_pdu_hex)


            # whole nas pdu including the outer security header and mac
            '''if hasattr(packet.ngap,'nas_pdu'):
                nas_pdu = bytes.fromhex(packet.ngap.nas_pdu.raw_value)
            elif hasattr(packet.ngap,'pdusessionnas_pdu'):
                nas_pdu = bytes.fromhex(packet.ngap.pdusessionnas_pdu.raw_value)
            else:
                raise Exception('no nas_pdu found!') '''
            # get outer security header and mac+seq.
            outer_header = nas_pdu[0:7]

            # get ciphered payload only.
            ciphered_payload = nas_pdu[7:]
  
            # initial counter block for AES input  should be :
            # COUNT[0] .. COUNT[31] │ BEARER[0] .. BEARER[4] │ DIRECTION │ 0^26 (i.e. 26 zero bits)
            bearer = self.new_bearer_id  # bearer would be 0 in old spec 33.501 and 1 in new spec.
            plain_payload = None
            logger.debug('decipher 5gs 1')
            logger.debug(f'cipher_key: {cipher_key}')
            #self.ue_dict[gnb_ip]['algorithm_id_5g'] = '2'   # Change to '1' for 0001 snow3g
            logger.debug(f'count_for_ciphering: {count_for_ciphering}')
            alg_id_for_print = self.ue_dict[gnb_ip]['algorithm_id_5g']
            logger.info(f'algorithm_id_5g: {alg_id_for_print}')
            # if AES ciphering:
            # algorithm_id_5g = self.ue_dict[ran_ue_ngap_id][gnb_ip]['algorithm_id_5g']
            if self.ue_dict[gnb_ip]['algorithm_id_5g'] == '2' and count_for_ciphering is not None:
                bearer = 1
                first_byte_of_bearer_and_direction = (bearer << 3) | (direction << 2)
                # counter_block for AES should be 16 bytes long binary string.
                logger.info("AES function called")
                counter_block = count_for_ciphering.to_bytes(4,byteorder='big') + \
                                first_byte_of_bearer_and_direction.to_bytes(1,byteorder='big') + \
                                b'\x00\x00\x00' + b'\x00'*8
                logger.debug(cipher_key)
                crypto = AES.new(cipher_key, mode=AES.MODE_CTR, nonce=counter_block[0:8],initial_value=counter_block[8:16])
                plain_payload = crypto.decrypt(ciphered_payload)
            # elif snow3G algorithm:
            elif self.ue_dict[gnb_ip]['algorithm_id_5g'] == '1' and count_for_ciphering is not None:

                logger.info(f'Ciphered Key: {cipher_key.hex()} \n count_for_ciphering : {count_for_ciphering} \n ciphered_payload : {ciphered_payload.hex()}\n' )

                bearer = 1
                logger.debug('snow_f8 called for nas-5gs packet')
                plain_payload = pysnow.snow_f8(cipher_key, count_for_ciphering, bearer,
                                               direction, ciphered_payload, len(ciphered_payload)*8)
                logger.info(f'Plain Payload in Hex : {plain_payload.hex()}')
            # elif ZUC algorithm:
            elif self.ue_dict[gnb_ip]['algorithm_id_5g'] == '3' and count_for_ciphering is not None:
                plain_payload = pyzuc.zuc_eea3(cipher_key, count_for_ciphering, bearer,
                                               direction, len(ciphered_payload) * 8, ciphered_payload)
            # end if
           
            logger.info(f'NAS PDU OLD: {nas_pdu.hex()}\n\n')
            replaced_nas = None
      

            #packet['nas-5gs'].nas_5gs_ciphered_msg.raw_value = plain_payload.hex()

            #logger.debug(packet['nas-eps'].nas_eps_ciphered_msg.raw_value)

            replaced_nas = outer_header+plain_payload
            logger.info(f'NAS PDU NEW: {replaced_nas.hex()}\n\n')
            udp_payload = packet.udp.payload.raw_value
            logger.debug(udp_payload)
            logger.debug(len(udp_payload))

            udp_payload_in_bits = self.hex_to_bin(udp_payload)
            nas_pdu_old_in_bit = self.hex_to_bin(nas_pdu.hex())
            nas_pdu_new_in_bit = self.hex_to_bin(replaced_nas.hex())
            logger.debug('Going to compare ciphered NAS message in ciphered UDP payload\n')
            if nas_pdu_old_in_bit in udp_payload_in_bits:
                logger.debug('Ciphered NAS message bits are present in ciphered UDP payload bits\n')
                logger.debug(len(udp_payload_in_bits))
                new_udp_payload_in_bits = udp_payload_in_bits.replace(nas_pdu_old_in_bit,nas_pdu_new_in_bit)
                logger.debug(len(udp_payload_in_bits))
                old_udp_bytes = bytes.fromhex(udp_payload)
                logger.debug(old_udp_bytes.hex())
                new_udp_bytes = bytes.fromhex(self.bin_to_hex(new_udp_payload_in_bits))
                logger.debug(new_udp_bytes.hex())
            else:
                logger.debug('Ciphered NAS message bits are NOT present in ciphered UDP payload bits\n')
                extra_bits_udp_payload = udp_payload[0:4]
                udp_payload = udp_payload[4:]
                udp_bit_string = self.hex_to_bin(udp_payload)
                logger.debug('\n\n\n')
                logger.debug(len(udp_bit_string))
                logger.debug('decipher 5gs 3')


                if (direction == 0):
                    ul_dcch_bits = udp_bit_string[0:17]
                    udp_bit_string = udp_bit_string[17:]
                    bit_len = len(udp_bit_string)
                    logger.debug('decipher 5gs 4')

                    if((bit_len%8) != 0):
                        udp_bit_string = udp_bit_string[0:(bit_len-(bit_len%8))]
                    else:
                        udp_bit_string = udp_bit_string[0:(bit_len-4)]

                    logger.debug(udp_bit_string)

                    hex_udp = self.bin_to_hex(udp_bit_string)
                elif (direction == 1):
                    ul_dcch_bits = udp_bit_string[0:19]
                    udp_bit_string = udp_bit_string[19:]
                    bit_len = len(udp_bit_string)
                    logger.debug('\n\n\n')
                    logger.debug(bit_len)
                    logger.debug(bit_len%8)
                    if((bit_len%8) != 0):
                        logger.debug('UDP packet length after modification is NOT a multiple of 8')
                        udp_bit_string = udp_bit_string[0:(bit_len-(bit_len%8))]
                    else:
                        logger.debug('UDP packet length after modification is a multiple of 8')
                        udp_bit_string = udp_bit_string[0:(bit_len-4)]

                    logger.debug(udp_bit_string)

                    hex_udp = self.bin_to_hex(udp_bit_string)


                logger.debug('\n\n\n')
                logger.debug('---------------------')
                logger.debug(hex_udp)
                logger.debug('---------------------')
                logger.debug('\n\n\n')

                logger.debug('decipher 5gs 5')

                old_udp_bytes = bytes.fromhex(packet.udp.payload.raw_value)

                logger.debug('decipher 5gs 6')

                logger.debug(self.hex_to_bin(extra_bits_udp_payload))

                if((bit_len%8) != 0):
                    new_udp_payload = self.hex_to_bin(extra_bits_udp_payload) + ul_dcch_bits + self.hex_to_bin(outer_header.hex())+self.hex_to_bin(plain_payload.hex()) + ('0')*(bit_len%8)
                else:
                    new_udp_payload = self.hex_to_bin(extra_bits_udp_payload) + ul_dcch_bits + self.hex_to_bin(outer_header.hex())+self.hex_to_bin(plain_payload.hex()) + '0000'

                logger.debug('decipher 5gs 7')

                hex_new_udp_payload = self.bin_to_hex(new_udp_payload)

                logger.debug('decipher 5gs 8')

                logger.debug(hex_new_udp_payload)

                new_udp_bytes = bytes.fromhex(hex_new_udp_payload)

                logger.debug('decipher 5gs 9')




               # hex_udp = "{0:0>4X}".format(int(udp_bit_string, 2))






                #packetHexRaw = packet['eth'].dst.raw_value + packet['eth'].src.raw_value + packet['eth'].type.raw_value \
                #      + packet['ip'].version.raw_value + packet['ip'].hdr_len.raw_value + packet['ip'].dsfield.raw_value \
                #      + packet['ip'].len.raw_value + packet['ip'].id.raw_value + packet['ip'].flags.raw_value + packet['ip'].frag_offset.raw_value \
                #      + packet['ip'].ttl.raw_value + packet['ip'].proto.raw_value + packet['ip'].checksum.raw_value  \
                #      + packet['ip'].src.raw_value + packet['ip'].dst.raw_value + packet['udp'].srcport.raw_value + packet['udp'].dstport.raw_value \
                #      + packet['udp'].length.raw_value + packet['udp'].checksum.raw_value + packet['udp'].payload.raw_value
                #

                #packetHexRaw = 'd43d7e1be7a60050c2bd268308004500002e0000400040110cd80101010102020202d4e0270f001a5a2c01024801a4f8dc95a5404adf56b51bd81800'
                #packetBytes = bytes.fromhex(packetHexRaw)
                # logger.debug(packet)


                #with open('test.pcap', "wb") as file:
                 #   file.write(packetBytes)

                #if old_udp_bytes in self.buffer:
                #    print('\nYES, NAS PDU IS PRESENT\n')
                #else:
                #    print('\nNA, NAS PDU NOT PRESENT\n')

                if direction == 0:
                    file_header_values = ['\n', str(self.packet_number), 'UL',  packet.ip.src, packet.ip.dst, plain_payload.hex(), '\n']
                elif direction == 1:
                    file_header_values = ['\n', str(self.packet_number), 'DL',  packet.ip.src, packet.ip.dst, plain_payload.hex(), '\n']


                join_str = '            '

                join_str = join_str.join(file_header_values)


                #with open('deciphered_nas.txt', 'a') as file:
                #        file.write(join_str)
                #        file.close()
                #
            logger.debug(f'Debug Old UDP:\n{old_udp_bytes.hex()}')
            logger.debug(f'Debug New UDP:\n{new_udp_bytes.hex()}')
            if len(old_udp_bytes.hex()) != len(new_udp_bytes.hex()):
                logger.warning('Old and New UDP Payload length mismatced')
                return True

            if plain_payload: # and plain_payload.startswith(b'\x7e'):
                logger.debug('decipher 5gs 10')
                self.buffer = self.buffer.replace(old_udp_bytes, new_udp_bytes)
                return True

        except Exception as e:
            logger.warning(f'error: error deciphering '
                       f' packet : IP identification: {packet.ip.id.raw_value},'
                       f'src IP:{packet.ip.src} \n')
            logger.warning(f'the error info is : {str(e)}\n')
            #traceback.print_exc(file=sys.stdout)
            #traceback.print_stack(file=sys.stdout)

            return False

    def process_handover(self,packet, gnb_ip, amf_ip):
        logger.info('Going to process the Handover Message')
        Kamf = self.ue_dict[gnb_ip]['kamf']
        logger.info(f'Kamf: {Kamf.hex()}')
        # Computing new Kasme after the handover from 5G to 4G
        logger.info('Computing new Kasme after the handover from 5G to 4G')
        NAS_Downlink_Count_Value = bytes.fromhex(packet[len(packet.layers)-1].nas_SecurityParamFromNR)
        logger.info(f'NAS Downlink Count Value: {NAS_Downlink_Count_Value.hex()}')
        S_for_Kasme = '74' + '000000' + NAS_Downlink_Count_Value.hex() + '0004'              # Check Annexure A.14.2 Handover in TS 33.501
        logger.debug(S_for_Kasme)
        Kasme = HMAC.new(Kamf, bytes.fromhex(S_for_Kasme), SHA256)  # 256 bits
        Kasme = Kasme.hexdigest()
        logger.info(f'New Kasme after handover: {Kasme}')

        # Computing new Knasenc
        logger.info('Computing new Knasenc after the handover from 5G to 4G')
        input_string_hex = ''
        try:
            if self.ue_dict[amf_ip]['algorithm_id_4g'] == '1':
                logger.debug('log1')
                input_string_hex = '15' + '01' + '0001' + '01' + '0001'
            elif self.ue_dict[amf_ip]['algorithm_id_4g'] == '2':
                logger.debug('log2')
                input_string_hex = '15' + '01' + '0001' + '02' + '0001'
        except Exception as e:
            logger.info(f"Error in extracting Algorithm ID. Error: {e}")
        input_string = bytes.fromhex(input_string_hex)
        Knasenc = (HMAC.new(bytes.fromhex(Kasme), input_string, SHA256).hexdigest())[32:]
        logger.info(f'New Knasenc after handover: {Knasenc}')

        logger.info('Storing new Ciphering Key, Algorithm ID and 4G bearer into the ue_dict list')
        cipher_key_4g = bytes.fromhex(Knasenc)
        self.cipher_key_4g = cipher_key_4g
        self.new_bearer_id = 0
        #self.ue_dict[gnb_ip]['algorithm_id_4g'] = '1'
        #self.ue_dict[amf_ip]['algorithm_id_4g'] = '1'
        logger.info(self.ue_dict)

    def filter_pcap(self):
        if self.file_location:
            file_name = self.file_location
        else:
            logger.error("critical error: the pcap file doesn't exist!\n")
            return False
        #
        #    file_name = None
        #    if len(sys.argv) >= 2:
        #        if sys.argv[1]:
        #            file_name = sys.argv[1]
        #    else:
        #        file_name='d:\\5G-ZUC.pcap'
        #

        # check if file exists, if not, exit program,else,define a new file name for filtered pcap file.
        if not os.path.exists(file_name):
            logger.error("critical error: the pcap file doesn't exist!\n")
            return False
        else:
            self.file_name = file_name

        if not (file_name.upper().endswith('.PCAP') or file_name.upper().endswith('.CAP')):
            logger.error("the input file must be ended with .pcap or .cap!\n")
            return False

        self.filtered_file_name = file_name.replace('.pcap', '').replace('.PCAP', '').replace('.CAP', '').replace('.cap', '')
        self.filtered_file_name = self.filtered_file_name + '_filtered.pcap'
        # get tshark path and filter source pcap file by ngap
        tshark_path = 'C:\\Program Files\\Wireshark\\tshark.exe' #self.get_tshark_path()
        if tshark_path is None:
            logger.error('fatal error: no tshark.exe from wireshark found in system, make sure you have'
                              'wireshark installed, or manually specify the path of wireshark in GUI\n')
            return False
        #parameters = [tshark_path, '-r', '"'+file_name+'"', '-2', '-R', '', '-w', '"'+self.filtered_file_name+'"']
        parameters = [tshark_path, '-r', '"'+file_name+'"', '-w', '"'+self.filtered_file_name+'"']
        parameters = ' '.join(parameters)
        tshark_process = subprocess.Popen(parameters)
        wait_count = 0
        while True:
            logger.info(f'waiting for pcap filtered by ngap protocol,{wait_count} seconds passed.\n')
            if wait_count > self.TIME_OUT_FILTER_PCAP:
                logger.error('filter pcap by ngap timed out,please use a smaller pcap '
                                  'instead or filter it by ngap manually before decrypting it!\n')
                tshark_process.kill()
                return False
            if tshark_process.poll() is not None:
                tshark_process.kill()
                return True
            else:
                module_time_sleep(1)
                wait_count += 1

    def main_test(self):
        self.filter_pcap()
        logger.info("filter pcap finished, now start dectypting!\n")
        #else:
         #   logger.error('error filtering pcap by ngap protocol, operation aborted!\n')
          #  return False

        #file_header_list = ['Packet No.', 'Direction', 'Source', 'Destination', 'Deciphered NAS Message']
        #join_str = '            '

        #join_str = join_str.join(file_header_list)

        #with open('deciphered_nas.txt', 'w') as file:
        #            file.write(join_str)
        #            file.close()
        
        # check if filtered_file_name generated by tshark successfully.
        if not os.path.exists(self.filtered_file_name):
            logger.error(f'error: the file {self.filtered_file_name} seems not generated successfully,operation aborted!\n')
            return False
        # real all contents inside filtered_file_name into buffer.
        #with open(self.filtered_file_name, "rb") as file:
        logger.debug("log 1")
        with open(self.filtered_file_name, "rb") as file:
            self.buffer = file.read()
        logger.debug("log 2")
    
        # start reading packet in file by call tshark process.
        # to be done: need to make sure the option "try to decode EEA0" is enabled before launch tshark process.
        if self.tshark_path:
            self.capture = pyshark.FileCapture(self.filtered_file_name,tshark_path=self.tshark_path)
        else:
            self.capture = pyshark.FileCapture(self.filtered_file_name,tshark_path=self.tshark_path)
        # if the wireshark was not enabled with "try to decode EEA0" option, the output of tshark would not
        # have message type value in some message like securityMode command/complete, need to figure out a
        # way how to enable that option in wireshark automatically before running tshark.
        logger.debug("log 3")
        self.capture.load_packets()
        logger.debug("log 4")
        #num = len(self.capture)
        packet_number = 0
        for packet in self.capture:

            packet_number += 1
            self.packet_number = packet_number
            logger.info(f"\n\n\nPacket Number: {packet_number}\n")
            logger.info(f"Packet layers: {packet.layers}\n\n")


            try:
                # logger.info(f"Security Header Type: {packet['nas-eps']}")
                logger.info(f"Security Header Type: {packet['nas-eps'].nas_eps_security_header_type}\n\n")
                logger.info(f"Security Header Type: {packet['nas-eps'].nas_eps_nas_msg_emm_type}\n\n")
                # pyshark.WriteFile(packet, 'result.pcap')
            except:
                logger.info("\nException caught in printing logs")

            if not (hasattr(packet,'ip') and hasattr(packet.ip,'src') and hasattr(packet.ip,'dst')):
                logger.debug("log 5")
                '''and hasattr(packet,'ngap') and hasattr(packet.ngap,'ran_ue_ngap_id')
                and (hasattr(packet.ngap,'nas_pdu') or hasattr(packet.ngap,'pdusessionnas_pdu'))
                and hasattr(packet.ngap,'procedurecode')
                and hasattr(packet.ngap,'nas_5gs_security_header_type')):'''
                logger.warning(f'error: one or more mandatory IE in packet {packet_number} is missing, skip this packet!\n')
                continue
            else:
                try:
                    logger.debug("log 6")
                    gnb_ip = packet.ip.src.raw_value
                    amf_ip = packet.ip.dst.raw_value
                    logger.info(f"gnb ip: {gnb_ip}, amf ip: {amf_ip}")
                    # ran_ue_ngap_id = packet.ngap.ran_ue_ngap_id.raw_value
                except Exception as e:
                    logger.warning(f'error: error handling ran_ue_ngap_id in {packet_number}, skip this packet!\n')
                    continue

            # if procedurecode is "initialUEMessage"(0x0f),create new UE item in dictionary:
            if hasattr(packet, 'nas-5gs'):
                logger.debug("log 7")
                # hasattr(packet, 'nas-5gs'):
                # skip this packet if initialUEMessage has no nas_5gs_mm_message_type, note only plain nas
                # has this parameter.
                logger.debug(f'NAS-5GS packet received, Packet Number: {packet_number}')
                try:
                    logger.debug("log 8")
                    gnb_ip = packet.ip.src.raw_value
                    amf_ip = packet.ip.dst.raw_value
                    logger.info(f"gnb_ip: {gnb_ip}, amf_ip: {amf_ip}")
                except Exception as e:
                    logger.warning(
                        f'error: error handling source/dest IP in {packet_number}, skip this packet!\n')
                    continue
                # if not hasattr(packet['nas-5gs'],'nas_5gs_mm_message_type'):
                # logger.warning(f'error: one or more mandatory IE in packet {packet_number} is missing, skip this packet!\n')
                # continue
                # if amf_ip and (amf_ip not in self.amf_ip_list):
                # self.amf_ip_list.append(amf_ip)
                # if message type is "registration request".


                if not (gnb_ip in self.ue_dict):
                    self.ue_dict[gnb_ip] = {}

                if amf_ip and (amf_ip not in self.amf_ip_list):
                        self.amf_ip_list.append(amf_ip)

                if hasattr(packet['nas-5gs'],'nas_5gs_mm_message_type'):
                    logger.debug("log 9")
                    logger.info(f"{packet['nas-5gs'].nas_5gs_mm_message_type.raw_value}")
                    if packet['nas-5gs'].nas_5gs_mm_message_type.raw_value == '41':
                        gnb_ip = packet.ip.src.raw_value
                        amf_ip = packet.ip.dst.raw_value
                        self.amf_ip = amf_ip
                        self.gnb_ip = gnb_ip
                        logger.info('Going to process 5G Registration Request')
                        self.process_reg_request(packet,gnb_ip,amf_ip)

                    elif packet['nas-5gs'].nas_5gs_mm_message_type.raw_value == '56':
                        direction = 0
                        logger.debug('Authentication Request Arrived')
                        security_header_type = packet['nas-5gs'].nas_5gs_security_header_type.raw_value
                        # if it's plain nas message:
                        if security_header_type == '0':
                        # if wireshark dissection for null encryption is enabled:
                            if hasattr(packet['nas-5gs'], 'nas_5gs_mm_message_type'):
                                # if packet is authentication request,get rand,autn,abba,SQN,AK,MAC from message.
                                    #if amf_ip and (amf_ip not in self.amf_ip_list):
                                     #   self.amf_ip_list.append(amf_ip)
                                    self.process_auth_request_for_5gs(packet,gnb_ip)

                    # if it's plain nas message but integrity enabled.
                    elif packet['nas-5gs'].nas_5gs_mm_message_type.raw_value == '5d':
                        try:
                                logger.info(f"Security Command Mode Arrived\n")
                                #if amf_ip and (amf_ip not in self.amf_ip_list):
                                 #   self.amf_ip_list.append(amf_ip)
                                # get the algorithm type, then compute KDF_ALGKEY. if algkey is 128 bits,
                                # use the last 128 bits of 256 bits long algkey.
                                self.process_securitymode_command_5gs(packet,gnb_ip,amf_ip)
                        except Exception as e:
                            logger.error('failed to handle integrity enabled downlink message, probably securityModeCommand message.\n')
                            logger.error(f'the error info is :{str(e)}\n')
                            continue


                    # elif message type is "service request"
                    elif packet['nas-5gs'].nas_5gs_mm_message_type.raw_value == '4c':
                        # need further coding here.
                        pass

                elif hasattr(packet['nas-5gs'], 'nas_5gs_security_header_type'):
                    logger.debug('Security Header Type is')
                    logger.debug(packet['nas-5gs'].nas_5gs_security_header_type.raw_value)
                    logger.debug(packet.ip.src.raw_value)
                    logger.debug(self.amf_ip)
                    try:
                        logger.info(f"Security Header Type is: {packet['nas-5gs'].nas_5gs_security_header_type.raw_value}")
                        logger.info(f"{packet.ip.src.raw_value}")
                        logger.info(f"{self.amf_ip}")
                    except:
                        logger.info("Exception caught 1")
                    # self.ue_dict[gnb_ip]['algorithm_id_5g'] = '1'
                    security_header_type = packet['nas-5gs'].nas_5gs_security_header_type.raw_value
                    logger.info(f'NAS-5GS Security Header Type: {security_header_type}')
                    if packet.ip.src.raw_value == self.amf_ip:
                        if (security_header_type == '2') or (security_header_type == '4'):
                            logger.info('Processing Downlink 5GS wireshark captures')
                            direction = 1
                            # if null encryption, do nothing but continue for next packet.
                            if self.ue_dict[gnb_ip]['algorithm_id_5g'] == '0':
                                logger.info(f'skip packet {packet_number} due to null encryption.\n')
                                continue
                            # otherwise, decipher packet.
                            self.decipher_nas_5gs(packet, gnb_ip, direction)
                            logger.info(f'deciphering packet {packet_number} successfully!\n')
                            #else:
                                #logger.error(f'error deciphering packet {packet_number}\n')
                            # end if
                            continue
                    if (packet.ip.dst.raw_value == self.amf_ip):
                        if (security_header_type == '2') or (security_header_type == '4'):
                            direction = 0
                            logger.debug('Processing Uplink 5GS wireshark captures')
                            # if null encryption, do nothing but continue for next packet.
                            if self.ue_dict[gnb_ip]['algorithm_id_5g'] == '0':
                                logger.info(f'skip packet {packet_number} due to null encryption.\n')
                                continue
                            # otherwise, decipher packet.
                            self.decipher_nas_5gs(packet, gnb_ip, direction)
                            logger.info(f'deciphering packet {packet_number} successfully!\n')
                            #else:
                             #   logger.error(f'error deciphering packet {packet_number}\n')
                            # end if
                            continue

            # elif down-link NAS Transport message.
            elif hasattr(packet, 'nas-eps') and hasattr(packet['nas-eps'], 'nas_eps_nas_msg_emm_type'): #and  (packet.ip.src.raw_value == self.amf_ip):#packet.ip.src.raw_value in self.amf_ip_list:
                logger.info("Checking for NAS-EPS")
                try:
                    logger.debug(self.amf_ip)
                    gnb_ip = packet.ip.dst.raw_value
                    amf_ip = packet.ip.src.raw_value
                    security_header_type = packet['nas-eps'].nas_eps_security_header_type.raw_value
                    logger.info(f'NAS-EPS Security Header Type: {security_header_type}')
                except Exception as e:
                    logger.warning(
                        f'error: error handling src/dst IP in {packet_number}, skip this packet!\n')
                    continue

                #if packet['nas-eps'].nas_eps_nas_msg_emm_type.raw_value == '41':
                #    gnb_ip = packet.ip.dst.raw_value
                #    amf_ip = packet.ip.src.raw_value
                #    self.amf_ip = amf_ip
                #    self.gnb_ip = gnb_ip
                #
                ## check if UE record in self.ue_dict had already been added.
                # if not, skip this packet.

                #if not ((gnb_ip in self.ue_dict) and
                #        ('snn' in self.ue_dict[gnb_ip])):# and ('supi' in self.ue_dict[gnb_ip])):
                #    logger.warning(
                #    f'error: error finding matched UE record in dictionary'
                #    f' for packet#{packet_number}, skip this packet!\n')
                #    continue

                # direction paramet`er for ciphering input, 0 for uplink and 1 for downlink.
                # EPS Authentication Request, Should always be a downlink packet
                logger.info(f"{packet['nas-eps'].nas_eps_nas_msg_emm_type.raw_value}\n")
                if packet['nas-eps'].nas_eps_nas_msg_emm_type.raw_value == '52':
                    direction = 0
                    security_header_type = packet['nas-eps'].nas_eps_security_header_type.raw_value
                    # if it's plain nas message:
                    if security_header_type == '0':
                    # if wireshark dissection for null encryption is enabled:
                        if hasattr(packet['nas-eps'], 'nas_eps_nas_msg_emm_type'):
                            # if packet is authentication request,get rand,autn,abba,SQN,AK,MAC from message.
                            if packet['nas-eps'].nas_eps_nas_msg_emm_type.raw_value == '52':
                                #if amf_ip and (amf_ip not in self.amf_ip_list):
                                 #   self.amf_ip_list.append(amf_ip)
                                logger.info(f'gnb_ip: {gnb_ip} and amf_ip: {amf_ip}')
                                self.gnb_ip = gnb_ip
                                self.amf_ip = amf_ip
                                self.process_auth_request(packet,gnb_ip)

                # if it's plain nas message but integrity enabled.
                elif (security_header_type == '1' or security_header_type == '3') and hasattr(packet['nas-eps'], 'nas_eps_nas_msg_emm_type'):
                    try:

                        #if packet.ngap.nas_pdu.raw_value[18:20] == '5d':
                        if packet['nas-eps'].nas_eps_nas_msg_emm_type.raw_value == '5d':
                            logger.info(f"Security Mode Command Arrived\n")
                            #if amf_ip and (amf_ip not in self.amf_ip_list):
                             #   self.amf_ip_list.append(amf_ip)
                            # get the algorithm type, then compute KDF_ALGKEY. if algkey is 128 bits,
                            # use the last 128 bits of 256 bits long algkey.
                            self.process_securitymode_command(packet,gnb_ip)
                    except Exception as e:
                        logger.error('failed to handle integrity enabled downlink message, probably securityModeCommand message.\n')
                        logger.error(f'the error info is :{str(e)}\n')
                        continue

            elif hasattr(packet, 'nas-eps') and (packet.ip.src.raw_value == self.amf_ip):
                # elif it's ciphered nas message.
                gnb_ip = packet.ip.dst.raw_value
                amf_ip = packet.ip.src.raw_value
                logger.info(f'In Downlink packet processing for packet : {packet_number}\n')
                security_header_type = packet['nas-eps'].nas_eps_security_header_type.raw_value
                direction = 1
                if security_header_type == '2' or security_header_type == '4':
                    # if null encryption, do nothing but continue for next packet.
                    logger.info(f'Ciphered Packet Arrived : {packet_number}\n\n')
                    #if self.ue_dict[amf_ip]['algorithm_id_4g'] == '0':
                     #   logger.info(f'skip packet {packet_number} due to null encryption.\n')
                      #  continue
                    # otherwise, decipher packet.

                    logger.debug(packet.udp.payload.raw_value)
                    logger.debug(packet.udp.payload.raw_value.startswith('01012006'))
                    '''
                    if packet.udp.payload.raw_value.startswith('01012006'):
                        logger.debug('RRC RECONFIGURATION PACKET SKIPPING....')
                        continue
                    '''
                    self.decipher_nas(packet,gnb_ip,direction)
                    logger.info(f'deciphering packet {packet_number} successfully!\n')
                    #else:
                     #   logger.error(f'error deciphering packet {packet_number}\n')
                    # end if
                    continue

            # elif up-link NAS Transport message.
            #elif packet.ip.dst.raw_value in self.amf_ip_list:
            elif hasattr(packet, 'nas-eps') and (packet.ip.dst.raw_value == self.amf_ip):
                logger.info(f'In Uplink NAS Transport for packet : {packet_number}\n')
                try:
                    gnb_ip = packet.ip.src.raw_value
                    amf_ip = packet.ip.dst.raw_value
                except Exception as e:
                    logger.warning(
                        f'error: error handling src/dst IP in {packet_number}, skip this packet!\n')
                    continue
                # if packet is "identity response for GUTI attach", handle it on priority before other handling.
                '''
                if hasattr(packet , 'nas-5gs'):
                    if hasattr(packet['nas-5gs'],'nas_5gs_mm_message_type'):
                        if packet['nas-5gs'].nas_5gs_mm_message_type.raw_value == '5c':
                            self.process_reg_request(packet, gnb_ip, amf_ip)

                if not ((gnb_ip in self.ue_dict) and
                        ('snn' in self.ue_dict[gnb_ip]) and ('supi' in self.ue_dict[gnb_ip])):
                    logger.warning(
                    f'error: error finding matched UE record in dictionary'
                    f' for packet#{packet_number}, skip this packet!\n')
                    continue
                '''
                if not (gnb_ip in self.ue_dict):
                    self.ue_dict[gnb_ip] = {}

                direction = 0
                if hasattr(packet, 'nas-eps'):
                    security_header_type = packet['nas-eps'].nas_eps_security_header_type.raw_value
                    # if plain nas message:
                    if security_header_type == '0' or security_header_type == '1' or security_header_type == '3':
                        # if packet is authentication response:
                        if packet['nas-5gs'].nas_5gs_mm_message_type.raw_value == '57':
                            if amf_ip and (amf_ip not in self.amf_ip_list):
                                self.amf_ip_list.append(amf_ip)

                    # elif it's ciphered nas message.
                    elif security_header_type == '2' or security_header_type == '4':
                        # if null encryption, do nothing but continue for next packet.
                        logger.debug('HELL')
                        if self.ue_dict[gnb_ip]['algorithm_id_4g'] == '0':
                            logger.info(f'skip packet {packet_number} due to null encryption.\n')
                            continue
                        # otherwise, decipher packet.
                        self.decipher_nas(packet, gnb_ip, direction)
                        logger.info(f'deciphering packet {packet_number} successfully!\n')
                        #else:
                         #   logger.error(f'error deciphering packet {packet_number}\n')
                        # end if
                        continue

            # else: none of initialUE/downlinktransport/uplinktransport,
            # then determine uplink or downlink based on source and dest IP.
           # else:
            #    logger.error(f'packet {packet_number} not belongs to any of initialUE/uplinktransport/dlinktransport'
             #                f'skipped this packet!\n')
                continue

            # Checking for handover message (Mobility from NR Command) 5G -> 4G using N26 Handover
            elif hasattr(packet, 'nr-rrc') and hasattr(packet[len(packet.layers)-1], 'mobilityFromNRCommand_element'):
                logger.info('Mobility from NR Command received: Handover from 5G to 4G is going to happen')
                logger.info('Keys are going to be regenerated for NAS-EPS Packets')
                gnb_ip = packet.ip.src.raw_value
                amf_ip = packet.ip.dst.raw_value
                logger.info(self.ue_dict)
                ret = self.process_handover(packet, gnb_ip, amf_ip)
                if ret is True:
                    logger.info('Handover/Mobility from NR Command Packet handled successfully')
                else:
                    logger.info('Handover/Mobility from NR Command Packet handled unsuccessfully')
            else:
                logger.info('Packet has no required attributes. Going to continue without processing this packet')
        # end of for loop
        # write deciphered buffer back to pcap file.
        try:
            with open(self.filtered_file_name, "wb") as file:
                logger.debug('Writing in pcap file\n')
                file.write(self.buffer)
            logger.info(f'file {self.filtered_file_name} with deciphered content created!\n')

            # UE Capability Info dumping into text files
            #dumpCmd = self.filtered_file_name
            #dumpCmd = 'C:\\ACP\\SA_EXE\\hw_v7\\ue_capability_info.exe ' + '\"' + dumpCmd + '\"'
            # ue_capability_info.fun(dumpCmd)
            #try:
            #    os.system(dumpCmd)
            #except OSError as e:
            #    logger.info("Error running UE Capability Info command")
            #    logger.info(e)
            #del self.buffer,self.ue_dict,self.amf_ip_list
            #return True
        except Exception as e:
            logger.error("error happened during writing decrypted content into pcap, operation aborted!\n")
            logger.debug(f"the error info is : {str(e)}")
            return False


class ThreadedClient:
    """
    Launch the main part of the GUI and the decrypting thread. periodicCall and
    endApplication could reside in the GUI part, but putting them here
    means that you have all the thread controls in a single place.
    """
    def __init__(self, master):
        """
        Start the GUI and the asynchronous threads. We are in the main
        (original) thread of the application, which will later be used by
        the GUI as well. We spawn a new thread for decrypting.
        """
        self.master = master

        # Create the queue
        self.queue = queue.Queue()
        # decryption object will be instantiated later by start_decrypting function.
        self.decryption = None
        # Set up the GUI part
        #self.gui = GuiPart(master, self.queue, self.end_application, self.start_decrypting)
        self.start_decrypting()
        self.running = 1
        self.thread1 = None
        # Start the periodic call in the GUI to check if the queue contains
        # anything
        self.LOGFILE = "decipher" + str(datetime.now()).replace(":", "-").replace(" ", "-") + ".log"
        level = logging.FATAL
        #self.init_log(level)
        self.periodic_call()
        self.end_application()

    def init_log(self,log_level=logging.INFO):
        try:
            # create logger
            logger.propagate = False
            logger.setLevel(log_level)

            # create file handler, with a formatter and set level to info
            ch = logging.handlers.RotatingFileHandler(self.LOGFILE,
                                                      mode='a', maxBytes=10000000, backupCount=5)
            # need to check whether failed with creating lscheck.log here.
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            ch.setFormatter(formatter)
            ch.setLevel(log_level)
            logger.addHandler(ch)
            # create one more handler for output to stdout.
            handler = logging.StreamHandler(sys.stdout)
            handler.setLevel(log_level)
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)

            # add queue handler into logger so that any log message would be recorded into thread queue as well.
            # GUI part would read the queue periodically and print it into GUI window.
            if self.queue:
                logger.debug(f"queue handler: {self.queue}")
                queue_handler = QueueHandler(self.queue)
                queue_handler.setFormatter(formatter)
                queue_handler.setLevel(log_level)
                logger.addHandler(queue_handler)
                logger.debug("success with add queue handler.\n")

            logger.debug("log file is generated by file name:"+self.LOGFILE)
            return logger
        except Exception as e:
            print("initialize a new log file and writing into it failure,"
                  " make sure your current account has write privilege to current directory!\n")
            logger.error("error: " + str(e)+'\n')
            return logger

    def periodic_call(self):
        """
        Check every 200 ms if there is something new in the queue.
        """
        #self.gui.process_incoming()
        if not self.running:
            # do some cleanup before  shutting it down.
            #del self.gui,self.decryption
            sys.exit(1)
        self.master.after(200, self.periodic_call)

    def start_decrypting(self):
        # Set up the thread to do decrypting.
        # decrypt_suci, private_key, secret_key, use_op, op, opc, file_location, tshark_path,new_bearer_id = self.gui.get_gui_input()
        # decrypt_suci, private_key, secret_key, use_op, op, opc, file_location, tshark_path,new_bearer_id = self.gui.get_gui_input()

        number_of_cli = len(sys.argv) # Reading number of command line arguments
        if number_of_cli < 2:
            logger.error('No command line argument received')
            sys.exit()
        file_path = sys.argv[1]

        '''
        try:
            list_of_files = glob.glob(file_path + '/*.pcap')    # * means all if need specific format then *.csv
            # list_of_files = glob.glob('./**/*.pcap', recursive=True) # for searching all the sub-directories and the current directory for .pcap
            if not list_of_files:
                logger.error('No .pcap files at the given path')
                sys.exit()
            latest_file = max(list_of_files, key=os.path.getctime)
        except (OSError, FileNotFoundError, ValueError) as e:
            logger.error(e)
        file_location = latest_file
        '''
        file_location = file_path

        tshark_path = 'C:/Program Files/Wireshark/tshark.exe'
        new_bearer_id = 0
        # op = bytes.fromhex('')
        # secret_key = bytes.fromhex('54484953204953204120534543524554')
        # opc = bytes.fromhex('576FE92DC7B03D69F47801E3B02ED0D7')

        #if secret_key is None or file_location is None:
        if file_location is None:
            logger.error("get input failed, abort decryption!\n")
            return False
        logger.info("Calling func Decryption")
        #self.decryption = Decryption(secret_key, op, opc, file_location, self.queue, tshark_path, new_bearer_id)
        self.decryption = Decryption(file_location, self.queue, tshark_path, new_bearer_id)
        self.thread1 = threading.Thread(target=self.decryption.main_test)
        self.thread1.start()

    def end_application(self):
        self.running = 0
        module_time_sleep(0.2)
        #del self.gui,self.decryption
        logger.debug("closing")
        sys.exit(1)
        quit()

logger.info("HELLO!!!")
root = tkinter.Tk()
client = ThreadedClient(root)
root.mainloop()
sys.exit()


