import fire
import datetime
import sys
import json
import os
import shutil
import maya
import traceback
import msgpack
import ipfshttpclient
import yagmail


import keyvalue
from timeit import default_timer as timer
from umbral.keys import UmbralPublicKey, UmbralPrivateKey

from nucypher.characters.lawful import Bob, Ursula, Enrico
from nucypher.config.characters import AliceConfiguration
from nucypher.config.constants import TEMPORARY_DOMAIN
from nucypher.crypto.kits import UmbralMessageKit
from nucypher.crypto.powers import DecryptingPower, SigningPower
from nucypher.network.middleware import RestMiddleware
from nucypher.datastore.keypairs import DecryptingKeypair, SigningKeypair

class nuCLI(object):
    """A simple nuCLI class having all nuCypher capabilities"""

    def __init__(self):
        '''Configuring local node'''
        # can be initialized based on inputs, but let's keep it like this for easy testing for now
        self.SEEDNODE_URI = "localhost:11500"
        self.TEMP_ALICE_DIR = os.path.join('/', 'tmp', 'alice-data')
        self.TEMP_BOB_DIR = "{}/bob-files".format(os.path.dirname(os.path.abspath(__file__)))

        self.POLICY_FILENAME = "policy-metadata.json"
        self.passphrase = "TEST_ALICIA_INSECURE_DEVELOPMENT_PASSWORD"
        self.PUBLIC_JSON = 'public.json'
        self.PRIVATE_JSON = 'private.json'


    def initialize(self, email, password, restore=False):
        '''Initializing stuff, generating key pair'''
        # Creating ipfs api object
        self.api = ipfshttpclient.connect('/dns/localhost/tcp/5001/http')
        self.email = email
        self.email_app_pass = '' # https://support.google.com/mail/?p=BadCredentials

        enc_privkey = UmbralPrivateKey.gen_key()
        sig_privkey = UmbralPrivateKey.gen_key()

        privkeys = {
            'enc': enc_privkey.to_bytes().hex(),
            'sig': sig_privkey.to_bytes().hex(),
        }

        with open(self.PRIVATE_JSON, 'w') as f:
            json.dump(privkeys, f)

        enc_pubkey = enc_privkey.get_pubkey()
        sig_pubkey = sig_privkey.get_pubkey()
        pubkeys = {
            'enc': enc_pubkey.to_bytes().hex(),
            'sig': sig_pubkey.to_bytes().hex()
        }
        with open(self.PUBLIC_JSON, 'w') as f:
            json.dump(pubkeys, f)
        
        ############################
        # Initializing Alice
        ursula = Ursula.from_seed_and_stake_info(seed_uri=self.SEEDNODE_URI,
                                            federated_only=True,
                                            minimum_stake=0)

        # If anything fails, let's create Alicia from scratch
        # Remove previous demo files and create new ones
        shutil.rmtree(self.TEMP_ALICE_DIR, ignore_errors=True)
        
        alice_config = AliceConfiguration(
            config_root=os.path.join(self.TEMP_ALICE_DIR),
            domains={TEMPORARY_DOMAIN},
            known_nodes={ursula},
            start_learning_now=False,
            federated_only=True,
            learn_on_same_thread=True,
        )

        alice_config.initialize(password=self.passphrase)
        alice_config.keyring.unlock(password=self.passphrase)
        
        # We will save Alicia's config to a file for later use
        alice_config_file = alice_config.to_configuration_file()
        
        with open(os.path.join(self.TEMP_ALICE_DIR, 'alice.config.json'), 'w') as f:
            f.write(open(alice_config_file).read())
        
        alicia = alice_config.produce()
        
        # Let's get to learn about the NuCypher network
        alicia.start_learning_loop(now=True)

        ##############################
        # Initializing Bob

        # Getting private keys
        with open(self.PRIVATE_JSON) as f:
            stored_keys = json.load(f)
        bob_privkeys = dict()
        for key_type, key_str in stored_keys.items():
            bob_privkeys[key_type] = UmbralPrivateKey.from_bytes(bytes.fromhex(key_str))

        ursula = Ursula.from_seed_and_stake_info(seed_uri=self.SEEDNODE_URI,
                                            federated_only=True,
                                            minimum_stake=0)

        shutil.rmtree(self.TEMP_BOB_DIR, ignore_errors=True)

        bob_enc_keypair = DecryptingKeypair(private_key=bob_privkeys["enc"])
        bob_sig_keypair = SigningKeypair(private_key=bob_privkeys["sig"])
        enc_power = DecryptingPower(keypair=bob_enc_keypair)
        sig_power = SigningPower(keypair=bob_sig_keypair)
        power_ups = [enc_power, sig_power]

        print("Creating Bob ...")

        bob = Bob(
            domains={TEMPORARY_DOMAIN},
            federated_only=True,
            crypto_power_ups=power_ups,
            start_learning_now=True,
            abort_on_learning_error=True,
            known_nodes=[ursula],
            save_metadata=False,
            network_middleware=RestMiddleware(),
        )
        print("Bob = ", bob)

        self.alice = alicia
        self.bob = bob


    def get_policy_pubkey(self, label):
        '''
        Alicia can create the public key associated to the policy label,
        even before creating any associated policy
        '''
        alicia = self.get_alice()
        label = label.encode()
        policy_pubkey = alicia.get_policy_encrypting_key_from_label(label)
        # print("The policy public key for "
            #   "label '{}' is {}".format(label.decode("utf-8"), policy_pubkey.to_bytes().hex()))
        return policy_pubkey

    # Not needed probably
    def get_alice(self):
        '''Get Alice actor'''
        ursula = Ursula.from_seed_and_stake_info(seed_uri=self.SEEDNODE_URI,
                                            federated_only=True,
                                            minimum_stake=0)
        # A new Alice is restored from the configuration file
        new_alice_config = AliceConfiguration.from_configuration_file(
            filepath=os.path.join(self.TEMP_ALICE_DIR, 'alice.config.json'),
            domains={TEMPORARY_DOMAIN},
            known_nodes={ursula},
            start_learning_now=False,
            federated_only=True,
            learn_on_same_thread=True,
        )

        # Alice unlocks her restored keyring from disk
        new_alice_config.attach_keyring()
        new_alice_config.keyring.unlock(password=self.passphrase)
        new_alice = new_alice_config()
        new_alice.start_learning_loop(now=True)

        return new_alice

    def encrypt(self, label, file_path):
        '''Encrypting a full folder with files and uploading it to ipfs'''
        policy_pubkey = self.get_policy_pubkey(label)
        data_source = Enrico(policy_encrypting_key=policy_pubkey)
        data_source_public_key = bytes(data_source.stamp)
        print(file_path)

        with open(file_path, "rb") as f:
            plaintext = f.read()

        ciphertext, signature = data_source.encrypt_message(plaintext)
        
        print("Signature", signature)
        data = {
            'image_data': ciphertext.to_bytes(),
            'data_source': data_source_public_key
        }
        
        with open(file_path + '_encrypted', "wb") as f:
            msgpack.dump(data, f, use_bin_type=True)
        
        enc_file = file_path + '_encrypted'
        ipfsHash = self.api.add(enc_file)
        ipfsHash = ipfsHash['Hash']
        
        return ipfsHash


    def share(self, label, bob_pubkeys, email, ipfsHash):
        '''
        Alicia creates a policy granting access to Bob.
        The policy is sent to the NuCypher network and bob recieves an email with policy info.
        '''

        # TODO: Get bob_pubkeys from email
        # TODO: Send email with policydata and ipfsHash

        alicia = self.get_alice()
        label = label.encode()
        # We create a view of the Bob who's going to be granted access.
        active_listener = Bob.from_public_keys(verifying_key=bob_pubkeys['sig'],
                                            encrypting_key=bob_pubkeys['enc'],
                                            federated_only=True)
        print("Creating access policy for the Listener...")
        # Policy expiration date
        policy_end_datetime = maya.now() + datetime.timedelta(days=5)
        # m-out-of-n: This means Alicia splits the re-encryption key in 2 pieces and
        #              she requires Bob to seek collaboration of at least 1 Ursulas
        m, n = 1, 2

        policy = alicia.grant(bob=active_listener,
                            label=label,
                            m=m,
                            n=n,
                            expiration=policy_end_datetime)
        data = json.dumps({
            "policy_pubkey": policy.public_key.to_bytes().hex(),
            "alice_sig_pubkey": bytes(alicia.stamp).hex(),
            "label": label.decode(),
            "ipfsHash": ipfsHash
        })
        yag = yagmail.SMTP(self.email, self.email_app_pass)
        contents = [
            "Hey there!", "I am happy to give you access to my files for the next 24hrs",
            "These are the things you would require to access these files, ", data
        ]
        print(contents)
        yag.send(email, 'Giving Access to ' + label, contents)



    def fetch(self, policy_metadata, ipfsHash): 
        '''Fetches data from ipfs and then decrypts it'''
        # Join Policy
        bob = self.bob
        policy_pubkey = UmbralPublicKey.from_bytes(bytes.fromhex(policy_metadata["policy_pubkey"]))
        alices_sig_pubkey = UmbralPublicKey.from_bytes(bytes.fromhex(policy_metadata["alice_sig_pubkey"]))
        label = policy_metadata["label"].encode()

        print("Joins policy for label '{}'".format(label.decode("utf-8")))
        bob.join_policy(label, alices_sig_pubkey)
        
        # Re-encrypt the data and then decrypt it
        # Getting data from ipfs
        enc_data = self.api.cat(ipfsHash)
        data = msgpack.loads(enc_data)
        message_kit = UmbralMessageKit.from_bytes((data[b'track_segment_data']))
        data_source = Enrico.from_public_keys(
            verifying_key=data[b'data_source'],
            policy_encrypting_key=policy_pubkey
        )
        plaintext = None
        try:
            start = timer()
            retrieved_plaintexts = bob.retrieve(
                message_kit,
                label=label,
                enrico=data_source,
                alice_verifying_key=alices_sig_pubkey
            )
            end = timer()
            plaintext = retrieved_plaintexts[0]

        except Exception as e:
            # We just want to know what went wrong and continue the demo
            traceback.print_exc()
        return plaintext

if __name__ == '__main__':
  fire.Fire(nuCLI)