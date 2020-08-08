import fire
import datetime
import sys
import json
import os
import shutil
import maya
import traceback
import msgpack

from timeit import default_timer as timer
from umbral.keys import UmbralPublicKey

from nucypher.characters.lawful import Bob, Ursula, Enrico
from nucypher.config.characters import AliceConfiguration
from nucypher.config.constants import TEMPORARY_DOMAIN
from nucypher.crypto.kits import UmbralMessageKit
from nucypher.crypto.powers import DecryptingPower, SigningPower
from nucypher.network.middleware import RestMiddleware
from nucypher.datastore.keypairs import DecryptingKeypair, SigningKeypair
# from nucypher.utilities.logging import GlobalLoggerSettings

# from listener_keys import get_listener_pubkeys

# Twisted Logger
# GlobalLoggerSettings.start_console_logging()

class nuCLI(object):
    """A simple nuCLI class having all nuCypher capabilities"""

    def __init__(self):
        self.SEEDNODE_URI = "localhost:11500"
        self.TEMP_ALICE_DIR = os.path.join('/', 'tmp', 'alice-data')

        self.POLICY_FILENAME = "policy-metadata.json"
        self.passphrase = "TEST_ALICIA_INSECURE_DEVELOPMENT_PASSWORD"

    def get_alice(self):
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


    def initialize_alice(self):
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
        return alicia, alice_config_file


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


    def grant_access_policy(self, label, bob_pubkeys):
        '''
        Alicia creates a policy granting access to Bob.
        The policy is sent to the NuCypher network.
        '''
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
        print(json.dumps({
            "policy_pubkey": policy.public_key.to_bytes().hex(),
            "alice_sig_pubkey": bytes(alicia.stamp).hex(),
            "label": label.decode(),
        }))

    def initialize_bob(self, bob_privkeys):
        ursula = Ursula.from_seed_and_stake_info(seed_uri=self.SEEDNODE_URI,
                                            federated_only=True,
                                            minimum_stake=0)
        TEMP_DOCTOR_DIR = "{}/buyer-files".format(os.path.dirname(os.path.abspath(__file__)))

        # Remove previous demo files and create new ones
        shutil.rmtree(TEMP_DOCTOR_DIR, ignore_errors=True)

        bob_enc_keypair = DecryptingKeypair(private_key=bob_privkeys["enc"])
        bob_sig_keypair = SigningKeypair(private_key=bob_privkeys["sig"])
        enc_power = DecryptingPower(keypair=bob_enc_keypair)
        sig_power = SigningPower(keypair=bob_sig_keypair)
        power_ups = [enc_power, sig_power]

        print("Creating the Buyer ...")

        buyer = Bob(
            domains={TEMPORARY_DOMAIN},
            federated_only=True,
            crypto_power_ups=power_ups,
            start_learning_now=True,
            abort_on_learning_error=True,
            known_nodes=[ursula],
            save_metadata=False,
            network_middleware=RestMiddleware(),
        )

        print("Buyer = ", buyer)
        return buyer


    def join_policy(self, buyer, policy_metadata): 
        # Let's join the policy generated by Alicia. We just need some info about it.

        policy_pubkey = UmbralPublicKey.from_bytes(bytes.fromhex(policy_metadata["policy_pubkey"]))
        alices_sig_pubkey = UmbralPublicKey.from_bytes(bytes.fromhex(policy_metadata["alice_sig_pubkey"]))
        label = policy_metadata["label"].encode()

        print("The Buyer joins policy for label '{}'".format(label.decode("utf-8")))
        buyer.join_policy(label, alices_sig_pubkey)
        return label.decode("utf-8")

    def reencrypt_segment(self, enc_data, policy_metadata, listener):
        policy_pubkey = UmbralPublicKey.from_bytes(bytes.fromhex(policy_metadata["policy_pubkey"]))
        alices_sig_pubkey = UmbralPublicKey.from_bytes(bytes.fromhex(policy_metadata["alice_sig_pubkey"]))
        label = policy_metadata["label"].encode()
        
        data = msgpack.loads(enc_data)
        message_kit = UmbralMessageKit.from_bytes((data[b'track_segment_data']))
        data_source = Enrico.from_public_keys(
            verifying_key=data[b'data_source'],
            policy_encrypting_key=policy_pubkey
        )
        plaintext = None
        try:
            start = timer()
            retrieved_plaintexts = listener.retrieve(
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