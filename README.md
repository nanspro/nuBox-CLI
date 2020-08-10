# nuBox-CLI
A CLI tool to share files with users seamlessly using nuCypher

**Demo Video**

https://youtu.be/HumiZaXp9mI

## User Commands
**To see all possible commands**

    `python3 run.py` 

**To initialize your keys, set your email to public key mapping. You could also provide your existing keys to restore your account**

    `python3 run.py initialize <email>`

**Get Bob**

    `python3 run.py get_bob`

**Get Alice**

    `python3 run.py get_alice`

**Encrypt the directory you want to share and upload it to ipfs**

_Note: We also store md5 checksum of each file and check whether it has been updated or not. If a file has not been uploaded then we don't encrypt it again and upload. Later we could run a cron job here to track files and upload it whenever something changes_

    `python3 encrypt <label> <directory_path>`

**Share the directory with anyone using their email. We grant access to that user and email him the policy-metadata and other info like ipfs hash list of files as an attachment**

_Note: Suppose we can't find mapping of a email with public key in our db then we generate a keypair for the that user and send him the privatekeys also. The idea is if we want to share something with a user then it's fine for us to generate private keys for him if he doesn't have them already_ 

    `python3 share <label> <email>`

**Fetch the data shared with you by re-encrypting and decrypting it**

    `python3 fetch <path_to_details file received via email> <target_directory where you want to store content>`


## Local Setup
`pip3 install -r reqs.txt`
`python3 run.py`