
## Introduction
This is the capstone project for CS564: Cyber Effects at University of Massachusetts Amherst. 

The purpose of this capstone is to utilize an existing remote exploit and develop a Command and Control (C2) system and Implant to retrieve arbitrary files from an exploited system.

## Target
For this project, we targeted a vulnerable Exim system. Exim is a mail transfer agent (MTA) that has had many vulnerabilities throughout the years and is incredibly common on many servers. You can read more about it [here](https://en.wikipedia.org/wiki/Exim).

We specifically utilized [CVE-2019-10149](https://nvd.nist.gov/vuln/detail/cve-2019-10149).
    
We also utilized a PoC (Proof of Concept) exploit that we adapted to send payloads on the vulnerable machine. This PoC code is located within the base exploit code folder.

## Team and Responsibilities
Team: Cyberpunks

    - Arnab Das 
        - Developed C2 obfuscation protocol, implemented Diffe-Hellman Key Exchange for C2 and Implant, assisted Tristan on payload development, initial C2/Implant development
    - Tristan Carel
        - Set up environment and scenario, key part of payload development and testing
    - Chinmai Anandh Chappa
        - Primary C2 and Implant development especially on communication protocol and the actual systems
## Setup
We utilized two VMs, a Kali VM simulating an attacker and an Ubuntu VM that has the vulnerable version of Exim installed (specifically 4.89).  You will need to download the two VMs at this (link)  ##Insert google drive link here TODO:

    - To test the C2 and Implant, Exim needs to be started on the Ubuntu VM.
    - TODO: Add steps to run exploit and C2/Implant on systems

## C2 Security
Commands are listed as standard Exim commands to try and hide traffic from the server admin. The idea behind this is to mask the C2 as just another user communicating with the Exim server.

Diffe-Hellman is used to have session keys to encrypt communication between the C2 and Implant.

## Implant Security
Diffe-Hellman Key Exchange is used for the same purpose as in the C2.

On disconnect from C2 or via command, implant will destroy itself and its related files on the vulnerable machine.

Implant hides exim server logs to not draw attention to itself from server admins.

## Exfiltration Security
Messages are transferred via a flask app interface and endpoints.

AES is used to encrypt the commands.

## Video showing presentation and demo
TODO: add link here []()

