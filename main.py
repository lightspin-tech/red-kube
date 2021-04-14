import json
import subprocess, platform
import argparse
import sys
from art import text2art
import termcolor
from clint.textui import colored, puts, indent
import time

mitre_tactics = ["privilege_escalation", "discovery", "command_and_control", "credential_access"]


def kubectl_path():
    platform_name = platform.system()

    if platform_name == "Linux":
        w_proc = subprocess.Popen("which kubectl", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = w_proc.communicate()
        k_path = stdout.decode()

    if platform_name == "Windows":
        k_path = "kubectl"

    return k_path


def kubectl_subproc(kubectl_command):
    k_proc = subprocess.Popen(kubectl_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = k_proc.communicate()

    return stdout, stderr


def get_mitre_tactics():
    print_logo()

    with indent(2):
        puts(colored.white("Supported MITRE ATT&CK Tactics:"))
        print("")

        for mitre_tactic in mitre_tactics:

            with indent(2):
                puts(colored.red("+ %s" % mitre_tactic))


def run_kubectl(technique):
    technique_command = technique['command']
    technique_id = technique['id']
    technique_leading_to = technique['leading_to']
    puts(colored.white('\n'))

    with indent(4):
        puts(colored.yellow("ID:        "), newline=False), puts(colored.white("%s" % technique_id))
        puts(colored.yellow("Technique: "), newline=False), puts(colored.white("%s" % technique['name']))
        puts(colored.yellow("Command:   "), newline=False), puts(colored.white("%s" % technique_command))
        out, err = kubectl_subproc(technique_command)

        with indent(2):

            if out:
                puts(colored.white('\n'))
                puts(colored.green('✔  found\n'))

                with indent(2):
                    puts(colored.green(out.decode()))

                    if technique_leading_to:
                        puts(colored.yellow("Leading to technique id: %s" % technique_leading_to))

            else:
                puts(colored.white('\n'))
                puts(colored.red('✘  none found\n'))


def print_logo():
    text_art = text2art("RED   KUBE")
    print(termcolor.colored(text_art, 'red'))
    puts(colored.white("            +++ WELCOME TO RED-KUBE +++\n\n"))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--type', action='store', dest='type', type=str,
                        help='scan type (passive/active)', required=False)
    parser.add_argument('--tactic', action='store', dest='tactic', type=str,
                        help='specific tactic', required=False)
    parser.add_argument('--show_tactics', action='store_true',help='show tactics')

    cmd_args = parser.parse_args()
    scan_tactic = ""

    if cmd_args.type:
        scan_type = cmd_args.type

    if cmd_args.tactic:
        scan_tactic = cmd_args.tactic

    if cmd_args.show_tactics:
        get_mitre_tactics()
        sys.exit()
        
    k_path = kubectl_path()

    if scan_tactic in mitre_tactics:
        print_logo()
        scan_tactic = scan_tactic
        puts(colored.red("%s tactic chosen " % scan_tactic))

        with open('attacks/%s.json' % scan_tactic) as tactic_file:
            tactic_data = json.load(tactic_file)

            for technique in tactic_data:
                run_kubectl(technique)
                time.sleep(1)

    else:
        print_logo()
        puts(colored.red("Please choose a tactic using --tactic TACTIC_NAME"))
        sys.exit()


