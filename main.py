import json
import subprocess
import argparse
import sys
from art import text2art
import termcolor
from clint.textui import colored, puts, indent
import time

mitre_tactics = ["privilege_escalation", "discovery", "command_and_control", "credential_access", "persistence",
                 "collection"]


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


def run_kubectl(technique, scan_mode):
    technique_command = technique['command']
    technique_id = technique['id']
    technique_leading_to = technique['leading_to']
    technique_mode = technique['mode']
    technique_args = technique['args']

    puts(colored.white('\n'))

    with indent(4):
        puts(colored.yellow("ID:        "), newline=False), puts(colored.white("%s" % technique_id))
        puts(colored.yellow("Technique: "), newline=False), puts(colored.white("%s" % technique['name']))
        puts(colored.yellow("Command:   "), newline=False), puts(colored.white("%s" % technique_command))

        if scan_mode == 'all' or technique_mode == scan_mode:
            if not technique_args:
                out, err = kubectl_subproc(technique_command)

                with indent(2):

                    if out:
                        puts(colored.white('\n'))
                        if technique_mode == 'active':
                            puts(colored.green('✔  command output: \n'))
                        else:
                            puts(colored.green('✔  found, printing output:\n'))

                        with indent(2):
                            puts(colored.green(out.decode()))

                            if technique_leading_to:
                                puts(colored.cyan("Leading to technique id: %s" % technique_leading_to))

                    else:
                        puts(colored.white('\n'))
                        puts(colored.red('✘  none found\n'))

            else:
                with indent(4):
                    puts(colored.red("✘  This command might need specific parameters, run on your own."))
                    time.sleep(2)

        else:
            with indent(4):
                puts(colored.red("✘  This command mode does not match your scan mode."))
                time.sleep(2)


def print_logo():
    text_art = text2art("RED   KUBE")
    print(termcolor.colored(text_art, 'red'))
    puts(colored.white("            +++ WELCOME TO RED-KUBE +++\n\n"))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--mode', action='store', dest='mode', type=str,
                        help='scan mode (passive/active/all)', required=False, default='passive')
    parser.add_argument('--tactic', action='store', dest='tactic', type=str,
                        help='specific tactic', required=False)
    parser.add_argument('--show_tactics', action='store_true', help='show tactics')

    cmd_args = parser.parse_args()
    scan_tactic = ''
    scan_mode = 'passive'

    if cmd_args.mode:
        scan_mode = cmd_args.mode

    if cmd_args.tactic:
        scan_tactic = cmd_args.tactic

    if cmd_args.show_tactics:
        get_mitre_tactics()
        sys.exit()

    if scan_tactic in mitre_tactics:
        print_logo()
        scan_tactic = scan_tactic
        puts(colored.red("%s tactic chosen " % scan_tactic))

        with open('attacks/%s.json' % scan_tactic) as tactic_file:
            tactic_data = json.load(tactic_file)

            for technique in tactic_data:
                run_kubectl(technique, scan_mode)
                time.sleep(1)

    else:
        print_logo()
        puts(colored.red("Please choose a tactic using --tactic TACTIC_NAME"))
        sys.exit()
