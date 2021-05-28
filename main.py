import json
import subprocess
import argparse
import sys
from art import text2art
import termcolor
from clint.textui import colored, puts, indent
import time

mitre_tactics = ["privilege_escalation", "discovery", "command_and_control", "credential_access", "persistence",
                 "collection", "defense_evasion", "execution", "reconnaissance", "lateral_movement", "initial_access"]


def kubectl_subproc(kubectl_command):
    k_proc = subprocess.run(kubectl_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout = k_proc.stdout
    stderr = k_proc.stderr

    return stdout, stderr


def kubectl_print(k_out, k_err, k_mode, k_lead):
    with indent(2):

        if k_out:
            puts(colored.white('\n'))
            if k_mode == 'active':
                puts(colored.green('✔  command output: \n'))
            else:
                puts(colored.green('✔  found, printing output:\n'))

            with indent(2):
                puts(colored.green(k_out.decode()))

                if k_lead:
                    puts(colored.cyan("Leading to technique id: %s" % k_lead))

        elif k_err:
            puts(colored.white('\n'))
            puts(colored.red(k_err.decode()))

        else:
            puts(colored.white('\n'))
            puts(colored.red('✘  none found\n'))


def get_mitre_tactics():
    print_logo()

    with indent(2):
        puts(colored.white("Supported MITRE ATT&CK Tactics:"))
        print("")

        for mitre_tactic in mitre_tactics:

            with indent(2):
                puts(colored.red("+ %s" % mitre_tactic))


def run_kubectl(rk_technique, rk_scan_mode):
    technique_command = rk_technique.get('command')
    technique_id = rk_technique['id']
    technique_leading_to = rk_technique['leading_to']
    technique_mode = rk_technique['mode']
    technique_args = rk_technique['args']
    technique_arg_list = rk_technique.get('arg_list')
    technique_multistep = rk_technique.get('multistep')
    technique_steps = rk_technique.get('commands')
    puts(colored.white('\n'))

    with indent(4):
        puts(colored.yellow("ID:        "), newline=False), puts(colored.white("%s" % technique_id))
        puts(colored.yellow("Technique: "), newline=False), puts(colored.white("%s" % rk_technique['name']))
        puts(colored.yellow("Command:   "), newline=False), puts(colored.white("%s" % technique_command))

        if rk_scan_mode == 'all' or technique_mode == rk_scan_mode:
            if not technique_args:

                if not technique_multistep:

                    out, err = kubectl_subproc(technique_command)
                    kubectl_print(out, err, technique_mode, technique_leading_to)

                else:
                    for cmd_step in technique_steps:

                        out, err = kubectl_subproc(cmd_step)
                        kubectl_print(out, err, technique_mode, technique_leading_to)
                        time.sleep(2)

            else:
                with indent(4):

                    puts(colored.white('\n'))
                    puts(colored.red("✘  The command requires specific parameters:"))
                    puts(colored.white('\n'))

                    for arg in technique_arg_list:
                        x = input("         %s:" % arg)
                        technique_command = technique_command.replace("$%s" % arg, x)

                    puts(colored.green("✔  command updated, running: ", technique_command))
                    out, err = kubectl_subproc(technique_command)
                    kubectl_print(out, err, technique_mode, technique_leading_to)
                    time.sleep(2)

        else:
            with indent(4):
                puts(colored.red("✘  This command mode does not match your scan mode."))
                time.sleep(2)


def print_logo():
    text_art = text2art("RED   KUBE")
    print(termcolor.colored(text_art, 'red'))
    puts(colored.white("            +++ WELCOME TO RED-KUBE +++\n\n"))


def cleanup():
    out, err = kubectl_subproc("kubectl delete pods trivy awscli")

    with indent(2):
        puts(colored.green(out.decode()))
        puts(colored.red(err.decode()))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--mode', action='store', dest='mode', type=str,
                        help='scan mode (passive/active/all)', required=False, default='passive')
    parser.add_argument('--tactic', action='store', dest='tactic', type=str,
                        help='specific tactic', required=False)
    parser.add_argument('--show_tactics', action='store_true', help='show tactics')
    parser.add_argument('--cleanup', action='store_true', required=False)

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

    if cmd_args.cleanup:
        cleanup()
        sys.exit()

    if scan_tactic in mitre_tactics:
        print_logo()
        scan_tactic = scan_tactic
        with indent(4):
            puts(colored.red("MITRE ATT&CK Tactic %s chosen " % scan_tactic))

        with open('attacks/%s.json' % scan_tactic) as tactic_file:
            tactic_data = json.load(tactic_file)

            for technique in tactic_data:
                run_kubectl(technique, scan_mode)
                time.sleep(1)

    else:
        print_logo()
        puts(colored.red("Please choose a tactic using --tactic TACTIC_NAME"))
        sys.exit()
