# utils.py
import subprocess
import sys
from threading import Thread
from queue import Queue, Empty

def _enqueue_output(out, queue):
    """Lit la sortie du processus et la met dans une queue"""
    for line in iter(out.readline, b''):
        queue.put(line.decode('utf-8').rstrip())
    out.close()

def run_cmd(cmd, real_time=True, save_output=True):
    """
    Exécute une commande avec affichage en temps réel
    :param cmd: Liste contenant la commande et ses arguments
    :param real_time: Affiche la sortie en temps réel si True
    :param save_output: Sauvegarde la sortie pour le retour si True
    :return: La sortie complète de la commande ou None en cas d'erreur
    """
    try:
        output_lines = []
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=1,
            universal_newlines=True
        )

        # Gestion de la sortie en temps réel
        if real_time:
            while True:
                line = process.stdout.readline()
                if not line and process.poll() is not None:
                    break
                if line:
                    line = line.rstrip()
                    print(line)
                    if save_output:
                        output_lines.append(line)

            # Récupération des erreurs éventuelles
            for line in process.stderr:
                line = line.rstrip()
                print(f"[!] {line}", file=sys.stderr)
                if save_output:
                    output_lines.append(f"[!] {line}")
        else:
            # Mode classique sans temps réel
            out, err = process.communicate()
            if save_output:
                output_lines = out.splitlines()
            if err:
                print(f"[!] {err}", file=sys.stderr)

        if process.returncode != 0:
            print(f"[!] La commande a échoué avec le code {process.returncode}")
            
        return "\n".join(output_lines) if save_output else None

    except subprocess.CalledProcessError as err:
        print(f"[!] Erreur lors de l'exécution de: {' '.join(cmd)}")
        print(f"[!] {err}")
        return None
    except Exception as e:
        print(f"[!] Erreur inattendue: {str(e)}")
        return None
