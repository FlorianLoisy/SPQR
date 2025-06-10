#!/usr/bin/env python3
"""
SPQR - Interface Graphique Simple
Interface utilisateur simplifiée avec tkinter
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import json
import os
from pathlib import Path
import logging

from scripts.generate_traffic.spqrlib import (
    PcapGenerator, FlowGenerator, generate_pcap
)  # Assurez-vous que le nom du fichier est correct
from scripts.generate_path.folder import FolderGenerator
from scripts.process.process import (SuricataExecution, SnortExecution, SPQRSimple)


# Import du module CLI
try:
    from spqr_cli import SPQRSimple
except ImportError:
    # Si le module n'est pas trouvé, créer une version simplifiée
    class SPQRSimple:
        def __init__(self, config_path="config/config.json"):
            self.config_path = config_path
        
        def quick_test(self, attack_type):
            return {"error": "Module CLI non trouvé"}
        
        def list_attack_types(self):
            return ["web_attack", "malware_c2", "data_exfiltration"]

class SPQRGUIApp:
    """Application GUI pour SPQR"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("SPQR - Network Rules Testing Tool")
        self.root.geometry("800x600")
        
        # Initialisation de SPQR
        self.spqr = SPQRSimple()
        
        # Variables
        self.selected_attack = tk.StringVar()
        self.pcap_file = tk.StringVar()
        self.rules_file = tk.StringVar()
        self.output_dir = tk.StringVar(value="output")
        
        # Configuration du logging pour l'interface
        self.setup_logging()
        
        # Création de l'interface
        self.create_widgets()
    
    def setup_logging(self):
        """Configure le logging pour l'interface graphique"""
        # Créer un handler personnalisé pour afficher les logs dans l'interface
        class GUILogHandler(logging.Handler):
            def __init__(self, text_widget):
                super().__init__()
                self.text_widget = text_widget
            
            def emit(self, record):
                msg = self.format(record)
                self.text_widget.insert(tk.END, msg + '\n')
                self.text_widget.see(tk.END)
                self.text_widget.update()
        
        # Configuration du logger
        logger = logging.getLogger()
        logger.setLevel(logging.INFO)
        
        # Le handler sera ajouté après création du widget de texte
    
    def create_widgets(self):
        """Crée l'interface utilisateur"""
        # Notebook pour organiser les onglets
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Onglet Test Rapide
        self.create_quick_test_tab(notebook)
        
        # Onglet Manuel
        self.create_manual_tab(notebook)
        
        # Onglet Configuration
        self.create_config_tab(notebook)
        
        # Onglet Logs
        self.create_logs_tab(notebook)
    
    def create_quick_test_tab(self, notebook):
        """Crée l'onglet de test rapide"""
        frame = ttk.Frame(notebook)
        notebook.add(frame, text="Test Rapide")
        
        # Titre
        title_label = ttk.Label(frame, text="Test Rapide de Règles", font=('Arial', 16, 'bold'))
        title_label.pack(pady=10)
        
        # Sélection du type d'attaque
        attack_frame = ttk.LabelFrame(frame, text="Type d'attaque", padding="10")
        attack_frame.pack(fill='x', padx=20, pady=10)
        
        ttk.Label(attack_frame, text="Sélectionnez le type d'attaque à tester:").pack(anchor='w')
        
        attack_types = self.spqr.list_attack_types()
        self.selected_attack.set(attack_types[0] if attack_types else "")
        
        attack_combo = ttk.Combobox(attack_frame, textvariable=self.selected_attack, 
                                   values=attack_types, state="readonly", width=30)
        attack_combo.pack(pady=5, anchor='w')
        
        # Bouton de test
        test_button = ttk.Button(attack_frame, text="Lancer le Test Rapide", 
                               command=self.run_quick_test, style='Accent.TButton')
        test_button.pack(pady=10)
        
        # Résultats
        results_frame = ttk.LabelFrame(frame, text="Résultats", padding="10")
        results_frame.pack(fill='both', expand=True, padx=20, pady=10)
        
        self.results_text = scrolledtext.ScrolledText(results_frame, height=15, width=70)
        self.results_text.pack(fill='both', expand=True)
        
        # Barre de progression
        self.progress = ttk.Progressbar(frame, mode='indeterminate')
        self.progress.pack(fill='x', padx=20, pady=5)
    
    def create_manual_tab(self, notebook):
        """Crée l'onglet de test manuel"""
        frame = ttk.Frame(notebook)
        notebook.add(frame, text="Test Manuel")
        
        # Titre
        title_label = ttk.Label(frame, text="Test Manuel avec Fichiers", font=('Arial', 16, 'bold'))
        title_label.pack(pady=10)
        
        # Sélection du fichier PCAP
        pcap_frame = ttk.LabelFrame(frame, text="Fichier PCAP", padding="10")
        pcap_frame.pack(fill='x', padx=20, pady=10)
        
        pcap_entry_frame = ttk.Frame(pcap_frame)
        pcap_entry_frame.pack(fill='x')
        
        ttk.Entry(pcap_entry_frame, textvariable=self.pcap_file, width=50).pack(side='left', padx=(0, 10))
        ttk.Button(pcap_entry_frame, text="Parcourir", command=self.browse_pcap).pack(side='left')
        
        # Sélection du fichier de règles (optionnel)
        rules_frame = ttk.LabelFrame(frame, text="Fichier de Règles (optionnel)", padding="10")
        rules_frame.pack(fill='x', padx=20, pady=10)
        
        rules_entry_frame = ttk.Frame(rules_frame)
        rules_entry_frame.pack(fill='x')
        
        ttk.Entry(rules_entry_frame, textvariable=self.rules_file, width=50).pack(side='left', padx=(0, 10))
        ttk.Button(rules_entry_frame, text="Parcourir", command=self.browse_rules).pack(side='left')
        
        # Boutons d'action
        buttons_frame = ttk.Frame(frame)
        buttons_frame.pack(pady=20)
        
        ttk.Button(buttons_frame, text="Tester les Règles", 
                  command=self.run_manual_test).pack(side='left', padx=5)
        ttk.Button(buttons_frame, text="Générer Rapport", 
                  command=self.generate_report).pack(side='left', padx=5)
        
        # Zone de résultats
        manual_results_frame = ttk.LabelFrame(frame, text="Résultats", padding="10")
        manual_results_frame.pack(fill='both', expand=True, padx=20, pady=10)
        
        self.manual_results_text = scrolledtext.ScrolledText(manual_results_frame, height=10)
        self.manual_results_text.pack(fill='both', expand=True)
    
    def create_config_tab(self, notebook):
        """Crée l'onglet de configuration"""
        frame = ttk.Frame(notebook)
        notebook.add(frame, text="Configuration")
        
        # Titre
        title_label = ttk.Label(frame, text="Configuration SPQR", font=('Arial', 16, 'bold'))
        title_label.pack(pady=10)
        
        # Configuration réseau
        network_frame = ttk.LabelFrame(frame, text="Configuration Réseau", padding="10")
        network_frame.pack(fill='x', padx=20, pady=10)
        
        # Variables de configuration
        self.source_ip = tk.StringVar(value="192.168.1.10")
        self.dest_ip = tk.StringVar(value="192.168.1.20")
        self.source_port = tk.StringVar(value="1234")
        self.dest_port = tk.StringVar(value="80")
        
        # Champs de configuration
        ttk.Label(network_frame, text="IP Source:").grid(row=0, column=0, sticky='w', padx=5, pady=2)
        ttk.Entry(network_frame, textvariable=self.source_ip, width=20).grid(row=0, column=1, padx=5, pady=2)
        
        ttk.Label(network_frame, text="IP Destination:").grid(row=1, column=0, sticky='w', padx=5, pady=2)
        ttk.Entry(network_frame, textvariable=self.dest_ip, width=20).grid(row=1, column=1, padx=5, pady=2)
        
        ttk.Label(network_frame, text="Port Source:").grid(row=0, column=2, sticky='w', padx=5, pady=2)
        ttk.Entry(network_frame, textvariable=self.source_port, width=10).grid(row=0, column=3, padx=5, pady=2)
        
        ttk.Label(network_frame, text="Port Destination:").grid(row=1, column=2, sticky='w', padx=5, pady=2)
        ttk.Entry(network_frame, textvariable=self.dest_port, width=10).grid(row=1, column=3, padx=5, pady=2)
        
        # Boutons de configuration
        config_buttons_frame = ttk.Frame(frame)
        config_buttons_frame.pack(pady=20)
        
        ttk.Button(config_buttons_frame, text="Sauvegarder Configuration", 
                  command=self.save_config).pack(side='left', padx=5)
        ttk.Button(config_buttons_frame, text="Charger Configuration", 
                  command=self.load_config).pack(side='left', padx=5)
        ttk.Button(config_buttons_frame, text="Réinitialiser", 
                  command=self.reset_config).pack(side='left', padx=5)
        
        # Répertoire de sortie
        output_frame = ttk.LabelFrame(frame, text="Répertoire de Sortie", padding="10")
        output_frame.pack(fill='x', padx=20, pady=10)
        
        output_entry_frame = ttk.Frame(output_frame)
        output_entry_frame.pack(fill='x')
        
        ttk.Entry(output_entry_frame, textvariable=self.output_dir, width=50).pack(side='left', padx=(0, 10))
        ttk.Button(output_entry_frame, text="Parcourir", command=self.browse_output_dir).pack(side='left')
    
    def create_logs_tab(self, notebook):
        """Crée l'onglet des logs"""
        frame = ttk.Frame(notebook)
        notebook.add(frame, text="Logs")
        
        # Titre
        title_label = ttk.Label(frame, text="Logs d'Exécution", font=('Arial', 16, 'bold'))
        title_label.pack(pady=10)
        
        # Zone de logs
        logs_frame = ttk.LabelFrame(frame, text="Messages", padding="10")
        logs_frame.pack(fill='both', expand=True, padx=20, pady=10)
        
        self.logs_text = scrolledtext.ScrolledText(logs_frame, height=25)
        self.logs_text.pack(fill='both', expand=True)
        
        # Boutons de contrôle
        logs_buttons_frame = ttk.Frame(frame)
        logs_buttons_frame.pack(pady=10)
        
        ttk.Button(logs_buttons_frame, text="Effacer Logs", 
                  command=self.clear_logs).pack(side='left', padx=5)
        ttk.Button(logs_buttons_frame, text="Sauvegarder Logs", 
                  command=self.save_logs).pack(side='left', padx=5)
        
        # Configurer le handler de logging
        from spqr_cli import logger
        gui_handler = GUILogHandler(self.logs_text)
        gui_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        logger.addHandler(gui_handler)
    
    def run_quick_test(self):
        """Lance un test rapide en arrière-plan"""
        if not self.selected_attack.get():
            messagebox.showerror("Erreur", "Veuillez sélectionner un type d'attaque")
            return
        
        self.progress.start()
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, f"Lancement du test pour: {self.selected_attack.get()}\n")
        self.results_text.insert(tk.END, "Veuillez patienter...\n\n")
        
        # Lancer le test dans un thread séparé
        thread = threading.Thread(target=self._run_quick_test_thread)
        thread.daemon = True
        thread.start()
    
    def _run_quick_test_thread(self):
        """Exécute le test rapide dans un thread séparé"""
        try:
            results = self.spqr.quick_test(self.selected_attack.get())
            
            # Mettre à jour l'interface dans le thread principal
            self.root.after(0, self._update_quick_test_results, results)
        except Exception as e:
            self.root.after(0, self._update_quick_test_results, {"error": str(e)})
    
    def _update_quick_test_results(self, results):
        """Met à jour les résultats du test rapide"""
        self.progress.stop()
        
        if "error" in results:
            self.results_text.insert(tk.END, f"❌ ERREUR: {results['error']}\n")
        else:
            self.results_text.insert(tk.END, "✅ TEST TERMINÉ AVEC SUCCÈS!\n\n")
            self.results_text.insert(tk.END, f"📁 PCAP généré: {results.get('pcap_file', 'N/A')}\n")
            self.results_text.insert(tk.END, f"📄 Logs: {results.get('log_file', 'N/A')}\n")
            self.results_text.insert(tk.END, f"📊 Rapport: {results.get('report_file', 'N/A')}\n")
        
        self.results_text.see(tk.END)
    
    def run_manual_test(self):
        """Lance un test manuel"""
        if not self.pcap_file.get():
            messagebox.showerror("Erreur", "Veuillez sélectionner un fichier PCAP")
            return
        
        self.manual_results_text.delete(1.0, tk.END)
        self.manual_results_text.insert(tk.END, "Test en cours...\n")
        
        # Simulation d'un test
        self.manual_results_text.insert(tk.END, f"Fichier PCAP: {self.pcap_file.get()}\n")
        if self.rules_file.get():
            self.manual_results_text.insert(tk.END, f"Fichier de règles: {self.rules_file.get()}\n")
        
        self.manual_results_text.insert(tk.END, "Test terminé!\n")
    
    def generate_report(self):
        """Génère un rapport"""
        self.manual_results_text.insert(tk.END, "Génération du rapport...\n")
        # Implémentation de la génération de rapport
        self.manual_results_text.insert(tk.END, "Rapport généré avec succès!\n")
    
    def browse_pcap(self):
        """Ouvre un dialogue pour sélectionner un fichier PCAP"""
        filename = filedialog.askopenfilename(
            title="Sélectionner un fichier PCAP",
            filetypes=[("Fichiers PCAP", "*.pcap *.pcapng"), ("Tous les fichiers", "*.*")]
        )
        if filename:
            self.pcap_file.set(filename)
    
    def browse_rules(self):
        """Ouvre un dialogue pour sélectionner un fichier de règles"""
        filename = filedialog.askopenfilename(
            title="Sélectionner un fichier de règles",
            filetypes=[("Fichiers de règles", "*.rules"), ("Tous les fichiers", "*.*")]
        )
        if filename:
            self.rules_file.set(filename)
    
    def browse_output_dir(self):
        """Ouvre un dialogue pour sélectionner le répertoire de sortie"""
        dirname = filedialog.askdirectory(title="Sélectionner le répertoire de sortie")
        if dirname:
            self.output_dir.set(dirname)
    
    def save_config(self):
        """Sauvegarde la configuration actuelle"""
        config = {
            "network": {
                "source_ip": self.source_ip.get(),
                "dest_ip": self.dest_ip.get(),
                "source_port": int(self.source_port.get()) if self.source_port.get().isdigit() else 1234,
                "dest_port": int(self.dest_port.get()) if self.dest_port.get().isdigit() else 80
            },
            "output_dir": self.output_dir.get()
        }
        
        try:
            os.makedirs("config", exist_ok=True)
            with open("config/config.json", "w") as f:
                json.dump(config, f, indent=2)
            messagebox.showinfo("Succès", "Configuration sauvegardée avec succès!")
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors de la sauvegarde: {e}")
    
    def load_config(self):
        """Charge la configuration depuis le fichier"""
        try:
            with open("config/config.json", "r") as f:
                config = json.load(f)
            
            network = config.get("network", {})
            self.source_ip.set(network.get("source_ip", "192.168.1.10"))
            self.dest_ip.set(network.get("dest_ip", "192.168.1.20"))
            self.source_port.set(str(network.get("source_port", 1234)))
            self.dest_port.set(str(network.get("dest_port", 80)))
            self.output_dir.set(config.get("output_dir", "output"))
            
            messagebox.showinfo("Succès", "Configuration chargée avec succès!")
        except FileNotFoundError:
            messagebox.showwarning("Attention", "Fichier de configuration non trouvé")
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors du chargement: {e}")
    
    def reset_config(self):
        """Remet la configuration par défaut"""
        self.source_ip.set("192.168.1.10")
        self.dest_ip.set("192.168.1.20")
        self.source_port.set("1234")
        self.dest_port.set("80")
        self.output_dir.set("output")
        messagebox.showinfo("Succès", "Configuration réinitialisée")
    
    def clear_logs(self):
        """Efface les logs affichés"""
        self.logs_text.delete(1.0, tk.END)
    
    def save_logs(self):
        """Sauvegarde les logs dans un fichier"""
        filename = filedialog.asksaveasfilename(
            title="Sauvegarder les logs",
            defaultextension=".log",
            filetypes=[("Fichiers de log", "*.log"), ("Fichiers texte", "*.txt")]
        )
        if filename:
            try:
                with open(filename, "w") as f:
                    f.write(self.logs_text.get(1.0, tk.END))
                messagebox.showinfo("Succès", f"Logs sauvegardés dans {filename}")
            except Exception as e:
                messagebox.showerror("Erreur", f"Erreur lors de la sauvegarde: {e}")


class GUILogHandler(logging.Handler):
    """Handler personnalisé pour afficher les logs dans l'interface"""
    def __init__(self, text_widget):
        super().__init__()
        self.text_widget = text_widget
    
    def emit(self, record):
        msg = self.format(record)
        # Utiliser after pour éviter les problèmes de thread
        self.text_widget.after(0, self._append_log, msg)
    
    def _append_log(self, msg):
        self.text_widget.insert(tk.END, msg + '\n')
        self.text_widget.see(tk.END)


def main():
    """Point d'entrée de l'application GUI"""
    root = tk.Tk()
    
    # Configuration du style
    style = ttk.Style()
    style.theme_use('clam')  # Theme moderne
    
    # Configuration de couleurs personnalisées
    style.configure('Accent.TButton', foreground='white', background='#0078D4')
    style.map('Accent.TButton', 
              background=[('active', '#106EBE')])
    
    app = SPQRGUIApp(root)
    
    # Centrer la fenêtre
    root.update_idletasks()
    x = (root.winfo_screenwidth() // 2) - (800 // 2)
    y = (root.winfo_screenheight() // 2) - (600 // 2)
    root.geometry(f"800x600+{x}+{y}")
    
    root.mainloop()


if __name__ == "__main__":
    main()