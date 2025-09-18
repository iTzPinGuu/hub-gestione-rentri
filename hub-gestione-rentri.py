#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RENTRI Manager - Complete Edition with Certificate Management + Gestione FIR
============================================================================
Versione finale completa con:
• Dashboard moderno con CustomTkinter
• Gestione fornitori con ricerca
• Vidimazione FIR automatizzata
• Logo personalizzabile
• Tema scuro/chiaro
• PDF Tools integrati:
  - Crea lettera di consegna
  - Unisci FIR per stamparli
• Credits con link LinkedIn
• NUOVO: Avvio a schermo intero (FIX cross-platform)
• NUOVO: Progress window sempre in primo piano
• NUOVO: Gestione certificato con date e aggiornamento
• NUOVO: Sezione Gestione FIR con tabella e ricerca
• NUOVO: API Annullamento FIR funzionante
"""

import customtkinter as ctk
from tkinter import filedialog, messagebox
import threading
import queue
import time
import json
import base64
import os
import re
import sys
import traceback
import requests
import jwt
import hashlib
import webbrowser
from datetime import datetime, timezone, timedelta
from pathlib import Path
from PIL import Image

# PDF processing imports
import PyPDF2

# Crypto imports
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.serialization import (
    pkcs12, Encoding, PrivateFormat, NoEncryption)
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec

# Set modern theme
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# Constants
CONF_FILE = Path("fornitori.json")
SETTINGS_FILE = Path("settings.json")
BASE_URL = "https://api.rentri.gov.it"
AUDIENCE = "rentrigov.api"
RATE_WINDOW_SEC = 5
RATE_MAX_5S = 90
APP_TITLE = "RENTRI Manager - Complete Edition"

# Modern color palette
COLORS = {
    "primary": "#1f538d",
    "secondary": "#14375e",
    "accent": "#00d4aa",
    "success": "#00b894",
    "warning": "#fdcb6e",
    "error": "#e17055",
    "text": "#2d3436",
    "bg": "#dfe6e9",
    "card": "#ffffff",
    "sidebar": "#2d3436"
}

def dbg(msg: str):
    print(f"[DEBUG] {msg}", file=sys.stderr, flush=True)

def estrai_ragione_sociale(cert: x509.Certificate) -> str:
    for oid in (NameOID.ORGANIZATION_NAME, NameOID.COMMON_NAME):
        try:
            return cert.subject.get_attributes_for_oid(oid)[0].value
        except Exception:
            pass
    return "Sconosciuto"

def estrai_codice_fiscale(cert: x509.Certificate) -> str:
    """Estrae il codice fiscale dal certificato"""
    testo = cert.subject.rfc4514_string()
    
    # Cerca pattern IT-XXXXXXXXXXX o CF:IT-XXXXXXXXXXX
    m = re.search(r"CF:IT-([A-Z0-9]{11,16})", testo)
    if m:
        return m.group(1)
    
    m = re.search(r"IT-([A-Z0-9]{11,16})", testo)
    if m:
        return m.group(1)
    
    # Cerca codice fiscale 16 caratteri alfanumerici
    m = re.search(r"\b([A-Z]{6}[0-9]{2}[A-Z][0-9]{2}[A-Z][0-9]{3}[A-Z])\b", testo)
    if m:
        return m.group(1)
    
    # Cerca codice fiscale 11 cifre numeriche
    m = re.search(r"\b(\d{11})\b", testo)
    if m:
        return m.group(1)
    
    try:
        serial = cert.subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER)[0].value
        m = re.search(r"\b([A-Z0-9]{11,16})\b", serial)
        if m:
            return m.group(1)
    except Exception:
        pass
    
    return ""

def get_certificate_dates(cert_path: str, password: str) -> tuple:
    """Estrae le date di emissione e scadenza dal certificato"""
    try:
        pw = password.encode() if password else None
        pk, cert, _ = pkcs12.load_key_and_certificates(
            Path(cert_path).read_bytes(), pw, backend=default_backend())
        
        # Estrai le date
        not_before = cert.not_valid_before
        not_after = cert.not_valid_after
        
        return not_before, not_after
    except Exception as e:
        dbg(f"Errore estrazione date certificato: {e}")
        return None, None

def format_date(date_obj) -> str:
    """Formatta una data per la visualizzazione"""
    if date_obj is None:
        return "N/A"
    return date_obj.strftime("%d/%m/%Y")

def is_certificate_expired(cert_path: str, password: str) -> bool:
    """Controlla se il certificato è scaduto"""
    try:
        _, not_after = get_certificate_dates(cert_path, password)
        if not_after is None:
            return True
        return datetime.now() > not_after.replace(tzinfo=None)
    except Exception:
        return True

class SettingsManager:
    def __init__(self, path: Path):
        self.path = path
        self.settings = self.load_settings()
        dbg(f"Settings caricati: {self.settings}")
    
    def load_settings(self):
        default_settings = {
            "logo_path": "",
            "logo_text": "RENTRI",
            "theme": "dark"
        }
        
        if self.path.exists():
            try:
                with open(self.path, 'r', encoding='utf-8') as f:
                    loaded = json.load(f)
                    return {**default_settings, **loaded}
            except Exception as e:
                dbg(f"Errore caricamento settings: {e}")
                return default_settings
        return default_settings
    
    def save_settings(self):
        try:
            with open(self.path, 'w', encoding='utf-8') as f:
                json.dump(self.settings, f, indent=2, ensure_ascii=False)
            dbg(f"Settings salvati: {self.settings}")
        except Exception as e:
            dbg(f"Errore salvataggio settings: {e}")
    
    def get(self, key, default=None):
        return self.settings.get(key, default)
    
    def set(self, key, value):
        self.settings[key] = value
        self.save_settings()
        dbg(f"Setting aggiornato: {key} = {value}")

class FornitoriDB:
    def __init__(self, path: Path):
        self.path = path
        self.data = {}
        self.load_data()
        dbg(f"Database fornitori caricato: {len(self.data)} fornitori")

    def load_data(self):
        """Carica i dati dal file JSON"""
        if self.path.exists():
            try:
                with open(self.path, 'r', encoding='utf-8') as f:
                    self.data = json.load(f)
                dbg(f"Dati caricati: {list(self.data.keys())}")
            except Exception as e:
                dbg(f"Errore caricamento fornitori.json: {e}")
                self.data = {}
        else:
            dbg("File fornitori.json non trovato, creato nuovo database")
            self.data = {}

    def save(self):
        try:
            with open(self.path, 'w', encoding='utf-8') as f:
                json.dump(self.data, f, indent=2, ensure_ascii=False)
            dbg("Database fornitori salvato")
        except Exception as e:
            dbg(f"Errore salvataggio fornitori: {e}")

    def elenco(self):
        """Restituisce la lista dei fornitori"""
        fornitori = list(self.data.values())
        dbg(f"Elenco fornitori richiesto: {len(fornitori)} trovati")
        return fornitori

    def search(self, query):
        """Ricerca fornitori per ragione sociale o codice fiscale"""
        if not query:
            return self.elenco()
        
        query = query.lower()
        results = []
        
        for fornitore in self.data.values():
            # Ricerca per ragione sociale
            if query in fornitore.get("ragione_sociale", "").lower():
                results.append(fornitore)
            # Ricerca per codice fiscale
            elif query in fornitore.get("codice_fiscale", "").lower():
                results.append(fornitore)
        
        dbg(f"Ricerca '{query}': {len(results)} risultati")
        return results

    def add(self, p12_path, pwd, rag_soc, codice_fiscale):
        fid = codice_fiscale or rag_soc
        self.data[fid] = {
            "id": fid, "p12": p12_path, "pwd": pwd,
            "ragione_sociale": rag_soc, "codice_fiscale": codice_fiscale
        }
        self.save()
        dbg(f"Fornitore aggiunto: {rag_soc}")

    def get(self, fid):
        return self.data.get(fid)

    def delete(self, fid):
        """Elimina un fornitore"""
        if fid in self.data:
            del self.data[fid]
            self.save()
            dbg(f"Fornitore eliminato: {fid}")
            return True
        return False
    
    def update_certificate(self, fid, new_p12_path, new_password):
        """Aggiorna il certificato di un fornitore"""
        if fid in self.data:
            self.data[fid]["p12"] = new_p12_path
            self.data[fid]["pwd"] = new_password
            self.save()
            dbg(f"Certificato aggiornato per fornitore: {fid}")
            return True
        return False

class RentriREST:
    def __init__(self, cfg: dict):
        self.p12 = cfg["p12"]
        self.pwd = cfg["pwd"]
        self.rag = cfg["ragione_sociale"]
        self.cf = cfg["codice_fiscale"]
        self.req_t = []
        self.jwt_alg = None
        self.pk = None
        self.cert = None
        self._load_p12()

    def _load_p12(self):
        for enc in ('utf-8', 'latin-1', None):
            try:
                pw = self.pwd.encode(enc) if (enc and self.pwd) else None
                pk, cert, _ = pkcs12.load_key_and_certificates(
                    Path(self.p12).read_bytes(), pw, backend=default_backend())
                self.pk, self.cert = pk, cert
                self.jwt_alg = "RS256" if isinstance(pk, rsa.RSAPrivateKey) else "ES256"
                dbg(f"Certificato caricato per CF: {self.cf}")
                return
            except Exception:
                continue
        raise RuntimeError("Certificato P12 non valido")

    def _jwt_auth(self):
        now = datetime.now(timezone.utc)
        hdr = {"alg": self.jwt_alg, "typ": "JWT",
               "x5c": [base64.b64encode(self.cert.public_bytes(Encoding.DER)).decode()]}
        pay = {"aud": AUDIENCE, "iss": self.cf, "sub": self.cf,
               "iat": int(now.timestamp()), "nbf": int(now.timestamp()),
               "exp": int((now+timedelta(minutes=5)).timestamp()),
               "jti": f"auth-{int(now.timestamp()*1000)}"}
        key = self.pk.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode()
        return jwt.encode(pay, key, algorithm=self.jwt_alg, headers=hdr)

    def _jwt_sig(self, body: bytes, ctype: str):
        dig = base64.b64encode(hashlib.sha256(body).digest()).decode()
        now = datetime.now(timezone.utc)
        hdr = {"alg": self.jwt_alg, "typ": "JWT",
               "x5c": [base64.b64encode(self.cert.public_bytes(Encoding.DER)).decode()]}
        pay = {"aud": AUDIENCE, "iss": self.cf, "sub": self.cf,
               "iat": int(now.timestamp()), "nbf": int(now.timestamp()),
               "exp": int((now+timedelta(minutes=5)).timestamp()),
               "jti": f"sig-{int(now.timestamp()*1000)}",
               "signed_headers":[{"digest":f"SHA-256={dig}"},{"content-type":ctype}]}
        key = self.pk.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode()
        return jwt.encode(pay, key, algorithm=self.jwt_alg, headers=hdr), f"SHA-256={dig}"

    def _slot(self):
        t = time.time()
        self.req_t = [x for x in self.req_t if t-x < RATE_WINDOW_SEC]
        if len(self.req_t) >= RATE_MAX_5S:
            time.sleep(RATE_WINDOW_SEC - (t-self.req_t[0]) + 0.05)
        self.req_t.append(time.time())

    def _call(self, meth, url, **kw):
        self._slot()
        r = meth(url, **kw, timeout=30)
        if r.status_code == 429:
            dbg("HTTP 429 – sleep 10s")
            time.sleep(10)
            self._slot()
            r = meth(url, **kw, timeout=30)
        return r

    def blocchi(self):
        h = {"Authorization": f"Bearer {self._jwt_auth()}"}
        r = self._call(requests.get, f"{BASE_URL}/vidimazione-formulari/v1.0",
                       headers=h, params={"identificativo": self.cf})
        return r.json() if r.ok else []

    def formulari(self, blocco):
        h = {"Authorization": f"Bearer {self._jwt_auth()}"}
        r = self._call(requests.get, f"{BASE_URL}/vidimazione-formulari/v1.0/{blocco}",
                       headers=h)
        return r.json() if r.ok else []

    def post_vidima(self, blocco):
        tok = self._jwt_auth()
        sig,dig = self._jwt_sig(b"", "application/json; charset=utf-8")
        h = {"Authorization": f"Bearer {tok}", "Agid-JWT-Signature": sig,
             "Digest": dig, "Content-Type": "application/json; charset=utf-8"}
        r = self._call(requests.post,
                       f"{BASE_URL}/vidimazione-formulari/v1.0/{blocco}",
                       headers=h)
        return r.ok

    def dl_pdf(self, blocco, prog, nfir, outdir):
        h = {"Authorization": f"Bearer {self._jwt_auth()}", "Accept": "application/json"}
        r = self._call(requests.get,
                       f"{BASE_URL}/vidimazione-formulari/v1.0/{blocco}/{prog}/pdf",
                       headers=h)
        if not r.ok:
            dbg(f"Errore download PDF: {r.status_code} - {r.text}")
            return False
        
        try:
            json_resp = r.json()
            b64 = json_resp.get("content", "")
            if not b64:
                dbg("Nessun contenuto base64 nel PDF")
                return False
            
            filename = f"{nfir.replace('/','-').replace(' ','_')}.pdf"
            Path(outdir, filename).write_bytes(base64.b64decode(b64))
            dbg(f"PDF salvato: {filename}")
            return True
        except Exception as e:
            dbg(f"Errore parsing PDF: {e}")
            return False

    def annulla_fir(self, codice_blocco, progressivo):
        """NUOVO: Annulla un FIR specifico utilizzando l'API RENTRI"""
        try:
            tok = self._jwt_auth()
            sig, dig = self._jwt_sig(b"", "application/json; charset=utf-8")
            h = {
                "Authorization": f"Bearer {tok}",
                "Agid-JWT-Signature": sig,
                "Digest": dig,
                "Content-Type": "application/json; charset=utf-8",
                "Accept": "application/problem+json, application/json"
            }
            
            r = self._call(
                requests.put,
                f"{BASE_URL}/vidimazione-formulari/v1.0/{codice_blocco}/{progressivo}/annulla",
                headers=h
            )
            
            dbg(f"Annullamento FIR {codice_blocco}/{progressivo}: {r.status_code}")
            return r.ok, r.status_code, r.text
            
        except Exception as e:
            dbg(f"Errore annullamento FIR {codice_blocco}/{progressivo}: {e}")
            return False, 500, str(e)

    def verify_fir_exists(self, numero_fir):
        """Verifica l'esistenza di un numero FIR"""
        try:
            h = {"Authorization": f"Bearer {self._jwt_auth()}"}
            r = self._call(requests.get, f"{BASE_URL}/vidimazione-formulari/v1.0/verifica/{numero_fir}",
                           headers=h)
            return r.json() if r.ok else None
        except Exception as e:
            dbg(f"Errore verifica FIR {numero_fir}: {e}")
            return None

class Worker(threading.Thread):
    def __init__(self, rest: RentriREST, blocco: str, quanti: int,
                 out_dir: str, q: queue.Queue):
        super().__init__(daemon=True)
        self.rest, self.blocco, self.n, self.out, self.q = rest, blocco, quanti, out_dir, q

    def run(self):
        try:
            self.q.put(("msg", "Snapshot iniziale blocco…"))
            prima = {str(f.get("progressivo")) for f in self.rest.formulari(self.blocco)}

            # POST vidimazioni
            vidimazioni_ok = 0
            for i in range(self.n):
                self.q.put(("msg", f"POST vidimazione {i+1}/{self.n}"))
                ok = self.rest.post_vidima(self.blocco)
                if ok:
                    vidimazioni_ok += 1
                self.q.put(("post_inc", ok))
                time.sleep(2)

            self.q.put(("msg", f"Attesa 8 s per registrazione ({vidimazioni_ok} vidimazioni riuscite)…"))
            time.sleep(8)

            # Recupera nuovi formulari
            after = self.rest.formulari(self.blocco)
            nuovi = [f for f in after if str(f.get("progressivo")) not in prima]
            nuovi.sort(key=lambda x: int(x.get("progressivo", 0)), reverse=True)
            nuovi = nuovi[:vidimazioni_ok]
            self.q.put(("pdf_max", len(nuovi)))

            # Download PDF
            pdf_ok = 0
            for i, f in enumerate(nuovi):
                prog = f.get("progressivo")
                nfir = f.get("numero_fir", f"{prog}")
                self.q.put(("msg", f"Scarico PDF {i+1}/{len(nuovi)} – {nfir}"))
                ok = self.rest.dl_pdf(self.blocco, prog, nfir, self.out)
                if ok:
                    pdf_ok += 1
                self.q.put(("pdf_inc", ok))
                time.sleep(1)

            self.q.put(("done", f"Completato: {vidimazioni_ok} vidimazioni, {pdf_ok} PDF scaricati"))
        except Exception as e:
            traceback.print_exc()
            self.q.put(("err", str(e)))

# PDF Tools Workers
class PDFDeliveryWorker(threading.Thread):
    """Worker per generare la stringa serie separata da |"""
    def __init__(self, paths, q):
        super().__init__(daemon=True)
        self.paths = paths
        self.q = q
    
    def run(self):
        try:
            names = [Path(p).stem for p in self.paths]
            result = "|".join(names)
            self.q.put(("done", result, len(names)))
        except Exception as e:
            self.q.put(("err", str(e)))

class PDFMergeWorker(threading.Thread):
    """Worker per processare e unire PDF"""
    def __init__(self, paths, q):
        super().__init__(daemon=True)
        self.paths = paths
        self.q = q
        self.tmp_files = []
    
    def estrai_numero(self, filename):
        """Estrae il numero dal nome del file con regex migliorata"""
        match = re.search(r'\b(\d{6})\b', filename)
        if match:
            return int(match.group(1))
        else:
            match = re.search(r'\d+', filename)
            return int(match.group(0)) if match else 0
    
    def run(self):
        try:
            total = len(self.paths)
            output_dir = Path(self.paths[0]).parent
            
            # Step 1: Process PDFs
            for i, path in enumerate(self.paths):
                progress = (i / total) * 50  # Prima metà
                self.q.put(("status", f"Elaborazione {i+1}/{total}: {Path(path).name}", progress))
                
                with open(path, 'rb') as file:
                    pdf = PyPDF2.PdfReader(file)
                    if len(pdf.pages) < 2:
                        continue
                    
                    output = PyPDF2.PdfWriter()
                    # Duplica le prime due pagine due volte
                    for _ in range(2):
                        output.add_page(pdf.pages[0])
                        output.add_page(pdf.pages[1])
                    
                    original_name = Path(path).stem
                    output_path = output_dir / f"{original_name}_processed.pdf"
                    
                    with open(output_path, 'wb') as output_file:
                        output.write(output_file)
                    
                    self.tmp_files.append(output_path)
            
            # Step 2: Sort and merge
            self.q.put(("status", "Ordinamento file...", 60))
            self.tmp_files.sort(key=lambda x: self.estrai_numero(x.stem))
            
            self.q.put(("status", "Unione PDF in corso...", 70))
            merger = PyPDF2.PdfMerger()
            for pdf_file in self.tmp_files:
                merger.append(str(pdf_file))
            
            merged_path = output_dir / "merged_formulari.pdf"
            merger.write(str(merged_path))
            merger.close()
            
            # Step 3: Cleanup
            self.q.put(("status", "Pulizia file temporanei...", 90))
            for pdf_file in self.tmp_files:
                os.unlink(str(pdf_file))
            
            self.q.put(("done", f"PDF unito creato con successo!\nSalvato in: {merged_path}", 100))
            
        except Exception as e:
            self.q.put(("err", str(e)))

class ModernProgressWindow:
    def __init__(self, parent, title, fornitore_info):
        self.window = ctk.CTkToplevel(parent)
        self.window.title(title)
        self.window.geometry("600x400")
        self.window.resizable(False, False)
        
        # NUOVO: Assicura che la finestra si apra in primo piano
        self.window.lift()
        self.window.focus_force()
        self.window.grab_set()  # Rende la finestra modale
        
        # Centra la finestra sullo schermo
        self.window.update_idletasks()
        width = self.window.winfo_width()
        height = self.window.winfo_height()
        x = (self.window.winfo_screenwidth() // 2) - (width // 2)
        y = (self.window.winfo_screenheight() // 2) - (height // 2)
        self.window.geometry(f"{width}x{height}+{x}+{y}")
        
        # Mantieni sempre in primo piano
        self.window.attributes("-topmost", True)
        
        # Header
        header_frame = ctk.CTkFrame(self.window, height=80, fg_color=COLORS["primary"])
        header_frame.pack(fill="x", padx=0, pady=0)
        header_frame.pack_propagate(False)
        
        title_label = ctk.CTkLabel(
            header_frame, 
            text=title, 
            font=ctk.CTkFont(size=24, weight="bold"),
            text_color="white"
        )
        title_label.pack(pady=20)
        
        # Content frame
        content_frame = ctk.CTkFrame(self.window, fg_color="transparent")
        content_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Fornitore info
        self.info_label = ctk.CTkLabel(
            content_frame,
            text=fornitore_info,
            font=ctk.CTkFont(size=14),
            anchor="w",
            justify="left"
        )
        self.info_label.pack(pady=(0, 20), fill="x")
        
        # Status label
        self.status_label = ctk.CTkLabel(
            content_frame,
            text="Preparazione...",
            font=ctk.CTkFont(size=16, weight="bold"),
            anchor="w"
        )
        self.status_label.pack(pady=(0, 10), fill="x")
        
        # Progress bars frame
        progress_frame = ctk.CTkFrame(content_frame, fg_color="transparent")
        progress_frame.pack(fill="x", pady=(0, 20))
        
        # Vidimazioni progress
        vidim_label = ctk.CTkLabel(progress_frame, text="Vidimazioni:", font=ctk.CTkFont(size=14))
        vidim_label.pack(anchor="w")
        
        self.vidim_progress = ctk.CTkProgressBar(progress_frame, height=20)
        self.vidim_progress.pack(fill="x", pady=(5, 15))
        self.vidim_progress.set(0)
        
        # PDF progress
        pdf_label = ctk.CTkLabel(progress_frame, text="Download PDF:", font=ctk.CTkFont(size=14))
        pdf_label.pack(anchor="w")
        
        self.pdf_progress = ctk.CTkProgressBar(progress_frame, height=20)
        self.pdf_progress.pack(fill="x", pady=(5, 0))
        self.pdf_progress.set(0)
        
        # Stats frame
        stats_frame = ctk.CTkFrame(content_frame)
        stats_frame.pack(fill="x", pady=(0, 20))
        
        self.stats_label = ctk.CTkLabel(
            stats_frame,
            text="Statistiche operazione",
            font=ctk.CTkFont(size=14, weight="bold")
        )
        self.stats_label.pack(pady=10)
        
        self.vidim_max = 0
        self.pdf_max = 0
        
    def update_status(self, message):
        self.status_label.configure(text=message)
        self.window.update()
        
    def update_vidim_progress(self, value=None):
        if value is not None:
            self.vidim_progress.set(value / self.vidim_max if self.vidim_max > 0 else 0)
        self.window.update()
        
    def update_pdf_progress(self, value=None):
        if value is not None:
            self.pdf_progress.set(value / self.pdf_max if self.pdf_max > 0 else 0)
        self.window.update()
        
    def set_vidim_max(self, max_val):
        self.vidim_max = max_val
        
    def set_pdf_max(self, max_val):
        self.pdf_max = max_val
        
    def close(self):
        self.window.grab_release()  # Rilascia il grab modale
        self.window.destroy()

class DashboardCard:
    def __init__(self, parent, title, value, color=None):
        self.frame = ctk.CTkFrame(parent, height=120, fg_color=color or COLORS["card"])
        self.frame.pack_propagate(False)
        
        # Title
        title_label = ctk.CTkLabel(
            self.frame,
            text=title,
            font=ctk.CTkFont(size=14, weight="bold"),
            anchor="w"
        )
        title_label.pack(pady=(15, 5), padx=20, fill="x")
        
        # Value
        self.value_label = ctk.CTkLabel(
            self.frame,
            text=str(value),
            font=ctk.CTkFont(size=32, weight="bold"),
            text_color=COLORS["primary"]
        )
        self.value_label.pack(pady=(0, 15), padx=20)
        
    def update_value(self, value):
        self.value_label.configure(text=str(value))

class CertificateCard:
    """Card speciale per mostrare informazioni del certificato"""
    def __init__(self, parent, title, cert_info, update_callback):
        self.frame = ctk.CTkFrame(parent, height=120, fg_color=COLORS["card"])
        self.frame.pack_propagate(False)
        self.update_callback = update_callback
        
        # Title
        title_label = ctk.CTkLabel(
            self.frame,
            text=title,
            font=ctk.CTkFont(size=14, weight="bold"),
            anchor="w"
        )
        title_label.pack(pady=(10, 5), padx=20, fill="x")
        
        # Certificate info
        if cert_info:
            info_text = f"Emesso: {cert_info['issued']}\nScade: {cert_info['expires']}"
            color = COLORS["error"] if cert_info['expired'] else COLORS["primary"]
        else:
            info_text = "Certificato non caricato"
            color = COLORS["error"]
            
        self.info_label = ctk.CTkLabel(
            self.frame,
            text=info_text,
            font=ctk.CTkFont(size=12),
            text_color=color,
            anchor="w",
            justify="left"
        )
        self.info_label.pack(pady=(0, 5), padx=20, fill="x")
        
        # Update button
        update_btn = ctk.CTkButton(
            self.frame,
            text="🔄 Aggiorna",
            command=self.update_certificate,
            height=25,
            width=100,
            font=ctk.CTkFont(size=12)
        )
        update_btn.pack(pady=(0, 10), padx=20, anchor="e")
        
    def update_certificate(self):
        if self.update_callback:
            self.update_callback()

class ClickableLabel(ctk.CTkLabel):
    def __init__(self, master, text, url, **kwargs):
        super().__init__(master, text=text, **kwargs)
        self.url = url
        self.bind("<Button-1>", self.on_click)
        self.bind("<Enter>", self.on_enter)
        self.bind("<Leave>", self.on_leave)
        
    def on_click(self, event):
        webbrowser.open(self.url)
        
    def on_enter(self, event):
        self.configure(text_color=COLORS["accent"])
        
    def on_leave(self, event):
        self.configure(text_color="white")

# PDF Tools Views
class PDFDeliveryView(ctk.CTkFrame):
    def __init__(self, parent):
        super().__init__(parent)
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)
        
        # Title
        title = ctk.CTkLabel(
            self,
            text="✉️ Crea lettera di consegna",
            font=ctk.CTkFont(size=26, weight="bold")
        )
        title.grid(row=0, column=0, sticky="w", pady=(0, 20))
        
        # Description
        desc = ctk.CTkLabel(
            self,
            text="Seleziona i file PDF per generare la stringa serie separata da | per le lettere di consegna",
            font=ctk.CTkFont(size=14),
            text_color="gray"
        )
        desc.grid(row=1, column=0, sticky="w", pady=(0, 15))
        
        # Button frame
        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.grid(row=2, column=0, sticky="ew", pady=(0, 15))
        
        btn = ctk.CTkButton(
            btn_frame,
            text="📂 Seleziona PDF",
            command=self.choose_files,
            height=40,
            font=ctk.CTkFont(size=14, weight="bold")
        )
        btn.pack(side="left")
        
        # Output textbox
        self.textbox = ctk.CTkTextbox(self, height=200)
        self.textbox.grid(row=3, column=0, sticky="nsew", pady=(15, 0))
        
        # Status
        self.status = ctk.CTkLabel(self, text="Pronto", text_color="gray")
        self.status.grid(row=4, column=0, sticky="w", pady=(10, 0))
        
        # Queue for worker communication
        self.q = queue.Queue()
        self.after_id = None
    
    def choose_files(self):
        paths = filedialog.askopenfilenames(
            title="Seleziona file PDF",
            filetypes=[("PDF Files", "*.pdf")]
        )
        if not paths:
            return
        
        self.status.configure(text="Generazione serie in corso...")
        self.textbox.delete("1.0", "end")
        
        PDFDeliveryWorker(paths, self.q).start()
        self.poll_queue()
    
    def poll_queue(self):
        try:
            while True:
                message = self.q.get_nowait()
                typ = message[0]
                
                if typ == "done":
                    serie, count = message[1], message[2]
                    self.textbox.insert("end", serie)
                    self.status.configure(text=f"Serie creata con {count} file")
                elif typ == "err":
                    messagebox.showerror("Errore", message[1])
                    self.status.configure(text="Errore durante la generazione")
                
                self.q.task_done()
        except queue.Empty:
            self.after_id = self.after(100, self.poll_queue)

class PDFMergeView(ctk.CTkFrame):
    def __init__(self, parent):
        super().__init__(parent)
        self.grid_columnconfigure(0, weight=1)
        
        # Title
        title = ctk.CTkLabel(
            self,
            text="🗜️ Unisci FIR per stamparli",
            font=ctk.CTkFont(size=26, weight="bold")
        )
        title.grid(row=0, column=0, sticky="w", pady=(0, 20))
        
        # Description
        desc = ctk.CTkLabel(
            self,
            text="Seleziona i file FIR da processare. Ogni PDF verrà duplicato (prime 2 pagine × 2) e unito in un singolo file",
            font=ctk.CTkFont(size=14),
            text_color="gray",
            wraplength=800
        )
        desc.grid(row=1, column=0, sticky="w", pady=(0, 15))
        
        # Button frame
        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.grid(row=2, column=0, sticky="ew", pady=(0, 15))
        
        btn = ctk.CTkButton(
            btn_frame,
            text="📂 Seleziona PDF",
            command=self.choose_files,
            height=40,
            font=ctk.CTkFont(size=14, weight="bold")
        )
        btn.pack(side="left")
        
        # Progress section
        progress_frame = ctk.CTkFrame(self)
        progress_frame.grid(row=3, column=0, sticky="ew", pady=(15, 0), padx=0)
        
        progress_label = ctk.CTkLabel(
            progress_frame,
            text="Progresso elaborazione:",
            font=ctk.CTkFont(size=14, weight="bold")
        )
        progress_label.pack(pady=(20, 10), padx=20, anchor="w")
        
        self.progress = ctk.CTkProgressBar(progress_frame, height=20)
        self.progress.pack(fill="x", padx=20, pady=(0, 10))
        self.progress.set(0)
        
        self.status = ctk.CTkLabel(
            progress_frame,
            text="Pronto",
            font=ctk.CTkFont(size=12),
            text_color="gray"
        )
        self.status.pack(pady=(0, 20), padx=20, anchor="w")
        
        # Queue for worker communication
        self.q = queue.Queue()
        self.after_id = None
    
    def choose_files(self):
        paths = filedialog.askopenfilenames(
            title="Seleziona file PDF da unire",
            filetypes=[("PDF Files", "*.pdf")]
        )
        if not paths:
            return
        
        self.progress.set(0)
        self.status.configure(text="Avvio elaborazione...")
        
        PDFMergeWorker(paths, self.q).start()
        self.poll_queue()
    
    def poll_queue(self):
        try:
            while True:
                message = self.q.get_nowait()
                typ = message[0]
                
                if typ == "status":
                    msg, progress = message[1], message[2]
                    self.status.configure(text=msg)
                    self.progress.set(progress / 100)
                elif typ == "done":
                    msg, progress = message[1], message[2]
                    self.progress.set(progress / 100)
                    messagebox.showinfo("Completato", msg)
                    self.status.configure(text="Elaborazione completata")
                elif typ == "err":
                    messagebox.showerror("Errore", message[1])
                    self.status.configure(text="Errore durante l'elaborazione")
                
                self.q.task_done()
        except queue.Empty:
            self.after_id = self.after(100, self.poll_queue)

# SEZIONE GESTIONE FIR CON API ANNULLAMENTO FUNZIONANTE
class FIRAnnullaView(ctk.CTkFrame):
    def __init__(self, parent, rest_client=None):
        super().__init__(parent)
        self.rest = rest_client
        self.current_fir_list = []
        self.filtered_fir_list = []
        self.cancelled_fir_cache = {}  # NUOVA riga: cache locale FIR annullati {(blocco, progressivo): True}
        ...
        # (il resto del tuo __init__)

    def determine_fir_status(self, fir, codice_blocco=None):
        """Determina lo stato corretto di un FIR"""
        if codice_blocco is None:
            codice_blocco = fir.get('codice_blocco', '')
    
        progressivo = str(fir.get('progressivo', ''))
        cache_key = (codice_blocco, progressivo)
    
        # 1. PRIMA controlla se è nella cache degli annullati
        if cache_key in self.cancelled_fir_cache:
            return "Annullato"
    
        # 2. Controlla lo stato dall'API
        api_state = (fir.get('stato') or '').strip().lower()
        if api_state == "annullato":
            return "Annullato"
    
        # 3. Controlla il flag annullato
        if fir.get('is_annullato', False) is True:
            return "Annullato"
    
        # 4. SOLO SE NON È ANNULLATO, controlla se è vidimato
        # Un FIR annullato può ancora avere numero_fir, ma deve rimanere "Annullato"
        if fir.get('numero_fir') and fir.get('numero_fir') != 'N/A':
            return "Vidimato"
    
        # 5. Altrimenti è disponibile
        return "Vidimato"

    def _set_local_status(self, codice_blocco, progressivo, stato):
        """Aggiorna lo stato locale di un FIR"""
        cache_key = (codice_blocco, str(progressivo))
    
        if stato == "Annullato":
            self.cancelled_fir_cache[cache_key] = True
        elif cache_key in self.cancelled_fir_cache and stato != "Annullato":
            del self.cancelled_fir_cache[cache_key]
    
    # Aggiorna lo stato in tutte le liste
        for lst in (self.current_fir_list, self.filtered_fir_list):
            for f in lst:
                if (f['codice_blocco'] == codice_blocco and 
                    str(f['progressivo']) == str(progressivo)):
                    f['stato'] = stato


    def load_fir_data(self):
        # ... (inizio come prima)
        try:
            blocchi = self.rest.blocchi()
            block_values = ["Tutti i blocchi"] + [f"{b['codice_blocco']}" for b in blocchi]
            self.block_filter.configure(values=block_values)
            for blocco in blocchi:
                try:
                    formulari = self.rest.formulari(blocco['codice_blocco'])
                    for fir in formulari:
                        stato = self.determine_fir_status(fir, blocco['codice_blocco'])
                        fir_data = {
                            'numero_fir': fir.get('numero_fir', 'N/A'),
                            'codice_blocco': blocco['codice_blocco'],
                            'progressivo': fir.get('progressivo', 'N/A'),
                            'data_vidimazione': fir.get('data_vidimazione', 'N/A'),
                            'stato': stato,
                            'selected': False,
                            'raw_data': fir
                        }
                        self.current_fir_list.append(fir_data)
                except Exception as e:
                    print(f"Errore caricamento FIR per blocco {blocco['codice_blocco']}: {e}")
            self.filtered_fir_list = self.current_fir_list.copy()
            self.update_fir_display()
            self.results_label.configure(text=f"✅ Caricati {len(self.current_fir_list)} FIR da {len(blocchi)} blocchi")
        except Exception as e:
            self.results_label.configure(text=f"❌ Errore caricamento: {str(e)}")

    def execute_cancellation_worker(self, fir_list):
        def annulla_worker():
            for fir in fir_list:
                success, status_code, response_text = self.rest.annulla_fir(
                    fir['codice_blocco'], fir['progressivo']
                )
                if success:
                    cb, pr = fir['codice_blocco'], str(fir['progressivo'])
                    cache_key = (cb, pr)
                    def update_cache_and_display():
                        self.cancelled_fir_cache[cache_key] = True
                        self._set_local_status(cb, pr, "Annullato")
                        self.update_fir_display()
                    self.after(0, update_cache_and_display)
                time.sleep(0.5)
            self.after(0, lambda: self.finalize_cancellation(...))
        threading.Thread(target=annulla_worker, daemon=True).start()
    """View per la gestione e ricerca FIR con API annullamento funzionante"""
    def __init__(self, parent, rest_client=None):
        super().__init__(parent)
        self.rest = rest_client
        self.current_fir_list = []
        self.filtered_fir_list = []
        self.cancelled_fir_cache = {}  # {(codice_blocco, progressivo): True}
        
        # Configure grid
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)
        
        # Create UI
        self.create_header()
        self.create_search_section()
        self.create_fir_table()
        self.create_action_buttons()
        
        # Load FIR data if REST client available
        if self.rest:
            self.load_fir_data()
    
    def create_header(self):
        """Crea la sezione header"""
        header_frame = ctk.CTkFrame(self, height=80, fg_color="transparent")
        header_frame.grid(row=0, column=0, sticky="ew", pady=(0, 20))
        header_frame.grid_columnconfigure(0, weight=1)
        header_frame.grid_propagate(False)
        
        title_label = ctk.CTkLabel(
            header_frame,
            text="🗑️ Gestione e Ricerca FIR",
            font=ctk.CTkFont(size=32, weight="bold"),
            anchor="w"
        )
        title_label.grid(row=0, column=0, sticky="w", pady=20)
        
        refresh_btn = ctk.CTkButton(
            header_frame,
            text="🔄 Aggiorna Lista",
            command=self.load_fir_data,
            height=40,
            font=ctk.CTkFont(size=14, weight="bold")
        )
        refresh_btn.grid(row=0, column=1, pady=20, padx=(20, 0))
    
    def create_search_section(self):
        """Crea la sezione di ricerca"""
        search_frame = ctk.CTkFrame(self)
        search_frame.grid(row=1, column=0, sticky="ew", pady=(0, 20))
        search_frame.grid_columnconfigure(1, weight=1)
        
        # Search label
        search_label = ctk.CTkLabel(
            search_frame,
            text="Ricerca FIR:",
            font=ctk.CTkFont(size=16, weight="bold")
        )
        search_label.grid(row=0, column=0, padx=(20, 10), pady=20, sticky="w")
        
        # Search entry
        self.search_entry = ctk.CTkEntry(
            search_frame,
            placeholder_text="🔍 Inserisci numero FIR, codice blocco, o parte del numero...",
            height=40,
            font=ctk.CTkFont(size=14)
        )
        self.search_entry.grid(row=0, column=1, sticky="ew", padx=(0, 10), pady=20)
        self.search_entry.bind("<KeyRelease>", self.on_search_change)
        
        # Clear search button
        clear_btn = ctk.CTkButton(
            search_frame,
            text="✕",
            command=self.clear_search,
            width=40,
            height=40,
            fg_color="transparent",
            hover_color="#e17055",
            font=ctk.CTkFont(size=16, weight="bold")
        )
        clear_btn.grid(row=0, column=2, padx=(0, 20), pady=20)
        
        # Filter options
        filter_frame = ctk.CTkFrame(search_frame, fg_color="transparent")
        filter_frame.grid(row=1, column=0, columnspan=3, sticky="ew", padx=20, pady=(0, 20))
        
        # Block filter
        block_label = ctk.CTkLabel(filter_frame, text="Blocco:", font=ctk.CTkFont(size=14))
        block_label.grid(row=0, column=0, padx=(0, 10), sticky="w")
        
        self.block_filter = ctk.CTkComboBox(
            filter_frame,
            values=["Tutti i blocchi"],
            command=self.on_filter_change,
            width=200
        )
        self.block_filter.grid(row=0, column=1, padx=(0, 20))
        
        # Status filter
        status_label = ctk.CTkLabel(filter_frame, text="Stato:", font=ctk.CTkFont(size=14))
        status_label.grid(row=0, column=2, padx=(0, 10), sticky="w")
        
        self.status_filter = ctk.CTkComboBox(
            filter_frame,
            values=["Tutti", "Vidimato", "Annullato"],
            command=self.on_filter_change,
            width=150
        )
        self.status_filter.grid(row=0, column=3, padx=(0, 20))
    
    def create_fir_table(self):
        """Crea la tabella dei FIR"""
        # Table frame
        table_frame = ctk.CTkFrame(self)
        table_frame.grid(row=2, column=0, sticky="nsew", pady=(0, 20))
        table_frame.grid_columnconfigure(0, weight=1)
        table_frame.grid_rowconfigure(1, weight=1)
        
        # Table header
        header_frame = ctk.CTkFrame(table_frame, height=50)
        header_frame.grid(row=0, column=0, sticky="ew", padx=20, pady=(20, 10))
        header_frame.grid_propagate(False)
        
        # Column headers
        headers = ["Sel", "Numero FIR", "Blocco", "Progressivo", "Data Vidimazione", "Stato", "Azioni"]
        col_weights = [1, 3, 2, 1, 2, 1, 2]
        
        for i, (header, weight) in enumerate(zip(headers, col_weights)):
            header_frame.grid_columnconfigure(i, weight=weight)
            label = ctk.CTkLabel(
                header_frame,
                text=header,
                font=ctk.CTkFont(size=14, weight="bold"),
                anchor="center"
            )
            label.grid(row=0, column=i, padx=5, pady=10, sticky="ew")
        
        # Scrollable frame for FIR rows
        self.fir_scroll_frame = ctk.CTkScrollableFrame(
            table_frame,
            label_text="Formulari FIR"
        )
        self.fir_scroll_frame.grid(row=1, column=0, sticky="nsew", padx=20, pady=(0, 20))
        self.fir_scroll_frame.grid_columnconfigure(0, weight=1)
        
        # Results info
        self.results_label = ctk.CTkLabel(
            table_frame,
            text="Caricamento FIR in corso...",
            font=ctk.CTkFont(size=12),
            text_color="gray"
        )
        self.results_label.grid(row=2, column=0, padx=20, pady=(0, 10), sticky="w")
    
    def create_action_buttons(self):
        """Crea i pulsanti di azione"""
        action_frame = ctk.CTkFrame(self, fg_color="transparent")
        action_frame.grid(row=3, column=0, sticky="ew", pady=(10, 0))
        
        # Select all/none buttons
        select_all_btn = ctk.CTkButton(
            action_frame,
            text="☑️ Seleziona Tutti",
            command=self.select_all_fir,
            height=40,
            width=150,
            font=ctk.CTkFont(size=14)
        )
        select_all_btn.pack(side="left", padx=(0, 10))
        
        select_none_btn = ctk.CTkButton(
            action_frame,
            text="☐ Deseleziona Tutti",
            command=self.select_none_fir,
            height=40,
            width=150,
            font=ctk.CTkFont(size=14)
        )
        select_none_btn.pack(side="left", padx=(0, 20))
        
        # Action buttons
        download_btn = ctk.CTkButton(
            action_frame,
            text="📥 Scarica PDF Selezionati",
            command=self.download_selected_fir,
            height=40,
            width=200,
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color="#00b894",
            hover_color="#00d4aa"
        )
        download_btn.pack(side="left", padx=(0, 10))
        
        # NUOVO: Pulsante annullamento ABILITATO con API funzionante
        self.cancel_btn = ctk.CTkButton(
            action_frame,
            text="🗑️ Annulla Selezionati",
            command=self.annulla_selected_fir,  # NUOVO metodo
            height=40,
            width=180,
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color="#e17055",
            hover_color="#d63031",
            state="normal"  # ABILITATO!
        )
        self.cancel_btn.pack(side="left", padx=(0, 10))
        
        # Info button
        info_btn = ctk.CTkButton(
            action_frame,
            text="ℹ️ Info API",
            command=self.show_api_info,
            height=40,
            width=100,
            font=ctk.CTkFont(size=14)
        )
        info_btn.pack(side="right")
    
    def load_fir_data(self):
        """Carica i dati FIR da tutti i blocchi"""
        if not self.rest:
            self.results_label.configure(text="⚠️ Nessun fornitore selezionato")
            return
        
        self.results_label.configure(text="🔄 Caricamento FIR in corso...")
        self.current_fir_list = []
        
        try:
            # Get all blocks
            blocchi = self.rest.blocchi()
            block_values = ["Tutti i blocchi"] + [f"{b['codice_blocco']}" for b in blocchi]
            self.block_filter.configure(values=block_values)
            
            # Get FIR from each block
            for blocco in blocchi:
                try:
                    formulari = self.rest.formulari(blocco['codice_blocco'])
                    for fir in formulari:
                        fir_data = {
                            'numero_fir': fir.get('numero_fir', 'N/A'),
                            'codice_blocco': blocco['codice_blocco'],
                            'progressivo': fir.get('progressivo', 'N/A'),
                            'data_vidimazione': fir.get('data_vidimazione', 'N/A'),
                            'stato': self.determine_fir_status(fir),
                            'selected': False,
                            'raw_data': fir
                        }
                        self.current_fir_list.append(fir_data)
                except Exception as e:
                    print(f"Errore caricamento FIR per blocco {blocco['codice_blocco']}: {e}")
            
            # Update display
            self.filtered_fir_list = self.current_fir_list.copy()
            self.update_fir_display()
            self.results_label.configure(text=f"✅ Caricati {len(self.current_fir_list)} FIR da {len(blocchi)} blocchi")
            
        except Exception as e:
            self.results_label.configure(text=f"❌ Errore caricamento: {str(e)}")

    def on_search_change(self, event):
        """Gestisce la ricerca in tempo reale"""
        query = self.search_entry.get().lower().strip()
        self.apply_filters()
    
    def on_filter_change(self, value=None):
        """Gestisce i cambi di filtro"""
        self.apply_filters()
    
    def apply_filters(self):
        """Applica tutti i filtri attivi"""
        query = self.search_entry.get().lower().strip()
        block_filter = self.block_filter.get()
        status_filter = self.status_filter.get()
        
        self.filtered_fir_list = []
        
        for fir in self.current_fir_list:
            # Text search filter
            if query:
                searchable_text = f"{fir['numero_fir']} {fir['codice_blocco']} {fir['progressivo']}".lower()
                if query not in searchable_text:
                    continue
            
            # Block filter
            if block_filter != "Tutti i blocchi":
                if fir['codice_blocco'] != block_filter:
                    continue
            
            # Status filter
            if status_filter != "Tutti":
                if fir['stato'] != status_filter:
                    continue
            
            self.filtered_fir_list.append(fir)
        
        self.update_fir_display()
        self.update_results_label()
        self.update_selection_count()
    
    def update_fir_display(self):
        """Aggiorna la visualizzazione dei FIR"""
        # Clear existing rows
        for widget in self.fir_scroll_frame.winfo_children():
            widget.destroy()
        
        if not self.filtered_fir_list:
            no_results_label = ctk.CTkLabel(
                self.fir_scroll_frame,
                text="🔍 Nessun FIR trovato con i criteri attuali",
                font=ctk.CTkFont(size=16),
                text_color="gray"
            )
            no_results_label.pack(pady=50)
            return
        
        # Create rows for each FIR
        for i, fir in enumerate(self.filtered_fir_list):
            self.create_fir_row(fir, i)
    
    def create_fir_row(self, fir, row_index):
        """Crea una riga per un FIR"""
        row_frame = ctk.CTkFrame(self.fir_scroll_frame, height=60)
        row_frame.pack(fill="x", padx=10, pady=2)
        row_frame.pack_propagate(False)
        
        # Configure grid
        col_weights = [1, 3, 2, 1, 2, 1, 2]
        for i, weight in enumerate(col_weights):
            row_frame.grid_columnconfigure(i, weight=weight)
        
        # Checkbox
        checkbox_var = ctk.BooleanVar(value=fir['selected'])
        checkbox = ctk.CTkCheckBox(
            row_frame,
            text="",
            variable=checkbox_var,
            command=lambda f=fir, v=checkbox_var: self.on_fir_select(f, v.get())
        )
        checkbox.grid(row=0, column=0, padx=5, pady=15)
        
        # Numero FIR
        fir_label = ctk.CTkLabel(
            row_frame,
            text=fir['numero_fir'],
            font=ctk.CTkFont(size=14, weight="bold"),
            anchor="center"
        )
        fir_label.grid(row=0, column=1, padx=5, pady=15, sticky="ew")
        
        # Blocco
        block_label = ctk.CTkLabel(
            row_frame,
            text=fir['codice_blocco'],
            font=ctk.CTkFont(size=12),
            anchor="center"
        )
        block_label.grid(row=0, column=2, padx=5, pady=15, sticky="ew")
        
        # Progressivo
        prog_label = ctk.CTkLabel(
            row_frame,
            text=str(fir['progressivo']),
            font=ctk.CTkFont(size=12),
            anchor="center"
        )
        prog_label.grid(row=0, column=3, padx=5, pady=15, sticky="ew")
        
        # Data vidimazione
        date_label = ctk.CTkLabel(
            row_frame,
            text=fir['data_vidimazione'],
            font=ctk.CTkFont(size=12),
            anchor="center"
        )
        date_label.grid(row=0, column=4, padx=5, pady=15, sticky="ew")
        
        # Stato con colori
        status_colors = {
            "Vidimato": "#00b894",
            "Annullato": "#e17055"
        }
        status_color = status_colors.get(fir['stato'], "#636e72")
        status_label = ctk.CTkLabel(
            row_frame,
            text=fir['stato'],
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=status_color,
            anchor="center"
        )
        status_label.grid(row=0, column=5, padx=5, pady=15, sticky="ew")
        
        # Action buttons
        action_frame = ctk.CTkFrame(row_frame, fg_color="transparent")
        action_frame.grid(row=0, column=6, padx=5, pady=10, sticky="ew")
        
        # Download button
        download_btn = ctk.CTkButton(
            action_frame,
            text="📥",
            command=lambda f=fir: self.download_single_fir(f),
            width=30,
            height=30,
            font=ctk.CTkFont(size=12)
        )
        download_btn.pack(side="left", padx=2)
        
        # Details button
        details_btn = ctk.CTkButton(
            action_frame,
            text="👁️",
            command=lambda f=fir: self.show_fir_details(f),
            width=30,
            height=30,
            font=ctk.CTkFont(size=12)
        )
        details_btn.pack(side="left", padx=2)
    
    def on_fir_select(self, fir, selected):
        """Gestisce la selezione di un FIR"""
        fir['selected'] = selected
        self.update_selection_count()
    
    def update_selection_count(self):
        """NUOVO: Aggiorna il conteggio delle selezioni e abilita il pulsante"""
        selected_count = sum(1 for fir in self.filtered_fir_list if fir['selected'])
        if selected_count > 0:
            self.cancel_btn.configure(
                text=f"🗑️ Annulla Selezionati ({selected_count})",
                state="normal"
            )
        else:
            self.cancel_btn.configure(
                text="🗑️ Annulla Selezionati",
                state="normal"  # Mantieni sempre abilitato
            )
    
    def update_results_label(self):
        """Aggiorna il label dei risultati"""
        total = len(self.current_fir_list)
        filtered = len(self.filtered_fir_list)
        
        if total == filtered:
            self.results_label.configure(text=f"📊 Visualizzati {total} FIR")
        else:
            self.results_label.configure(text=f"📊 Visualizzati {filtered} di {total} FIR")
    
    def clear_search(self):
        """Cancella la ricerca"""
        self.search_entry.delete(0, "end")
        self.block_filter.set("Tutti i blocchi")
        self.status_filter.set("Tutti")
        self.apply_filters()
    
    def select_all_fir(self):
        """Seleziona tutti i FIR visibili"""
        for fir in self.filtered_fir_list:
            fir['selected'] = True
        self.update_fir_display()
        self.update_selection_count()
    
    def select_none_fir(self):
        """Deseleziona tutti i FIR"""
        for fir in self.current_fir_list:
            fir['selected'] = False
        self.update_fir_display()
        self.update_selection_count()
    
    def download_single_fir(self, fir):
        """Scarica un singolo FIR"""
        if not self.rest:
            messagebox.showerror("Errore", "Nessun fornitore selezionato")
            return
        
        # Ask for output directory
        output_dir = filedialog.askdirectory(title="Seleziona cartella di destinazione")
        if not output_dir:
            return
        
        try:
            success = self.rest.dl_pdf(
                fir['codice_blocco'],
                fir['progressivo'],
                fir['numero_fir'],
                output_dir
            )
            
            if success:
                messagebox.showinfo("Successo", f"PDF scaricato per FIR {fir['numero_fir']}")
            else:
                messagebox.showerror("Errore", f"Errore nel download del PDF per FIR {fir['numero_fir']}")
                
        except Exception as e:
            messagebox.showerror("Errore", f"Errore durante il download: {str(e)}")
    
    def download_selected_fir(self):
        """Scarica tutti i FIR selezionati"""
        selected_fir = [fir for fir in self.filtered_fir_list if fir['selected']]
        
        if not selected_fir:
            messagebox.showwarning("Attenzione", "Nessun FIR selezionato")
            return
        
        if not self.rest:
            messagebox.showerror("Errore", "Nessun fornitore selezionato")
            return
        
        # Ask for output directory
        output_dir = filedialog.askdirectory(title="Seleziona cartella di destinazione")
        if not output_dir:
            return
        
        # Download in thread
        def download_worker():
            success_count = 0
            for fir in selected_fir:
                try:
                    success = self.rest.dl_pdf(
                        fir['codice_blocco'],
                        fir['progressivo'],
                        fir['numero_fir'],
                        output_dir
                    )
                    if success:
                        success_count += 1
                except Exception as e:
                    print(f"Errore download FIR {fir['numero_fir']}: {e}")
            
            # Show result
            self.after(0, lambda: messagebox.showinfo(
                "Download Completato", 
                f"Scaricati {success_count} di {len(selected_fir)} PDF"
            ))
        
        threading.Thread(target=download_worker, daemon=True).start()
    
    def show_fir_details(self, fir):
        """Mostra i dettagli di un FIR"""
        details_window = ctk.CTkToplevel(self)
        details_window.title(f"Dettagli FIR {fir['numero_fir']}")
        details_window.geometry("600x500")
        
        # Title
        title_label = ctk.CTkLabel(
            details_window,
            text=f"Dettagli FIR {fir['numero_fir']}",
            font=ctk.CTkFont(size=20, weight="bold")
        )
        title_label.pack(pady=20)
        
        # Details frame
        details_frame = ctk.CTkScrollableFrame(details_window)
        details_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Display all FIR data
        details_text = ""
        for key, value in fir['raw_data'].items():
            details_text += f"{key}: {value}\n"
        
        text_widget = ctk.CTkTextbox(details_frame, height=300)
        text_widget.pack(fill="both", expand=True)
        text_widget.insert("1.0", details_text)
    
    # NUOVO: Metodo per annullare FIR selezionati con API
    def annulla_selected_fir(self):
        """NUOVO: Annulla i FIR selezionati utilizzando l'API RENTRI"""
        selected_fir = [fir for fir in self.filtered_fir_list if fir['selected']]
        
        if not selected_fir:
            messagebox.showwarning("Attenzione", "Nessun FIR selezionato per l'annullamento")
            return
        
        if not self.rest:
            messagebox.showerror("Errore", "Nessun fornitore selezionato")
            return
        
        # Filtra solo i FIR che possono essere annullati (Vidimati)
        annullabili = [fir for fir in selected_fir if fir['stato'] == "Vidimato"]
        
        if not annullabili:
            messagebox.showwarning(
                "Attenzione", 
                "Nessun FIR selezionato è annullabile.\n\nPossono essere annullati solo i FIR in stato 'Vidimato'."
            )
            return
        
        # Conferma dell'operazione
        if not messagebox.askyesno(
            "Conferma Annullamento", 
            f"Sei sicuro di voler annullare {len(annullabili)} FIR selezionati?\n\n"
            "⚠️ ATTENZIONE: Questa operazione è irreversibile!\n\n"
            f"FIR da annullare:\n" + "\n".join([f"• {fir['numero_fir']} (Blocco: {fir['codice_blocco']})" for fir in annullabili[:5]]) +
            (f"\n... e altri {len(annullabili)-5} FIR" if len(annullabili) > 5 else "")
        ):
            return
        
        # Esegui annullamento in thread separato con progress
        self.execute_cancellation_worker(annullabili)
    
    def execute_cancellation_worker(self, fir_list):
        """Esegue l'annullamento in background con progress"""
        def annulla_worker():
            success_count = 0
            errors = []
            total = len(fir_list)
            
            for i, fir in enumerate(fir_list):
                try:
                    # Aggiorna UI
                    progress_msg = f"🗑️ Annullamento {i+1}/{total}: {fir['numero_fir']}"
                    self.after(0, lambda msg=progress_msg: self.update_cancel_status(msg))
                    
                    # Chiamata API
                    success, status_code, response_text = self.rest.annulla_fir(
                        fir['codice_blocco'], 
                        fir['progressivo']
                    )
                    
                    if success:
                        success_count += 1
                        # Aggiorna stato locale
                        fir['stato'] = "Annullato"
                    else:
                        # Gestisci errori HTTP specifici
                        if status_code == 404:
                            error_msg = f"FIR {fir['numero_fir']}: Non trovato"
                        elif status_code == 403:
                            error_msg = f"FIR {fir['numero_fir']}: Non autorizzato"
                        elif status_code == 423:
                            error_msg = f"FIR {fir['numero_fir']}: Bloccato, non annullabile"
                        else:
                            error_msg = f"FIR {fir['numero_fir']}: HTTP {status_code}"
                        errors.append(error_msg)
                        
                except Exception as e:
                    errors.append(f"FIR {fir['numero_fir']}: {str(e)}")
                
                time.sleep(0.5)  # Pausa breve tra le chiamate
            
            # Aggiorna UI finale
            self.after(0, lambda: self.finalize_cancellation(success_count, errors, total))
        
        # Avvia worker
        threading.Thread(target=annulla_worker, daemon=True).start()
    
    def update_cancel_status(self, message):
        """Aggiorna il messaggio di stato durante l'annullamento"""
        self.results_label.configure(text=message)
    
    def finalize_cancellation(self, success_count, errors, total):
        """Finalizza il processo di annullamento e mostra i risultati"""
        # Aggiorna la vista
        self.update_fir_display()
        self.update_results_label()
        
        # Mostra risultati
        if success_count == total:
            messagebox.showinfo(
                "Annullamento Completato", 
                f"✅ Tutti i {success_count} FIR sono stati annullati con successo!"
            )
        elif success_count > 0:
            error_details = "\n".join(errors[:3])  # Mostra primi 3 errori
            if len(errors) > 3:
                error_details += f"\n... e altri {len(errors)-3} errori"
                
            messagebox.showwarning(
                "Annullamento Parziale", 
                f"✅ {success_count} FIR annullati con successo\n"
                f"❌ {len(errors)} errori:\n\n{error_details}\n\n"
                "Controlla la console per dettagli completi."
            )
        else:
            error_details = "\n".join(errors[:3])
            if len(errors) > 3:
                error_details += f"\n... e altri {len(errors)-3} errori"
            messagebox.showerror(
                "Errore Annullamento", 
                f"❌ Nessun FIR annullato. Errori:\n\n{error_details}\n\n"
                "Controlla la console per dettagli completi."
            )
        
        # Reset selezioni
        for fir in self.filtered_fir_list:
            fir['selected'] = False
        self.update_selection_count()
        self.load_fir_data()

    
    def show_api_info(self):
        """Mostra informazioni sulle API aggiornate"""
        api_info = """
API RENTRI - Informazioni Tecniche Aggiornate

🔗 ENDPOINT DISPONIBILI:
• GET /vidimazione-formulari/v1.0 - Lista blocchi
• GET /vidimazione-formulari/v1.0/{blocco} - Lista FIR
• POST /vidimazione-formulari/v1.0/{blocco} - Vidima FIR
• GET /vidimazione-formulari/v1.0/{blocco}/{prog}/pdf - Download PDF
• PUT /vidimazione-formulari/v1.0/{blocco}/{prog}/annulla - Annulla FIR ✅

✅ ANNULLAMENTO FIR:
• Endpoint: PUT .../annulla
• Autenticazione: JWT + AGID Signature
• Solo FIR in stato "Vidimato" possono essere annullati
• Operazione irreversibile

📋 CODICI RISPOSTA:
• 200 OK - Annullamento riuscito
• 400 Bad Request - Richiesta non valida  
• 403 Forbidden - Non autorizzato
• 404 Not Found - FIR non trovato
• 423 Locked - FIR non annullabile
• 429 Too Many Requests - Rate limit superato
• 500 Internal Server Error - Errore server

📚 DOCUMENTAZIONE:
• https://api.rentri.gov.it/docs?api=vidimazione-formulari&v=v1.0

🔄 FUNZIONALITÀ:
Questa interfaccia supporta completamente l'API di annullamento.
        """
        
        api_window = ctk.CTkToplevel(self)
        api_window.title("Info API RENTRI")
        api_window.geometry("600x500")
        
        text_widget = ctk.CTkTextbox(api_window, wrap="word")
        text_widget.pack(fill="both", expand=True, padx=20, pady=20)
        text_widget.insert("1.0", api_info)
        text_widget.configure(state="disabled")

class ModernRentriManager:
    def __init__(self):
        self.root = ctk.CTk()
        self.root.title(APP_TITLE)
        
        # NUOVO: Fix completo per fullscreen cross-platform
        self.root.update_idletasks()
        screen_w = self.root.winfo_screenwidth()
        screen_h = self.root.winfo_screenheight()
        
        # Imposta geometria a schermo intero
        self.root.geometry(f"{screen_w}x{screen_h}+0+0")
        
        # Prova diversi metodi per il fullscreen in base al sistema
        try:
            if sys.platform.startswith('win'):
                # Windows: usa state zoomed
                self.root.state('zoomed')
            elif sys.platform.startswith('darwin'):
                # macOS: usa attributes zoomed
                self.root.attributes('-zoomed', True)
            else:
                # Linux/Unix: prova fullscreen poi zoomed come fallback
                try:
                    self.root.attributes('-fullscreen', True)
                except:
                    self.root.attributes('-zoomed', True)
        except Exception as e:
            # Fallback finale: imposta solo la geometria massima
            dbg(f"Fallback fullscreen: {e}")
            self.root.geometry(f"{screen_w}x{screen_h}+0+0")
        
        self.root.minsize(1200, 800)
        
        # Settings and data
        self.settings = SettingsManager(SETTINGS_FILE)
        self.db = FornitoriDB(CONF_FILE)
        self.rest = None
        self.current_blocchi = []
        
        # Initialize theme
        self.initialize_theme()
        
        # Create UI
        self.create_layout()
        self.create_sidebar()
        self.create_main_content()
        
        # Start with supplier selection if none exists
        if not self.db.elenco():
            self.root.after(100, self.show_supplier_selection)
        else:
            self.show_dashboard()
    
    def initialize_theme(self):
        """Inizializza il tema dell'applicazione"""
        theme = self.settings.get("theme", "dark")
        ctk.set_appearance_mode(theme)
        dbg(f"Tema inizializzato: {theme}")
    
    def create_layout(self):
        # Configure grid
        self.root.grid_columnconfigure(1, weight=1)
        self.root.grid_rowconfigure(0, weight=1)
        
        # Sidebar
        self.sidebar = ctk.CTkFrame(self.root, width=300, fg_color=COLORS["sidebar"])
        self.sidebar.grid(row=0, column=0, sticky="nsew", padx=(0, 2))
        self.sidebar.grid_propagate(False)
        
        # Main content
        self.main_frame = ctk.CTkFrame(self.root, fg_color="transparent")
        self.main_frame.grid(row=0, column=1, sticky="nsew", padx=(2, 0))
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(0, weight=1)
    
    def create_sidebar(self):
        # Logo/Title section
        logo_frame = ctk.CTkFrame(self.sidebar, height=80, fg_color="transparent")
        logo_frame.pack(fill="x", padx=20, pady=(20, 0))
        logo_frame.pack_propagate(False)
        
        # Logo display
        self.logo_label = ctk.CTkLabel(
            logo_frame,
            text=self.settings.get("logo_text", "RENTRI"),
            font=ctk.CTkFont(size=28, weight="bold"),
            text_color=COLORS["accent"]
        )
        self.logo_label.pack(pady=20)
        
        # Load custom logo if available
        self.load_custom_logo()
        
        # Fornitore info
        self.fornitore_frame = ctk.CTkFrame(self.sidebar, fg_color="#3a3a3a")
        self.fornitore_frame.pack(fill="x", padx=20, pady=(20, 0))
        
        self.fornitore_label = ctk.CTkLabel(
            self.fornitore_frame,
            text="Nessun fornitore selezionato",
            font=ctk.CTkFont(size=12),
            wraplength=250,
            anchor="w",
            justify="left"
        )
        self.fornitore_label.pack(pady=15, padx=15, fill="x")
        
        # Navigation buttons
        nav_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        nav_frame.pack(fill="x", padx=20, pady=(30, 0))
        
        self.nav_buttons = {}
        
        # Main sections
        sections = [
            ("dashboard", "📊 Dashboard", self.show_dashboard),
            ("suppliers", "🏢 Fornitori", self.show_supplier_selection),
            ("blocks", "📋 Blocchi", self.show_blocks_view),
            ("vidimation", "✅ Vidimazione", self.show_vidimation_view),
            ("fir_management", "🗑️ Gestione FIR", self.show_fir_management_view),  # SEZIONE AGGIORNATA
        ]
        
        for key, text, command in sections:
            self.nav_buttons[key] = ctk.CTkButton(
                nav_frame,
                text=text,
                command=command,
                height=50,
                fg_color="transparent",
                hover_color="#4a4a4a",
                anchor="w",
                font=ctk.CTkFont(size=14, weight="bold")
            )
            self.nav_buttons[key].pack(fill="x", pady=(0, 5))
        
        # PDF Tools section
        pdf_separator = ctk.CTkLabel(
            nav_frame,
            text="PDF Tools",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="gray"
        )
        pdf_separator.pack(fill="x", pady=(20, 10))
        
        # PDF Tools buttons
        pdf_tools = [
            ("delivery", "✉️ Crea lettera di consegna", self.show_delivery_view),
            ("merge", "🗜️ Unisci FIR per stamparli", self.show_merge_view),
        ]
        
        for key, text, command in pdf_tools:
            self.nav_buttons[key] = ctk.CTkButton(
                nav_frame,
                text=text,
                command=command,
                height=45,
                fg_color="transparent",
                hover_color="#4a4a4a",
                anchor="w",
                font=ctk.CTkFont(size=13, weight="bold")
            )
            self.nav_buttons[key].pack(fill="x", pady=(0, 3))
        
        # Settings button
        self.nav_buttons["settings"] = ctk.CTkButton(
            nav_frame,
            text="⚙️ Impostazioni",
            command=self.show_settings_view,
            height=50,
            fg_color="transparent",
            hover_color="#4a4a4a",
            anchor="w",
            font=ctk.CTkFont(size=14, weight="bold")
        )
        self.nav_buttons["settings"].pack(fill="x", pady=(20, 5))
        
        # Bottom section with theme toggle and credits
        bottom_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        bottom_frame.pack(fill="x", padx=20, pady=(50, 20), side="bottom")
        
        # Theme toggle
        self.theme_switch = ctk.CTkSwitch(
            bottom_frame,
            text="🌙 Tema scuro",
            command=self.toggle_theme,
            font=ctk.CTkFont(size=12)
        )
        self.theme_switch.pack(pady=(0, 15))
        
        # Set initial theme switch state
        current_theme = self.settings.get("theme", "dark")
        if current_theme == "dark":
            self.theme_switch.select()
        else:
            self.theme_switch.deselect()
        
        # Credits
        credits_frame = ctk.CTkFrame(bottom_frame, fg_color="transparent")
        credits_frame.pack(fill="x")
        
        created_label = ctk.CTkLabel(
            credits_frame,
            text="Created By ",
            font=ctk.CTkFont(size=10),
            text_color="gray"
        )
        created_label.pack(side="left")
        
        # Clickable LinkedIn link
        linkedin_label = ClickableLabel(
            credits_frame,
            text="Giovanni Pio",
            url="https://linkedin.com/in/giovanni-pio-familiari",
            font=ctk.CTkFont(size=10, weight="bold"),
            text_color="white"
        )
        linkedin_label.pack(side="left")
    
    def load_custom_logo(self):
        """Carica logo personalizzato se disponibile"""
        logo_path = self.settings.get("logo_path", "")
        if logo_path and os.path.exists(logo_path):
            try:
                # Prova a caricare l'immagine
                image = Image.open(logo_path)
                image = image.resize((200, 60), Image.Resampling.LANCZOS)
                
                # Converti in formato CustomTkinter
                photo = ctk.CTkImage(light_image=image, dark_image=image, size=(200, 60))
                self.logo_label.configure(image=photo, text="")
                self.logo_label.image = photo  # Mantieni riferimento
                dbg("Logo personalizzato caricato")
            except Exception as e:
                dbg(f"Errore caricamento logo: {e}")
                # Fallback al testo
                self.logo_label.configure(text=self.settings.get("logo_text", "RENTRI"))
        else:
            # Usa il testo del logo
            self.logo_label.configure(text=self.settings.get("logo_text", "RENTRI"))
    
    def create_main_content(self):
        # Create content frame
        self.content_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.content_frame.grid(row=0, column=0, sticky="nsew", padx=20, pady=20)
        self.content_frame.grid_columnconfigure(0, weight=1)
        self.content_frame.grid_rowconfigure(0, weight=1)
    
    def clear_content(self):
        for widget in self.content_frame.winfo_children():
            widget.destroy()
    
    def set_active_nav(self, active_button):
        # Reset all buttons
        for button in self.nav_buttons.values():
            button.configure(fg_color="transparent")
        
        # Set active button
        if active_button in self.nav_buttons:
            self.nav_buttons[active_button].configure(fg_color=COLORS["primary"])
    
    def update_fornitore_display(self):
        if self.rest:
            text = f"Fornitore: {self.rest.rag}\nCF: {self.rest.cf}"
        else:
            text = "Nessun fornitore selezionato"
        self.fornitore_label.configure(text=text)
    
    def get_certificate_info(self):
        """Ottiene informazioni sul certificato del fornitore corrente"""
        if not self.rest:
            return None
            
        try:
            not_before, not_after = get_certificate_dates(self.rest.p12, self.rest.pwd)
            if not_before and not_after:
                expired = is_certificate_expired(self.rest.p12, self.rest.pwd)
                return {
                    "issued": format_date(not_before),
                    "expires": format_date(not_after),
                    "expired": expired
                }
        except Exception as e:
            dbg(f"Errore lettura info certificato: {e}")
        
        return None
    
    def update_certificate(self):
        """Aggiorna il certificato del fornitore corrente"""
        if not self.rest:
            messagebox.showerror("Errore", "Nessun fornitore selezionato")
            return
        
        # File selection
        p12_file = filedialog.askopenfilename(
            title="Seleziona nuovo certificato .p12",
            filetypes=[("PKCS#12 files", "*.p12"), ("All files", "*.*")]
        )
        
        if not p12_file:
            return
        
        # Password dialog
        password_dialog = ctk.CTkInputDialog(
            text="Inserisci password del nuovo certificato:",
            title="Password Certificato"
        )
        password = password_dialog.get_input() or ""
        
        try:
            # Verifica che il certificato sia valido
            pw = password.encode() if password else None
            pk, cert, _ = pkcs12.load_key_and_certificates(
                Path(p12_file).read_bytes(), pw, backend=default_backend()
            )
            
            # Verifica che il CF sia lo stesso
            new_cf = estrai_codice_fiscale(cert)
            if new_cf != self.rest.cf:
                messagebox.showerror(
                    "Errore", 
                    f"Il codice fiscale del nuovo certificato ({new_cf}) non corrisponde a quello attuale ({self.rest.cf})"
                )
                return
            
            # Aggiorna nel database
            success = self.db.update_certificate(self.rest.cf, p12_file, password)
            if success:
                # Ricarica il RentriREST con il nuovo certificato
                supplier_data = self.db.get(self.rest.cf)
                if supplier_data:
                    self.rest = RentriREST(supplier_data)
                    messagebox.showinfo("Successo", "Certificato aggiornato con successo!")
                    # Aggiorna il dashboard per mostrare le nuove date
                    self.show_dashboard()
                else:
                    messagebox.showerror("Errore", "Errore nel recupero dei dati del fornitore")
            else:
                messagebox.showerror("Errore", "Errore nell'aggiornamento del certificato")
                
        except Exception as e:
            messagebox.showerror("Errore", f"Errore durante l'aggiornamento del certificato:\n{str(e)}")
    
    def show_dashboard(self):
        self.set_active_nav("dashboard")
        self.clear_content()
        
        # Header
        header_frame = ctk.CTkFrame(self.content_frame, height=80, fg_color="transparent")
        header_frame.grid(row=0, column=0, sticky="ew", pady=(0, 20))
        header_frame.grid_columnconfigure(0, weight=1)
        header_frame.grid_propagate(False)
        
        title_label = ctk.CTkLabel(
            header_frame,
            text="Dashboard",
            font=ctk.CTkFont(size=32, weight="bold"),
            anchor="w"
        )
        title_label.grid(row=0, column=0, sticky="w", pady=20)
        
        # Stats cards
        stats_frame = ctk.CTkFrame(self.content_frame, fg_color="transparent")
        stats_frame.grid(row=1, column=0, sticky="ew", pady=(0, 20))
        stats_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)
        
        # Regular cards data
        regular_cards_data = [
            ("Fornitori Configurati", len(self.db.elenco()), COLORS["success"]),
            ("Blocchi Disponibili", len(self.current_blocchi) if self.rest else 0, COLORS["warning"]),
            ("Stato Sistema", "Connesso" if self.rest else "Disconnesso", COLORS["accent"] if self.rest else COLORS["error"]),
        ]
        
        # Create regular cards
        for i, (title, value, color) in enumerate(regular_cards_data):
            card = DashboardCard(stats_frame, title, value, color)
            card.frame.grid(row=0, column=i, padx=(0 if i == 0 else 10, 10), sticky="ew")
        
        # Certificate card (sostituisce PDF Tools)
        cert_info = self.get_certificate_info()
        cert_card = CertificateCard(
            stats_frame, 
            "Certificato", 
            cert_info, 
            self.update_certificate
        )
        cert_card.frame.grid(row=0, column=3, padx=(0, 0), sticky="ew")
        
        # Quick actions
        if self.rest:
            actions_frame = ctk.CTkFrame(self.content_frame)
            actions_frame.grid(row=2, column=0, sticky="ew", pady=(0, 20))
            actions_frame.grid_columnconfigure((0, 1), weight=1)
            
            # Refresh blocks button
            refresh_btn = ctk.CTkButton(
                actions_frame,
                text="🔄 Aggiorna Blocchi",
                command=self.refresh_blocks,
                height=50,
                font=ctk.CTkFont(size=16, weight="bold")
            )
            refresh_btn.grid(row=0, column=0, padx=(20, 10), pady=20, sticky="ew")
            
            # Quick vidimation button
            vidim_btn = ctk.CTkButton(
                actions_frame,
                text="⚡ Vidimazione Rapida",
                command=self.show_vidimation_view,
                height=50,
                font=ctk.CTkFont(size=16, weight="bold"),
                fg_color=COLORS["success"],
                hover_color=COLORS["accent"]
            )
            vidim_btn.grid(row=0, column=1, padx=(10, 20), pady=20, sticky="ew")
    
    def show_supplier_selection(self):
        self.set_active_nav("suppliers")
        self.clear_content()
        
        dbg("Mostrando selezione fornitori")
        
        # Header
        header_frame = ctk.CTkFrame(self.content_frame, height=80, fg_color="transparent")
        header_frame.grid(row=0, column=0, sticky="ew", pady=(0, 20))
        header_frame.grid_columnconfigure(0, weight=1)
        header_frame.grid_propagate(False)
        
        title_label = ctk.CTkLabel(
            header_frame,
            text="Gestione Fornitori",
            font=ctk.CTkFont(size=32, weight="bold"),
            anchor="w"
        )
        title_label.grid(row=0, column=0, sticky="w", pady=20)
        
        # Add supplier button
        add_btn = ctk.CTkButton(
            header_frame,
            text="➕ Nuovo Fornitore",
            command=self.add_supplier,
            height=40,
            font=ctk.CTkFont(size=14, weight="bold")
        )
        add_btn.grid(row=0, column=1, pady=20, padx=(20, 0))
        
        # Search frame
        search_frame = ctk.CTkFrame(self.content_frame, fg_color="transparent")
        search_frame.grid(row=1, column=0, sticky="ew", pady=(0, 20))
        search_frame.grid_columnconfigure(0, weight=1)
        
        # Search entry with icon
        self.search_entry = ctk.CTkEntry(
            search_frame,
            placeholder_text="🔍 Cerca per ragione sociale o codice fiscale...",
            height=40,
            font=ctk.CTkFont(size=14)
        )
        self.search_entry.grid(row=0, column=0, sticky="ew", padx=(0, 10))
        self.search_entry.bind("<KeyRelease>", self.on_search_change)
        
        # Clear button
        clear_btn = ctk.CTkButton(
            search_frame,
            text="✕",
            command=self.clear_search,
            width=40,
            height=40,
            fg_color="transparent",
            hover_color=COLORS["error"],
            font=ctk.CTkFont(size=16, weight="bold")
        )
        clear_btn.grid(row=0, column=1)
        
        # Suppliers list frame
        self.suppliers_frame = ctk.CTkScrollableFrame(
            self.content_frame,
            label_text="Fornitori",
            height=400
        )
        self.suppliers_frame.grid(row=2, column=0, sticky="nsew")
        self.suppliers_frame.grid_columnconfigure(0, weight=1)
        
        # Load suppliers
        self.refresh_suppliers_display()
    
    def on_search_change(self, event):
        """Gestisce la ricerca in tempo reale"""
        query = self.search_entry.get().strip()
        self.refresh_suppliers_display(query)
    
    def clear_search(self):
        """Cancella la ricerca"""
        self.search_entry.delete(0, "end")
        self.refresh_suppliers_display()
    
    def refresh_suppliers_display(self, query=""):
        """Aggiorna la visualizzazione dei fornitori"""
        # Clear existing suppliers
        for widget in self.suppliers_frame.winfo_children():
            widget.destroy()
        
        # Get suppliers (filtered if query provided)
        if query:
            suppliers = self.db.search(query)
        else:
            suppliers = self.db.elenco()
        
        dbg(f"Visualizzando {len(suppliers)} fornitori")
        
        if not suppliers:
            if query:
                # No results found
                no_results_label = ctk.CTkLabel(
                    self.suppliers_frame,
                    text="🔍 Nessun risultato trovato\n\nProva con termini di ricerca diversi",
                    font=ctk.CTkFont(size=16),
                    text_color="gray"
                )
                no_results_label.pack(pady=50)
            else:
                # No suppliers at all
                no_suppliers_label = ctk.CTkLabel(
                    self.suppliers_frame,
                    text="📋 Nessun fornitore configurato\n\nClicca 'Nuovo Fornitore' per iniziare",
                    font=ctk.CTkFont(size=16),
                    text_color="gray"
                )
                no_suppliers_label.pack(pady=50)
        else:
            # Show suppliers
            for i, supplier in enumerate(suppliers):
                self.create_supplier_card(supplier, i)
    
    def create_supplier_card(self, supplier, row):
        """Crea una card per un fornitore"""
        card_frame = ctk.CTkFrame(self.suppliers_frame, height=120)
        card_frame.pack(fill="x", padx=20, pady=10)
        card_frame.pack_propagate(False)
        
        # Create internal grid
        card_frame.grid_columnconfigure(0, weight=1)
        
        # Info frame
        info_frame = ctk.CTkFrame(card_frame, fg_color="transparent")
        info_frame.grid(row=0, column=0, sticky="nsew", padx=20, pady=15)
        info_frame.grid_columnconfigure(0, weight=1)
        
        # Name
        name_label = ctk.CTkLabel(
            info_frame,
            text=supplier["ragione_sociale"],
            font=ctk.CTkFont(size=18, weight="bold"),
            anchor="w"
        )
        name_label.grid(row=0, column=0, sticky="w")
        
        # CF
        cf_label = ctk.CTkLabel(
            info_frame,
            text=f"CF: {supplier['codice_fiscale']}",
            font=ctk.CTkFont(size=14),
            anchor="w",
            text_color="gray"
        )
        cf_label.grid(row=1, column=0, sticky="w", pady=(5, 0))
        
        # Buttons frame
        buttons_frame = ctk.CTkFrame(card_frame, fg_color="transparent")
        buttons_frame.grid(row=0, column=1, padx=20, pady=15)
        
        # Select button
        select_btn = ctk.CTkButton(
            buttons_frame,
            text="Seleziona",
            command=lambda s=supplier: self.select_supplier(s),
            width=100,
            height=35
        )
        select_btn.grid(row=0, column=0, padx=(0, 10))
        
        # Delete button
        delete_btn = ctk.CTkButton(
            buttons_frame,
            text="Elimina",
            command=lambda s=supplier: self.delete_supplier(s),
            width=100,
            height=35,
            fg_color=COLORS["error"],
            hover_color="#d63031"
        )
        delete_btn.grid(row=0, column=1)
    
    def add_supplier(self):
        # File selection
        p12_file = filedialog.askopenfilename(
            title="Seleziona file certificato .p12",
            filetypes=[("PKCS#12 files", "*.p12"), ("All files", "*.*")]
        )
        
        if not p12_file:
            return
        
        # Password dialog
        password_dialog = ctk.CTkInputDialog(
            text="Inserisci password certificato:",
            title="Password Certificato"
        )
        password = password_dialog.get_input() or ""
        
        try:
            # Load certificate
            pw = password.encode() if password else None
            pk, cert, _ = pkcs12.load_key_and_certificates(
                Path(p12_file).read_bytes(), pw, backend=default_backend()
            )
            
            rag_soc = estrai_ragione_sociale(cert)
            cf = estrai_codice_fiscale(cert)
            
            if not cf:
                messagebox.showerror("Errore", "Impossibile estrarre il codice fiscale dal certificato")
                return
            
            # Save supplier
            self.db.add(p12_file, password, rag_soc, cf)
            
            messagebox.showinfo("Successo", f"Fornitore {rag_soc} aggiunto con successo!")
            
            # Refresh suppliers display
            self.refresh_suppliers_display()
            
        except Exception as e:
            messagebox.showerror("Errore", f"Errore durante l'aggiunta del fornitore:\n{str(e)}")
    
    def select_supplier(self, supplier):
        try:
            self.rest = RentriREST(supplier)
            self.update_fornitore_display()
            self.refresh_blocks()
            messagebox.showinfo("Successo", f"Fornitore {supplier['ragione_sociale']} selezionato")
            self.show_dashboard()
        except Exception as e:
            messagebox.showerror("Errore", f"Errore nella selezione del fornitore:\n{str(e)}")
    
    def delete_supplier(self, supplier):
        if messagebox.askyesno("Conferma", f"Eliminare il fornitore {supplier['ragione_sociale']}?"):
            success = self.db.delete(supplier["id"])
            if success:
                messagebox.showinfo("Successo", "Fornitore eliminato")
                # Refresh suppliers display
                self.refresh_suppliers_display()
            else:
                messagebox.showerror("Errore", "Errore nell'eliminazione del fornitore")
    
    def refresh_blocks(self):
        if not self.rest:
            return
        
        try:
            self.current_blocchi = self.rest.blocchi()
            dbg(f"Trovati {len(self.current_blocchi)} blocchi")
        except Exception as e:
            messagebox.showerror("Errore", f"Errore nel recupero blocchi:\n{str(e)}")
    
    def show_blocks_view(self):
        self.set_active_nav("blocks")
        self.clear_content()
        
        # Header
        header_frame = ctk.CTkFrame(self.content_frame, height=80, fg_color="transparent")
        header_frame.grid(row=0, column=0, sticky="ew", pady=(0, 20))
        header_frame.grid_columnconfigure(0, weight=1)
        header_frame.grid_propagate(False)
        
        title_label = ctk.CTkLabel(
            header_frame,
            text="Blocchi Disponibili",
            font=ctk.CTkFont(size=32, weight="bold"),
            anchor="w"
        )
        title_label.grid(row=0, column=0, sticky="w", pady=20)
        
        # Refresh button
        refresh_btn = ctk.CTkButton(
            header_frame,
            text="🔄 Aggiorna",
            command=self.refresh_blocks,
            height=40,
            font=ctk.CTkFont(size=14, weight="bold")
        )
        refresh_btn.grid(row=0, column=1, pady=20, padx=(20, 0))
        
        if not self.rest:
            no_supplier_label = ctk.CTkLabel(
                self.content_frame,
                text="Seleziona un fornitore per visualizzare i blocchi",
                font=ctk.CTkFont(size=16),
                text_color="gray"
            )
            no_supplier_label.grid(row=1, column=0, pady=50)
            return
        
        # Blocks list
        blocks_frame = ctk.CTkScrollableFrame(
            self.content_frame,
            label_text="Blocchi FIR"
        )
        blocks_frame.grid(row=1, column=0, sticky="nsew")
        blocks_frame.grid_columnconfigure(0, weight=1)
        
        if not self.current_blocchi:
            self.refresh_blocks()
        
        if not self.current_blocchi:
            no_blocks_label = ctk.CTkLabel(
                blocks_frame,
                text="Nessun blocco disponibile",
                font=ctk.CTkFont(size=16),
                text_color="gray"
            )
            no_blocks_label.grid(row=0, column=0, pady=50)
        else:
            for i, blocco in enumerate(self.current_blocchi):
                self.create_block_card(blocks_frame, blocco, i)
    
    def create_block_card(self, parent, blocco, row):
        card_frame = ctk.CTkFrame(parent, height=100)
        card_frame.grid(row=row, column=0, sticky="ew", padx=20, pady=10)
        card_frame.grid_columnconfigure(0, weight=1)
        card_frame.grid_propagate(False)
        
        # Info frame
        info_frame = ctk.CTkFrame(card_frame, fg_color="transparent")
        info_frame.grid(row=0, column=0, sticky="nsew", padx=20, pady=15)
        info_frame.grid_columnconfigure(0, weight=1)
        
        # Block code
        code_label = ctk.CTkLabel(
            info_frame,
            text=blocco["codice_blocco"],
            font=ctk.CTkFont(size=16, weight="bold"),
            anchor="w"
        )
        code_label.grid(row=0, column=0, sticky="w")
        
        # Description
        desc_label = ctk.CTkLabel(
            info_frame,
            text=blocco.get("descrizione", "Nessuna descrizione"),
            font=ctk.CTkFont(size=12),
            anchor="w",
            text_color="gray"
        )
        desc_label.grid(row=1, column=0, sticky="w", pady=(5, 0))
        
        # FIR count
        fir_label = ctk.CTkLabel(
            info_frame,
            text=f"FIR vidimati: {blocco.get('numero_fir_vidimati', 0)}",
            font=ctk.CTkFont(size=12),
            anchor="w",
            text_color="gray"
        )
        fir_label.grid(row=2, column=0, sticky="w", pady=(5, 0))
        
        # Select button
        select_btn = ctk.CTkButton(
            card_frame,
            text="Seleziona",
            command=lambda b=blocco: self.select_block_for_vidimation(b),
            width=120,
            height=35
        )
        select_btn.grid(row=0, column=1, padx=20, pady=15)
    
    def select_block_for_vidimation(self, blocco):
        self.selected_blocco = blocco
        self.show_vidimation_view()
    
    def show_vidimation_view(self):
        self.set_active_nav("vidimation")
        self.clear_content()
        
        # Header
        header_frame = ctk.CTkFrame(self.content_frame, height=80, fg_color="transparent")
        header_frame.grid(row=0, column=0, sticky="ew", pady=(0, 20))
        header_frame.grid_columnconfigure(0, weight=1)
        header_frame.grid_propagate(False)
        
        title_label = ctk.CTkLabel(
            header_frame,
            text="Vidimazione FIR",
            font=ctk.CTkFont(size=32, weight="bold"),
            anchor="w"
        )
        title_label.grid(row=0, column=0, sticky="w", pady=20)
        
        if not self.rest:
            no_supplier_label = ctk.CTkLabel(
                self.content_frame,
                text="Seleziona un fornitore per procedere con la vidimazione",
                font=ctk.CTkFont(size=16),
                text_color="gray"
            )
            no_supplier_label.grid(row=1, column=0, pady=50)
            return
        
        # Vidimation form
        form_frame = ctk.CTkFrame(self.content_frame)
        form_frame.grid(row=1, column=0, sticky="ew", pady=(0, 20))
        form_frame.grid_columnconfigure(1, weight=1)
        
        # Block selection
        block_label = ctk.CTkLabel(form_frame, text="Blocco:", font=ctk.CTkFont(size=14, weight="bold"))
        block_label.grid(row=0, column=0, padx=20, pady=20, sticky="w")
        
        if not self.current_blocchi:
            self.refresh_blocks()
        
        block_values = [f"{b['codice_blocco']} - {b.get('descrizione', '')}" for b in self.current_blocchi]
        self.block_combo = ctk.CTkComboBox(form_frame, values=block_values, width=400)
        self.block_combo.grid(row=0, column=1, padx=20, pady=20, sticky="ew")
        
        # Quantity selection
        qty_label = ctk.CTkLabel(form_frame, text="Quantità FIR:", font=ctk.CTkFont(size=14, weight="bold"))
        qty_label.grid(row=1, column=0, padx=20, pady=20, sticky="w")
        
        self.qty_entry = ctk.CTkEntry(form_frame, placeholder_text="Numero di FIR da vidimare", width=200)
        self.qty_entry.grid(row=1, column=1, padx=20, pady=20, sticky="w")
        
        # Output directory
        dir_label = ctk.CTkLabel(form_frame, text="Cartella PDF:", font=ctk.CTkFont(size=14, weight="bold"))
        dir_label.grid(row=2, column=0, padx=20, pady=20, sticky="w")
        
        dir_frame = ctk.CTkFrame(form_frame, fg_color="transparent")
        dir_frame.grid(row=2, column=1, padx=20, pady=20, sticky="ew")
        dir_frame.grid_columnconfigure(0, weight=1)
        
        self.dir_entry = ctk.CTkEntry(dir_frame, placeholder_text="Seleziona cartella di destinazione")
        self.dir_entry.grid(row=0, column=0, sticky="ew", padx=(0, 10))
        
        dir_btn = ctk.CTkButton(dir_frame, text="Sfoglia", command=self.select_output_directory, width=100)
        dir_btn.grid(row=0, column=1)
        
        # Start button
        start_btn = ctk.CTkButton(
            form_frame,
            text="🚀 Avvia Vidimazione",
            command=self.start_vidimation,
            height=50,
            font=ctk.CTkFont(size=16, weight="bold"),
            fg_color=COLORS["success"],
            hover_color=COLORS["accent"]
        )
        start_btn.grid(row=3, column=0, columnspan=2, padx=20, pady=30, sticky="ew")
    
    def select_output_directory(self):
        directory = filedialog.askdirectory(title="Seleziona cartella di destinazione PDF")
        if directory:
            self.dir_entry.delete(0, "end")
            self.dir_entry.insert(0, directory)
    
    def start_vidimation(self):
        # Validate inputs
        if not self.block_combo.get():
            messagebox.showerror("Errore", "Seleziona un blocco")
            return
        
        try:
            qty = int(self.qty_entry.get())
            if qty <= 0:
                raise ValueError()
        except ValueError:
            messagebox.showerror("Errore", "Inserisci un numero valido di FIR")
            return
        
        output_dir = self.dir_entry.get()
        if not output_dir:
            messagebox.showerror("Errore", "Seleziona una cartella di destinazione")
            return
        
        # Get selected block
        block_text = self.block_combo.get()
        block_code = block_text.split(" - ")[0]
        selected_block = next((b for b in self.current_blocchi if b["codice_blocco"] == block_code), None)
        
        if not selected_block:
            messagebox.showerror("Errore", "Blocco non trovato")
            return
        
        # Start vidimation process
        self.run_vidimation_worker(selected_block["codice_blocco"], qty, output_dir)
    
    def run_vidimation_worker(self, blocco, qty, output_dir):
        q = queue.Queue()
        worker = Worker(self.rest, blocco, qty, output_dir, q)
        
        # Create progress window
        fornitore_info = f"Fornitore: {self.rest.rag}\nCF: {self.rest.cf}\nBlocco: {blocco}"
        progress_window = ModernProgressWindow(self.root, "Vidimazione in corso", fornitore_info)
        progress_window.set_vidim_max(qty)
        
        vidim_count = 0
        pdf_count = 0
        
        def poll_worker():
            nonlocal vidim_count, pdf_count
            try:
                while True:
                    typ, val = q.get_nowait()
                    if typ == "msg":
                        progress_window.update_status(val)
                    elif typ == "post_inc":
                        if val:
                            vidim_count += 1
                        progress_window.update_vidim_progress(vidim_count)
                    elif typ == "pdf_max":
                        progress_window.set_pdf_max(val)
                    elif typ == "pdf_inc":
                        if val:
                            pdf_count += 1
                        progress_window.update_pdf_progress(pdf_count)
                    elif typ == "done":
                        progress_window.close()
                        messagebox.showinfo("Completato", val)
                        self.show_dashboard()
                        return
                    elif typ == "err":
                        progress_window.close()
                        messagebox.showerror("Errore", val)
                        return
            except queue.Empty:
                pass
            
            self.root.after(200, poll_worker)
        
        self.root.after(200, poll_worker)
        worker.start()
    
    # SEZIONE GESTIONE FIR (AGGIORNATA)
    def show_fir_management_view(self):
        """Mostra la vista di gestione FIR con API annullamento funzionante"""
        self.set_active_nav("fir_management")
        self.clear_content()
        
        FIRAnnullaView(self.content_frame, self.rest).grid(row=0, column=0, sticky="nsew")
    
    # PDF Tools Views
    def show_delivery_view(self):
        self.set_active_nav("delivery")
        self.clear_content()
        
        PDFDeliveryView(self.content_frame).grid(row=0, column=0, sticky="nsew")
    
    def show_merge_view(self):
        self.set_active_nav("merge")
        self.clear_content()
        
        PDFMergeView(self.content_frame).grid(row=0, column=0, sticky="nsew")
    
    def show_settings_view(self):
        self.set_active_nav("settings")
        self.clear_content()
        
        # Header
        header_frame = ctk.CTkFrame(self.content_frame, height=80, fg_color="transparent")
        header_frame.grid(row=0, column=0, sticky="ew", pady=(0, 20))
        header_frame.grid_columnconfigure(0, weight=1)
        header_frame.grid_propagate(False)
        
        title_label = ctk.CTkLabel(
            header_frame,
            text="Impostazioni",
            font=ctk.CTkFont(size=32, weight="bold"),
            anchor="w"
        )
        title_label.grid(row=0, column=0, sticky="w", pady=20)
        
        # Settings content
        settings_frame = ctk.CTkScrollableFrame(self.content_frame)
        settings_frame.grid(row=1, column=0, sticky="nsew")
        settings_frame.grid_columnconfigure(0, weight=1)
        
        # Logo settings section
        logo_section = ctk.CTkFrame(settings_frame)
        logo_section.grid(row=0, column=0, sticky="ew", padx=20, pady=20)
        logo_section.grid_columnconfigure(0, weight=1)
        
        logo_title = ctk.CTkLabel(
            logo_section,
            text="Personalizzazione Logo",
            font=ctk.CTkFont(size=18, weight="bold"),
            anchor="w"
        )
        logo_title.grid(row=0, column=0, sticky="w", padx=20, pady=(20, 10))
        
        # Logo options frame
        logo_options_frame = ctk.CTkFrame(logo_section, fg_color="transparent")
        logo_options_frame.grid(row=1, column=0, sticky="ew", padx=20, pady=(0, 20))
        logo_options_frame.grid_columnconfigure(1, weight=1)
        
        # Logo text
        logo_text_label = ctk.CTkLabel(
            logo_options_frame,
            text="Testo Logo:",
            font=ctk.CTkFont(size=14, weight="bold")
        )
        logo_text_label.grid(row=0, column=0, sticky="w", pady=(0, 10))
        
        self.logo_text_entry = ctk.CTkEntry(
            logo_options_frame,
            placeholder_text="Inserisci testo del logo",
            width=300
        )
        self.logo_text_entry.grid(row=0, column=1, sticky="ew", padx=(10, 0), pady=(0, 10))
        self.logo_text_entry.insert(0, self.settings.get("logo_text", "RENTRI"))
        
        # Logo image
        logo_image_label = ctk.CTkLabel(
            logo_options_frame,
            text="Immagine Logo:",
            font=ctk.CTkFont(size=14, weight="bold")
        )
        logo_image_label.grid(row=1, column=0, sticky="w", pady=(0, 10))
        
        logo_image_frame = ctk.CTkFrame(logo_options_frame, fg_color="transparent")
        logo_image_frame.grid(row=1, column=1, sticky="ew", padx=(10, 0), pady=(0, 10))
        logo_image_frame.grid_columnconfigure(0, weight=1)
        
        self.logo_path_entry = ctk.CTkEntry(
            logo_image_frame,
            placeholder_text="Seleziona file immagine logo"
        )
        self.logo_path_entry.grid(row=0, column=0, sticky="ew", padx=(0, 10))
        self.logo_path_entry.insert(0, self.settings.get("logo_path", ""))
        
        logo_browse_btn = ctk.CTkButton(
            logo_image_frame,
            text="Sfoglia",
            command=self.browse_logo_file,
            width=100
        )
        logo_browse_btn.grid(row=0, column=1)
        
        # Logo buttons
        logo_buttons_frame = ctk.CTkFrame(logo_options_frame, fg_color="transparent")
        logo_buttons_frame.grid(row=2, column=0, columnspan=2, pady=(20, 0))
        
        save_logo_btn = ctk.CTkButton(
            logo_buttons_frame,
            text="💾 Salva Logo",
            command=self.save_logo_settings,
            fg_color=COLORS["success"],
            hover_color=COLORS["accent"]
        )
        save_logo_btn.grid(row=0, column=0, padx=(0, 10))
        
        reset_logo_btn = ctk.CTkButton(
            logo_buttons_frame,
            text="🔄 Reset Logo",
            command=self.reset_logo_settings,
            fg_color=COLORS["error"],
            hover_color="#d63031"
        )
        reset_logo_btn.grid(row=0, column=1)
        
        # Theme setting
        theme_section = ctk.CTkFrame(settings_frame)
        theme_section.grid(row=1, column=0, sticky="ew", padx=20, pady=(0, 20))
        theme_section.grid_columnconfigure(0, weight=1)
        
        theme_title = ctk.CTkLabel(
            theme_section,
            text="Tema dell'applicazione",
            font=ctk.CTkFont(size=18, weight="bold"),
            anchor="w"
        )
        theme_title.grid(row=0, column=0, sticky="w", padx=20, pady=(20, 10))
        
        current_theme = self.settings.get("theme", "dark")
        self.theme_var = ctk.StringVar(value=current_theme)
        theme_radio_frame = ctk.CTkFrame(theme_section, fg_color="transparent")
        theme_radio_frame.grid(row=1, column=0, sticky="w", padx=20, pady=(0, 20))
        
        dark_radio = ctk.CTkRadioButton(
            theme_radio_frame,
            text="Scuro",
            variable=self.theme_var,
            value="dark",
            command=self.change_theme
        )
        dark_radio.grid(row=0, column=0, padx=(0, 20))
        
        light_radio = ctk.CTkRadioButton(
            theme_radio_frame,
            text="Chiaro",
            variable=self.theme_var,
            value="light",
            command=self.change_theme
        )
        light_radio.grid(row=0, column=1, padx=(0, 20))
        
        system_radio = ctk.CTkRadioButton(
            theme_radio_frame,
            text="Sistema",
            variable=self.theme_var,
            value="system",
            command=self.change_theme
        )
        system_radio.grid(row=0, column=2)
        
        # About section
        about_section = ctk.CTkFrame(settings_frame)
        about_section.grid(row=2, column=0, sticky="ew", padx=20, pady=(0, 20))
        
        about_title = ctk.CTkLabel(
            about_section,
            text="Informazioni",
            font=ctk.CTkFont(size=18, weight="bold"),
            anchor="w"
        )
        about_title.grid(row=0, column=0, sticky="w", padx=20, pady=(20, 10))
        
        about_text = ctk.CTkLabel(
            about_section,
            text="RENTRI Manager - Complete Edition + Gestione FIR\n\n"
                 "✅ Gestione fornitori con ricerca avanzata\n"
                 "✅ Vidimazione automatizzata FIR\n"
                 "✅ Dashboard moderno con statistiche\n"
                 "✅ PDF Tools integrati\n"
                 "✅ Logo personalizzabile\n"
                 "✅ Tema scuro/chiaro\n"
                 "✅ Interface moderna con CustomTkinter\n"
                 "✅ Avvio a schermo intero (FIX cross-platform)\n"
                 "✅ Progress window sempre in primo piano\n"
                 "✅ Gestione certificato con date e aggiornamento\n"
                 "✅ Gestione FIR con tabella e ricerca avanzata\n"
                 "✅ API Annullamento FIR completamente funzionante\n\n"
                 "Progettata per massima usabilità e performance",
            font=ctk.CTkFont(size=14),
            anchor="w",
            justify="left"
        )
        about_text.grid(row=1, column=0, padx=20, pady=(0, 20), sticky="w")
    
    def browse_logo_file(self):
        file_path = filedialog.askopenfilename(
            title="Seleziona file logo",
            filetypes=[
                ("Image files", "*.png *.jpg *.jpeg *.gif *.bmp"),
                ("PNG files", "*.png"),
                ("JPEG files", "*.jpg *.jpeg"),
                ("All files", "*.*")
            ]
        )
        if file_path:
            self.logo_path_entry.delete(0, "end")
            self.logo_path_entry.insert(0, file_path)
    
    def save_logo_settings(self):
        logo_text = self.logo_text_entry.get().strip()
        logo_path = self.logo_path_entry.get().strip()
        
        if not logo_text:
            logo_text = "RENTRI"
        
        # Validate logo path if provided
        if logo_path and not os.path.exists(logo_path):
            messagebox.showerror("Errore", "Il file immagine selezionato non esiste")
            return
        
        # Save settings
        self.settings.set("logo_text", logo_text)
        self.settings.set("logo_path", logo_path)
        
        # Update logo display
        self.load_custom_logo()
        
        messagebox.showinfo("Successo", "Impostazioni logo salvate!")
    
    def reset_logo_settings(self):
        if messagebox.askyesno("Conferma", "Ripristinare le impostazioni logo predefinite?"):
            self.settings.set("logo_text", "RENTRI")
            self.settings.set("logo_path", "")
            
            # Update UI
            self.logo_text_entry.delete(0, "end")
            self.logo_text_entry.insert(0, "RENTRI")
            self.logo_path_entry.delete(0, "end")
            
            # Update logo display
            self.load_custom_logo()
            
            messagebox.showinfo("Successo", "Impostazioni logo ripristinate!")
    
    def change_theme(self):
        """Cambia tema dalle impostazioni"""
        theme = self.theme_var.get()
        ctk.set_appearance_mode(theme)
        self.settings.set("theme", theme)
        
        # Update switch state
        if theme == "dark":
            self.theme_switch.select()
        else:
            self.theme_switch.deselect()
        
        dbg(f"Tema cambiato a: {theme}")
    
    def toggle_theme(self):
        """Toggle tema dalla sidebar"""
        if self.theme_switch.get():
            new_theme = "dark"
        else:
            new_theme = "light"
        
        ctk.set_appearance_mode(new_theme)
        self.settings.set("theme", new_theme)
        
        # Update radio buttons if settings are visible
        if hasattr(self, 'theme_var'):
            self.theme_var.set(new_theme)
        
        dbg(f"Tema toggle: {new_theme}")
    
    def run(self):
        self.root.mainloop()

def main():
    try:
        app = ModernRentriManager()
        app.run()
    except Exception as e:
        messagebox.showerror("Errore Fatale", f"Errore durante l'avvio dell'applicazione:\n{str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()