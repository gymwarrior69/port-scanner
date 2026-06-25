"""
Απλό Port Scanner - Εκπαιδευτικό Script
-----------------------------------------
Σκοπός: να καταλάβουμε πώς δουλεύουν τα sockets στην Python
και πώς ελέγχουμε αν μια πόρτα είναι ανοιχτή σε έναν host.

ΣΗΜΑΝΤΙΚΟ: Χρησιμοποίησέ το ΜΟΝΟ σε δικά σου συστήματα/δίκτυα
ή σε συστήματα που έχεις ρητή άδεια να ελέγξεις (π.χ. localhost,
ή VM που έχεις φτιάξει εσύ). Το να σκανάρεις ports σε δίκτυα
που δεν σου ανήκουν χωρίς άδεια είναι παράνομο σε πολλές χώρες.
"""

import socket  # βιβλιοθήκη για δικτυακή επικοινωνία (TCP/IP)

# Dictionary: port -> όνομα υπηρεσίας (θυμάσαι, το είδαμε στο Βήμα 2)
KNOWN_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    443: "HTTPS",
    3306: "MySQL",
    8080: "HTTP-Alt"
}


def scan_port(host, port, timeout=1):
    """
    Ελέγχει αν μια συγκεκριμένη πόρτα είναι ανοιχτή σε έναν host.

    Πώς δουλεύει:
    1. Φτιάχνουμε ένα "socket" - σαν να ανοίγουμε μια "πρίζα"
       επικοινωνίας στο δίκτυο.
    2. Προσπαθούμε να συνδεθούμε (connect) στο host:port.
    3. Αν η σύνδεση πετύχει -> η πόρτα είναι ΑΝΟΙΧΤΗ.
    4. Αν αποτύχει/κάνει timeout -> η πόρτα είναι ΚΛΕΙΣΤΗ.
    """
    # AF_INET = χρησιμοποιούμε IPv4
    # SOCK_STREAM = χρησιμοποιούμε TCP (όχι UDP)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)  # μην περιμένεις για πάντα να απαντήσει

    try:
        # connect_ex() επιστρέφει 0 αν η σύνδεση πέτυχε
        result = sock.connect_ex((host, port))
        return result == 0
    finally:
        sock.close()  # ΠΑΝΤΑ κλείνουμε το socket μετά τη χρήση


def scan_range(host, start_port, end_port):
    """
    Σκανάρει ένα εύρος (range) από ports σε έναν host
    και επιστρέφει λίστα με τα ανοιχτά.
    """
    open_ports = []

    print(f"\nScanning {host} από port {start_port} έως {end_port}...\n")

    # range(start, end+1) γιατί το range() στην Python ΔΕΝ
    # συμπεριλαμβάνει το τελευταίο νούμερο
    for port in range(start_port, end_port + 1):
        if scan_port(host, port):
            service = KNOWN_SERVICES.get(port, "Unknown")
            print(f"[OPEN]  Port {port:5d} -> {service}")
            open_ports.append(port)

    return open_ports


def scan_network(network_prefix, start_host, end_host, start_port, end_port):
    """
    Σκανάρει ΠΟΛΛΟΥΣ hosts σε ένα δίκτυο, και για ΚΑΘΕ host
    ελέγχει ένα εύρος από ports.

    Παράδειγμα: scan_network("192.168.1", 1, 10, 20, 25)
    θα ελέγξει τις IPs 192.168.1.1 έως 192.168.1.10,
    και σε καθεμία θα ελέγξει τα ports 20 έως 25.

    Επιστρέφει ένα dictionary: { host: [λίστα ανοιχτών ports] }
    αλλά ΜΟΝΟ για hosts που είχαν τουλάχιστον ένα ανοιχτό port.
    """
    results = {}  # άδειο dictionary: host -> λίστα ανοιχτών ports

    # ΕΞΩΤΕΡΙΚΟ loop: διατρέχει κάθε host στο δίκτυο
    for last_octet in range(start_host, end_host + 1):
        host = f"{network_prefix}.{last_octet}"  # π.χ. "192.168.1.5"

        # ΕΣΩΤΕΡΙΚΟ loop: για ΑΥΤΟ το host, σκανάρισε όλα τα ports
        # (αυτό είναι ΑΚΡΙΒΩΣ η ίδια scan_range() που είχαμε ήδη!)
        open_ports = scan_range(host, start_port, end_port)

        # αν βρέθηκε τουλάχιστον ένα ανοιχτό port σε αυτό το host,
        # το αποθηκεύουμε στο dictionary αποτελεσμάτων
        if open_ports:
            results[host] = open_ports

    return results


def main():
    print("=== Simple Port Scanner ===")
    print("1) Σκανάρισμα ΕΝΟΣ host")
    print("2) Σκανάρισμα ΟΛΟΚΛΗΡΟΥ δικτύου (πολλά hosts)")
    choice = input("Επιλογή (1 ή 2): ").strip()

    if choice == "2":
        # --- Σκανάρισμα δικτύου ---
        prefix = input("Πρόθεμα δικτύου (π.χ. 192.168.1): ").strip()
        start_host = int(input("Από τελευταίο octet (π.χ. 1): ").strip())
        end_host = int(input("Έως τελευταίο octet (π.χ. 254): ").strip())
        start_port = int(input("Από port: ").strip())
        end_port = int(input("Έως port: ").strip())

        results = scan_network(prefix, start_host, end_host, start_port, end_port)

        print(f"\n=== Αποτελέσματα δικτύου ===")
        if results:
            for host, ports in results.items():
                print(f"{host} -> ανοιχτά ports: {ports}")
        else:
            print("Δεν βρέθηκε κανένας host με ανοιχτό port.")

    else:
        # --- Σκανάρισμα ενός host (όπως πριν) ---
        host = input("Δώσε host/IP για scan (π.χ. localhost ή 127.0.0.1): ").strip()
        start = int(input("Από port: ").strip())
        end = int(input("Έως port: ").strip())

        open_ports = scan_range(host, start, end)

        print(f"\nΣύνολο ανοιχτών ports: {len(open_ports)}")
        if open_ports:
            print(f"Ανοιχτά ports: {open_ports}")
        else:
            print("Δεν βρέθηκαν ανοιχτά ports.")


# Αυτό σημαίνει: "τρέξε το main() ΜΟΝΟ αν αυτό το αρχείο
# τρέχει απευθείας, όχι αν γίνεται import από άλλο script"
if __name__ == "__main__":
    main()
