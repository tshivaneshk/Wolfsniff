import hashlib
import binascii

def extract_ja3(packet):
    try:
        from scapy.layers.tls.all import TLS, TLSClientHello
        if packet.haslayer(TLSClientHello):
            ch = packet[TLSClientHello]
            version = ch.version if hasattr(ch, 'version') else 0
            
            # Ciphers
            ciphers = []
            if hasattr(ch, 'ciphers'):
                ciphers = [str(c) for c in ch.ciphers]
                
            # Extensions
            exts = []
            if hasattr(ch, 'ext'):
                for e in ch.ext:
                    exts.append(str(e.type))
                    
            ja3_string = f"{version},{'-'.join(ciphers)},{'-'.join(exts)},,"
            return hashlib.md5(ja3_string.encode()).hexdigest()
    except Exception:
        pass
    return None

MALICIOUS_JA3 = {
    "51c64c77e60f3980eea90869b68c58a8": "Cobalt Strike Beacon",
    "6734f37431670b3ab4292b8f60f29984": "Trickbot C2",
    "b32309a26951912be7dba376398abc3b": "Emotet Loader",
    "28c117d969248df92c423ba0c5a31a10": "Metasploit Meterpreter"
}
