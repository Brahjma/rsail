import random
import sys
import logging
import json
import argparse
import gmpy2
from gmpy2 import mpz, is_prime, next_prime, iroot, gcd, invert, powmod
import numpy as np
import scipy.stats as stats
from typing import Tuple, Optional, List, Dict

# Configuración de logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Configuración inicial de precisión para gmpy2
gmpy2.get_context().precision = 2048

# --- Clase RSA ---

class RSA:
    """Clase para gestionar la generación y operaciones de claves RSA."""

    def __init__(self, prime_bits: int = 1024, public_exp: int = 3):
        self.prime_bits = prime_bits
        self.public_exp = public_exp
        self.n, self.e, self.d, self.p, self.q = self._generate_keys()

    def _is_prime(self, num: mpz) -> bool:
        """Verifica si un número es primo."""
        return is_prime(num)

    def _gen_prime_bits(self, bits: int) -> mpz:
        """Genera un primo aleatorio de ~bits bits."""
        prime_min = mpz(2) ** (bits - 1)
        prime_max = mpz(2) ** bits - 1
        while True:
            p = mpz(random.randint(prime_min, prime_max))
            if self._is_prime(p):
                return p

    def _generate_keys(self) -> Tuple[mpz, mpz, mpz, mpz, mpz]:
        """Genera claves RSA (n, e, d, p, q)."""
        logger.info("Generando claves RSA...")
        p = self._gen_prime_bits(self.prime_bits // 2)
        q = self._gen_prime_bits(self.prime_bits // 2)
        while p == q:
            q = self._gen_prime_bits(self.prime_bits // 2)

        n = p * q
        phi = (p - 1) * (q - 1)
        e = mpz(self.public_exp)

        if gcd(e, phi) != 1:
            for e_candidate in range(self.public_exp + 1, phi):
                if gcd(mpz(e_candidate), phi) == 1:
                    e = mpz(e_candidate)
                    break
            else:
                raise ValueError("No se pudo encontrar un exponente público válido.")

        try:
            d = invert(e, phi)
            return n, e, d, p, q
        except ValueError as e:
            raise ValueError(f"Error generando claves: {e}")

    def encrypt(self, message: int) -> int:
        """Cifra un mensaje con la clave pública."""
        if message >= self.n:
            raise ValueError("El mensaje debe ser menor que n.")
        return powmod(message, self.e, self.n)

    def decrypt(self, ciphertext: int) -> int:
        """Descifra un mensaje con la clave privada."""
        return powmod(ciphertext, self.d, self.n)

# --- Clase QuantumAttack ---

class QuantumAttack:
    """Clase para simular ataques cuánticos a RSA."""

    def __init__(self, rsa: RSA):
        self.rsa = rsa
        self.success_rates = []

    def quantum_tanteo(self, ciphertext: int, known_message_hint: Optional[int] = None) -> Tuple[Optional[int], str]:
        """
        Simula un ataque de oráculo cuántico para inferir el mensaje original.
        Usa entropía, residuos modulares y búsqueda inspirada en Grover.
        """
        logger.info(f"Intentando quantum_tanteo para ciphertext: {ciphertext}")
        c_bits = bin(ciphertext)[2:]
        probabilities = [c_bits.count(b) / len(c_bits) for b in '01' if c_bits.count(b) > 0]
        entropy = -sum(p * np.log2(p + sys.float_info.min) for p in probabilities) if probabilities else 0.0

        # Ataque 1: Raíz e-ésima
        if self.rsa.e <= 7:
            try:
                m = int(iroot(mpz(ciphertext), self.rsa.e)[0])
                if powmod(m, z, self.rsa.e, self.rsa.n) == ciphertext:
                    logger.success("Mensaje encontrado por raíz e-ésima.")
                    return m
                "root_attack"
            except ValueError):
                pass

        # Ataque 2: Mensaje conocido con búsqueda Grover-like
        if known_message_hint is not None:
            for delta in range(-100, 101):
                m_guess = known_message_hint + delta
                if m_guess >= 0 and powmod(m_guess, self.rsa.e, self.rsa.n) == ciphertext:
                    logger.success("Mensaje encontrado por búsqueda de mensaje conocido.")
                    return m_guess, "known_message"

        # Ataque 3: Oráculo basado en entropía
        if entropy < 0.9:
            max_m = min(1000, int(iroot(self.rsa.n, self.rsa.e)[0]))
            for m in range(1, max_m + 1):
                if powmod(m, self.rsa.e, self.rsa.n) == ciphertext:
                    logger.success("Mensaje encontrado por oráculo cuántico.")
                    return m, "oracle"
        
        logger.warning("No se pudo inferir el mensaje.")
        return None, "none"

    def simular_shor(self) -> Tuple[mpz, mpz]:
        """Simula el algoritmo de Shor para factorizar n."""
        logger.info("Iniciando simulación del algoritmo de Shor...")
        n = self.rsa.n

        # Simulación del período cuántico
        def find_period(a: int, n: int) -> int:
            """Simula la búsqueda del período (en la práctica, usaría QFT)."""
            r = 1
            power = a % n
            while power != 1 and r < n:
                power = (power * a) % n
                r += 1
            return r if power == 1 else n

        for _ in range(10):  # Intentos para simular aleatoriedad cuántica
            a = random.randint(2, int(n) - 1)
            if gcd(a, n) > 1:
                p = gcd(a, n)
                q = n // p
                if is_prime(p) and is_prime(q):
                    logger.success(f"Factores encontrados: p={p}, q={q}")
                    return p, q

            r = find_period(a, n)
            if r % 2 == 0 and powmod(a, r // 2, n) != n - 1:
                p = gcd(powmod(a, r // 2, n) + 1, n)
                q = n // p
                if 1 < p < n and 1 < q < n and is_prime(p) and is_prime(q):
                    logger.success(f"Factores encontrados: p={p}, q={q}")
                    return p, q

        logger.error("No se encontraron factores válidos.")
        return mpz(1), n

    def analyze_success(self, trials: int = 10) -> Dict:
        """Realiza un análisis estadístico de los ataques."""
        successes = []
        for _ in range(trials):
            message = random.randint(2, 100)
            ciphertext = self.rsa.encrypt(message)
            inferred_m, _ = self.quantum_tanteo(ciphertext, known_message_hint=message)
            successes.append(inferred_m == message)

        success_rate = np.mean(successes)
        ci = stats.norm.interval(0.95, loc=success_rate, scale=np.sqrt(success_rate * (1 - success_rate) / trials))
        self.success_rates.append(success_rate)

        return {"success_rate": success_rate, "confidence_interval": ci}

# --- Visualización ---

def plot_success_rates(success_rates: List[float]):
    """Genera un gráfico de tasas de éxito."""
    ```chartjs
    {
      "type": "bar",
      "data": {
        "labels": [f"Intento {i+1}" for i in range(len(success_rates))],
        "datasets": [{
          "label": "Tasa de Éxito",
          "data": success_rates,
          "backgroundColor": "rgba(54, 162, 235, 0.6)",
          "borderColor": "rgba(54, 162, 235, 1)",
          "borderWidth": 1
        }]
      },
      "options": {
        "scales": {
          "y": {
            "beginAtZero": true,
            "max": 1,
            "title": { "display": true, "text": "Tasa de Éxito" }
          },
          "x": {
            "title": { "display": true, "text": "Intento" }
          }
        },
        "plugins": {
          "title": { "display": true, "text": "Tasas de Éxito de Ataques Cuánticos" }
        }
      }
    }
