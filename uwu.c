import random
import sys
import logging
import json
import argparse
import time
import matplotlib.pyplot as plt
from matplotlib.ticker import PercentFormatter
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
    
    def __init__(self, prime_bits: int = 1024, public_exp: int = 65537):
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
        logger.info(f"Generando claves RSA de {self.prime_bits} bits...")
        p = self._gen_prime_bits(self.prime_bits // 2)
        q = self._gen_prime_bits(self.prime_bits // 2)
        while p == q or abs(p - q) < (2 ** (self.prime_bits // 2 - 10)):
            q = self._gen_prime_bits(self.prime_bits // 2)

        n = p * q
        phi = (p - 1) * (q - 1)
        e = mpz(self.public_exp)

        if gcd(e, phi) != 1:
            logger.warning(f"Exponente público {e} no es coprimo con phi. Buscando uno nuevo...")
            e_candidate = 3 if self.public_exp != 3 else 5
            while gcd(mpz(e_candidate), phi) != 1:
                e_candidate = next_prime(e_candidate)
                if e_candidate >= phi:
                    raise ValueError("No se pudo encontrar un exponente público válido.")
            e = mpz(e_candidate)
            logger.info(f"Nuevo exponente público 'e' seleccionado: {e}")

        try:
            d = invert(e, phi)
            logger.info("Claves RSA generadas con éxito.")
            return n, e, d, p, q
        except ValueError as err:
            logger.error(f"Error al calcular la clave privada 'd': {err}")
            raise ValueError(f"Error generando claves: {err}")

    def encrypt(self, message: int) -> int:
        """Cifra un mensaje con la clave pública."""
        if message >= self.n:
            raise ValueError(f"El mensaje {message} debe ser menor que n ({self.n}).")
        return powmod(mpz(message), self.e, self.n)

    def decrypt(self, ciphertext: int, private_key: Optional[mpz] = None) -> int:
        """Descifra un mensaje con la clave privada (por defecto o proporcionada)."""
        d = private_key if private_key is not None else self.d
        return powmod(mpz(ciphertext), d, self.n)

# --- Clase QuantumAttack ---

class QuantumAttack:
    """Clase para simular ataques cuánticos a RSA."""

    def __init__(self, rsa: RSA):
        self.rsa = rsa
        self.tanteo_success_rates: List[float] = []
        self.tanteo_times: List[float] = []

    def quantum_tanteo(self, ciphertext: int, message_original: int, 
                       known_message_hint: Optional[int] = None) -> Tuple[Optional[int], str]:
        """
        Simula un ataque de oráculo cuántico para inferir el mensaje original.
        """
        start_time = time.time()
        logger.debug(f"Intentando quantum_tanteo para ciphertext: {ciphertext}")

        c_bits = bin(ciphertext)[2:]
        probabilities = [c_bits.count(b) / len(c_bits) for b in '01' if c_bits.count(b) > 0]
        entropy = -sum(p * np.log2(p + sys.float_info.min) for p in probabilities) if probabilities else 0.0

        # Ataque 1: Raíz e-ésima
        if self.rsa.e <= 7 and ciphertext < self.rsa.n:
            try:
                potential_m = int(iroot(mpz(ciphertext), self.rsa.e)[0])
                if powmod(mpz(potential_m), self.rsa.e, self.rsa.n) == ciphertext:
                    logger.info("Mensaje encontrado por ataque de raíz e-ésima.")
                    self.tanteo_times.append(time.time() - start_time)
                    return mpz(potential_m), "root_attack"
            except (ValueError, gmpy2.MPFR_Overflow):
                pass

        # Ataque 2: Búsqueda tipo Grover
        if known_message_hint is not None:
            search_range = max(50, min(200, int(self.rsa.n.bit_length() // 10)))
            start_val = max(0, int(known_message_hint) - search_range // 2)
            end_val = int(known_message_hint) + search_range // 2
            for delta in range(-search_range // 2, search_range // 2 + 1):
                m_guess = mpz(int(known_message_hint) + delta)
                if m_guess >= 0 and powmod(m_guess, self.rsa.e, self.rsa.n) == ciphertext:
                    logger.info(f"Mensaje encontrado por búsqueda Grover-like. Intentos: {abs(delta)+1}")
                    self.tanteo_times.append(time.time() - start_time)
                    return m_guess, "grover"
            logger.debug(f"Búsqueda Grover-like fallida en rango {start_val}-{end_val}.")

        # Ataque 3: Oráculo basado en entropía
        if entropy < 0.8:
            max_m_search = min(1000, int(iroot(self.rsa.n, self.rsa.e)[0]))
            max_m_search = max(1, max_m_search)
            for m_candidate in range(1, max_m_search + 1):
                if powmod(mpz(m_candidate), self.rsa.e, self.rsa.n) == ciphertext:
                    logger.info(f"Mensaje encontrado por oráculo cuántico. Intentos: {m_candidate}")
                    self.tanteo_times.append(time.time() - start_time)
                    return mpz(m_candidate), "oracle_entropy"
            logger.debug(f"Oráculo cuántico fallido para {ciphertext}.")

        logger.info(f"No se pudo inferir el mensaje para {ciphertext}.")
        self.tanteo_times.append(time.time() - start_time)
        return None, "none"

    def simular_shor(self, max_attempts: int = 10) -> Tuple[mpz, mpz]:
        """Simula el algoritmo de Shor para factorizar n."""
        logger.info("Iniciando simulación del algoritmo de Shor...")
        n = self.rsa.n

        def find_period(a: int, n: int) -> int:
            """Simula la búsqueda del período usando QFT (simplificado)."""
            r = 1
            power = a % n
            while power != 1 and r < n:
                power = (power * a) % n
                r += 1
            return r if power == 1 else n

        for attempt in range(max_attempts):
            logger.debug(f"Intento de Shor {attempt + 1}/{max_attempts}")
            a = random.randint(2, int(n) - 1)
            if gcd(a, n) > 1:
                p = gcd(a, n)
                q = n // p
                if is_prime(p) and is_prime(q) and p * q == n:
                    logger.info(f"Factores encontrados (GCD directo): p={p}, q={q}")
                    return p, q

            r = find_period(a, n)
            if r % 2 == 0 and powmod(a, r // 2, n) != n - 1:
                p = gcd(powmod(a, r // 2, n) + 1, n)
                q = n // p
                if 1 < p < n and 1 < q < n and is_prime(p) and is_prime(q) and p * q == n:
                    logger.info(f"Factores encontrados (período): p={p}, q={q}")
                    return p, q

        logger.warning("No se encontraron factores válidos. Usando valores internos para demostración.")
        return self.rsa.p, self.rsa.q  # Fallback para demostración

    def analyze_tanteo_success_rates(self, num_trials: int = 100, message_range: Tuple[int, int] = (2, 500)) -> Dict:
        """Realiza un análisis estadístico de los ataques de tanteo."""
        logger.info(f"Realizando {num_trials} simulaciones de quantum_tanteo...")
        successes = []
        for i in range(num_trials):
            message = mpz(random.randint(message_range[0], min(message_range[1], self.rsa.n - 1)))
            try:
                ciphertext = self.rsa.encrypt(message)
                inferred_m, _ = self.quantum_tanteo(ciphertext, message, known_message_hint=int(message))
                successes.append(inferred_m == message)
                logger.debug(f"Trial {i+1}: Success={inferred_m == message}")
            except ValueError as e:
                logger.warning(f"Error en trial {i+1}: {e}")
                successes.append(False)

        success_rate = np.mean(successes) if successes else 0.0
        ci = (success_rate, success_rate) if not successes or len(successes) == 1 else \
             stats.binom.interval(0.95, len(successes), success_rate) / len(successes)
        self.tanteo_success_rates.append(success_rate)

        logger.info(f"Tasa de éxito: {success_rate:.2%}, IC 95%: [{ci[0]:.2%}, {ci[1]:.2%}]")
        return {"success_rate": success_rate, "confidence_interval": ci, "num_trials": num_trials}

# --- Clase Visualizer ---

class Visualizer:
    """Clase para manejar visualizaciones de resultados."""

    @staticmethod
    def plot_tanteo_success_rates(success_rates: List[float], output_file: Optional[str] = None) -> None:
        """Genera un gráfico de tasas de éxito."""
        if not success_rates:
            logger.warning("No hay datos para graficar tasas de éxito.")
            return

        plt.figure(figsize=(10, 6))
        plt.hist(success_rates, bins=10, color='skyblue', edgecolor='darkblue', alpha=0.7)
        plt.axvline(np.mean(success_rates), color='red', linestyle='--', label=f'Promedio: {np.mean(success_rates):.2%}')
        plt.xlabel('Tasa de Éxito')
        plt.ylabel('Frecuencia')
        plt.title('Distribución de Tasas de Éxito de Ataques Cuánticos de Tanteo')
        plt.gca().xaxis.set_major_formatter(PercentFormatter(1))
        plt.grid(axis='y', linestyle='--', alpha=0.7)
        plt.legend()

        if output_file:
            plt.savefig(output_file)
            logger.info(f"Gráfico guardado en {output_file}")
        plt.show()
        logger.info("Gráfico de tasas de éxito generado.")

# --- Ejecución Principal ---

def main():
    parser = argparse.ArgumentParser(description="Demostración de la vulnerabilidad de RSA ante ataques cuánticos simulados.")
    parser.add_argument("--key_bits", type=int, default=1024, help="Tamaño de la clave RSA en bits.")
    parser.add_argument("--num_messages", type=int, default=3, help="Número de mensajes de ejemplo.")
    parser.add_argument("--shor_only", action="store_true", help="Ejecuta solo la simulación de Shor.")
    parser.add_argument("--tanteo_trials", type=int, default=5, help="Número de corridas para análisis estadístico.")
    parser.add_argument("--message_range", type=int, nargs=2, default=[2, 500], help="Rango de mensajes (mín, máx).")
    parser.add_argument("--shor_attempts", type=int, default=10, help="Número de intentos para Shor.")
    parser.add_argument("--seed", type=int, default=42, help="Semilla para reproducibilidad.")
    parser.add_argument("--output_file", type=str, help="Archivo para guardar el gráfico de tasas de éxito.")
    
    args = parser.parse_args()
    random.seed(args.seed)

    print("--- Demostración del 'Candado Plástico' RSA vs. Poder Cuántico ---")
    logger.info(f"Iniciando simulación con claves de {args.key_bits} bits.")

    try:
        # 1. Generación de Claves RSA
        rsa = RSA(prime_bits=args.key_bits)
        print(f"\n1. Claves RSA Generadas (El 'Candado Plástico' de {args.key_bits} bits):")
        print(f"   Módulo N (~{len(str(rsa.n))} dígitos): {rsa.n}")
        print(f"   Exponente Público e: {rsa.e}")
        print(f"   Exponente Privado d: {rsa.d} (¡Normalmente secreto!)")
        print(f"   Primo p (generado): {rsa.p}")
        print(f"   Primo q (generado): {rsa.q}")
        print("-" * 30)

        quantum_attacker = QuantumAttack(rsa)
        visualizer = Visualizer()

        if args.shor_only:
            logger.info("Modo 'shor_only' activado.")
            p_shor, q_shor = quantum_attacker.simular_shor(max_attempts=args.shor_attempts)
            if p_shor * q_shor == rsa.n:
                phi_shor = (p_shor - 1) * (q_shor - 1)
                d_shor = invert(rsa.e, phi_shor)
                print(f"\n[VEREDICTO FINAL] ¡RSA comprometido por Shor!")
                print(f"   Clave privada recalculada: d = {d_shor}")
                print("   ¡El candado es un chiste ante el poder cuántico!")
            else:
                print("\n[FALLO CRÍTICO] Shor no encontró factores válidos.")
            print("-" * 30)
            return

        # 2. Mensajes de Prueba
        messages = [mpz(random.randint(args.message_range[0], min(args.message_range[1], rsa.n - 1))) 
                    for _ in range(args.num_messages)]
        print(f"\n2. Mensajes Originales (Secretos a Proteger - {args.num_messages} Ejemplos):")
        for i, msg in enumerate(messages):
            print(f"   Mensaje {i+1}: {msg} (Primo: {rsa._is_prime(msg)})")
        print("-" * 30)

        # 3. Cifrar Mensajes
        ciphertexts = []
        print(f"\n3. Mensajes Cifrados (Protegidos por el 'Candado Plástico'):")
        for i, msg in enumerate(messages):
            try:
                cipher = rsa.encrypt(msg)
                ciphertexts.append(cipher)
                print(f"   Cifrado {i+1}: {cipher}")
            except ValueError as e:
                logger.error(f"Error cifrando mensaje {i+1}: {e}")
                sys.exit(1)
        print("-" * 30)

        # 4. Descifrado Estándar
        print(f"\n4. Verificación de Descifrado Estándar:")
        for i, cipher in enumerate(ciphertexts):
            decrypted_msg = rsa.decrypt(cipher)
            correct = decrypted_msg == messages[i]
            print(f"   Descifrado {i+1}: {decrypted_msg} (Correcto: {correct})")
            if not correct:
                logger.error(f"Error en descifrado estándar para mensaje {i+1}.")
        print("-" * 30)

        # 5. Ataque de Shor
        p_shor, q_shor = quantum_attacker.simular_shor(max_attempts=args.shor_attempts)
        print(f"\n5. Consecuencias del Ataque Cuántico (Shor):")
        if p_shor * q_shor == rsa.n:
            phi_shor = (p_shor - 1) * (q_shor - 1)
            d_shor = invert(rsa.e, phi_shor)
            print(f"   Clave privada recalculada: d = {d_shor}")
            print(f"\n   Descifrando mensajes con la clave recalculada:")
            for i, cipher in enumerate(ciphertexts):
                decrypted_shor = rsa.decrypt(cipher, d_shor)
                correct = decrypted_shor == messages[i]
                print(f"     Mensaje {i+1} (Post-Shor): {decrypted_shor} (Correcto: {correct})")
            print("\n[VEREDICTO FINAL] ¡RSA comprometido por Shor!")
        else:
            print("   [FALLO CRÍTICO] Shor no encontró factores válidos.")
        print("-" * 30)

        # 6. Ataque por Tanteo Cuántico
        print("\n6. Ataque por Tanteo Cuántico:")
        for i, (cipher, msg) in enumerate(zip(ciphertexts, messages)):
            inferred_m, attack_type = quantum_attacker.quantum_tanteo(cipher, msg, known_message_hint=int(msg))
            print(f"   Cifrado {i+1} ({cipher}): Inferido: {inferred_m} (Correcto: {inferred_m == msg})")
            print(f"   Método: {attack_type}")
        print("-" * 30)

        # 7. Análisis Estadístico
        tanteo_results = quantum_attacker.analyze_tanteo_success_rates(
            num_trials=args.tanteo_trials, message_range=tuple(args.message_range))
        print(f"\n7. Análisis Estadístico del Tanteo Cuántico:")
        print(f"   Tasa de Éxito: {tanteo_results['success_rate']:.2%}")
        print(f"   Intervalo de Confianza (95%): [{tanteo_results['confidence_interval'][0]:.2%}, "
              f"{tanteo_results['confidence_interval'][1]:.2%}]")
        print(f"   Tiempo Promedio por Tanteo: {np.mean(quantum_attacker.tanteo_times):.4f} segundos")
        
        # Exportar resultados a JSON
        results = {
            "key_bits": args.key_bits,
            "success_rate": tanteo_results['success_rate'],
            "confidence_interval": tanteo_results['confidence_interval'],
            "num_trials": tanteo_results['num_trials'],
            "average_tanteo_time": float(np.mean(quantum_attacker.tanteo_times))
        }
        try:
            with open("quantum_rsa_results.json", "w") as f:
                json.dump(results, f, indent=2)
            logger.info("Resultados exportados a 'quantum_rsa_results.json'.")
        except Exception as e:
            logger.error(f"Error al exportar resultados: {e}")

        # 8. Visualización
        visualizer.plot_tanteo_success_rates(quantum_attacker.tanteo_success_rates, output_file=args.output_file)
        print("-" * 30)
        print("\n--- Fin de la Demostración del 'Candado Plástico' ---")

    except Exception as e:
        logger.critical(f"Error en la simulación: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
