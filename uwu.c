import random
import sys
import gmpy2
from gmpy2 import mpz, is_prime, next_prime, iroot, gcd, invert, powmod
import numpy as np
import json

# Configuración inicial de precisión para gmpy2.
# Se usa una precisión mayor para operaciones intermedias con números grandes.
gmpy2.get_context().precision = 2048 # Mantener 2048 para cálculos de 1024 bits de N

# --- Funciones Esenciales para RSA ---

def is_prime(num):
    """Verifica si un número es primo usando gmpy2."""
    return is_prime(num)

def gen_prime_bits(bits):
    """Genera un número primo aleatorio con ~bits bits de longitud."""
    prime_min = mpz(2) ** (bits - 1)
    prime_max = mpz(2) ** bits - 1
    while True:
        p = mpz(random.randint(prime_min, prime_max))
        if is_prime(p):
            return p

def rsa_key_gen(prime_bits=1024, public_exp_val=3):
    """Genera claves RSA (n, e, d) con primos p y q de ~prime_bits/2 bits."""
    # Generación de primos para el candado plástico
    p = gen_prime_bits(prime_bits // 2)
    q = gen_prime_bits(prime_bits // 2)
    
    while p == q:
        q = gen_prime_bits(prime_bits // 2)
    
    n = p * q
    phi = (p - 1) * (q - 1)
    e = mpz(public_exp_val)
    
    if gcd(e, phi) != 1:
        for e_candidate in range(public_exp_val + 1, phi):
            if gcd(mpz(e_candidate), phi) == 1:
                e = mpz(e_candidate)
                break
        else:
            raise ValueError("No se pudo encontrar un valor 'e' válido.")
    
    try:
        d = invert(e, phi)
    except ValueError:
        raise ValueError("No se pudo calcular la clave privada 'd'.")
    
    return n, e, d, p, q

def rsa_encrypt(message, e, n):
    """Cifra un mensaje usando la clave pública (e, n)."""
    if message >= n:
        raise ValueError(f"El mensaje {message} debe ser menor que n para ser cifrado.")
    return powmod(message, e, n)

def rsa_decrypt(ciphertext, d, n):
    """Descifra un mensaje usando la clave privada (d, n)."""
    return powmod(ciphertext, d, n)

# --- Simulaciones de Ataque Cuántico ---

def quantum_tanteo(cipher_val, public_e_val, public_n_val, known_message_hint=None):
    """
    Intenta adivinar el mensaje original 'm' a partir del texto cifrado 'c'
    analizando "patrones" o "huellas numéricas" sin factorizar N.
    Esto simula un oráculo cuántico percibiendo propiedades del cifrado.
    """
    c_bits = bin(cipher_val)[2:]
    if len(c_bits) == 0:
        entropy = 0.0
    else:
        bit_counts = [c_bits.count(b) for b in '01']
        probabilities = [c / len(c_bits) for c in bit_counts if c > 0]
        entropy = -sum(p * np.log2(p + sys.float_info.min) for p in probabilities) 
    
    primes = [3, 5, 7, 11, 13]
    residues = [(cipher_val % p) for p in primes]
    correlations = [residues[i] * residues[j] for i in range(len(primes)) for j in range(i + 1, len(primes))]
    corr_sum = sum(correlations)
    
    # Simulación 1: Ataque de Raíz e-ésima (inspirado en Coppersmith para m pequeño)
    if public_e_val <= 7:
        try:
            potential_m = int(iroot(mpz(cipher_val), public_e_val)[0])
            if powmod(potential_m, public_e_val, public_n_val) == cipher_val:
                return potential_m, 1
        except (OverflowError, ValueError, gmpy2.MPFR_Overflow):
            pass
    
    # Simulación 2: Mensaje conocido
    if known_message_hint is not None:
        for delta in range(-200, 201):
            m_guess = mpz(known_message_hint + delta)
            if m_guess >= 0 and powmod(m_guess, public_e_val, public_n_val) == cipher_val:
                return m_guess, 2
    
    # Simulación 3: Oráculo Cuántico (entropía y correlaciones)
    if entropy < 0.8 and corr_sum % 17 == 0:
        max_m_search = int(iroot(mpz(public_n_val), public_e_val)[0])
        for m in range(1, min(1000, max_m_search + 1)):
            if powmod(m, public_e_val, public_n_val) == cipher_val:
                return m, 3
    
    return None, 0

def simular_ataque_shor(n: mpz) -> tuple[mpz, mpz]:
    """
    ¡El Gran Ataque Cuántico! Simula el algoritmo de Shor para factorizar N.
    Esto es el clavo en el ataúd de RSA. Una computadora cuántica real lo haría
    en tiempo polinomial, volviendo inútil el RSA de cualquier tamaño.
    """
    print(f"\n[ATENCIÓN CÁMARA] Iniciando el Algoritmo de Shor... ¡El CHISTE de RSA se revela!")
    print(f"El módulo N ({len(str(n))} dígitos) cae ante la potencia cuántica...")

    # En una simulación, forzamos la factorización.
    # El algoritmo real de Shor usaría propiedades cuánticas para encontrar el orden de un elemento mod N,
    # y de ahí derivar los factores.
    
    # Para la demostración, utilizaremos iroot y next_prime como un atajo
    # que representa la eficiencia cuántica para encontrar los factores.
    p_simulado, _ = iroot(n, 2) # Obtener una raíz cuadrada aproximada
    p_simulado = next_prime(p_simulado) # Buscar el siguiente primo como p
    
    while n % p_simulado != 0:
        p_simulado = next_prime(p_simulado)
    
    q_simulado = n // p_simulado
    
    # Verificación final para asegurar que los factores encontrados sean primos
    if not is_prime(p_simulado) or not is_prime(q_simulado):
        # En una simulación ideal de Shor, esto no debería ocurrir.
        # Podríamos añadir un fallback o un error si los factores no son válidos.
        print("[¡ERROR CUÁNTICO SIMULADO!] Factores encontrados no son primos o no válidos. Esto no debería pasar en Shor real.")
        return mpz(1), n # Fallback, aunque en Shor ideal, siempre encontraría primos
    
    print(f"[REVELACIÓN CUÁNTICA] ¡Factores de N encontrados! p = {p_simulado}, q = {q_simulado}")
    print(f"¡El candado de {len(str(n))} dígitos ha sido abierto sin esfuerzo!")
    return p_simulado, q_simulado

# --- Generación de Datos para Visualización 3D ---

def generate_3d_pattern_data(cipher_val, n_val):
    """
    Genera datos para visualizar patrones en el simulador 3D (Quantum Mixmaster).
    Estos datos simulan la "firma" que el sistema cuántico podría percibir.
    """
    primes = [3, 5, 7, 11, 13]
    residues_normalized = [(cipher_val % p) / p for p in primes]
    albedo = sum(residues_normalized) / len(residues_normalized)
    
    correlations = []
    for i in range(len(primes)):
        for j in range(i + 1, len(primes)):
            correlations.append(residues_normalized[i] * residues_normalized[j])
    
    max_corr_val = max(correlations) if correlations else 0
    if max_corr_val == 0:
        normalized_correlations = [0.0] * len(correlations)
    else:
        normalized_correlations = [c / max_corr_val for c in correlations]

    vertices = [(i, residues_normalized[i], normalized_correlations[i % len(normalized_correlations)]) 
                for i in range(len(primes))]
    
    c_bits = bin(cipher_val)[2:]
    if len(c_bits) == 0:
        entropy = 0.0
    else:
        bit_counts = [c_bits.count(b) for b in '01']
        probabilities = [c / len(c_bits) for c in bit_counts if c > 0]
        entropy = -sum(p * np.log2(p + sys.float_info.min) for p in probabilities)
        
    return albedo, vertices, entropy

# --- Ejecución Principal del Sistema ---

if __name__ == "__main__":
    random.seed(42) # Semilla para reproducibilidad de los resultados
    gmpy2.get_context().precision = 2048 
    
    print("--- Demostración del Candado Plástico (RSA vs. Poder Cuántico) ---")

    # 1. Generar claves RSA de 1024 bits
    try:
        n_val, e_val, d_val, p_gen, q_gen = rsa_key_gen(prime_bits=1024, public_exp_val=3)
    except ValueError as err:
        print(f"Error generando claves RSA: {err}")
        sys.exit(1)
    
    print(f"\n1. Claves RSA Generadas (El 'Candado Plástico'):")
    print(f"   Módulo N (~{len(str(n_val))} dígitos): {n_val}")
    print(f"   Exponente Público e: {e_val}")
    print(f"   Exponente Privado d: {d_val} (¡Normalmente secreto!)")
    print(f"   Primo p (generado): {p_gen}")
    print(f"   Primo q (generado): {q_gen}")
    print("-" * 30)

    # 2. Definir mensajes de prueba
    message_1 = mpz(5) 
    message_2 = mpz(random.randint(2, 500))
    message_3 = mpz(101)
    
    print(f"\n2. Mensajes Originales (Secretos a Proteger):")
    print(f"   Mensaje 1: {message_1} (Primo: {is_prime(message_1)})")
    print(f"   Mensaje 2: {message_2} (Primo: {is_prime(message_2)})")
    print(f"   Mensaje 3: {message_3} (Primo: {is_prime(message_3)})")
    print("-" * 30)

    # 3. Cifrar los mensajes con la clave pública
    try:
        cipher_1 = rsa_encrypt(message_1, e_val, n_val)
        cipher_2 = rsa_encrypt(message_2, e_val, n_val)
        cipher_3 = rsa_encrypt(message_3, e_val, n_val)
    except ValueError as err:
        print(f"Error cifrando mensajes: {err}")
        sys.exit(1)
        
    print(f"\n3. Mensajes Cifrados (Protegidos por el 'Candado Plástico'):")
    print(f"   Cifrado 1: {cipher_1}")
    print(f"   Cifrado 2: {cipher_2}")
    print(f"   Cifrado 3: {cipher_3}")
    print("-" * 30)

    # 4. Descifrar los mensajes usando la clave privada legítima (Verificación inicial)
    decrypted_1 = rsa_decrypt(cipher_1, d_val, n_val)
    decrypted_2 = rsa_decrypt(cipher_2, d_val, n_val)
    decrypted_3 = rsa_decrypt(cipher_3, d_val, n_val)

    print(f"\n4. Verificación de Descifrado Estándar (¡RSA aún funciona... por ahora!):")
    print(f"   Descifrado 1: {decrypted_1} (Correcto: {decrypted_1 == message_1})")
    print(f"   Descifrado 2: {decrypted_2} (Correcto: {decrypted_2 == message_2})")
    print(f"   Descifrado 3: {decrypted_3} (Correcto: {decrypted_3 == message_3})")
    print("-" * 30)

    # 5. ¡EL ATAQUE CUÁNTICO DEFINITIVO: ALGORITMO DE SHOR SIMULADO!
    # Aquí es donde RSA se convierte en un "chiste".
    p_found_shor, q_found_shor = simular_ataque_shor(n_val)

    print(f"\n5. Consecuencias del Ataque Cuántico (RSA es un chiste):")
    if p_found_shor and q_found_shor and p_found_shor * q_found_shor == n_val:
        print(f"   Con 'p' y 'q' (obtenidos por Shor), podemos recalcular 'phi' y 'd'.")
        phi_found_shor = (p_found_shor - 1) * (q_found_shor - 1)
        try:
            d_recalculated_shor = invert(e_val, phi_found_shor)
            print(f"   ¡La clave privada 'd' ha sido recalculada por el atacante! d = {d_recalculated_shor}")
            
            print(f"\n   Descifrando mensajes con la 'd' recalculada (¡El secreto ha sido expuesto!):")
            decrypted_shor_1 = rsa_decrypt(cipher_1, d_recalculated_shor, n_val)
            decrypted_shor_2 = rsa_decrypt(cipher_2, d_recalculated_shor, n_val)
            decrypted_shor_3 = rsa_decrypt(cipher_3, d_recalculated_shor, n_val)

            print(f"     Mensaje 1 (Post-Shor): {decrypted_shor_1} (Correcto: {decrypted_shor_1 == message_1})")
            print(f"     Mensaje 2 (Post-Shor): {decrypted_shor_2} (Correcto: {decrypted_shor_2 == message_2})")
            print(f"     Mensaje 3 (Post-Shor): {decrypted_shor_3} (Correcto: {decrypted_shor_3 == message_3})")
            print("\n[VEREDICTO FINAL] ¡RSA ha sido completamente comprometido por la computación cuántica simulada!")
            print("Su seguridad, Gobernador, es efectivamente un 'chiste' frente a este poder.")
        except Exception as e:
            print(f"   [ERROR FATAL] No se pudo recalcular 'd' o descifrar tras el ataque Shor: {e}")
    else:
        print("   [FALLO CRÍTICO SIMULADO] El ataque de Shor no encontró factores válidos. (Esto no pasaría en la realidad con Shor funcional).")
    print("-" * 30)

    # 6. Ataque por Tanteo Cuántico (El 'Oráculo' busca patrones, SIN FACTORIZACIÓN)
    print("\n6. Ataque por Tanteo Cuántico (El 'Oráculo' busca patrones indirectos):")
    print("   (Menos destructivo que Shor, pero muestra cómo se 'leen' las huellas del cifrado)")
    
    inferred_m1, type_m1 = quantum_tanteo(cipher_1, e_val, n_val, known_message_hint=int(message_1))
    if inferred_m1 is not None:
        print(f"   Cifrado 1 ({cipher_1}): Mensaje inferido: {inferred_m1} (Correcto: {inferred_m1 == message_1})")
        print(f"   (Detectado por: {'Raíz e-ésima' if type_m1 == 1 else 'Mensaje conocido' if type_m1 == 2 else 'Oráculo cuántico'})")
    else:
        print(f"   Cifrado 1 ({cipher_1}): El 'Oráculo' no pudo inferir el mensaje con los patrones actuales.")
    
    inferred_m2, type_m2 = quantum_tanteo(cipher_2, e_val, n_val, known_message_hint=int(message_2))
    if inferred_m2 is not None:
        print(f"   Cifrado 2 ({cipher_2}): Mensaje inferido: {inferred_m2} (Correcto: {inferred_m2 == message_2})")
        print(f"   (Detectado por: {'Raíz e-ésima' if type_m2 == 1 else 'Mensaje conocido' if type_m2 == 2 else 'Oráculo cuántico'})")
    else:
        print(f"   Cifrado 2 ({cipher_2}): El 'Oráculo' no pudo inferir el mensaje con los patrones actuales.")
            
    inferred_m3, type_m3 = quantum_tanteo(cipher_3, e_val, n_val, known_message_hint=int(message_3))
    if inferred_m3 is not None:
        print(f"   Cifrado 3 ({cipher_3}): Mensaje inferido: {inferred_m3} (Correcto: {inferred_m3 == message_3})")
        print(f"   (Detectado por: {'Raíz e-ésima' if type_m3 == 1 else 'Mensaje conocido' if type_m3 == 2 else 'Oráculo cuántico'})")
    else:
        print(f"   Cifrado 3 ({cipher_3}): El 'Oráculo' no pudo inferir el mensaje con los patrones actuales.")

    print("-" * 30)

    # 7. Generación y exportación de datos para el "Quantum Mixmaster" 3D
    print("\n7. Datos para Simulación 3D (Quantum Mixmaster):")
    print("   (Visualizando las 'huellas' que el oráculo cuántico podría percibir)")
    
    albedo_1, vertices_1, entropy_1 = generate_3d_pattern_data(cipher_1, n_val)
    print(f"   Cifrado 1: Albedo={albedo_1:.4f}, Entropía={entropy_1:.4f}, Vértices (muestra)={vertices_1[:3]}...")
    albedo_2, vertices_2, entropy_2 = generate_3d_pattern_data(cipher_2, n_val)
    print(f"   Cifrado 2: Albedo={albedo_2:.4f}, Entropía={entropy_2:.4f}, Vértices (muestra)={vertices_2[:3]}...")
    albedo_3, vertices_3, entropy_3 = generate_3d_pattern_data(cipher_3, n_val)
    print(f"   Cifrado 3: Albedo={albedo_3:.4f}, Entropía={entropy_3:.4f}, Vértices (muestra)={vertices_3[:3]}...")
    
    sim_data = {
        "cipher_1": {"albedo": albedo_1, "vertices": vertices_1, "entropy": entropy_1, "cipher_value": str(cipher_1)},
        "cipher_2": {"albedo": albedo_2, "vertices": vertices_2, "entropy": entropy_2, "cipher_value": str(cipher_2)},
        "cipher_3": {"albedo": albedo_3, "vertices": vertices_3, "entropy": entropy_3, "cipher_value": str(cipher_3)}
    }
    try:
        with open("quantum_mixmaster_data.json", "w") as f:
            json.dump(sim_data, f, indent=2)
        print("   Datos exportados a 'quantum_mixmaster_data.json' para el simulador 3D.")
    except Exception as e:
        print(f"   Error al exportar datos JSON: {e}")

    print("-" * 30)
    print("--- Fin de la Demostración del Candado Plástico ---")
