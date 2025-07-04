"""
Enhanced Security Analysis for fRSA (Transcendental Function-Based Encryption)
This module provides comprehensive security analysis tools for the fRSA cryptographic system.
"""

import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from typing import Dict, List, Tuple, Optional
import math
import random
import time
from collections import Counter
import hashlib
import secrets
from frsa_rrsa_redacted import fRSA_keygen, fRSA_encrypt, fRSA_decrypt, TranscendentalFunctionBasedEncryption

class SecurityAnalyzer:
    """
    Comprehensive security analysis for fRSA cryptographic system
    """
    
    def __init__(self, key_size: int = 1024):
        self.key_size = key_size
        self.tfbe = TranscendentalFunctionBasedEncryption()
        
    def analyze_randomness_quality(self, num_samples: int = 1000) -> Dict[str, float]:
        """
        Analyze the quality of randomness in key generation and encryption
        """
        print("🔍 Analyzing randomness quality...")
        
        # Generate multiple key pairs
        public_keys = []
        private_keys = []
        
        for i in range(num_samples):
            if i % 100 == 0:
                print(f"  Generating key pair {i+1}/{num_samples}")
            pub_key, priv_key = fRSA_keygen(self.key_size)
            public_keys.append(pub_key)
            private_keys.append(priv_key)
        
        # Analyze randomness in various components
        analysis = {}
        
        # 1. Modulus (n) distribution analysis
        moduli = [pub_key[0] for pub_key in public_keys]
        analysis['modulus_entropy'] = self._calculate_entropy(moduli)
        
        # 2. Seed distribution analysis
        seeds = [pub_key[2] for pub_key in public_keys]
        analysis['seed_entropy'] = self._calculate_entropy(seeds)
        analysis['seed_uniqueness'] = len(set(seeds)) / len(seeds)
        
        # 3. Transcendental base distribution
        bases = []
        for seed in seeds[:min(100, len(seeds))]:  # Limit for performance
            base = self.tfbe.generate_transcendental_base(seed)
            bases.append(float(base))
        
        analysis['transcendental_base_entropy'] = self._calculate_entropy(bases)
        analysis['transcendental_base_mean'] = np.mean(bases)
        analysis['transcendental_base_std'] = np.std(bases)
        
        # 4. Bit-level randomness test
        bit_sequences = []
        for modulus in moduli[:min(50, len(moduli))]:
            bit_seq = bin(modulus)[2:]  # Remove '0b' prefix
            bit_sequences.append(bit_seq)
        
        all_bits = ''.join(bit_sequences)
        analysis['bit_entropy'] = self._calculate_bit_entropy(all_bits)
        analysis['bit_balance'] = all_bits.count('1') / len(all_bits)
        
        return analysis
    
    def analyze_ciphertext_distribution(self, num_samples: int = 1000) -> Dict[str, float]:
        """
        Analyze the distribution of ciphertext values
        """
        print("🔍 Analyzing ciphertext distribution...")
        
        # Generate a key pair
        pub_key, priv_key = fRSA_keygen(self.key_size)
        n = pub_key[0]
        
        # Generate plaintexts and corresponding ciphertexts
        plaintexts = []
        ciphertexts = []
        
        for i in range(num_samples):
            if i % 100 == 0:
                print(f"  Encrypting message {i+1}/{num_samples}")
            
            # Generate random plaintext
            plaintext = secrets.randbelow(n)
            plaintexts.append(plaintext)
            
            # Encrypt
            ciphertext = fRSA_encrypt(plaintext, pub_key)
            ciphertexts.append(ciphertext)
        
        # Analyze distributions
        analysis = {}
        
        # 1. Ciphertext entropy
        analysis['ciphertext_entropy'] = self._calculate_entropy(ciphertexts)
        
        # 2. Plaintext vs ciphertext correlation
        correlation = np.corrcoef(plaintexts, ciphertexts)[0, 1]
        analysis['plaintext_ciphertext_correlation'] = correlation
        
        # 3. Ciphertext uniformity test
        # Divide range into bins and check distribution
        num_bins = 100
        bin_counts, _ = np.histogram(ciphertexts, bins=num_bins)
        expected_count = len(ciphertexts) / num_bins
        
        # Chi-square test for uniformity
        chi_square = sum((count - expected_count)**2 / expected_count for count in bin_counts)
        analysis['ciphertext_uniformity_chi_square'] = chi_square
        
        # 4. Avalanche effect test
        avalanche_scores = []
        for i in range(min(100, num_samples)):
            if i % 50 == 0:
                print(f"  Testing avalanche effect {i+1}/100")
            
            # Original plaintext
            original = plaintexts[i]
            original_cipher = ciphertexts[i]
            
            # Flip one bit
            bit_position = secrets.randbelow(original.bit_length())
            modified = original ^ (1 << bit_position)
            
            # Encrypt modified plaintext
            if modified < n:
                modified_cipher = fRSA_encrypt(modified, pub_key)
                
                # Calculate bit difference
                xor_result = original_cipher ^ modified_cipher
                bit_diff = bin(xor_result).count('1')
                total_bits = max(original_cipher.bit_length(), modified_cipher.bit_length())
                
                if total_bits > 0:
                    avalanche_ratio = bit_diff / total_bits
                    avalanche_scores.append(avalanche_ratio)
        
        analysis['avalanche_effect_mean'] = np.mean(avalanche_scores) if avalanche_scores else 0
        analysis['avalanche_effect_std'] = np.std(avalanche_scores) if avalanche_scores else 0
        
        return analysis
    
    def analyze_transcendental_security(self, num_samples: int = 500) -> Dict[str, float]:
        """
        Analyze security aspects specific to transcendental functions
        """
        print("🔍 Analyzing transcendental function security...")
        
        analysis = {}
        
        # 1. Transcendental base predictability
        seeds = [secrets.randbelow(1000000) for _ in range(num_samples)]
        bases = []
        
        for i, seed in enumerate(seeds):
            if i % 100 == 0:
                print(f"  Generating transcendental base {i+1}/{num_samples}")
            base = self.tfbe.generate_transcendental_base(seed)
            bases.append(float(base))
        
        # Check for patterns in bases
        analysis['transcendental_base_entropy'] = self._calculate_entropy(bases)
        analysis['transcendental_base_variance'] = np.var(bases)
        
        # 2. Seed-to-base mapping analysis
        # Test if similar seeds produce similar bases
        seed_base_correlations = []
        for i in range(min(100, num_samples - 1)):
            seed1, seed2 = seeds[i], seeds[i + 1]
            base1, base2 = bases[i], bases[i + 1]
            
            # Normalize seeds and bases for comparison
            seed_diff = abs(seed1 - seed2) / max(seed1, seed2) if max(seed1, seed2) > 0 else 0
            base_diff = abs(base1 - base2) / max(base1, base2) if max(base1, base2) > 0 else 0
            
            if seed_diff > 0:
                correlation = base_diff / seed_diff
                seed_base_correlations.append(correlation)
        
        analysis['seed_base_correlation_mean'] = np.mean(seed_base_correlations) if seed_base_correlations else 0
        
        # 3. Transcendental power computation security
        # Test resistance to small exponent attacks
        base = self.tfbe.generate_transcendental_base(12345)
        small_exponents = [2, 3, 5, 7, 11, 13, 17, 19]
        power_results = []
        
        for exp in small_exponents:
            try:
                power = self.tfbe.compute_transcendental_power(base, exp)
                power_results.append(float(power))
            except:
                power_results.append(0)
        
        analysis['transcendental_power_entropy'] = self._calculate_entropy(power_results)
        
        # 4. Modular reduction security
        # Test if modular reduction preserves randomness
        modulus = 2**1024 - 1  # Large modulus
        mod_results = []
        
        for i in range(min(200, num_samples)):
            if i % 50 == 0:
                print(f"  Testing modular reduction {i+1}/200")
            
            base = bases[i]
            exponent = secrets.randbelow(100) + 1
            
            try:
                mod_result = self.tfbe.modular_transcendental_exp(base, exponent, modulus)
                mod_results.append(mod_result)
            except:
                continue
        
        analysis['modular_reduction_entropy'] = self._calculate_entropy(mod_results)
        analysis['modular_reduction_uniformity'] = self._test_uniformity(mod_results, modulus)
        
        return analysis
    
    def timing_attack_analysis(self, num_samples: int = 100) -> Dict[str, float]:
        """
        Analyze resistance to timing attacks
        """
        print("🔍 Analyzing timing attack resistance...")
        
        # Generate key pair
        pub_key, priv_key = fRSA_keygen(self.key_size)
        n = pub_key[0]
        
        # Test encryption timing
        encryption_times = []
        plaintexts = []
        
        for i in range(num_samples):
            if i % 20 == 0:
                print(f"  Timing encryption {i+1}/{num_samples}")
            
            plaintext = secrets.randbelow(n)
            plaintexts.append(plaintext)
            
            # Measure encryption time
            start_time = time.perf_counter()
            ciphertext = fRSA_encrypt(plaintext, pub_key)
            end_time = time.perf_counter()
            
            encryption_times.append(end_time - start_time)
        
        # Test decryption timing
        decryption_times = []
        ciphertexts = []
        
        for i in range(num_samples):
            if i % 20 == 0:
                print(f"  Timing decryption {i+1}/{num_samples}")
            
            # Use plaintexts from encryption test
            plaintext = plaintexts[i]
            ciphertext = fRSA_encrypt(plaintext, pub_key)
            ciphertexts.append(ciphertext)
            
            # Measure decryption time
            start_time = time.perf_counter()
            decrypted = fRSA_decrypt(ciphertext, priv_key)
            end_time = time.perf_counter()
            
            decryption_times.append(end_time - start_time)
        
        # Analyze timing patterns
        analysis = {}
        
        # 1. Timing variance
        analysis['encryption_time_variance'] = np.var(encryption_times)
        analysis['decryption_time_variance'] = np.var(decryption_times)
        
        # 2. Correlation between input size and timing
        input_sizes = [p.bit_length() for p in plaintexts]
        enc_time_correlation = np.corrcoef(input_sizes, encryption_times)[0, 1]
        dec_time_correlation = np.corrcoef(input_sizes, decryption_times)[0, 1]
        
        analysis['encryption_input_time_correlation'] = enc_time_correlation
        analysis['decryption_input_time_correlation'] = dec_time_correlation
        
        # 3. Timing predictability
        analysis['encryption_time_predictability'] = self._calculate_predictability(encryption_times)
        analysis['decryption_time_predictability'] = self._calculate_predictability(decryption_times)
        
        return analysis
    
    def chosen_plaintext_attack_analysis(self, num_samples: int = 100) -> Dict[str, float]:
        """
        Analyze resistance to chosen plaintext attacks
        """
        print("🔍 Analyzing chosen plaintext attack resistance...")
        
        # Generate key pair
        pub_key, priv_key = fRSA_keygen(self.key_size)
        n = pub_key[0]
        
        analysis = {}
        
        # 1. Test with sequential plaintexts
        sequential_plaintexts = list(range(1, min(num_samples + 1, n)))
        sequential_ciphertexts = []
        
        for i, plaintext in enumerate(sequential_plaintexts):
            if i % 20 == 0:
                print(f"  Testing sequential plaintext {i+1}/{len(sequential_plaintexts)}")
            
            ciphertext = fRSA_encrypt(plaintext, pub_key)
            sequential_ciphertexts.append(ciphertext)
        
        # Check for patterns in sequential encryption
        seq_correlation = np.corrcoef(sequential_plaintexts, sequential_ciphertexts)[0, 1]
        analysis['sequential_plaintext_correlation'] = seq_correlation
        
        # 2. Test with powers of 2
        power_plaintexts = [2**i for i in range(1, min(20, n.bit_length()))]
        power_ciphertexts = []
        
        for i, plaintext in enumerate(power_plaintexts):
            if plaintext < n:
                ciphertext = fRSA_encrypt(plaintext, pub_key)
                power_ciphertexts.append(ciphertext)
        
        # Check for patterns in power-of-2 encryption
        if len(power_ciphertexts) > 1:
            power_correlation = np.corrcoef(power_plaintexts[:len(power_ciphertexts)], power_ciphertexts)[0, 1]
            analysis['power_of_2_correlation'] = power_correlation
        else:
            analysis['power_of_2_correlation'] = 0
        
        # 3. Test multiplicative property
        # Check if E(m1) * E(m2) has any relation to E(m1 * m2)
        multiplicative_scores = []
        
        for i in range(min(50, num_samples)):
            if i % 10 == 0:
                print(f"  Testing multiplicative property {i+1}/50")
            
            m1 = secrets.randbelow(int(n**0.5)) + 1
            m2 = secrets.randbelow(int(n**0.5)) + 1
            
            if m1 * m2 < n:
                c1 = fRSA_encrypt(m1, pub_key)
                c2 = fRSA_encrypt(m2, pub_key)
                c_product = fRSA_encrypt(m1 * m2, pub_key)
                
                # Check if there's any simple relationship
                combined = (c1 * c2) % n
                difference = abs(combined - c_product)
                multiplicative_scores.append(difference)
        
        analysis['multiplicative_property_mean'] = np.mean(multiplicative_scores) if multiplicative_scores else 0
        analysis['multiplicative_property_std'] = np.std(multiplicative_scores) if multiplicative_scores else 0
        
        return analysis
    
    def comprehensive_security_report(self) -> Dict[str, Dict[str, float]]:
        """
        Generate a comprehensive security analysis report
        """
        print("🛡️  Generating comprehensive security report...")
        print("=" * 60)
        
        report = {}
        
        # Run all security analyses
        report['randomness'] = self.analyze_randomness_quality(500)
        report['ciphertext_distribution'] = self.analyze_ciphertext_distribution(500)
        report['transcendental_security'] = self.analyze_transcendental_security(300)
        report['timing_resistance'] = self.timing_attack_analysis(100)
        report['chosen_plaintext_resistance'] = self.chosen_plaintext_attack_analysis(100)
        
        return report
    
    def _calculate_entropy(self, data: List[float]) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0
        
        # Convert to integers for counting
        int_data = [int(x) for x in data]
        counts = Counter(int_data)
        total = len(int_data)
        
        entropy = 0
        for count in counts.values():
            p = count / total
            if p > 0:
                entropy -= p * math.log2(p)
        
        return entropy
    
    def _calculate_bit_entropy(self, bit_string: str) -> float:
        """Calculate entropy of a bit string"""
        if not bit_string:
            return 0
        
        ones = bit_string.count('1')
        zeros = bit_string.count('0')
        total = len(bit_string)
        
        if ones == 0 or zeros == 0:
            return 0
        
        p1 = ones / total
        p0 = zeros / total
        
        return -(p1 * math.log2(p1) + p0 * math.log2(p0))
    
    def _test_uniformity(self, data: List[int], modulus: int) -> float:
        """Test uniformity of data distribution"""
        if not data or modulus <= 0:
            return 0
        
        # Create bins
        num_bins = min(100, modulus)
        bin_size = modulus // num_bins
        
        bin_counts = [0] * num_bins
        for value in data:
            bin_index = min(value // bin_size, num_bins - 1)
            bin_counts[bin_index] += 1
        
        # Calculate uniformity score (1 - normalized variance)
        expected = len(data) / num_bins
        variance = sum((count - expected)**2 for count in bin_counts) / num_bins
        normalized_variance = variance / (expected**2) if expected > 0 else 0
        
        return max(0, 1 - normalized_variance)
    
    def _calculate_predictability(self, times: List[float]) -> float:
        """Calculate predictability of timing measurements"""
        if len(times) < 2:
            return 0
        
        # Calculate autocorrelation
        mean_time = np.mean(times)
        numerator = sum((times[i] - mean_time) * (times[i-1] - mean_time) for i in range(1, len(times)))
        denominator = sum((t - mean_time)**2 for t in times)
        
        if denominator == 0:
            return 0
        
        autocorr = numerator / denominator
        return abs(autocorr)
    
    def visualize_security_results(self, report: Dict[str, Dict[str, float]]):
        """Create visualizations of security analysis results"""
        print("📊 Creating security analysis visualizations...")
        
        # Create subplots
        fig, axes = plt.subplots(2, 3, figsize=(18, 12))
        fig.suptitle('fRSA Security Analysis Dashboard', fontsize=16, fontweight='bold')
        
        # 1. Randomness Quality
        ax1 = axes[0, 0]
        randomness_data = report['randomness']
        rand_metrics = ['modulus_entropy', 'seed_entropy', 'transcendental_base_entropy', 'bit_entropy']
        rand_values = [randomness_data.get(metric, 0) for metric in rand_metrics]
        
        ax1.bar(range(len(rand_metrics)), rand_values, color='blue', alpha=0.7)
        ax1.set_title('Randomness Quality Metrics')
        ax1.set_ylabel('Entropy Score')
        ax1.set_xticks(range(len(rand_metrics)))
        ax1.set_xticklabels(['Modulus', 'Seed', 'Trans. Base', 'Bit Level'], rotation=45)
        
        # 2. Ciphertext Distribution
        ax2 = axes[0, 1]
        cipher_data = report['ciphertext_distribution']
        cipher_metrics = ['ciphertext_entropy', 'avalanche_effect_mean']
        cipher_values = [cipher_data.get(metric, 0) for metric in cipher_metrics]
        
        ax2.bar(range(len(cipher_metrics)), cipher_values, color='green', alpha=0.7)
        ax2.set_title('Ciphertext Distribution Analysis')
        ax2.set_ylabel('Score')
        ax2.set_xticks(range(len(cipher_metrics)))
        ax2.set_xticklabels(['Entropy', 'Avalanche Effect'], rotation=45)
        
        # 3. Transcendental Security
        ax3 = axes[0, 2]
        trans_data = report['transcendental_security']
        trans_metrics = ['transcendental_base_entropy', 'transcendental_power_entropy', 'modular_reduction_entropy']
        trans_values = [trans_data.get(metric, 0) for metric in trans_metrics]
        
        ax3.bar(range(len(trans_metrics)), trans_values, color='red', alpha=0.7)
        ax3.set_title('Transcendental Function Security')
        ax3.set_ylabel('Entropy Score')
        ax3.set_xticks(range(len(trans_metrics)))
        ax3.set_xticklabels(['Base', 'Power', 'Mod Reduction'], rotation=45)
        
        # 4. Timing Attack Resistance
        ax4 = axes[1, 0]
        timing_data = report['timing_resistance']
        timing_metrics = ['encryption_time_variance', 'decryption_time_variance']
        timing_values = [timing_data.get(metric, 0) for metric in timing_metrics]
        
        ax4.bar(range(len(timing_metrics)), timing_values, color='purple', alpha=0.7)
        ax4.set_title('Timing Attack Resistance')
        ax4.set_ylabel('Variance')
        ax4.set_xticks(range(len(timing_metrics)))
        ax4.set_xticklabels(['Encryption', 'Decryption'], rotation=45)
        
        # 5. Chosen Plaintext Attack Resistance
        ax5 = axes[1, 1]
        cpa_data = report['chosen_plaintext_resistance']
        cpa_metrics = ['sequential_plaintext_correlation', 'power_of_2_correlation']
        cpa_values = [abs(cpa_data.get(metric, 0)) for metric in cpa_metrics]
        
        ax5.bar(range(len(cpa_metrics)), cpa_values, color='orange', alpha=0.7)
        ax5.set_title('Chosen Plaintext Attack Resistance')
        ax5.set_ylabel('Correlation (lower is better)')
        ax5.set_xticks(range(len(cpa_metrics)))
        ax5.set_xticklabels(['Sequential', 'Power of 2'], rotation=45)
        
        # 6. Overall Security Score
        ax6 = axes[1, 2]
        # Calculate overall security score
        security_scores = {
            'Randomness': np.mean([randomness_data.get(k, 0) for k in ['modulus_entropy', 'seed_entropy', 'bit_entropy']]),
            'Ciphertext': cipher_data.get('ciphertext_entropy', 0),
            'Transcendental': np.mean([trans_data.get(k, 0) for k in ['transcendental_base_entropy', 'transcendental_power_entropy']]),
            'Timing': 1 / (1 + np.mean([timing_data.get(k, 0) for k in ['encryption_time_variance', 'decryption_time_variance']])),
            'CPA Resistance': 1 - np.mean([abs(cpa_data.get(k, 0)) for k in ['sequential_plaintext_correlation', 'power_of_2_correlation']])
        }
        
        categories = list(security_scores.keys())
        scores = list(security_scores.values())
        
        ax6.bar(range(len(categories)), scores, color='teal', alpha=0.7)
        ax6.set_title('Overall Security Assessment')
        ax6.set_ylabel('Security Score')
        ax6.set_xticks(range(len(categories)))
        ax6.set_xticklabels(categories, rotation=45)
        ax6.set_ylim(0, max(scores) * 1.1)
        
        plt.tight_layout()
        plt.savefig('frsa_security_analysis.png', dpi=300, bbox_inches='tight')
        plt.show()
        
        # Print security summary
        print("\n" + "="*60)
        print("🛡️  SECURITY ANALYSIS SUMMARY")
        print("="*60)
        
        overall_score = np.mean(list(security_scores.values()))
        print(f"Overall Security Score: {overall_score:.3f} / 1.000")
        
        if overall_score >= 0.8:
            print("🟢 EXCELLENT: High security level detected")
        elif overall_score >= 0.6:
            print("🟡 GOOD: Moderate security level detected")
        elif overall_score >= 0.4:
            print("🟠 FAIR: Some security concerns identified")
        else:
            print("🔴 POOR: Significant security vulnerabilities detected")
        
        print("\nDetailed Analysis:")
        for category, score in security_scores.items():
            status = "✓" if score >= 0.7 else "⚠" if score >= 0.4 else "✗"
            print(f"  {status} {category}: {score:.3f}")
        
        return security_scores

def main():
    """Main function to run security analysis"""
    print("🔐 Starting fRSA Security Analysis")
    print("=" * 50)
    
    # Initialize analyzer
    analyzer = SecurityAnalyzer(key_size=1024)
    
    # Generate comprehensive report
    report = analyzer.comprehensive_security_report()
    
    # Visualize results
    security_scores = analyzer.visualize_security_results(report)
    
    print("\n✅ Security analysis completed!")
    print("📊 Charts saved as 'frsa_security_analysis.png'")
    
    return report, security_scores

if __name__ == "__main__":
    main()
