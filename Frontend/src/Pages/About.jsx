import React from 'react'
import NavBar from '../Components/NavBar.jsx'
import Dashboard from '../Components/Dashboard'
import '../About.css'

const About = () => {
  return (
    <div className='About'>
        <NavBar />
        <div className="content">
            {/* <Dashboard /> */}
            <div className="description">
                <h1>Fadeveil: A Ransomware Analysis and Decryption System</h1>
                <p>
                    Fadeveil is a ransomware analysis and decryption tool designed to detect, analyze, and mitigate ransomware attacks without requiring victims to pay a ransom. It focuses on identifying encryption techniques, primarily AES (Advanced Encryption Standard) and RSA (Rivest-Shamir-Adleman), using both static and dynamic analysis. The system integrates with industry-standard malware analysis tools like Ghidra, x64dbg, and Cuckoo Sandbox, providing cybersecurity researchers and forensic analysts with valuable insights into ransomware behavior.
                </p>

                <h2>Key Features and Functionality</h2>
                <p>
                    Fadeveil employs a hybrid detection system that combines signature-based and anomaly-based detection techniques. This approach allows it to identify both known ransomware strains and new, evolving threats. The system can automatically detect whether ransomware uses AES, RSA, or a combination of both for encryption and key exchange. It attempts decryption by extracting encryption keys, analyzing malware behavior, and leveraging vulnerabilities in ransomware implementations.
                </p>

                <h2>System Components</h2>
                <ul>
                    <li><strong>Encryption Module</strong> – Demonstrates ransomware behavior by using AES for file encryption and RSA for key exchange.</li>
                    <li><strong>Analysis Module</strong> – Conducts static and dynamic analysis to examine ransomware binaries, recognize encryption algorithms, and identify malware signatures.</li>
                    <li><strong>Decryption Module</strong> – Uses RSA private keys to decrypt AES keys, restores encrypted files, and handles incomplete decryption attempts.</li>
                </ul>

                <h2>Implementation and Development</h2>
                <p>
                    Developed as a web application, Fadeveil allows users to upload encrypted files for analysis and decryption. The interface is built using React.js, with Python handling encryption, decryption, and malware analysis functionalities. The system integrates tools such as Ghidra and x64dbg for reverse engineering, and cryptographic libraries for encryption and decryption processes.
                </p>

                <h2>Target Users</h2>
                <ul>
                    <li><strong>Cybersecurity researchers</strong> – To analyze and reverse-engineer ransomware.</li>
                    <li><strong>Incident response teams</strong> – To detect ransomware quickly and attempt file recovery.</li>
                    <li><strong>Digital forensic analysts</strong> – To investigate ransomware behavior and mitigate future threats.</li>
                </ul>
            </div>
        </div>
    </div>
  )
}

export default About
