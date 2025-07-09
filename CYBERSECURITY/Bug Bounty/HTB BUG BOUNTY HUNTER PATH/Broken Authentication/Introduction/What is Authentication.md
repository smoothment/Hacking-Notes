Authentication is defined as "The process of verifying a claim that a system entity or system resource has a certain attribute value" in [RFC 4949](https://datatracker.ietf.org/doc/rfc4949/). In information security, authentication is the process of confirming an entity's identity, ensuring they are who they claim to be. On the other hand, authorization is an "approval that is granted to a system entity to access a system resource"; while this module will not cover authorization deeply, understanding the major difference between it and authentication is vital to approach this module with the appropriate mindset.

![image](https://academy.hackthebox.com/storage/modules/269/auth_vs_auth.png)

The most widespread authentication method in web applications is`login forms`, where users enter their username and password to prove their identity. Login forms can be found on many websites including email providers, online banking, and HTB Academy:

 ![](https://academy.hackthebox.com/storage/modules/269/intro/intro_1.png)

Authentication is probably the most widespread security measure and the first defense against unauthorized access. As web application penetration testers, we aim to verify if authentication is implemented securely. This module will focus on various exploitation methods and techniques against login forms to bypass authentication and gain unauthorized access.

---

## Common Authentication Methods

Information technology systems can implement different authentication methods. Typically, they can be divided into the following three major categories:

- Knowledge-based authentication
- Ownership-based authentication
- Inherence-based authentication

#### Knowledge

Authentication based on knowledge factors relies on something that the user knows to prove their identity. The user provides information such as passwords, passphrases, PINs, or answers to security questions.

#### Ownership

Authentication based on ownership factors relies on something the user possesses. The user proves their identity by proving the ownership of a physical object or device, such as ID cards, security tokens, or smartphones with authentication apps. #### Inherence

Lastly, authentication based on inherence factors relies on something the user is or does. This includes biometric factors such as fingerprints, facial patterns, and voice recognition, or signatures. Biometric authentication is highly effective since biometric traits are inherently tied to an individual user.

|Knowledge|Ownership|Inherence|
|---|---|---|
|Password|ID card|Fingerprint|
|PIN|Security Token|Facial Pattern|
|Answer to Security Question|Authenticator App|Voice Recognition|

---

## Single-Factor Authentication vs Multi-Factor Authentication

Single-factor authentication relies solely on a single methods. For instance, password authentication solely relies on knowledge of the password. As such, it is a single-factor authentication method.

On the other hand, multi-factor authentication (MFA) involves multiple authentication methods. For instance, if a web application requires a password and a time-based one-time password (TOTP), it relies on knowledge of the password and ownership of the TOTP device for authentication. In the particular case when exactly two factors are required, MFA is commonly referred to as 2-factor authentication (2FA).
