pwm (password manager) is a python script capable of encryption, hashing, storing, and analyzing of user-supplied passwords.

ip.py (insecure phrases) is a custom import for pwm that contains a list of insecure phrases for passwords (password, password123, etc). The password strength check
module of PWM will compare the supplied password against the database. (hopefully outsourcing this to an API if i can find one)

This script also uses the HaveIBeenPwned API to compared the password against data breaches.
