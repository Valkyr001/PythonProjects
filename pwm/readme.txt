pwm (password manager) is a python script capable of encryption, hashing, storing, and analyzing of user-supplied passwords. It currently has two versions:
pwm_tk.py and pwm_cmdline.py. The tk version handles user interaction using the Tkinter library, while the cmdline version handles user interaction via 
command prompt/terminal.

ip.py (insecure phrases) is a custom import for pwm that contains a list of insecure phrases for passwords (password, password123, etc). The password strength check
module of PWM will compare the supplied password against the database. (hopefully outsourcing this to an API if i can find one).

This script also uses the HaveIBeenPwned API to compared the password against data breaches.

