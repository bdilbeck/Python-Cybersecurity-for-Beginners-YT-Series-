# Python-Cybersecurity-for-Beginners-YT-Series-
Python Cybersecurity for Beginners (YT Series)

All the scripts related to my Youtube series on Python Cybersecurity mini-projects
The playlist can be found here: https://www.youtube.com/playlist?list=PLB7R26sRn2aLhKbDDRtd7wluaX91pqAQD

Questions + Comments?
Twitter: @faanross
Email: moi@faanross.com

** Constructive critique ALWAYS welcome **
|in sterquiliniis invenitur|


7/29/2023 - Blair Dilbeck - Adding functionality to basic firewall project. 
* Current goal: Give the firewall the ability to send emails to a user when an IP is blocked.

8/5/2023 - Blair Dilbeck - The firewall script is now capable of sending emails to a specified user to alert them when a Nimda Worm packet is detected.
* New Goal: Create a visual interface for the firewall script via Flask.

8/14/2023 - Blair Dilbeck - The firewall script can now connect to the Flask app on app.py but the information transfer is not yet dynamic on either end.

9/4/2023 - Blair Dilbeck - The firewall script is now capable of sending blocked IPs to a text file called blacklist.txt, and those blocked IPs are displayed on interface.html powered by the Flask app. The page can be updated in real time as the script runs by refreshing the page.

Development will now focus on improving the interface and working out issues with the script and txt file.

*Ongoing issues:
- The script sometimes puts the same address in the txt file multiple times.
