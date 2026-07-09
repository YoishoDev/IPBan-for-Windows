The script uses a log from the ESET security solution (https://protect.eset.com/) to block IP addresses in the local firewall. The blocked IP addresses are sent to a Graylog-based SIEM.
Feel free to use the script as a basis for your own ideas.

![ESET firewall log](https://github.com/user-attachments/assets/a3a6af11-643e-42b1-89d1-8ab5e4cc26cd)  
ESET firewall log

The use of RMM must be explicitly enabled in the ESET configuration; the path of the program being used, in this case the PS, must then be entered as permitted. The configuration is carried out via a central guideline, which system in the DMZ is automatically assigned based on a dynamic group.

![ESET firewall log](https://github.com/user-attachments/assets/acd5f33d-2d48-4bf4-a5d2-a5068e31591e)  
Activation of RMM and authorization for the PS
