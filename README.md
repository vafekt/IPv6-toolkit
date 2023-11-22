# IPv6-generator
This project is created as a part of my Master Thesis. There is a toolkit located in folder Tools which is used for performing different types of scanning and attacks on the IPv6 network.

Author: Viet Anh Phan, MPC-IBE 2021-2023 at Brno University of Technology, Czech Republic.

To use this toolkit:
```bash

# Enter repo
cd Tools

# Example of running the tool mldv2_report within the toolkit for removing all listeners in the multicast group with address ff08::db8
python3 mldv2_report.py eth0 -lmar "rtype=3;mip=ff08::db8;src=[]"
```
