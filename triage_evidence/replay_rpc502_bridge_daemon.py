#!/usr/bin/env python3
"""Independent original daemon guard replay with original thin-image backing.
O(visits+effects) time, O(one private map+journals) space. No probe reuse.
"""
from daemon_receive_tools import IMAGE,CS
from replay_kernel_vm_mig import Replay
class View:
 def __init__(self):self.k=self;self.cs=CS
 def read(self,a,n):return IMAGE.read(a,n)
 def logical_page(self,a):return IMAGE.read(a,4096)
