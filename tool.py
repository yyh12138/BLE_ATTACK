import sys, os
from BlueShiro import BlueShiro

blueShiro = BlueShiro("70:a6:cc:b5:92:70", "/dev/ttyACM0", "a4:c1:38:7d:ab:b9")

blueShiro.driver.close


