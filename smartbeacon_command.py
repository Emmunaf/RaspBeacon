from threading import Timer
def sb_open():
    print("Gate opened")
    return 1

def sb_timer():
    t = Timer(10.0, sb_open)
    t.start()
    print("Timer was set (10sec), wait")
