"""Piège n° 3 au niveau de labctl : un Ctrl+C pendant `labctl test` ne doit laisser aucune panne active."""
import labctl


class FakeProc:
    def __init__(self, interrupts, code=0):
        self.interrupts = interrupts
        self.code = code
        self.killed = False

    def wait(self):
        if self.interrupts:
            self.interrupts -= 1
            raise KeyboardInterrupt
        return self.code

    def kill(self):
        self.killed = True
        self.interrupts = 0
        self.code = -9


def test_first_ctrl_c_waits_for_pytest_teardown_then_heals():
    proc, healed = FakeProc(interrupts=1, code=2), []
    assert labctl.wait_child_then_heal(proc, lambda: healed.append(1)) == 2
    assert healed == [1] and not proc.killed


def test_second_ctrl_c_kills_pytest_and_still_heals():
    proc, healed = FakeProc(interrupts=5), []
    assert labctl.wait_child_then_heal(proc, lambda: healed.append(1)) == 130
    assert proc.killed and healed == [1]
