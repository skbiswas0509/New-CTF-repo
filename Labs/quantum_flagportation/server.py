from qutip.qip.operations.gates import cnot, snot, x_gate, z_gate
from qutip.measurement import measure_povm
from qutip import basis, tensor, qeye

class QuantumProcessor:
    def __init__(self):
        pass

    def Z(self, n, target):
        return z_gate(n, target)

    def X(self, n, target):
        return x_gate(n, target)

    def H(self, qubits, target):
        return snot(qubits, target)

    def CNOT(self, qubits, control, target):
        return cnot(qubits, control, target)

    def single_projector(self, _basis):
        if _basis == "Z":
            return basis(2, 0).proj(), basis(2, 1).proj()
        
        elif _basis == "X":
            plus = (basis(2, 0) + basis(2, 1)).unit()
            minus = (basis(2, 0) - basis(2, 1)).unit()
            
            return plus.proj(), minus.proj()
        
        else:
            print(f"Basis '{_basis}' is invalid or unexpected.")
            return ()
    
    def projector(self, basis, qubits, target):
        single_projector = self.single_projector(basis)

        projectors = []
        for projector in single_projector:
            operators = [qeye(2)] * qubits
            operators[target] = projector
            
            projectors.append(tensor(operators))
        
        return projectors

    def measure(self, basis, qubits, target, state):
        projectors = self.projector(basis, qubits, target)
        
        if not projectors:
            return (None, state)

        return measure_povm(state, projectors)

class Teleporter:
    def __init__(self):
        self.proc = QuantumProcessor()

        self.encoder = {
            "00": [basis(2, 0), "Z"],
            "01": [basis(2, 1), "Z"],
            "10": [(basis(2, 0) + basis(2, 1)).unit(), "X"],
            "11": [(basis(2, 0) - basis(2, 1)).unit(), "X"]
        }

    def bytes_to_bitpairs(self, data: bytes):
        bits = ''.join(f"{byte:08b}" for byte in data)
        return [bits[i : i + 2] for i in range(0, len(bits), 2)]

    def prepare(self, bits: str):
        q0, _basis = self.encoder[bits]
        q1 = basis(2, 0)
        q2 = basis(2, 0)
        
        state = tensor(q0, q1, q2)

        state = self.proc.H(3, 1) * state
        state = self.proc.CNOT(3, 1, 2) * state

        state = self.proc.CNOT(3, 0, 1) * state
        state = self.proc.H(3, 0) * state

        return state, _basis

    def apply_instructions(self, instructions, state):
        instructions = instructions.split(";")

        for instr in instructions:
            parts = instr.split(":")

            if len(parts) != 2:
                print(f"Invalid instruction: {instr}. Expected format: <gate>:<params>")
                print("Examples: H:<target> | RX:<phase>,<target>")
                return None

            gate, params = parts

            try:
                params = [ int(p) for p in params.split(",") ]
            except:
                print("Quantum gate input parameters must be integers.")
                print("Examples: Z:0 | X:1")
                return None

            if   gate == "Z": state = self.proc.Z(3, params[0]) * state
            elif gate == "X": state = self.proc.X(3, params[0]) * state
            elif gate == "H": state = self.proc.H(3, params[0]) * state
            else:
                print(f"Quantum gate '{gate}' is invalid or unexpected.")
                return None

        return state

def main():
    print("""
        ╔═════════════════════════════╗
        ║    Qubitrix's Teleporter    ║
        ║       Terminal (QTT)        ║    
        ╠═════════════════════════════╣
        ║ Every 24 hours, Qubitrix    ║
        ║ will release a secret       ║
        ║ message to our partners.    ║
        ║ Please follow the           ║
        ║ instructions we sent you    ║
        ║ by email from               ║
        ║ info@qubitrix.com.          ║
        ╚═════════════════════════════╝
    """)    
    
    tp = Teleporter()

    bitpairs = tp.bytes_to_bitpairs(open('flag.txt', 'rb').read())
    
    for i, bits in enumerate(bitpairs):
        print(f"Qubit {i + 1}/{len(bitpairs)}")

        state, basis = tp.prepare(bits)
        print(f"Basis : {basis}")

        result, state = tp.proc.measure("Z", 3, 0, state)
        print(f"Measurement of qubit 0 : {result}")

        result, state = tp.proc.measure("Z", 3, 1, state)
        print(f"Measurement of qubit 1 : {result}")

        instructions = input('Specify the instructions : ')
        state = tp.apply_instructions(instructions, state)

        if not state:
            print("Closing QTT...")
            return

        basis = input("Specify the measurement basis : ")
        result, state = tp.proc.measure(basis, 3, 2, state)

        if result is None:
            print("Closing QTT...")
            return

        print(f"Measurement of qubit 2 : {result}")

if __name__ == '__main__':
    main()