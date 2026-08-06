import socket
import time

HOST = "154.57.164.80"
PORT = 31913

def connect():
    return socket.socket(socket.AF_INET, socket.SOCK_STREAM)

def recv_line(sock):
    data = b''
    while True:
        chunk = sock.recv(1)
        if not chunk:
            break
        data += chunk
        if data.endswith(b'\n'):
            break
    return data.decode(errors='ignore').strip()

def recv_until(sock, delimiter):
    data = b''
    while True:
        chunk = sock.recv(1)
        if not chunk:
            break
        data += chunk
        if data.endswith(delimiter):
            break
    return data

def send_data(sock, data):
    sock.send(data.encode() if isinstance(data, str) else data)

reconstructed_bit_pairs = []

try:
    sock = connect()
    sock.connect((HOST, PORT))
    
    # Small delay to let connection establish
    time.sleep(0.1)
    
    # Print initial banner if any
    try:
        initial = sock.recv(1024)
        if initial:
            print("Initial:", initial.decode(errors='ignore'))
    except:
        pass
    
    round_num = 0
    while True:
        round_num += 1
        print(f"\n[Round {round_num}] Waiting for Basis...")
        
        # Wait for "Basis : "
        recv_until(sock, b"Basis : ")
        basis = recv_line(sock)
        print(f"Basis: {basis}")
        
        # Get m0 and m1 lines
        m0_line = recv_line(sock)
        m1_line = recv_line(sock)
        print(f"m0 line: {m0_line}")
        print(f"m1 line: {m1_line}")
        
        # Extract the last number from each line
        m0 = int(m0_line.split()[-1])
        m1 = int(m1_line.split()[-1])
        print(f"m0: {m0}, m1: {m1}")
        
        # Apply teleportation correction
        if m0 == 0 and m1 == 0:
            instructions = "Z:2;Z:2"
        elif m0 == 1 and m1 == 0:
            instructions = "Z:2"
        elif m0 == 0 and m1 == 1:
            instructions = "X:2"
        elif m0 == 1 and m1 == 1:
            instructions = "Z:2;X:2"
        else:
            instructions = "Z:2;Z:2"
        
        print(f"Instructions: {instructions}")
        
        # Send instructions
        send_data(sock, "Specify the instructions : ")
        response = recv_until(sock, b"Specify the instructions : ")
        send_data(sock, instructions + "\n")
        print(f"Sent instructions: {instructions}")
        
        # Send measurement basis
        send_data(sock, "Specify the measurement basis : ")
        response = recv_until(sock, b"Specify the measurement basis : ")
        send_data(sock, basis + "\n")
        print(f"Sent basis: {basis}")
        
        # Get final measurement
        res_line = recv_line(sock)
        print(f"Response line: {res_line}")
        
        if not res_line:
            print("Empty response, breaking...")
            break
            
        parts = res_line.split()
        if not parts:
            print("No parts in response, breaking...")
            break
            
        final_measurement = int(parts[-1])
        print(f"Final measurement: {final_measurement}")
        
        first_bit = '0' if basis == 'Z' else '1'
        reconstructed_bit_pairs.append(first_bit + str(final_measurement))
        print(f"Added bit pair: {first_bit}{final_measurement}")
        print(f"Total pairs so far: {len(reconstructed_bit_pairs)}")

except KeyboardInterrupt:
    print("\nInterrupted by user")
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
finally:
    print("\n" + "="*50)
    if reconstructed_bit_pairs:
        binary_string = ''.join(reconstructed_bit_pairs)
        print(f"Binary string: {binary_string}")
        
        if binary_string:
            n = int(binary_string, 2)
            flag_bytes = n.to_bytes((n.bit_length() + 7) // 8, 'big')
            try:
                flag = flag_bytes.decode()
            except:
                flag = flag_bytes
            print('FLAG:', flag)
    else:
        print("No bit pairs were collected")
    sock.close()
