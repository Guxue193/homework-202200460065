import json

d = 5
rounds_f = 8
rounds_p = 57
p = 21888242871839275222246405745257275088548364400416034343698204186575808495617  # BN254 field

ark = [i + 1 for i in range(2 * (rounds_f + rounds_p))]  # 130元素
M = [[2, 3],
     [3, 4]]

def sbox(x):
    return pow(x, d, p)

def poseidon2_hash(preimage):
    state = [preimage, 0]
    ark_idx = 0

    for _ in range(rounds_f // 2):
        state = [(state[i] + ark[ark_idx + i]) % p for i in range(2)]
        ark_idx += 2
        state = [sbox(state[i]) for i in range(2)]
        state = [(M[i][0] * state[0] + M[i][1] * state[1]) % p for i in range(2)]

    for _ in range(rounds_p):
        state = [(state[i] + ark[ark_idx + i]) % p for i in range(2)]
        ark_idx += 2
        state[0] = sbox(state[0])
        state = [(M[i][0] * state[0] + M[i][1] * state[1]) % p for i in range(2)]

    for _ in range(rounds_f // 2):
        state = [(state[i] + ark[ark_idx + i]) % p for i in range(2)]
        ark_idx += 2
        state = [sbox(state[i]) for i in range(2)]
        state = [(M[i][0] * state[0] + M[i][1] * state[1]) % p for i in range(2)]

    return state[0]

def generate_input(preimage_value, output_file='inputs/input_t2.json'):
    hash_value = poseidon2_hash(preimage_value)
    input_data = {
        "preimage": [str(preimage_value)],
        "expected_hash": str(hash_value)
    }
    with open(output_file, 'w') as f:
        json.dump(input_data, f, indent=2)
    print(f"Generated input_t2.json with expected_hash={hash_value}")

if __name__ == '__main__':
    preimage = int(input("Enter preimage (integer): "))
    generate_input(preimage)
