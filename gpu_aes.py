import pycuda.driver as cuda
import pycuda.autoinit
from pycuda.compiler import SourceModule
import numpy as np

# AES S-Box and constants generation
def make_sbox():
    sbox = [0] * 256
    p = 1
    q = 1
    
    def rotl8(x, shift):
        return ((x << shift) | (x >> (8 - shift))) & 0xff
    
    while True:
        # Multiply p by 3 in GF(2^8)
        # p * 3 = p * (x + 1) = (p * x) ^ p
        # p * x = (p << 1) ^ (0x1b if high_bit else 0)
        p_times_2 = (p << 1) ^ (0x1b if (p & 0x80) else 0)
        p = (p ^ p_times_2) & 0xff

        # Divide q by 3 in GF(2^8)
        q ^= q << 1
        q ^= q << 2
        q ^= q << 4
        if q & 0x80: q ^= 0x09
        q &= 0xff
        
        x = q ^ rotl8(q, 1) ^ rotl8(q, 2) ^ rotl8(q, 3) ^ rotl8(q, 4) ^ 0x63
        sbox[p] = x
        if p == 1: break
    sbox[0] = 0x63
    return np.array(sbox, dtype=np.uint8)

def make_inv_sbox(sbox):
    inv_sbox = [0] * 256
    for i in range(256):
        inv_sbox[sbox[i]] = i
    return np.array(inv_sbox, dtype=np.uint8)

def make_rcon():
    rcon = [0] * 11
    rcon[1] = 1
    for i in range(2, 11):
        rcon[i] = rcon[i-1] << 1
        if rcon[i-1] & 0x80:
            rcon[i] ^= 0x11b # Field polynomial
        rcon[i] &= 0xff
    return np.array(rcon, dtype=np.uint8)

# Key Expansion (CPU)
def key_expansion(key, sbox, rcon):
    # key is 16 bytes
    w = [0] * 44 # 4 words * 11 rounds
    
    def sub_word(word):
        return (int(sbox[(word >> 24) & 0xff]) << 24) | \
               (int(sbox[(word >> 16) & 0xff]) << 16) | \
               (int(sbox[(word >> 8) & 0xff]) << 8) | \
               (int(sbox[word & 0xff]))

    def rot_word(word):
        return ((word << 8) & 0xffffffff) | (word >> 24)

    for i in range(4):
        w[i] = (key[4*i] << 24) | (key[4*i+1] << 16) | (key[4*i+2] << 8) | key[4*i+3]

    for i in range(4, 44):
        temp = w[i-1]
        if i % 4 == 0:
            temp = sub_word(rot_word(temp)) ^ (int(rcon[i//4]) << 24)
        w[i] = w[i-4] ^ temp
        
    # Convert to bytes for GPU
    round_keys = []
    for word in w:
        round_keys.append((word >> 24) & 0xff)
        round_keys.append((word >> 16) & 0xff)
        round_keys.append((word >> 8) & 0xff)
        round_keys.append(word & 0xff)
        
    return np.array(round_keys, dtype=np.uint8)

CUDA_CODE = """
__device__ unsigned char mul2(unsigned char a) {
    return (a & 0x80) ? ((a << 1) ^ 0x1b) : (a << 1);
}

__device__ unsigned char mul(unsigned char a, unsigned char b) {
    unsigned char p = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        a = mul2(a);
        b >>= 1;
    }
    return p;
}

__global__ void aes_encrypt(unsigned char *out, const unsigned char *in, const unsigned char *roundKeys, const unsigned char *sbox, int num_blocks) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= num_blocks) return;

    unsigned char state[16];
    int offset = idx * 16;

    // Copy input to state
    for (int i = 0; i < 16; i++) state[i] = in[offset + i];

    // AddRoundKey (Round 0)
    for (int i = 0; i < 16; i++) state[i] ^= roundKeys[i];

    // Rounds 1 to 9
    for (int round = 1; round <= 9; round++) {
        // SubBytes
        for (int i = 0; i < 16; i++) state[i] = sbox[state[i]];

        // ShiftRows
        unsigned char tmp;
        // Row 1: shift 1
        tmp = state[1]; state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = tmp;
        // Row 2: shift 2
        tmp = state[2]; state[2] = state[10]; state[10] = tmp;
        tmp = state[6]; state[6] = state[14]; state[14] = tmp;
        // Row 3: shift 3
        tmp = state[15]; state[15] = state[11]; state[11] = state[7]; state[7] = state[3]; state[3] = tmp;

        // MixColumns
        unsigned char t[4];
        for (int c = 0; c < 4; c++) {
            int i = c * 4;
            t[0] = state[i]; t[1] = state[i+1]; t[2] = state[i+2]; t[3] = state[i+3];
            state[i]   = mul2(t[0] ^ t[1]) ^ t[1] ^ t[2] ^ t[3];
            state[i+1] = mul2(t[1] ^ t[2]) ^ t[2] ^ t[3] ^ t[0];
            state[i+2] = mul2(t[2] ^ t[3]) ^ t[3] ^ t[0] ^ t[1];
            state[i+3] = mul2(t[3] ^ t[0]) ^ t[0] ^ t[1] ^ t[2];
        }

        // AddRoundKey
        for (int i = 0; i < 16; i++) state[i] ^= roundKeys[round * 16 + i];
    }

    // Round 10
    // SubBytes
    for (int i = 0; i < 16; i++) state[i] = sbox[state[i]];

    // ShiftRows
    unsigned char tmp;
    tmp = state[1]; state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = tmp;
    tmp = state[2]; state[2] = state[10]; state[10] = tmp;
    tmp = state[6]; state[6] = state[14]; state[14] = tmp;
    tmp = state[15]; state[15] = state[11]; state[11] = state[7]; state[7] = state[3]; state[3] = tmp;

    // AddRoundKey
    for (int i = 0; i < 16; i++) state[i] ^= roundKeys[10 * 16 + i];

    // Copy to output
    for (int i = 0; i < 16; i++) out[offset + i] = state[i];
}

__global__ void aes_decrypt(unsigned char *out, const unsigned char *in, const unsigned char *roundKeys, const unsigned char *inv_sbox, int num_blocks) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= num_blocks) return;

    unsigned char state[16];
    int offset = idx * 16;

    for (int i = 0; i < 16; i++) state[i] = in[offset + i];

    // AddRoundKey (Round 10)
    for (int i = 0; i < 16; i++) state[i] ^= roundKeys[10 * 16 + i];

    // Rounds 9 to 1
    for (int round = 9; round >= 1; round--) {
        // InvShiftRows
        unsigned char tmp;
        // Row 1: inv shift 1 (shift right 1 = left 3)
        tmp = state[13]; state[13] = state[9]; state[9] = state[5]; state[5] = state[1]; state[1] = tmp;
        // Row 2: inv shift 2
        tmp = state[2]; state[2] = state[10]; state[10] = tmp;
        tmp = state[6]; state[6] = state[14]; state[14] = tmp;
        // Row 3: inv shift 3 (shift right 3 = left 1)
        tmp = state[3]; state[3] = state[7]; state[7] = state[11]; state[11] = state[15]; state[15] = tmp;

        // InvSubBytes
        for (int i = 0; i < 16; i++) state[i] = inv_sbox[state[i]];

        // AddRoundKey
        for (int i = 0; i < 16; i++) state[i] ^= roundKeys[round * 16 + i];

        // InvMixColumns
        unsigned char t[4];
        for (int c = 0; c < 4; c++) {
            int i = c * 4;
            t[0] = state[i]; t[1] = state[i+1]; t[2] = state[i+2]; t[3] = state[i+3];
            
            // Multiply by 0x0e, 0x0b, 0x0d, 0x09
            state[i]   = mul(t[0], 0x0e) ^ mul(t[1], 0x0b) ^ mul(t[2], 0x0d) ^ mul(t[3], 0x09);
            state[i+1] = mul(t[0], 0x09) ^ mul(t[1], 0x0e) ^ mul(t[2], 0x0b) ^ mul(t[3], 0x0d);
            state[i+2] = mul(t[0], 0x0d) ^ mul(t[1], 0x09) ^ mul(t[2], 0x0e) ^ mul(t[3], 0x0b);
            state[i+3] = mul(t[0], 0x0b) ^ mul(t[1], 0x0d) ^ mul(t[2], 0x09) ^ mul(t[3], 0x0e);
        }
    }

    // Round 0
    // InvShiftRows
    unsigned char tmp;
    tmp = state[13]; state[13] = state[9]; state[9] = state[5]; state[5] = state[1]; state[1] = tmp;
    tmp = state[2]; state[2] = state[10]; state[10] = tmp;
    tmp = state[6]; state[6] = state[14]; state[14] = tmp;
    tmp = state[3]; state[3] = state[7]; state[7] = state[11]; state[11] = state[15]; state[15] = tmp;

    // InvSubBytes
    for (int i = 0; i < 16; i++) state[i] = inv_sbox[state[i]];

    // AddRoundKey
    for (int i = 0; i < 16; i++) state[i] ^= roundKeys[i];

    for (int i = 0; i < 16; i++) out[offset + i] = state[i];
}
"""

class AESGpu:
    def __init__(self, key):
        self.key = key
        self.sbox = make_sbox()
        self.inv_sbox = make_inv_sbox(self.sbox)
        self.rcon = make_rcon()
        self.round_keys = key_expansion(key, self.sbox, self.rcon)
        
        # Compile CUDA
        self.mod = SourceModule(CUDA_CODE)
        self.encrypt_kernel = self.mod.get_function("aes_encrypt")
        self.decrypt_kernel = self.mod.get_function("aes_decrypt")
        
        # GPU Memory for constants
        self.sbox_gpu = cuda.mem_alloc(self.sbox.nbytes)
        cuda.memcpy_htod(self.sbox_gpu, self.sbox)
        
        self.inv_sbox_gpu = cuda.mem_alloc(self.inv_sbox.nbytes)
        cuda.memcpy_htod(self.inv_sbox_gpu, self.inv_sbox)
        
        self.round_keys_gpu = cuda.mem_alloc(self.round_keys.nbytes)
        cuda.memcpy_htod(self.round_keys_gpu, self.round_keys)

    def pad(self, data):
        # PKCS7 padding
        pad_len = 16 - (len(data) % 16)
        return data + bytes([pad_len] * pad_len)

    def unpad(self, data):
        pad_len = data[-1]
        return data[:-pad_len]

    def encrypt(self, data):
        # Pad data
        padded_data = self.pad(data)
        data_np = np.frombuffer(padded_data, dtype=np.uint8)
        num_blocks = len(data_np) // 16
        
        out_np = np.zeros_like(data_np)
        
        # GPU Alloc
        in_gpu = cuda.mem_alloc(data_np.nbytes)
        out_gpu = cuda.mem_alloc(out_np.nbytes)
        
        cuda.memcpy_htod(in_gpu, data_np)
        
        # Run Kernel
        block_size = 256
        grid_size = (num_blocks + block_size - 1) // block_size
        
        self.encrypt_kernel(out_gpu, in_gpu, self.round_keys_gpu, self.sbox_gpu, np.int32(num_blocks),
                            block=(block_size, 1, 1), grid=(grid_size, 1))
        
        cuda.memcpy_dtoh(out_np, out_gpu)
        
        return out_np.tobytes()

    def decrypt(self, data):
        data_np = np.frombuffer(data, dtype=np.uint8)
        num_blocks = len(data_np) // 16
        
        out_np = np.zeros_like(data_np)
        
        in_gpu = cuda.mem_alloc(data_np.nbytes)
        out_gpu = cuda.mem_alloc(out_np.nbytes)
        
        cuda.memcpy_htod(in_gpu, data_np)
        
        block_size = 256
        grid_size = (num_blocks + block_size - 1) // block_size
        
        self.decrypt_kernel(out_gpu, in_gpu, self.round_keys_gpu, self.inv_sbox_gpu, np.int32(num_blocks),
                            block=(block_size, 1, 1), grid=(grid_size, 1))
        
        cuda.memcpy_dtoh(out_np, out_gpu)
        
        decrypted_padded = out_np.tobytes()
        return self.unpad(decrypted_padded)
