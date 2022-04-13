#include <iostream>
#include <bitset>
#include <stdint.h>
#include <bits/stdc++.h>
using namespace std;
#define rep(i, l, r) for (int i = l; i < r; i++)
#define MAX_PLAINTEXT_LEN 8192

// IP��ʼ�û���
uint8_t pc_ip[64] = {58, 50, 42, 34, 26, 18, 10, 2,
                     60, 52, 44, 36, 28, 20, 12, 4,
                     62, 54, 46, 38, 30, 22, 14, 6,
                     64, 56, 48, 40, 32, 24, 16, 8,
                     57, 49, 41, 33, 25, 17, 9, 1,
                     59, 51, 43, 35, 27, 19, 11, 3,
                     61, 53, 45, 37, 29, 21, 13, 5,
                     63, 55, 47, 39, 31, 23, 15, 7};
//���ʼ�û���?
uint8_t pc_ip_1[64] = {40, 8, 48, 16, 56, 24, 64, 32,
                       39, 7, 47, 15, 55, 23, 63, 31,
                       38, 6, 46, 14, 54, 22, 62, 30,
                       37, 5, 45, 13, 53, 21, 61, 29,
                       36, 4, 44, 12, 52, 20, 60, 28,
                       35, 3, 43, 11, 51, 19, 59, 27,
                       34, 2, 42, 10, 50, 18, 58, 26,
                       33, 1, 41, 9, 49, 17, 57, 25};

// E����չ�任
uint8_t pc_e[48] = {32, 1, 2, 3, 4, 5,
                    4, 5, 6, 7, 8, 9,
                    8, 9, 10, 11, 12, 13,
                    12, 13, 14, 15, 16, 17,
                    16, 17, 18, 19, 20, 21,
                    20, 21, 22, 23, 24, 25,
                    24, 25, 26, 27, 28, 29,
                    28, 29, 30, 31, 32, 1};

// S��
uint8_t s_box[8][4][16] = {
    14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
    0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
    4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
    15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13,

    15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
    3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
    0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
    13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 10, 5, 14, 9,

    10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
    13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
    13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
    1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12,

    7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
    13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
    10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
    3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14,

    2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
    14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
    4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
    11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3,

    12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
    10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
    9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
    4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13,

    4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
    13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
    1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
    6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12,

    13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
    1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
    7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
    2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11};

// P���û���
uint8_t pc_p[32] = {16, 7, 20, 21,
                    29, 12, 28, 17,
                    1, 15, 23, 26,
                    5, 18, 31, 10,
                    2, 8, 24, 14,
                    32, 27, 3, 9,
                    19, 13, 30, 6,
                    22, 11, 4, 25};

//�û�ѡ��PC-1
uint8_t pc_1[56] = {57, 49, 41, 33, 25, 17,
                    9, 1, 58, 50, 42, 34, 26,
                    18, 10, 2, 59, 51, 43, 35,
                    27, 19, 11, 3, 60, 52, 44,
                    36, 63, 55, 47, 39, 31, 23,
                    15, 7, 62, 54, 46, 38, 30,
                    22, 14, 6, 61, 53, 45, 37,
                    29, 21, 13, 5, 28, 20, 12, 4};

//�û�ѡ��PC-2
uint8_t pc_2[48] = {14, 17, 11, 24, 1, 5,
                    3, 28, 15, 6, 21, 10,
                    23, 19, 12, 4, 26, 8,
                    16, 7, 27, 20, 13, 2,
                    41, 52, 31, 37, 47, 55,
                    30, 40, 51, 45, 33, 48,
                    44, 49, 39, 56, 34, 53,
                    46, 42, 50, 36, 29, 32};

void print_bit(bitset<32> bs)
{
    rep(i, 0, 4)
    {
        rep(j, 0, 8)
        {
            cout << bs[i * 8 + j];
        }
        cout << endl;
    }
}

void print_bitsets_by_hex(bitset<64> *bses, int bslen)
{
    rep(i, 0, bslen)
    {
        for (int j = 0; j < 64; j += 4)
        {
            int t = bses[i][j] * 8 + bses[i][j + 1] * 4 + bses[i][j + 2] * 2 + bses[i][j + 3];
            printf("%lx", t);
        }
        printf("\n");
    }
    printf("\n");
}


bitset<64> _initial_permutation(bitset<64> origin)
{
    bitset<64> after_ip;
    rep(i, 0, 64)
    {
        // after_ip[pc_ip[i] - 1] = origin[i];
        after_ip[i] = origin[pc_ip[i] - 1];
    }
    return after_ip;
}

bitset<64> *initial_permutation(bitset<64> *origins, int bslen)
{
    bitset<64> *copys = (bitset<64> *)malloc(bslen * 8);
    // memcpy(copy, origins, bslen * 8);
    rep(i, 0, bslen)
    {
        copys[i] = _initial_permutation(origins[i]);
    }
    return copys;
}

bitset<32> _get_bit64_left(bitset<64> bs)
{
    bitset<32> li;
    rep(i, 0, 32)
    {
        li[i] = bs[i];
    }
    return li;
}
bitset<32> _get_bit64_right(bitset<64> bs)
{
    bitset<32> ri;
    rep(i, 0, 32)
    {
        ri[i] = bs[i + 32];
    }
    return ri;
}

bitset<64> _merge_two_bit32(bitset<32> left, bitset<32> right)
{
    bitset<64> res;
    rep(i, 0, 32)
    {
        res[i] = left[i];
        res[i + 32] = right[i];
    }
    return res;
}

bitset<48> e_box_extend(bitset<32> input)
{
    bitset<48> output;
    rep(i, 0, 48)
    {
        output[i] = input[pc_e[i] - 1];
    }
    return output;
}

bitset<32> func_F(bitset<32> input, bitset<48> ki)
{
    bitset<32> output;
    bitset<48> after_e_box = e_box_extend(input);
    bitset<48> after_xor;
    // rep(i, 0, 48)
    // {
    //     after_xor[i] = after_e_box[i] ^ ki[i];
    // }
    after_xor = after_e_box ^ ki;
    bitset<32> after_s_box;
    rep(i, 0, 8)
    {
        int row = after_xor[i * 6] * 2 + after_xor[i * 6 + 5];
        int col = after_xor[i * 6 + 1] * 8 + after_xor[i * 6 + 2] * 4 + after_xor[i * 6 + 3] * 2 + after_xor[i * 6 + 4];
        uint8_t s_box_res = s_box[i][row][col];
        for (int j = 3; j >= 0; j--)
        {
            after_s_box[i * 4 + j] = s_box_res % 2;
            s_box_res >>= 1;
        }
    }
    rep(i, 0, 32)
    {
        output[i] = after_s_box[pc_p[i] - 1];
    }
    return output;
}

bitset<56> key_pc1_transform(bitset<64> pw_bs)
{
    bitset<56> res;
    rep(i, 0, 56)
    {
        res[i] = pw_bs[pc_1[i] - 1];
    }
    return res;
}

bitset<28> left_cyclic_shift_28(bitset<28> bs)
{
    bitset<28> res;
    // rep(i, 0, 27)
    // {
    //     res[i + 1] = bs[i];
    // }
    // res[0] = bs[27];
    rep(i, 1, 28)
    {
        res[i - 1] = bs[i];
    }
    res[27] = bs[0];
    return res;
}

bitset<48> *gen_sub_keys(bitset<64> pw_bs)
{
    // not use res[0]
    // string strval("0001001100110100010101110111100110011011101111001101111111110001");
    // bitset<64> pw_bs1(strval);
    bitset<48> *res = (bitset<48> *)malloc(17 * sizeof(bitset<48>));
    bitset<56> after_pc1_key = key_pc1_transform(pw_bs);
    bitset<28> C0, D0;
    rep(i, 0, 28)
    {
        C0[i] = after_pc1_key[i];
        D0[i] = after_pc1_key[i + 28];
    }
    bitset<28> C[17], D[17];
    C[0] = C0;
    D[0] = D0;
    for (int i = 1; i <= 16; i++)
    {
        if (i == 1 || i == 2 || i == 9 || i == 16)
        {
            C[i] = left_cyclic_shift_28(C[i - 1]);
            D[i] = left_cyclic_shift_28(D[i - 1]);
        }
        else
        {
            C[i] = left_cyclic_shift_28(C[i - 1]);
            C[i] = left_cyclic_shift_28(C[i]);
            D[i] = left_cyclic_shift_28(D[i - 1]);
            D[i] = left_cyclic_shift_28(D[i]);
        }
    }
    for (int i = 1; i <= 16; i++)
    {
        bitset<56> tmp;
        rep(j, 0, 28)
        {
            tmp[j] = C[i][j];
        }
        rep(j, 28, 56)
        {
            tmp[j] = D[i][j - 28];
        }
        rep(j, 0, 48)
        {
            res[i][j] = tmp[pc_2[j] - 1];
        }
    }
    return res;
}

bitset<64> one_round(bitset<32> li, bitset<32> ri, bitset<48> ki)
{
    bitset<64> output_after_swap;
    bitset<32> output_func_F = func_F(ri, ki);
    bitset<32> after_xor;
    rep(i, 0, 32)
    {
        after_xor[i] = li[i] ^ output_func_F[i];
    }
    output_after_swap = _merge_two_bit32(ri, after_xor);
    return output_after_swap;
}

bitset<64> *encrypt(bitset<64> *plains, int bslen, bitset<64> pw_bs, bool reverse)
{
    bitset<64> *ciphers = (bitset<64> *)malloc(bslen * 8);
    // ��ʼ�û�
    bitset<64> *after_ips = initial_permutation(plains, bslen);
    cout<<"\nAfter initial permutation:\n";
    print_bitsets_by_hex(after_ips,bslen);
    cout<<endl;
    bitset<48> *sub_keys = gen_sub_keys(pw_bs);
    rep(i, 0, bslen)
    {
        bitset<64> block = after_ips[i];
        bitset<32> li = _get_bit64_left(block);
        bitset<32> ri = _get_bit64_right(block);
        cout<<"block ["<<i<<"]\n";
        print_bitsets_by_hex(&block,1);
        cout<<endl;
        int round = 1;
        for (; round <= 16; round++)
        {
            int _round;
            if (reverse)
            {
                _round = 17 - round;
            }
            else
            {
                _round = round;
            }
            bitset<64> this_round_output = one_round(li, ri, sub_keys[_round]);
            li = _get_bit64_left(this_round_output);
            ri = _get_bit64_right(this_round_output);
            cout<<"  round ["<<round<<"]\n";
            cout<<"  left:\n";
            print_bit(li);
            cout<<"  right:\n";
            print_bit(ri);
            cout<<endl;
        }
        bitset<64> encrypted_block = _merge_two_bit32(ri, li);
        cout<<"Swap left and right:\n";
        print_bitsets_by_hex(&encrypted_block,1);
        cout<<"after IP^-1:\n";
        bitset<64> after_ip_1;
        rep(j, 0, 64)
        {
            after_ip_1[j] = encrypted_block[pc_ip_1[j] - 1];
        }
        print_bitsets_by_hex(&after_ip_1,1);
        cout<<endl;
        ciphers[i] = after_ip_1;
    }
    return ciphers;
}

string bitsets_to_str(bitset<64> bses[], int bytes)
{
    // bytes: size of bses
    char *chs = (char *)malloc(bytes);
    memset(chs, 0, bytes);
    for (int i = 0; i < bytes; i++)
    {
        uint8_t c = 0;
        for (int j = 0; j < 8; j++)
        {
            c <<= 1;
            c += bses[i / 8][(i % 8) * 8 + j];
        }
        chs[i] = c;
        //cout << (int)c << endl;
    }
    return string(chs);
}

bitset<64> *hex_to_bitsets(char *s, int *out_len)
{
    int cnt = 0;
    for (; s[cnt] != 0; cnt++)
    {
    }
    int bslen = -1;
    if (cnt % 16 == 0)
    {
        bslen = cnt / 16;
    }
    else
    {
        bslen = cnt / 16 + 1;
    }
    bitset<64> *res = (bitset<64> *)malloc(bslen * sizeof(bitset<64>));
    memset(res, 0, bslen * sizeof(bitset<64>));
    rep(i, 0, bslen)
    {
        for (int j = 0; j < 16 && i * 16 + j < cnt; j++)
        {
            char c = s[i * 16 + j];
            if (c >= '0' && c <= '9')
            {
                c -= '0';
            }
            else if (c >= 'A' && c <= 'F')
            {
                c -= 55; //'A'-10
            }
            else if (c >= 'a' && c <= 'f')
            {
                c -= 87; //'a'-10
            }
            else
            {
                cout << "There exist characters that cannot be converted to Hex. Check your input.\n";
                throw "There exist characters that cannot be converted to Hex";
                exit(1);
            }
            for (int k = 3; k >= 0; k--)
            {
                if (c % 2)
                {
                    res[i].set(j * 4 + k);
                }
                c /= 2;
            }
        }
    }
    *out_len = bslen;
    return res;
}

bitset<64> *str_to_bitsets(string s, int *out_len)
{
    int slen = s.length();
    int bslen = -1;
    if (slen % 8 == 0)
    {
        bslen = slen / 8;
    }
    else
    {
        bslen = slen / 8 + 1;
    }
    *out_len = bslen;
    bitset<64> *res = (bitset<64> *)malloc(bslen * 8);
    memset(res, 0, bslen * 8);
    rep(i, 0, bslen)
    {
        int jr = 8;
        if (i == bslen - 1)
        {
            jr = slen - 8 * i;
        }
        for (int j = 0; j < jr; j++)
        {
            char c = s[i * 8 + j];
            for (int k = 0; k < 8; k++)
            {
                if (c % 2)
                {
                    res[i].set(j * 8 + 7 - k);
                }
                else
                {
                    res[i].reset(j * 8 + 7 - k);
                }
                c /= 2;
            }
        }
    }
    return res;
}

// bitset<64> *reverse_bitsets(bitset<64> *bses, int bytes)
// {
//     bitset<64> *res = (bitset<64> *)malloc(bytes);
//     rep(i, 0, bytes)
//     {
//         for (int j = 0; j < 64; j += 8)
//         {
//         }
//     }
// }

void console_input_plain()
{
    char plaintext[MAX_PLAINTEXT_LEN];
    cout << "Plaintext to be encrypted (in one line) : \n";
    memset(plaintext, 0, MAX_PLAINTEXT_LEN);
    cin.getline(plaintext, MAX_PLAINTEXT_LEN);
    cout << "Select the type of PLAINTEXT you enter:\n  [S]tring (default)\n  [H]ex\n";
    string option;
    bool is_plaintext_string = true;
    cin >> option;
    if (option[0] == 'H' || option[0] == 'h')
    {
        is_plaintext_string = false;
    }
    string str(plaintext);
    int bslen;
    bitset<64> *bses;
    if (is_plaintext_string)
    {
        bses = str_to_bitsets(str, &bslen);
    }
    else
    {
        bses = hex_to_bitsets(plaintext, &bslen);
    }
    cout << "\nThe length of the plaintext you typed in: " << str.length() << endl;

    cout << "Key for encryption: \n";
    string password;
    cin >> password;
    cout << "Select the type of KEY you enter:\n  [S]tring (default)\n  [H]ex\n";
    bool is_key_string = true;
    cin >> option;
    bitset<64> pw_bs;
    if (option[0] == 'H' || option[0] == 'h')
    {
        is_key_string = false;
    }
    int pw_bs_len;
    if (is_key_string)
    {
        pw_bs = str_to_bitsets(password, &pw_bs_len)[0];
    }
    else
    {
        pw_bs = hex_to_bitsets(const_cast<char *>(password.c_str()), &pw_bs_len)[0];
    }
    cout << "The length of the key you typed in: " << password.length() << endl;
    if (password.length() > 8 && is_key_string || password.length() > 16 && !is_key_string)
    {
        cout << "WARNING: The key you entered exceeds 64 bits, and the exceeded part will be abandoned.\n";
    }

    bitset<64> *enceds = encrypt(bses, bslen, pw_bs, false);

    cout << "Encryption result (hex):\n";
    print_bitsets_by_hex(enceds, bslen);
    bitset<64> *deceds = encrypt(enceds, bslen, pw_bs, true);
    cout << "The plaintext you typed in (hex):\n";
    print_bitsets_by_hex(deceds, bslen);
}

void console_input_cipher()
{
    char plaintext[MAX_PLAINTEXT_LEN];
    cout << "Ciphertext to be encrypted (in one line) : \n(Hex): ";
    memset(plaintext, 0, MAX_PLAINTEXT_LEN);
    cin.getline(plaintext, MAX_PLAINTEXT_LEN);

    string str(plaintext);
    int bslen;
    bitset<64> *bses;
    bses = hex_to_bitsets(plaintext, &bslen);

    cout << "\nThe length of the ciphertext you typed in: " << str.length() << endl;

    cout << "Key for decryption: \n";
    string password;
    cin >> password;
    cout << "Select the type of KEY you enter:\n  [S]tring (default)\n  [H]ex\n";
    bool is_key_string = true;
    string option;
    cin >> option;
    bitset<64> pw_bs;
    if (option[0] == 'H' || option[0] == 'h')
    {
        is_key_string = false;
    }
    int pw_bs_len;
    if (is_key_string)
    {
        pw_bs = str_to_bitsets(password, &pw_bs_len)[0];
    }
    else
    {
        pw_bs = hex_to_bitsets(const_cast<char *>(password.c_str()), &pw_bs_len)[0];
    }
    cout << "The length of the key you typed in: " << password.length() << endl;
    if (password.length() > 8 && is_key_string || password.length() > 16 && !is_key_string)
    {
        cout << "WARNING: The key you entered exceeded 64 bits, and the exceeded part will be abandoned.\n";
    }

    bitset<64> *enceds = encrypt(bses, bslen, pw_bs, true);

    cout << "Decryption result (hex):\n";
    print_bitsets_by_hex(enceds, bslen);
    cout << "\nDecryption result (string):\n";
    cout << bitsets_to_str(enceds, 8 * bslen)<<endl;

    bitset<64> *deceds = encrypt(enceds, bslen, pw_bs, false);
    cout << "The ciphertext you typed in (hex):\n";
    print_bitsets_by_hex(deceds, bslen);
}

int main()
{
    string option;
    cout<<"Data Encryption Standard (DES) ECB Mode (zero padding) \n(Designed for network security course homework)\n";
    cout << "Do you want to encrypt or decrypt?\n  [E]ncrypt (default)\n  [D]ecrypt\n";
    cin >> option;
    getchar();
    if (option[0] == 'd' || option[0] == 'D')
    {
        console_input_cipher();
    }
    else
    {
        console_input_plain();
    }

    // // string res = bitsets_to_str(bses, str.length() + 8);
    // // cout << res << endl;
    // cout << "������" << endl;
    // cout << "-------" << endl;
    // // bitset ʹ��������ʼ��bitset
    // bitset<3> bs(3);
    // //���bs����λ��ֵ
    // cout << "bs[0] is " << bs[0] << endl;
    // cout << "bs[1] is " << bs[1] << endl;
    // cout << "bs[2] is " << bs[2] << endl;
    // //����������׳�outofindexexception
    // // cout<<"bs[3] is "<<bs[3]<<endl;
    // //ʹ���ַ�����ʼ��bitset
    // //ע�⣺ʹ��string��ʼ��ʱ���������������³�ʼ���ĸ���λ��ֵ����110������011
    // string strVal("011");
    // bitset<3> bs1(strVal);
    // //������?
    // cout << "bs1[0] is " << bs1[0] << endl;
    // cout << "bs1[1] is " << bs1[1] << endl;
    // cout << "bs1[2] is " << bs1[2] << endl;
    // // cout���ʱҲ�Ǵ��ұ���������?
    // cout << bs1 << endl;
    // // bitset�ķ���
    // // any()���������һλ�?1���򷵻�1
    // cout << "bs1.any() = " << bs1.any() << endl;
    // // none()�����������һ���?1none�򷵻�0�����ȫ�?0�򷵻�1
    // bitset<3> bsNone;
    // cout << "bsNone.none() = " << bsNone.none() << endl;
    // // count()���ؼ���λΪ1
    // cout << "bs1.count() = " << bs1.count() << endl;
    // // size()����λ��
    // cout << "bs1.size() = " << bs1.size() << endl;
    // // test()����ĳһλ�Ƿ�Ϊ1
    // // flip()��λȡ��
    // bitset<3> bsFlip = bs1.flip();
    // cout << "bsFlip = " << bsFlip << endl;
    // // to_ulong
    // unsigned long val = bs1.to_ulong();
    // cout << val;
    return 0;
}
